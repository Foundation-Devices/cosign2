pub use {
    secp256k1::{ecdsa::Signature, PublicKey, SecretKey},
    semver::Version,
};
use {
    sha2::Digest,
    std::{
        io::{Read, Write},
        str::FromStr,
    },
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct Header {
    magic: Magic,
    timestamp: Timestamp,
    date: Date,
    version: semver::Version,
    firmware_size: u32,
    pubkey1: Option<PublicKey>,
    signature1: secp256k1::ecdsa::Signature,
    pubkey2: Option<PublicKey>,
    signature2: secp256k1::ecdsa::Signature,
    /// Hash of the header (without signatures) and firmware code.
    hash: secp256k1::Message,
}

impl Header {
    /// Number of reserved bytes at the end of the header.
    ///
    /// These must be zeroed out when writing the header.
    const RESERVED: usize = 1808;

    /// Magic number.
    pub fn magic(&self) -> Magic {
        self.magic
    }

    /// Firmware timestamp.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Human-readable firmware date.
    pub fn date(&self) -> Date {
        self.date
    }

    /// Firmware version.
    pub fn version(&self) -> &semver::Version {
        &self.version
    }

    /// The size of the firmware.
    pub fn firmware_size(&self) -> u32 {
        self.firmware_size
    }

    /// Public key of the first signer.
    ///
    /// Returns `None` if the first signer is not present. In this case,
    /// [`signature1`] will be zeroed out.
    pub fn pubkey1(&self) -> Option<PublicKey> {
        self.pubkey1
    }

    /// First signature.
    pub fn signature1(&self) -> Signature {
        self.signature1
    }

    /// Public key of the second signer.
    ///
    /// Returns `None` if the second signer is not present. In this case,
    /// [`signature2`] will be zeroed out.
    pub fn pubkey2(&self) -> Option<PublicKey> {
        self.pubkey2
    }

    /// Second signature.
    pub fn signature2(&self) -> Signature {
        self.signature2
    }

    /// Create a new header and sign it.
    pub fn sign_new(
        magic: Magic,
        version: semver::Version,
        firmware_size: u32,
        signer: &Signer,
        mut data: impl Read,
    ) -> Result<Self, Error> {
        // Check version length.
        if version.to_string().len() > VERSION_SIZE {
            return Err(Error::VersionTooLong);
        }

        // Create the header and calculate the hash to sign.
        let timestamp = Timestamp::now();
        let mut header = Self {
            magic,
            timestamp,
            date: timestamp.date(),
            version,
            firmware_size,
            pubkey1: None,
            signature1: Signature::from_compact(&[0; 64]).expect("64 bytes"),
            pubkey2: None,
            signature2: Signature::from_compact(&[0; 64]).expect("64 bytes"),
            hash: secp256k1::Message::from_digest([0; 32]),
        };
        header.calculate_hash(&mut data)?;

        // Sign the header.
        match signer {
            Signer::Trusted(key) => {
                // Trusted key is used, so both first and second signatures need to be filled
                // in. This key is used for the first signature.
                let secp = secp256k1::Secp256k1::new();
                let pubkey = PublicKey::from_secret_key(&secp, key);
                let signature = secp.sign_ecdsa(&header.hash, key);
                header.pubkey1 = Some(pubkey);
                header.signature1 = signature;
            }
            Signer::Developer(key) => {
                // Developer key is used, so only the second signature is filled in.
                // The first signature is left empty (zeroed out).
                let secp = secp256k1::Secp256k1::new();
                let pubkey = PublicKey::from_secret_key(&secp, key);
                let signature = secp.sign_ecdsa(&header.hash, key);
                header.pubkey2 = Some(pubkey);
                header.signature2 = signature;
            }
        }

        Ok(header)
    }

    /// Parse a header from a reader.
    ///
    /// If the header is missing, `None` is returned, and only one byte is
    /// consumed from the reader. Otherwise, the reader is advanced to the end.
    pub fn parse(mut r: impl Read) -> Result<Option<Self>, Error> {
        // Parse all of the header fields.
        let Some(magic) = read_u32(&mut r)?.and_then(Magic::from_u32) else {
            // Magic value is missing or not recognized, so this is not a header.
            return Ok(None);
        };
        let timestamp = Timestamp::new(read_u32(&mut r)?.ok_or(Error::HeaderTooShort)?)?;
        // Parse the version string, terminating at the first zero byte.
        let version = read::<VERSION_SIZE>(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let first_zero = version.iter().position(|&b| b == 0).unwrap_or(VERSION_SIZE);
        let version =
            std::str::from_utf8(&version[..first_zero]).map_err(|_| Error::HeaderTooShort)?;
        let version =
            semver::Version::from_str(version).map_err(|_| Error::InvalidVersionSemver)?;
        let date = Date(read(&mut r)?.ok_or(Error::HeaderTooShort)?);
        let firmware_size = read_u32(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let pubkey1 = read::<33>(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let pubkey1 = if pubkey1 == [0; 33] {
            None
        } else {
            Some(PublicKey::from_slice(&pubkey1).map_err(|_| Error::InvalidPubkey1)?)
        };
        let signature1 =
            Signature::from_compact(&read::<64>(&mut r)?.ok_or(Error::HeaderTooShort)?)
                .map_err(|_| Error::InvalidSignature1)?;
        let pubkey2 = read::<33>(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let pubkey2 = if pubkey2 == [0; 33] {
            None
        } else {
            Some(PublicKey::from_slice(&pubkey2).map_err(|_| Error::InvalidPubkey2)?)
        };
        let signature2 =
            Signature::from_compact(&read::<64>(&mut r)?.ok_or(Error::HeaderTooShort)?)
                .map_err(|_| Error::InvalidSignature2)?;

        let signature1_zero = signature1.serialize_compact() == [0; 64];
        let signature2_zero = signature2.serialize_compact() == [0; 64];

        // There should always be at least one signature.
        if signature1_zero && signature2_zero {
            return Err(Error::HeaderWithNoSignature);
        }

        // Check that the reserved bytes are all zero.
        let reserved = read::<{ Self::RESERVED }>(&mut r)?.ok_or(Error::HeaderTooShort)?;
        if reserved.iter().any(|&b| b != 0) {
            return Err(Error::InvalidReservedBytes);
        }

        // Create the header and calculate the hash for signature verification.
        let mut header = Self {
            magic,
            timestamp,
            date,
            version,
            firmware_size,
            pubkey1,
            signature1,
            pubkey2,
            signature2,
            hash: secp256k1::Message::from_digest([0; 32]),
        };
        header.calculate_hash(&mut r)?;

        // Verify the signatures.
        let secp = secp256k1::Secp256k1::new();
        if signature1_zero {
            if pubkey1.is_some() {
                return Err(Error::InvalidSignature1);
            }
        } else {
            let pubkey = pubkey1.ok_or(Error::InvalidPubkey1)?;
            if pubkey.verify(&secp, &header.hash, &signature1).is_err() {
                return Err(Error::InvalidSignature1);
            }
        }
        if signature2_zero {
            if pubkey2.is_some() {
                return Err(Error::InvalidSignature2);
            }
        } else {
            let pubkey = pubkey2.ok_or(Error::InvalidPubkey2)?;
            if pubkey.verify(&secp, &header.hash, &signature2).is_err() {
                return Err(Error::InvalidSignature2);
            }
        }

        Ok(Some(header))
    }

    /// Serialize the header to a writer.
    pub fn serialize(&self, mut w: impl Write) -> Result<(), Error> {
        self.serialize_without_signatures(&mut w)?;
        if let Some(pubkey) = &self.pubkey1 {
            w.write_all(&pubkey.serialize())?;
        } else {
            w.write_all(&[0; 33])?;
        }
        w.write_all(&self.signature1.serialize_compact())?;
        if let Some(pubkey) = &self.pubkey2 {
            w.write_all(&pubkey.serialize())?;
        } else {
            w.write_all(&[0; 33])?;
        }
        w.write_all(&self.signature2.serialize_compact())?;
        w.write_all(&[0; Self::RESERVED])?;
        Ok(())
    }

    /// Serialize the header without the signatures.
    fn serialize_without_signatures(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(&self.magic.as_u32().to_le_bytes())?;
        w.write_all(&self.timestamp.secs_since_epoch().to_le_bytes())?;
        w.write_all(self.version.to_string().as_bytes())?;
        w.write_all(&self.date.0)?;
        w.write_all(&self.firmware_size.to_le_bytes())?;
        Ok(())
    }

    /// Add a second signature to the header.
    ///
    /// The first signature must be present, and the second signature must be
    /// missing, otherwise an error is returned.
    pub fn add_second_signature(&mut self, key: &SecretKey) -> Result<(), Error> {
        if self.signature1.serialize_compact() == [0; 64] {
            return Err(Error::FirstSignatureMissing);
        }
        if self.signature2.serialize_compact() != [0; 64] {
            return Err(Error::SecondSignaturePresent);
        }
        let secp = secp256k1::Secp256k1::new();
        self.pubkey2 = Some(key.public_key(&secp));
        self.signature2 = secp.sign_ecdsa(&self.hash, key);
        Ok(())
    }

    /// Calculate the hash of the header and firmware code.
    ///
    /// Updates the `hash` field of the header.
    fn calculate_hash(&mut self, data: &mut impl Read) -> Result<(), Error> {
        // Calculate the hash of the header and firmware code.
        let mut hasher = sha2::Sha256::new();
        // First hash the header itself.
        self.serialize_without_signatures(&mut hasher)?;
        // Hash the firmware code.
        let mut buf = [0; 1024];
        loop {
            let n = data.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let hash = hasher.finalize();

        // Do a second hash to avoid length extension attacks.
        self.hash =
            secp256k1::Message::from_digest_slice(&sha2::Sha256::digest(hash)).expect("32 bytes");

        Ok(())
    }
}

const VERSION_SIZE: usize = 20;

/// Who is signing the firmware.
pub enum Signer {
    /// Trusted key from Foundation Devices, Inc.
    ///
    /// Headers signed by trusted keys expect both signatures to be filled in.
    Trusted(SecretKey),
    /// Third-party developer key.
    ///
    /// Headers signed by developer keys expect only the second signature to be
    /// filled in. The first signature is left empty (zeroed out).
    Developer(SecretKey),
}

/// Magic number.
///
/// Used to identify the header, and to differentiate header formats for
/// different devices if needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Atsama5d27KeyOs,
}

impl Magic {
    /// Convert a u32 to a magic number.
    ///
    /// Returns `None` if the value is not recognized.
    fn from_u32(n: u32) -> Option<Self> {
        match n {
            0x12345678 => Some(Self::Atsama5d27KeyOs),
            _ => None,
        }
    }

    fn as_u32(&self) -> u32 {
        match self {
            Self::Atsama5d27KeyOs => 0x12345678,
        }
    }
}

/// A timestamp in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(chrono::DateTime<chrono::Utc>);

impl Timestamp {
    /// Create the timestamp given the number of seconds since the Unix epoch.
    fn new(timestamp: u32) -> Result<Self, Error> {
        chrono::DateTime::from_timestamp(timestamp.into(), 0)
            .ok_or(Error::InvalidTimestamp)
            .map(Self)
    }

    /// The timestamp at this moment.
    fn now() -> Self {
        Self(chrono::Utc::now())
    }

    /// The timestamp as seconds since the Unix epoch.
    pub fn secs_since_epoch(&self) -> u32 {
        self.0.timestamp().try_into().expect("year 2106")
    }

    /// The timestamp as a human-readable date.
    fn date(&self) -> Date {
        let mut buf = [0; 14];
        let date = self.0.format("%b %d %Y").to_string();
        let date = date.as_bytes();
        if date.len() > buf.len() {
            panic!(
                "date too long ({} > {}), should never happen",
                date.len(),
                buf.len()
            );
        }
        buf[..date.len()].copy_from_slice(date);
        Date(buf)
    }
}

/// Human-readable date.
///
/// Used for displaying in the firmware, where advanced date manipulation
/// functions are not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date([u8; 14]);

/// Read a fixed-size buffer from a reader.
///
/// If there are not enough bytes to read, `None` is returned.
fn read<const N: usize>(r: &mut impl Read) -> std::io::Result<Option<[u8; N]>> {
    let mut buf = [0; N];
    let n = r.read(&mut buf)?;
    if n != buf.len() {
        Ok(None)
    } else {
        Ok(Some(buf))
    }
}

/// Read a little-endian u32 from a reader.
///
/// Returns `None` if there are not enough bytes to read.
fn read_u32(r: &mut impl Read) -> std::io::Result<Option<u32>> {
    let mut buf = [0; 4];
    let n = r.read(&mut buf)?;
    if n != buf.len() {
        Ok(None)
    } else {
        Ok(Some(u32::from_le_bytes(buf)))
    }
}

#[derive(Debug)]
pub enum Error {
    HeaderWithNoSignature,
    HeaderTooShort,
    InvalidTimestamp,
    InvalidReservedBytes,
    DuplicatePubkeys,
    InvalidVersionUtf8,
    VersionTooLong,
    InvalidVersionSemver,
    InvalidPrivateKey,
    InvalidPubkey1,
    InvalidPubkey2,
    InvalidSignature1,
    InvalidSignature2,
    FirstSignatureMissing,
    SecondSignaturePresent,
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
