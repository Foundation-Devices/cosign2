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
    magic: [u8; 4],
    timestamp: [u8; 4],
    date: [u8; 14],
    version: [u8; 20],
    firmware_size: [u8; 4],
    pubkey1: [u8; 33],
    signature1: [u8; 64],
    pubkey2: [u8; 33],
    signature2: [u8; 64],
    /// Reserved zero bytes at the end of the header.
    reserved: [u8; 1808],
    /// Hash of the header and firmware code.
    hash: secp256k1::Message,
}

impl Header {
    /// Size of the header in bytes.
    pub const SIZE: usize = 2048;

    /// Magic number.
    pub fn magic(&self) -> Magic {
        Magic::from_bytes(self.magic).expect("validated")
    }

    /// Firmware timestamp in seconds since the Unix epoch.
    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes(self.timestamp)
    }

    /// Human-readable firmware date.
    ///
    /// Used for displaying the firmware date during device boot, where advanced
    /// date manipulation functions are not available.
    pub fn date(&self) -> String {
        let first_zero = self
            .date
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.date.len());
        std::str::from_utf8(&self.date[..first_zero])
            .expect("validated")
            .to_string()
    }

    /// Firmware version.
    pub fn version(&self) -> semver::Version {
        let first_zero = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.version.len());
        let version = std::str::from_utf8(&self.version[..first_zero]).expect("validated");
        semver::Version::from_str(version).expect("validated")
    }

    /// The size of the firmware.
    pub fn firmware_size(&self) -> u32 {
        u32::from_le_bytes(self.firmware_size)
    }

    /// Public key of the first signer.
    ///
    /// Returns `None` if the first signer is not present. In this case,
    /// [`signature1`] will be zeroed out.
    pub fn pubkey1(&self) -> Option<secp256k1::PublicKey> {
        if self.pubkey1 == [0; 33] {
            return None;
        }
        Some(secp256k1::PublicKey::from_slice(&self.pubkey1).expect("validated"))
    }

    /// First signature.
    pub fn signature1(&self) -> secp256k1::ecdsa::Signature {
        secp256k1::ecdsa::Signature::from_compact(&self.signature1).expect("validated")
    }

    /// Public key of the second signer.
    ///
    /// Returns `None` if the second signer is not present. In this case,
    /// [`signature2`] will be zeroed out.
    pub fn pubkey2(&self) -> Option<secp256k1::PublicKey> {
        if self.pubkey2 == [0; 33] {
            return None;
        }
        Some(secp256k1::PublicKey::from_slice(&self.pubkey2).expect("validated"))
    }

    /// Second signature.
    pub fn signature2(&self) -> secp256k1::ecdsa::Signature {
        secp256k1::ecdsa::Signature::from_compact(&self.signature2).expect("validated")
    }

    /// Create a new header and sign it.
    pub fn sign_new(
        magic: Magic,
        version: semver::Version,
        firmware_size: u32,
        signer: &Signer,
        data: impl Read,
    ) -> Result<Self, Error> {
        let time = chrono::Utc::now();
        let mut header = Self {
            magic: magic.as_bytes(),
            timestamp: u32::try_from(time.timestamp())
                .expect("year 2106")
                .to_le_bytes(),
            date: [0; 14],
            version: [0; 20],
            firmware_size: firmware_size.to_le_bytes(),
            pubkey1: [0; 33],
            signature1: [0; 64],
            pubkey2: [0; 33],
            signature2: [0; 64],
            reserved: [0; 1808],
            hash: secp256k1::Message::from_digest([0; 32]),
        };
        header.set_date(time);
        header.set_version(version)?;
        header.hash_and_validate(data, &[])?;

        // Sign the header.
        match signer {
            Signer::Trusted(key) => {
                // Trusted key is used, so both first and second signatures need to be filled
                // in. This key is used for the first signature.
                let secp = secp256k1::Secp256k1::new();
                let pubkey = secp256k1::PublicKey::from_secret_key(&secp, key);
                let signature = secp.sign_ecdsa(&header.hash, key);
                header.pubkey1 = pubkey.serialize();
                header.signature1 = signature.serialize_compact();
            }
            Signer::Developer(key) => {
                // Developer key is used, so only the second signature is filled in.
                // The first signature is left empty (zeroed out).
                let secp = secp256k1::Secp256k1::new();
                let pubkey = secp256k1::PublicKey::from_secret_key(&secp, key);
                let signature = secp.sign_ecdsa(&header.hash, key);
                header.pubkey2 = pubkey.serialize();
                header.signature2 = signature.serialize_compact();
            }
        }

        Ok(header)
    }

    /// Parse a header from a reader.
    ///
    /// Verifies that any existing signatures are signed by the given known
    /// signers. If the known signers slice is empty, any signer is
    /// accepted.
    ///
    /// If the header is missing, `None` is returned, and only the first four
    /// bytes are consumed from the reader. Otherwise, the reader is
    /// advanced to the end.
    pub fn parse(
        mut r: impl Read,
        known_signers: &[secp256k1::PublicKey],
    ) -> Result<Option<Self>, Error> {
        let magic = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        if Magic::from_bytes(magic).is_none() {
            // Magic value is missing or not recognized, so this is not a header.
            return Ok(None);
        }

        let timestamp = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let version = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let date = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let firmware_size = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let pubkey1 = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let signature1 = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let pubkey2 = read(&mut r)?.ok_or(Error::HeaderTooShort)?;
        let signature2 = read(&mut r)?.ok_or(Error::HeaderTooShort)?;

        dbg!(signature1, signature2);
        // When parsing an existing header, there should always be at least one
        // signature.
        if signature1 == [0; 64] && signature2 == [0; 64] {
            return Err(Error::HeaderWithNoSignature);
        }

        let reserved = read(&mut r)?.ok_or(Error::HeaderTooShort)?;

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
            reserved,
            hash: secp256k1::Message::from_digest([0; 32]),
        };

        header.hash_and_validate(r, known_signers)?;

        Ok(Some(header))
    }

    /// Serialize the header to a writer.
    pub fn serialize(&self, mut w: impl Write) -> Result<(), Error> {
        w.write_all(&self.magic)?;
        w.write_all(&self.timestamp)?;
        w.write_all(&self.version)?;
        w.write_all(&self.date)?;
        w.write_all(&self.firmware_size)?;
        w.write_all(&self.pubkey1)?;
        w.write_all(&self.signature1)?;
        w.write_all(&self.pubkey2)?;
        w.write_all(&self.signature2)?;
        w.write_all(&self.reserved)?;
        Ok(())
    }

    /// Add a second signature to the header.
    ///
    /// The first signature must be present, and the second signature must be
    /// missing, otherwise an error is returned.
    pub fn add_second_signature(&mut self, key: &secp256k1::SecretKey) -> Result<(), Error> {
        if self.signature1 == [0; 64] {
            return Err(Error::Signature1Missing);
        }
        if self.signature2 != [0; 64] {
            return Err(Error::Signature2Present);
        }
        let secp = secp256k1::Secp256k1::new();
        self.pubkey2 = key.public_key(&secp).serialize();
        self.signature2 = secp.sign_ecdsa(&self.hash, key).serialize_compact();
        Ok(())
    }

    /// Hash up the header and firmware code and validate the header, including
    /// signature checks over the hash.
    fn hash_and_validate(
        &mut self,
        mut data: impl Read,
        known_signers: &[secp256k1::PublicKey],
    ) -> Result<(), Error> {
        // Calculate the hash of the header and firmware code.
        let mut hasher = sha2::Sha256::new();
        // First hash the header itself, excluding only the signatures and pubkeys.
        hasher.update(self.magic);
        hasher.update(self.timestamp);
        hasher.update(self.version);
        hasher.update(self.date);
        hasher.update(self.firmware_size);
        hasher.update(self.reserved);
        // Hash the firmware code.
        let mut num_bytes_read = 0u32;
        let mut buf = [0; 1024];
        loop {
            let n = data.read(&mut buf)?;
            if n == 0 {
                break;
            }
            num_bytes_read = num_bytes_read
                .checked_add(n.try_into().unwrap())
                .ok_or(Error::FirmwareTooLong)?;
            hasher.update(&buf[..n]);
        }
        // Do a second hash to avoid length extension attacks.
        self.hash = secp256k1::Message::from_digest_slice(&sha2::Sha256::digest(hasher.finalize()))
            .expect("32 bytes");

        // The signatures are checked before doing anything else with the data.
        let secp = secp256k1::Secp256k1::new();
        if self.signature1 != [0; 64] {
            let pubkey = secp256k1::PublicKey::from_slice(&self.pubkey1)
                .map_err(|_| Error::InvalidPubkey1)?;
            if !known_signers.is_empty() && !known_signers.contains(&pubkey) {
                return Err(Error::UnknownPubkey1);
            }
            let signature = secp256k1::ecdsa::Signature::from_compact(&self.signature1)
                .map_err(|_| Error::InvalidSignature1)?;
            if pubkey.verify(&secp, &self.hash, &signature).is_err() {
                return Err(Error::InvalidSignature1);
            }
        }
        if self.signature2 != [0; 64] {
            let pubkey = secp256k1::PublicKey::from_slice(&self.pubkey2)
                .map_err(|_| Error::InvalidPubkey2)?;
            if !known_signers.is_empty() && !known_signers.contains(&pubkey) {
                return Err(Error::UnknownPubkey2);
            }
            let signature = secp256k1::ecdsa::Signature::from_compact(&self.signature2)
                .map_err(|_| Error::InvalidSignature2)?;
            if pubkey.verify(&secp, &self.hash, &signature).is_err() {
                return Err(Error::InvalidSignature2);
            }
        }

        // Validate that the version string is UTF-8 formatted according to SemVer, and
        // that the unused bytes are all zero.
        let first_zero = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.version.len());
        let version = std::str::from_utf8(&self.version[..first_zero])
            .map_err(|_| Error::InvalidVersionUtf8)?;
        semver::Version::from_str(version).map_err(|_| Error::InvalidVersionSemver)?;
        if self.version[first_zero..].iter().any(|&b| b != 0) {
            return Err(Error::InvalidVersionTrailingBytes);
        }

        // Validate that the date string is UTF-8, and that the unused bytes are all
        // zero.
        let first_zero = self
            .date
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.date.len());
        std::str::from_utf8(&self.date[..first_zero]).map_err(|_| Error::InvalidDateUtf8)?;
        if self.date[first_zero..].iter().any(|&b| b != 0) {
            return Err(Error::InvalidDateTrailingBytes);
        }

        // Verify that the firmware size is correct.
        let firmware_size = u32::from_le_bytes(self.firmware_size);
        if firmware_size != num_bytes_read {
            return Err(Error::InvalidFirmwareSize {
                in_header: firmware_size,
                actual: num_bytes_read,
            });
        }

        // If a signature is zero, the corresponding pubkey must also be zero.
        if self.signature1 == [0; 64] && self.pubkey1 != [0; 33] {
            return Err(Error::InvalidPubkey1);
        }
        if self.signature2 == [0; 64] && self.pubkey2 != [0; 33] {
            return Err(Error::InvalidPubkey2);
        }

        // Check that the reserved bytes are all zero.
        if self.reserved.iter().any(|&b| b != 0) {
            return Err(Error::InvalidReservedBytes);
        }

        Ok(())
    }

    /// Set the firmware date field.
    fn set_date(&mut self, time: chrono::DateTime<chrono::Utc>) {
        let date = time.format("%b %d %Y").to_string();
        let date = date.as_bytes();
        if date.len() > self.date.len() {
            panic!(
                "date too long ({} > {}), should never happen",
                date.len(),
                self.date.len()
            );
        }
        self.date[..date.len()].copy_from_slice(date);
    }

    /// Set the firmware version field.
    fn set_version(&mut self, version: semver::Version) -> Result<(), Error> {
        let version = version.to_string();
        let version = version.as_bytes();
        if version.len() > self.version.len() {
            return Err(Error::VersionTooLong);
        }
        self.version[..version.len()].copy_from_slice(version);
        Ok(())
    }
}

/// Who is signing the firmware.
pub enum Signer {
    /// Trusted key from Foundation Devices, Inc.
    ///
    /// Headers signed by trusted keys expect both signatures to be filled in.
    Trusted(secp256k1::SecretKey),
    /// Third-party developer key.
    ///
    /// Headers signed by developer keys expect only the second signature to be
    /// filled in. The first signature is left empty (zeroed out).
    Developer(secp256k1::SecretKey),
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
    fn from_bytes(b: [u8; 4]) -> Option<Self> {
        match u32::from_le_bytes(b) {
            0x12345678 => Some(Self::Atsama5d27KeyOs),
            _ => None,
        }
    }

    fn as_bytes(&self) -> [u8; 4] {
        match self {
            Self::Atsama5d27KeyOs => 0x12345678u32.to_le_bytes(),
        }
    }
}

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

#[derive(Debug)]
pub enum Error {
    HeaderWithNoSignature,
    HeaderTooShort,
    InvalidTimestamp,
    InvalidReservedBytes,
    DuplicatePubkeys,
    InvalidVersionUtf8,
    InvalidVersionTrailingBytes,
    VersionTooLong,
    InvalidVersionSemver,
    InvalidPrivateKey,
    InvalidPubkey1,
    UnknownPubkey1,
    InvalidPubkey2,
    UnknownPubkey2,
    InvalidSignature1,
    InvalidSignature2,
    Signature1Missing,
    Signature2Present,
    FirmwareTooLong,
    InvalidDateUtf8,
    InvalidDateTrailingBytes,
    InvalidFirmwareSize { in_header: u32, actual: u32 },
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO Proper impl
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
