#![no_std]

use {chrono::Datelike, core::str::FromStr, sha2::Digest};

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
    /// Hash of the header and firmware code.
    hash: secp256k1::Message,
}

impl Header {
    /// Size of the header in bytes.
    pub const SIZE: usize = 2048;

    /// Number of reserved bytes at the end of the header.
    const RESERVED: usize = 1808;

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
    pub fn date(&self) -> &str {
        let first_zero = self
            .date
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.date.len());
        core::str::from_utf8(&self.date[..first_zero]).expect("validated")
    }

    /// Firmware version.
    pub fn version(&self) -> &str {
        let first_zero = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.version.len());
        core::str::from_utf8(&self.version[..first_zero]).expect("validated")
    }

    /// The size of the firmware.
    pub fn firmware_size(&self) -> u32 {
        u32::from_le_bytes(self.firmware_size)
    }

    /// Public key of the first signer.
    ///
    /// Returns `None` if the pubkey is not present (zeroed out).
    pub fn pubkey1(&self) -> Option<secp256k1::PublicKey> {
        if self.pubkey1 == [0; 33] {
            return None;
        }
        Some(secp256k1::PublicKey::from_slice(&self.pubkey1).expect("validated"))
    }

    /// First signature.
    ///
    /// Returns `None` if the signature is not present (zeroed out).
    pub fn signature1(&self) -> Option<secp256k1::ecdsa::Signature> {
        if self.signature1 == [0; 64] {
            return None;
        }
        Some(secp256k1::ecdsa::Signature::from_compact(&self.signature1).expect("validated"))
    }

    /// Public key of the second signer.
    ///
    /// Returns `None` if the pubkey is not present (zeroed out).
    pub fn pubkey2(&self) -> Option<secp256k1::PublicKey> {
        if self.pubkey2 == [0; 33] {
            return None;
        }
        Some(secp256k1::PublicKey::from_slice(&self.pubkey2).expect("validated"))
    }

    /// Second signature.
    ///
    /// Returns `None` if the signature is not present (zeroed out).
    pub fn signature2(&self) -> Option<secp256k1::ecdsa::Signature> {
        if self.signature2 == [0; 64] {
            return None;
        }
        Some(secp256k1::ecdsa::Signature::from_compact(&self.signature2).expect("validated"))
    }

    /// Create a new header and sign it.
    pub fn sign_new(
        magic: Magic,
        version: &str,
        timestamp: u32,
        signer: Signer<'_>,
        firmware: &[u8],
    ) -> Result<Self, Error> {
        // Validate the version string.
        semver::Version::from_str(version).map_err(|_| Error::InvalidVersionSemver)?;

        let mut header = Self {
            magic: magic.as_bytes(),
            timestamp: timestamp.to_le_bytes(),
            date: [0; 14],
            version: [0; 20],
            firmware_size: u32::try_from(firmware.len())
                .map_err(|_| Error::FirmwareTooLong)?
                .to_le_bytes(),
            pubkey1: [0; 33],
            signature1: [0; 64],
            pubkey2: [0; 33],
            signature2: [0; 64],
            hash: secp256k1::Message::from_digest([0; 32]),
        };
        header.set_date(timestamp);
        header.set_version(version)?;
        header.hash_and_validate(firmware, &[])?;

        // Sign the header.
        let mut secp = StackAllocatedSecp256k1::new();
        let secp = secp.create_for_signing()?;
        match signer {
            Signer::Trusted(key) => {
                // Trusted key is used, so both first and second signatures need to be filled
                // in. This key is used for the first signature.
                let pubkey = secp256k1::PublicKey::from_secret_key(&secp, key);
                let signature = secp.sign_ecdsa(&header.hash, key);
                header.pubkey1 = pubkey.serialize();
                header.signature1 = signature.serialize_compact();
            }
            Signer::Developer(key) => {
                // Developer key is used, so only the second signature is filled in.
                // The first signature is left empty (zeroed out).
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
        data: &[u8],
        known_signers: &[secp256k1::PublicKey],
    ) -> Result<Option<Self>, Error> {
        if data.len() < 4 {
            return Ok(None);
        }

        let magic = data[..4].try_into().unwrap();
        if Magic::from_bytes(magic).is_none() {
            // Magic value is missing or not recognized, so this is not a header.
            return Ok(None);
        }

        // The data contains a header, so make sure it's of appropriate length.
        if data.len() < Self::SIZE {
            return Err(Error::HeaderTooShort);
        }

        let timestamp = data[4..8].try_into().unwrap();
        let date = data[8..22].try_into().unwrap();
        let version = data[22..42].try_into().unwrap();
        let firmware_size = data[42..46].try_into().unwrap();
        let pubkey1 = data[46..79].try_into().unwrap();
        let signature1 = data[79..143].try_into().unwrap();
        let pubkey2 = data[143..176].try_into().unwrap();
        let signature2 = data[176..240].try_into().unwrap();

        // When parsing an existing header, there should always be at least one
        // signature.
        if signature1 == [0; 64] && signature2 == [0; 64] {
            return Err(Error::HeaderWithNoSignature);
        }

        let reserved = &data[240..Self::SIZE];

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

        header.hash_and_validate(&data[Self::SIZE..], known_signers)?;

        // Check that the reserved bytes are all zero.
        if reserved.iter().any(|&b| b != 0) {
            return Err(Error::InvalidReservedBytes);
        }

        Ok(Some(header))
    }

    /// Serialize the header to a buffer. Exactly [`Self::SIZE`] bytes will be
    /// written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::SerializeBufferTooSmall);
        }

        buf[..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.timestamp);
        buf[8..22].copy_from_slice(&self.date);
        buf[22..42].copy_from_slice(&self.version);
        buf[42..46].copy_from_slice(&self.firmware_size);
        buf[46..79].copy_from_slice(&self.pubkey1);
        buf[79..143].copy_from_slice(&self.signature1);
        buf[143..176].copy_from_slice(&self.pubkey2);
        buf[176..240].copy_from_slice(&self.signature2);
        buf[240..Self::SIZE].copy_from_slice(&[0u8; Self::RESERVED]);

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
        let mut secp = StackAllocatedSecp256k1::new();
        let secp = secp.create_for_signing()?;
        if self.pubkey1 == key.public_key(&secp).serialize() {
            return Err(Error::PubkeyAlreadyUsed);
        }
        self.pubkey2 = key.public_key(&secp).serialize();
        self.signature2 = secp.sign_ecdsa(&self.hash, key).serialize_compact();
        Ok(())
    }

    /// Hash up the header and firmware code and validate the header, including
    /// signature checks over the hash.
    fn hash_and_validate(
        &mut self,
        firmware: &[u8],
        known_signers: &[secp256k1::PublicKey],
    ) -> Result<(), Error> {
        // Calculate the hash of the header and firmware code.
        let mut hasher = sha2::Sha256::new();
        // First hash the header itself, excluding only the signatures and pubkeys.
        hasher.update(self.magic);
        hasher.update(self.timestamp);
        hasher.update(self.date);
        hasher.update(self.version);
        hasher.update(self.firmware_size);
        // Include the reserved bytes in the hash.
        hasher.update([0u8; Self::RESERVED]);
        // Hash the firmware code.
        hasher.update(firmware);
        // Do a second hash to avoid length extension attacks.
        self.hash = secp256k1::Message::from_digest_slice(&sha2::Sha256::digest(hasher.finalize()))
            .expect("32 bytes");

        // The signatures are checked before doing anything else with the data.
        let mut secp = StackAllocatedSecp256k1::new();
        let secp = secp.create_for_verifying()?;
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
        let version = core::str::from_utf8(&self.version[..first_zero])
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
        core::str::from_utf8(&self.date[..first_zero]).map_err(|_| Error::InvalidDateUtf8)?;
        if self.date[first_zero..].iter().any(|&b| b != 0) {
            return Err(Error::InvalidDateTrailingBytes);
        }

        // Verify that the firmware size is correct.
        let firmware_size = u32::from_le_bytes(self.firmware_size);
        let actual_firmware_size =
            u32::try_from(firmware.len()).map_err(|_| Error::FirmwareTooLong)?;
        if firmware_size != actual_firmware_size {
            return Err(Error::InvalidFirmwareSize {
                in_header: firmware_size,
                actual: actual_firmware_size,
            });
        }

        // If a signature is zero, the corresponding pubkey must also be zero.
        if self.signature1 == [0; 64] && self.pubkey1 != [0; 33] {
            return Err(Error::InvalidPubkey1);
        }
        if self.signature2 == [0; 64] && self.pubkey2 != [0; 33] {
            return Err(Error::InvalidPubkey2);
        }

        Ok(())
    }

    /// Set the firmware date field.
    fn set_date(&mut self, timestamp: u32) {
        let date = chrono::DateTime::from_timestamp(timestamp.into(), 0).expect("before 2106");
        let month = match date.month() {
            1 => b"Jan",
            2 => b"Feb",
            3 => b"Mar",
            4 => b"Apr",
            5 => b"May",
            6 => b"Jun",
            7 => b"Jul",
            8 => b"Aug",
            9 => b"Sep",
            10 => b"Oct",
            11 => b"Nov",
            12 => b"Dec",
            _ => unreachable!(),
        };
        self.date[0..3].copy_from_slice(month);
        self.date[3] = b' ';
        let day = date.day();
        self.date[4] = ascii_digit(day / 10);
        self.date[5] = ascii_digit(day % 10);
        self.date[6] = b' ';
        let year: u32 = date.year().try_into().expect("year in timestamp is valid");
        self.date[7] = ascii_digit((year / 1000) % 10);
        self.date[8] = ascii_digit((year / 100) % 10);
        self.date[9] = ascii_digit((year / 10) % 10);
        self.date[10] = ascii_digit(year % 10);
    }

    /// Set the firmware version field.
    fn set_version(&mut self, version: &str) -> Result<(), Error> {
        if version.len() > self.version.len() {
            return Err(Error::VersionTooLong);
        }
        self.version[..version.len()].copy_from_slice(version.as_bytes());
        Ok(())
    }
}

/// Who is signing the firmware.
pub enum Signer<'a> {
    /// Trusted key from Foundation Devices, Inc.
    ///
    /// Headers signed by trusted keys expect both signatures to be filled in.
    Trusted(&'a secp256k1::SecretKey),
    /// Third-party developer key.
    ///
    /// Headers signed by developer keys expect only the second signature to be
    /// filled in. The first signature is left empty (zeroed out).
    Developer(&'a secp256k1::SecretKey),
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

fn ascii_digit(b: u32) -> u8 {
    match b {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        _ => unreachable!(),
    }
}

struct StackAllocatedSecp256k1([secp256k1::ffi::types::AlignedType; 256]);

impl StackAllocatedSecp256k1 {
    fn new() -> Self {
        Self([secp256k1::ffi::types::AlignedType::default(); 256])
    }

    fn create_for_signing(
        &mut self,
    ) -> Result<secp256k1::Secp256k1<secp256k1::SignOnlyPreallocated<'_>>, Error> {
        secp256k1::Secp256k1::preallocated_gen_new(&mut self.0).map_err(Error::Secp256k1)
    }

    fn create_for_verifying(
        &mut self,
    ) -> Result<secp256k1::Secp256k1<secp256k1::VerifyOnlyPreallocated<'_>>, Error> {
        secp256k1::Secp256k1::preallocated_gen_new(&mut self.0).map_err(Error::Secp256k1)
    }
}

#[derive(Debug)]
pub enum Error {
    FirmwareTooLong,
    HeaderTooShort,
    HeaderWithNoSignature,
    InvalidDateTrailingBytes,
    InvalidDateUtf8,
    InvalidFirmwareSize { in_header: u32, actual: u32 },
    InvalidPubkey1,
    InvalidPubkey2,
    InvalidReservedBytes,
    InvalidSignature1,
    InvalidSignature2,
    InvalidTimestamp,
    InvalidVersionSemver,
    InvalidVersionTrailingBytes,
    InvalidVersionUtf8,
    PubkeyAlreadyUsed,
    Secp256k1(secp256k1::Error),
    SerializeBufferTooSmall,
    Signature1Missing,
    Signature2Present,
    UnknownPubkey1,
    UnknownPubkey2,
    VersionTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FirmwareTooLong => write!(f, "firmware too long"),
            Self::HeaderTooShort => write!(f, "header too short"),
            Self::HeaderWithNoSignature => write!(f, "header with no signature"),
            Self::InvalidDateTrailingBytes => write!(f, "invalid date trailing bytes in header"),
            Self::InvalidDateUtf8 => write!(f, "invalid date UTF-8 in header"),
            Self::InvalidFirmwareSize { in_header, actual } => write!(
                f,
                "invalid firmware size in header: should be {actual}, but is {in_header}",
            ),
            Self::InvalidPubkey1 => write!(f, "invalid pubkey1 in header"),
            Self::InvalidPubkey2 => write!(f, "invalid pubkey2 in header"),
            Self::InvalidReservedBytes => write!(f, "invalid reserved bytes in header"),
            Self::InvalidSignature1 => write!(f, "invalid signature1 in header"),
            Self::InvalidSignature2 => write!(f, "invalid signature2 in header"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp in header"),
            Self::InvalidVersionSemver => write!(f, "invalid version SemVer"),
            Self::InvalidVersionTrailingBytes => {
                write!(f, "invalid version trailing bytes in header")
            }
            Self::InvalidVersionUtf8 => write!(f, "invalid version UTF-8 in header"),
            Self::PubkeyAlreadyUsed => write!(f, "attempting to sign with the same pubkey twice"),
            Self::Secp256k1(e) => write!(f, "secp256k1 error: {e}"),
            Self::SerializeBufferTooSmall => write!(f, "buffer too small for serialization"),
            Self::Signature1Missing => write!(f, "signature1 missing in header"),
            Self::Signature2Present => {
                write!(f, "signature2 already present in header")
            }
            Self::UnknownPubkey1 => write!(f, "unknown pubkey1 in header"),
            Self::UnknownPubkey2 => write!(f, "unknown pubkey2 in header"),
            Self::VersionTooLong => write!(f, "version too long to write in header"),
        }
    }
}
