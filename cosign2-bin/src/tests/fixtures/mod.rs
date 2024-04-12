pub const VALID_HEADER_ONE_SIGNATURE: &[u8] = include_bytes!("valid-header-one-signature.img");
pub const VALID_HEADER_TWO_SIGNATURES: &[u8] = include_bytes!("valid-header-two-signatures.img");
pub const INVALID_HEADER_TWO_SIGNATURES_MAGIC_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-magic-changed.img");
pub const INVALID_HEADER_ONE_SIGNATURE_TIMESTAMP_CHANGED: &[u8] =
    include_bytes!("invalid-header-one-signature-timestamp-changed.img");
pub const INVALID_HEADER_ONE_SIGNATURE_DATE_CHANGED: &[u8] =
    include_bytes!("invalid-header-one-signature-date-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_VERSION_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-version-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_FIRMWARE_SIZE_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-firmware-size-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_PUBKEY1_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-pubkey1-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_SIGNATURE1_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-signature1-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_PUBKEY2_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-pubkey2-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_SIGNATURE2_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-signature2-changed.img");
pub const INVALID_HEADER_TWO_SIGNATURES_RESERVED_CHANGED: &[u8] =
    include_bytes!("invalid-header-two-signatures-reserved-changed.img");
pub const INVALID_HEADER_ONE_SIGNATURE_FIRMWARE_CHANGED: &[u8] =
    include_bytes!("invalid-header-one-signature-firmware-changed.img");
