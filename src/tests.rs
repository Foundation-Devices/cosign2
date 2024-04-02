use {super::*, std::io};

const MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const DIGITS: [u8; 10] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9'];

#[test]
fn developer_singing() {
    let firmware = [0x01, 0x02, 0x03, 0x04];
    let secret_key =
        secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let header = Header::sign_new(
        Magic::Atsama5d27KeyOs,
        semver::Version::new(1, 2, 3),
        firmware.len().try_into().unwrap(),
        Signer::Developer(&secret_key),
        &firmware[..],
    )
    .unwrap();
    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();
    io::copy(&mut &firmware[..], &mut buf).unwrap();
    let parsed = Header::parse(
        &buf[..],
        &[secret_key.public_key(&secp256k1::Secp256k1::new())],
    )
    .unwrap()
    .unwrap();

    // The parsed header is the same as the serialized header.
    assert_eq!(header.magic(), parsed.magic());
    assert_eq!(header.timestamp(), parsed.timestamp());
    assert_eq!(header.date(), parsed.date());
    assert_eq!(header.version(), parsed.version());
    assert_eq!(header.firmware_size(), parsed.firmware_size());
    assert_eq!(header.pubkey1(), parsed.pubkey1());
    assert_eq!(header.signature1(), parsed.signature1());
    assert_eq!(header.pubkey2(), parsed.pubkey2());
    assert_eq!(header.signature2(), parsed.signature2());

    // The signing procedure filled in the correct field.
    assert!(header.pubkey1().is_none());
    assert!(header.signature1().is_none());
    assert!(header.pubkey2().is_some());
    assert!(header.signature2().is_some());

    // The binary representation is correct.
    assert_eq!(buf.len(), Header::SIZE + firmware.len());
    // Magic number.
    assert_eq!(buf[..4], [0x78, 0x56, 0x34, 0x12]);
    // Timestamp.
    assert_eq!(buf[4..8], header.timestamp().to_le_bytes(),);
    // Date.
    assert!(MONTHS.contains(&&buf[8..11]));
    assert_eq!(buf[11], b' ');
    assert!(DIGITS.contains(&buf[12]));
    assert!(DIGITS.contains(&buf[13]));
    assert_eq!(buf[14], b' ');
    assert!(DIGITS.contains(&buf[15]));
    assert!(DIGITS.contains(&buf[16]));
    assert!(DIGITS.contains(&buf[17]));
    assert!(DIGITS.contains(&buf[18]));
    assert_eq!(&buf[19..22], &[0, 0, 0]);
    // Version.
    assert_eq!(&buf[22..42], b"1.2.3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    // Firmware size.
    assert_eq!(buf[42..46], [4, 0, 0, 0]);
    // Public key 1.
    assert_eq!(&buf[46..79], [0; 33]);
    // Signature 1.
    assert_eq!(&buf[79..143], [0; 64]);
    // Public key 2.
    assert_eq!(
        &buf[143..176],
        [
            2, 185, 138, 127, 184, 204, 0, 112, 72, 98, 91, 100, 70, 173, 73, 161, 179, 167, 34,
            223, 140, 28, 169, 117, 184, 113, 96, 2, 62, 20, 209, 144, 151,
        ]
    );
    // Signature 2.
    assert_ne!(buf[176..240], [0; 64]);
    // Reserved.
    assert!(&buf[240..Header::SIZE].iter().all(|&b| b == 0));
}

#[test]
fn trusted_singing() {
    let firmware = [0x01, 0x02, 0x03, 0x04];
    let secret_key1 =
        secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let secret_key2 =
        secp256k1::SecretKey::from_slice(&[0xce; 32]).expect("32 bytes, within curve order");
    let mut header = Header::sign_new(
        Magic::Atsama5d27KeyOs,
        semver::Version::parse("1.2.3-alpha1").unwrap(),
        firmware.len().try_into().unwrap(),
        Signer::Trusted(&secret_key1),
        &firmware[..],
    )
    .unwrap();
    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();
    io::copy(&mut &firmware[..], &mut buf).unwrap();
    let parsed = Header::parse(
        &buf[..],
        &[secret_key1.public_key(&secp256k1::Secp256k1::new())],
    )
    .unwrap()
    .unwrap();

    // The parsed header is the same as the serialized header.
    assert_eq!(header.magic(), parsed.magic());
    assert_eq!(header.timestamp(), parsed.timestamp());
    assert_eq!(header.date(), parsed.date());
    assert_eq!(header.version(), parsed.version());
    assert_eq!(header.firmware_size(), parsed.firmware_size());
    assert_eq!(header.pubkey1(), parsed.pubkey1());
    assert_eq!(header.signature1(), parsed.signature1());
    assert_eq!(header.pubkey2(), parsed.pubkey2());
    assert_eq!(header.signature2(), parsed.signature2());

    // The signing procedure filled in the correct field.
    assert!(header.pubkey1().is_some());
    assert!(header.signature1().is_some());
    assert!(header.pubkey2().is_none());
    assert!(header.signature2().is_none());

    // The binary representation is correct.
    assert_eq!(buf.len(), Header::SIZE + firmware.len());
    // Magic number.
    assert_eq!(buf[..4], [0x78, 0x56, 0x34, 0x12]);
    // Timestamp.
    assert_eq!(buf[4..8], header.timestamp().to_le_bytes());
    // Date.
    assert!(MONTHS.contains(&&buf[8..11]));
    assert_eq!(buf[11], b' ');
    assert!(DIGITS.contains(&buf[12]));
    assert!(DIGITS.contains(&buf[13]));
    assert_eq!(buf[14], b' ');
    assert!(DIGITS.contains(&buf[15]));
    assert!(DIGITS.contains(&buf[16]));
    assert!(DIGITS.contains(&buf[17]));
    assert!(DIGITS.contains(&buf[18]));
    assert_eq!(&buf[19..22], &[0, 0, 0]);
    // Version.
    assert_eq!(&buf[22..42], b"1.2.3-alpha1\0\0\0\0\0\0\0\0");
    // Firmware size.
    assert_eq!(buf[42..46], [4, 0, 0, 0]);
    // Public key 1.
    assert_eq!(
        &buf[46..79],
        [
            2, 185, 138, 127, 184, 204, 0, 112, 72, 98, 91, 100, 70, 173, 73, 161, 179, 167, 34,
            223, 140, 28, 169, 117, 184, 113, 96, 2, 62, 20, 209, 144, 151,
        ]
    );
    // Signature 1.
    assert_ne!(&buf[79..143], [0; 64]);
    // Public key 2.
    assert_eq!(&buf[143..176], [0; 33]);
    // Signature 2.
    assert_eq!(buf[176..240], [0; 64]);
    // Reserved.
    assert!(&buf[240..Header::SIZE].iter().all(|&b| b == 0));

    // Add second signature.
    header.add_second_signature(&secret_key2).unwrap();

    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();
    io::copy(&mut &firmware[..], &mut buf).unwrap();
    let parsed = Header::parse(
        &buf[..],
        &[
            secret_key1.public_key(&secp256k1::Secp256k1::new()),
            secret_key2.public_key(&secp256k1::Secp256k1::new()),
        ],
    )
    .unwrap()
    .unwrap();

    // The parsed header is the same as the serialized header.
    assert_eq!(header.magic(), parsed.magic());
    assert_eq!(header.timestamp(), parsed.timestamp());
    assert_eq!(header.date(), parsed.date());
    assert_eq!(header.version(), parsed.version());
    assert_eq!(header.firmware_size(), parsed.firmware_size());
    assert_eq!(header.pubkey1(), parsed.pubkey1());
    assert_eq!(header.signature1(), parsed.signature1());
    assert_eq!(header.pubkey2(), parsed.pubkey2());
    assert_eq!(header.signature2(), parsed.signature2());

    // The signing procedure filled in the correct fields.
    assert!(header.pubkey1().is_some());
    assert!(header.signature1().is_some());
    assert!(header.pubkey2().is_some());
    assert!(header.signature2().is_some());

    // The binary representation is correct.
    assert_eq!(buf.len(), Header::SIZE + firmware.len());
    // Magic number.
    assert_eq!(buf[..4], [0x78, 0x56, 0x34, 0x12]);
    // Timestamp.
    assert_eq!(buf[4..8], header.timestamp().to_le_bytes());
    // Date.
    assert!(MONTHS.contains(&&buf[8..11]));
    assert_eq!(buf[11], b' ');
    assert!(DIGITS.contains(&buf[12]));
    assert!(DIGITS.contains(&buf[13]));
    assert_eq!(buf[14], b' ');
    assert!(DIGITS.contains(&buf[15]));
    assert!(DIGITS.contains(&buf[16]));
    assert!(DIGITS.contains(&buf[17]));
    assert!(DIGITS.contains(&buf[18]));
    assert_eq!(&buf[19..22], &[0, 0, 0]);
    // Version.
    assert_eq!(&buf[22..42], b"1.2.3-alpha1\0\0\0\0\0\0\0\0");
    // Firmware size.
    assert_eq!(buf[42..46], [4, 0, 0, 0]);
    // Public key 1.
    assert_eq!(
        &buf[46..79],
        [
            2, 185, 138, 127, 184, 204, 0, 112, 72, 98, 91, 100, 70, 173, 73, 161, 179, 167, 34,
            223, 140, 28, 169, 117, 184, 113, 96, 2, 62, 20, 209, 144, 151,
        ]
    );
    // Signature 1.
    assert_ne!(&buf[79..143], [0; 64]);
    // Public key 2.
    assert_eq!(
        &buf[143..176],
        [
            3, 102, 16, 204, 9, 96, 143, 51, 174, 250, 181, 32, 150, 5, 87, 7, 224, 45, 246, 160,
            105, 67, 84, 246, 158, 200, 197, 141, 128, 31, 161, 255, 163,
        ]
    );
    // Signature 2.
    assert_ne!(buf[176..240], [0; 64]);
    // Reserved.
    assert!(&buf[240..Header::SIZE].iter().all(|&b| b == 0));
}
