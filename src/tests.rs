use {super::*, std::io};

#[test]
fn sign_new_and_serialize_and_parse() {
    let firmware = [0x01, 0x02, 0x03, 0x04];
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let header = Header::sign_new(
        Magic::Atsama5d27KeyOs,
        Version::new(1, 2, 3),
        firmware.len().try_into().unwrap(),
        &Signer::Developer(secret_key),
        &firmware[..],
    )
    .unwrap();
    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();
    io::copy(&mut &firmware[..], &mut buf).unwrap();
    let parsed = Header::parse(&buf[..]).unwrap().unwrap();
    assert_eq!(header.magic(), parsed.magic());
    assert_eq!(header.timestamp(), parsed.timestamp());
    assert_eq!(header.date(), parsed.date());
    assert_eq!(header.version(), parsed.version());
    assert_eq!(header.firmware_size(), parsed.firmware_size());
    assert_eq!(header.pubkey1(), parsed.pubkey1());
    assert_eq!(header.signature1(), parsed.signature1());
    assert_eq!(header.pubkey2(), parsed.pubkey2());
    assert_eq!(header.signature2(), parsed.signature2());
    assert!(header.pubkey1().is_none());
    assert!(header.signature1().serialize_compact() == [0; 64]);
    assert!(header.pubkey2().is_some());
    assert!(header.signature2().serialize_compact() != [0; 64]);
}
