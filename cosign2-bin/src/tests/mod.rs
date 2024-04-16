use {
    crate::ExitCode,
    sha2::Digest,
    std::io::{Read, Write},
};

mod fixtures;

/// Try to dump header contents of a file with no header.
#[test]
fn dump_no_header() {
    let file = create_file(b"Hello, world!");
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("no header"));
    assert!(output.stderr.is_empty());
}

/// Dump header contents of a valid file with a header containing one signature.
#[test]
fn dump_valid_header_one_signature() {
    let file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(0));

    // Prints magic value.
    assert!(output.stdout.contains("atsama5d27-keyos"));
    // Prints human-readable timestamp in UTC.
    assert!(output.stdout.contains("2024-04-09 11:06:11 UTC"));
    // Prints timestamp as number of seconds since UNIX epoch.
    assert!(output.stdout.contains("1712660771"));
    // Prints human readable date as it is in the header.
    assert!(output.stdout.contains("Apr 09 2024"));
    // Prints version.
    assert!(output.stdout.contains("0.0.77"));
    // Prints firmware size.
    assert!(output.stdout.contains("18 B (18)"));
    // Prints first pubkey in hex.
    assert!(output
        .stdout
        .contains("02118f59082b8e26753c1cab1bfead3259344c03312cbb4ff7bdecceb915e92c9b"));
    // Prints first signature in hex.
    assert!(output
        .stdout
        .contains("37fc0e4efd34bcfa35ccf9d12c42024b8ef3458483aad7597eefa24d55c017d6"));
    assert!(output
        .stdout
        .contains("2a694d313949bab4cbb661a8d928d3f411cdca17164671b761edeb8810d08a49"));
    // Prints second pubkey in hex (all zeros).
    assert!(output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    // Prints second signature in hex (all zeros).
    assert!(output
        .stdout
        .contains("0000000000000000000000000000000000000000000000000000000000000000"));

    assert!(output.stderr.is_empty());
}

/// Dump header contents of a valid file with a header containing two
/// signatures.
#[test]
fn dump_valid_header_two_signatures() {
    let file = create_file(fixtures::VALID_HEADER_TWO_SIGNATURES);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(0));

    // Prints magic value.
    assert!(output.stdout.contains("atsama5d27-keyos"));
    // Prints human-readable timestamp in UTC.
    assert!(output.stdout.contains("2024-04-09 11:06:11 UTC"));
    // Prints timestamp as number of seconds since UNIX epoch.
    assert!(output.stdout.contains("1712660771"));
    // Prints human readable date as it is in the header.
    assert!(output.stdout.contains("Apr 09 2024"));
    // Prints version.
    assert!(output.stdout.contains("0.0.77"));
    // Prints firmware size.
    assert!(output.stdout.contains("18 B (18)"));
    // Prints first pubkey in hex.
    assert!(output
        .stdout
        .contains("02118f59082b8e26753c1cab1bfead3259344c03312cbb4ff7bdecceb915e92c9b"));
    // Prints first signature in hex.
    assert!(output
        .stdout
        .contains("37fc0e4efd34bcfa35ccf9d12c42024b8ef3458483aad7597eefa24d55c017d6"));
    assert!(output
        .stdout
        .contains("2a694d313949bab4cbb661a8d928d3f411cdca17164671b761edeb8810d08a49"));
    // Prints second pubkey in hex (all zeros).
    assert!(output
        .stdout
        .contains("0271a3e606578281f6bcb461a8ada671829c3348b688787c68baa75ad51916edfc"));
    // Prints second signature in hex (all zeros).
    assert!(output
        .stdout
        .contains("9a85952c86385190d32718b20aba7b54af79020b12109d46acf313ef1608bbc9"));
    assert!(output
        .stdout
        .contains("78ba7a29f833fe52c348c9fd7aa21368be08e0f83cdc5f10a688a0ec642cff7a"));

    assert!(output.stderr.is_empty());
}

/// Dump header with the magic value changed. This is interpreted as a file with
/// no header, since the magic value is used to identify the header.
#[test]
fn dump_invalid_magic() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_MAGIC_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("no header"));
    assert!(output.stderr.is_empty());
}

/// Dump headers with various fields changed, hence invalidating the signatures.
#[test]
fn dump_invalid_changed_fields() {
    let cases = [
        fixtures::INVALID_HEADER_ONE_SIGNATURE_TIMESTAMP_CHANGED,
        fixtures::INVALID_HEADER_ONE_SIGNATURE_DATE_CHANGED,
        fixtures::INVALID_HEADER_TWO_SIGNATURES_VERSION_CHANGED,
        fixtures::INVALID_HEADER_TWO_SIGNATURES_FIRMWARE_SIZE_CHANGED,
        fixtures::INVALID_HEADER_TWO_SIGNATURES_RESERVED_CHANGED,
        fixtures::INVALID_HEADER_ONE_SIGNATURE_FIRMWARE_CHANGED,
    ];

    for case in cases {
        let file = create_file(case);
        let output = test(["dump", "-i", file.path().to_str().unwrap()]);
        assert_eq!(output.exit_code, ExitCode(1));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.contains("invalid signature1"));
    }
}

/// Dump header with the first pubkey changed.
#[test]
fn dump_invalid_header_invalid_pubkey1() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_PUBKEY1_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature1"));
}

/// Dump header with the second pubkey changed.
#[test]
fn dump_invalid_header_invalid_pubkey2() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_PUBKEY2_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature2"));
}

/// Dump header with the first signature changed.
#[test]
fn dump_invalid_header_invalid_signature1() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_SIGNATURE1_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature1"));
}

/// Dump header with the second signature changed.
#[test]
fn dump_invalid_header_invalid_signature2() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_SIGNATURE2_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature2"));
}

/// Sign an image with two trusted keys (i.e. not developer keys).
#[test]
fn sign_with_trusted_keys() {
    // Sign the image with the first key.
    let input_file = create_file(fixtures::UNSIGNED);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--firmware-version",
        "1.2.4-alpha1",
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = test(["dump", "-i", output_file.path().to_str().unwrap()]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("atsama5d27-keyos"));
    assert!(output.stdout.contains("1.2.4-alpha1"));
    assert!(output.stdout.contains("18 B (18)"));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_1_HEX));
    assert!(output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    assert!(output.stderr.is_empty());

    // Sign the image with the second key.
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let final_output_file = tempfile::NamedTempFile::new().unwrap();
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        output_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        final_output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = test(["dump", "-i", final_output_file.path().to_str().unwrap()]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("atsama5d27-keyos"));
    assert!(output.stdout.contains("1.2.4-alpha1"));
    assert!(output.stdout.contains("18 B (18)"));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_1_HEX));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_2_HEX));
    assert!(!output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    assert!(!output
        .stdout
        .contains("0000000000000000000000000000000000000000000000000000000000000000"));
    assert!(output.stderr.is_empty());
}

/// Sign an image with a trusted key loaded from config.
#[test]
fn sign_with_trusted_key_from_config() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let config_file = create_file(
        format!(
            r#"
            pubkey = "{}"
            secret = "{}"
            known_pubkeys = ["{}", "{}"]
            target = "atsama5d27-keyos"
            "#,
            fixtures::PUBLIC_KEY_2_HEX,
            private_key_pem.path().to_str().unwrap(),
            fixtures::PUBLIC_KEY_1_HEX,
            fixtures::PUBLIC_KEY_2_HEX,
        )
        .as_bytes(),
    );

    let output = test([
        "sign",
        "-i",
        input_file.path().to_str().unwrap(),
        "--config",
        config_file.path().to_str().unwrap(),
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = test(["dump", "-i", output_file.path().to_str().unwrap()]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("atsama5d27-keyos"));
    assert!(output.stdout.contains("0.0.77"));
    assert!(output.stdout.contains("18 B (18)"));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_1_HEX));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_2_HEX));
    assert!(!output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    assert!(!output
        .stdout
        .contains("0000000000000000000000000000000000000000000000000000000000000000"));
    assert!(output.stderr.is_empty());
}

/// Attempt to specify the pubkey both in the config file and on the CLI.
#[test]
fn pubkey_in_config_and_cli() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let config_file = create_file(
        format!(
            r#"
            pubkey = "{}"
            "#,
            fixtures::PUBLIC_KEY_2_HEX,
        )
        .as_bytes(),
    );

    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "--pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--config",
        config_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("pubkey specified in both config and cli"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to specify the secret both in the config file and on the CLI.
#[test]
fn secret_in_config_and_cli() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let config_file = create_file(
        format!(
            r#"
            secret = "{}"
            "#,
            private_key_pem.path().to_str().unwrap(),
        )
        .as_bytes(),
    );

    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "--pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--config",
        config_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("secret specified in both config and cli"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to specify the known pubkeys both in the config file and on the CLI.
#[test]
fn known_pubkeys_in_config_and_cli() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let config_file = create_file(
        format!(
            r#"
            known_pubkeys = ["{}", "{}"]
            "#,
            fixtures::PUBLIC_KEY_2_HEX,
            fixtures::PUBLIC_KEY_1_HEX,
        )
        .as_bytes(),
    );

    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "--pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--config",
        config_file.path().to_str().unwrap(),
        "--known-pubkey",
        fixtures::PUBLIC_KEY_2_HEX,
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("known pubkeys specified in both config and cli"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to specify the target both in the config file and on the CLI.
#[test]
fn target_in_config_and_cli() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let config_file = create_file(
        r#"
        target = "atsama5d27-keyos"
        "#
        .as_bytes(),
    );

    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "--pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--config",
        config_file.path().to_str().unwrap(),
        "--known-pubkey",
        fixtures::PUBLIC_KEY_2_HEX,
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("target specified in both config and cli"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Sign an image with a single developer key.
#[test]
fn sign_with_developer_key() {
    let input_file = create_file(fixtures::UNSIGNED);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--developer",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--firmware-version",
        "1.2.4-alpha1",
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = test(["dump", "-i", output_file.path().to_str().unwrap()]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("atsama5d27-keyos"));
    assert!(output.stdout.contains("1.2.4-alpha1"));
    assert!(output.stdout.contains("18 B (18)"));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_1_HEX));
    assert!(output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    assert!(output.stderr.is_empty());
}

/// Sign an image in place with a single developer key.
#[test]
fn sign_with_developer_key_in_place() {
    let input_file = create_file(fixtures::UNSIGNED);
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--developer",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--firmware-version",
        "1.2.4-alpha1",
        "--target",
        "atsama5d27-keyos",
        "--in-place",
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let output = test(["dump", "-i", input_file.path().to_str().unwrap()]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.contains("atsama5d27-keyos"));
    assert!(output.stdout.contains("1.2.4-alpha1"));
    assert!(output.stdout.contains("18 B (18)"));
    assert!(output.stdout.contains(fixtures::PUBLIC_KEY_1_HEX));
    assert!(output
        .stdout
        .contains("000000000000000000000000000000000000000000000000000000000000000000"));
    assert!(output.stderr.is_empty());
}

/// Attempt to sign an image in place while also specifying an output file.
#[test]
fn sign_with_developer_key_in_place_with_output_file() {
    let input_file = create_file(fixtures::UNSIGNED);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--developer",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--firmware-version",
        "1.2.4-alpha1",
        "--target",
        "atsama5d27-keyos",
        "--in-place",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("cannot specify both --in-place and --output (-o)"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to resign an image which has already been signed with a developer
/// key.
#[test]
fn resign_with_developer_key() {
    let input_file = create_file(fixtures::DEVELOPER_SIGNED);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--developer",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("signature2 already present"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to sign with a private key that doesn't match the specified public
/// key.
#[test]
fn sign_pubkey_mismatch() {
    let input_file = create_file(fixtures::UNSIGNED);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--developer",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "--pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("public key does not match secret key"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to resign an image which has already been signed with the given
/// trusted key.
#[test]
fn resign_with_trusted_key() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("same pubkey twice"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to sign an image which has already been signed by an unknown key.
#[test]
fn sign_header_contains_unknown_pubkey() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--known-pubkey",
        fixtures::PUBLIC_KEY_2_HEX,
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("unknown pubkey1"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Attempt to sign an image using an unknown key.
#[test]
fn sign_header_with_unknown_pubkey() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--known-pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output
        .stderr
        .contains("signing key is not in known pubkeys list"));
    let mut buf = Vec::new();
    output_file.as_file().read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Sign an image with a second key which has already been signed by a
/// known key.
#[test]
fn sign_header_with_known_pubkeys() {
    let input_file = create_file(fixtures::VALID_HEADER_ONE_SIGNATURE);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
        "--known-pubkey",
        fixtures::PUBLIC_KEY_2_HEX,
        "--known-pubkey",
        fixtures::PUBLIC_KEY_1_HEX,
    ]);

    assert_eq!(output.exit_code, ExitCode(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

/// Attempt to sign an image with an invalid version UTF-8 in the header.
#[test]
fn sign_header_invalid_version_utf8() {
    let input_file = create_file(
        &DataWithHeader {
            magic: [0x78, 0x56, 0x34, 0x12],
            timestamp: [1; 4],
            date: [0; 14],
            version: [0xFF; 20],
            firmware_size: 13u32.to_le_bytes(),
            data: b"Hello, world!".to_vec(),
        }
        .sign(
            Some(secp256k1::SecretKey::from_slice(fixtures::SECRET_KEY_1_BYTES).unwrap()),
            None,
        ),
    );
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid version UTF-8"));
}

/// Attempt to sign an image with an invalid version SemVer in the header.
#[test]
fn sign_header_invalid_version_semver() {
    let mut data = DataWithHeader {
        magic: [0x78, 0x56, 0x34, 0x12],
        timestamp: [1; 4],
        date: [0; 14],
        version: [0; 20],
        firmware_size: 13u32.to_le_bytes(),
        data: b"Hello, world!".to_vec(),
    };
    let version = b"invalid";
    data.version[..version.len()].copy_from_slice(&version[..version.len()]);
    let input_file = create_file(&data.sign(
        Some(secp256k1::SecretKey::from_slice(fixtures::SECRET_KEY_1_BYTES).unwrap()),
        None,
    ));
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid version SemVer"));
}

/// Attempt to sign an image with an invalid date UTF-8 in the header.
#[test]
fn sign_header_invalid_date_utf8() {
    let mut data = DataWithHeader {
        magic: [0x78, 0x56, 0x34, 0x12],
        timestamp: [1; 4],
        date: [0xFF; 14],
        version: [0; 20],
        firmware_size: 13u32.to_le_bytes(),
        data: b"Hello, world!".to_vec(),
    };
    let version = b"1.0.0";
    data.version[..version.len()].copy_from_slice(&version[..version.len()]);
    let input_file = create_file(&data.sign(
        Some(secp256k1::SecretKey::from_slice(fixtures::SECRET_KEY_1_BYTES).unwrap()),
        None,
    ));
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_2_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid date UTF-8"));
}

/// Attempt to sign an image with an invalid firmware size.
#[test]
fn sign_header_invalid_firmware_size() {
    let mut data = DataWithHeader {
        magic: [0x78, 0x56, 0x34, 0x12],
        timestamp: [1; 4],
        date: [0; 14],
        version: [0; 20],
        firmware_size: 53u32.to_le_bytes(),
        data: b"Hello, world!".to_vec(),
    };
    let version = b"1.0.0";
    data.version[..version.len()].copy_from_slice(&version[..version.len()]);
    let input_file = create_file(&data.sign(
        Some(secp256k1::SecretKey::from_slice(fixtures::SECRET_KEY_2_BYTES).unwrap()),
        None,
    ));
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let private_key_pem = create_file(fixtures::PRIVATE_KEY_1_PEM);
    let output = test([
        "sign",
        "--secret",
        private_key_pem.path().to_str().unwrap(),
        "-i",
        input_file.path().to_str().unwrap(),
        "--target",
        "atsama5d27-keyos",
        "-o",
        output_file.path().to_str().unwrap(),
    ]);

    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid firmware size"));
    assert!(output.stderr.contains("53"));
    assert!(output.stderr.contains("13"));
}

fn test<const N: usize>(args: [&str; N]) -> Output {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code = crate::main_args(
        std::iter::once("cosign2").chain(args),
        &mut stdout,
        &mut stderr,
    );
    println!("* args: {:?}", args);
    println!("* exit_code: {:?}", exit_code);
    println!("* stdout:\n{}", String::from_utf8_lossy(&stdout));
    println!("* stderr:\n{}", String::from_utf8_lossy(&stderr));
    Output {
        exit_code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

#[derive(Debug)]
struct Output {
    exit_code: ExitCode,
    stdout: String,
    stderr: String,
}

fn create_file(data: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(data).unwrap();
    file
}

struct DataWithHeader {
    magic: [u8; 4],
    timestamp: [u8; 4],
    date: [u8; 14],
    version: [u8; 20],
    firmware_size: [u8; 4],
    data: Vec<u8>,
}

impl DataWithHeader {
    fn sign(
        self,
        secret1: Option<secp256k1::SecretKey>,
        secret2: Option<secp256k1::SecretKey>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.timestamp);
        buf.extend_from_slice(&self.date);
        buf.extend_from_slice(&self.version);
        buf.extend_from_slice(&self.firmware_size);
        let message = self.hash();
        let secp = secp256k1::Secp256k1::new();
        if let Some(pubkey1) = secret1 {
            let signature1 = secp.sign_ecdsa(&message, &pubkey1);
            buf.extend_from_slice(&pubkey1.public_key(&secp).serialize());
            buf.extend_from_slice(&signature1.serialize_compact());
        } else {
            buf.extend_from_slice(&[0; 33]);
            buf.extend_from_slice(&[0; 64]);
        }
        if let Some(pubkey2) = secret2 {
            let signature2 = secp.sign_ecdsa(&message, &pubkey2);
            buf.extend_from_slice(&pubkey2.public_key(&secp).serialize());
            buf.extend_from_slice(&signature2.serialize_compact());
        } else {
            buf.extend_from_slice(&[0; 33]);
            buf.extend_from_slice(&[0; 64]);
        }
        buf.extend_from_slice(&[0; cosign2::Header::RESERVED]);
        buf.extend_from_slice(&self.data);
        buf
    }

    fn hash(&self) -> secp256k1::Message {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.magic);
        hasher.update(self.timestamp);
        hasher.update(self.date);
        hasher.update(self.version);
        hasher.update(self.firmware_size);
        hasher.update([0; cosign2::Header::RESERVED]);
        hasher.update(self.data.as_slice());
        secp256k1::Message::from_digest_slice(&sha2::Sha256::digest(hasher.finalize()))
            .expect("32 bytes")
    }
}
