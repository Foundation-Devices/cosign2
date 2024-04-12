use {crate::ExitCode, std::io::Write};

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

// TODO Check the same thing when signing
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

// TODO Check the same thing when signing
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

// TODO Check the same thing when signing
/// Dump header with the first pubkey changed.
#[test]
fn dump_invalid_header_invalid_pubkey1() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_PUBKEY1_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid pubkey1"));
}

// TODO Check the same thing when signing
/// Dump header with the second pubkey changed.
#[test]
fn dump_invalid_header_invalid_pubkey2() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_PUBKEY2_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid pubkey2"));
}

// TODO Check the same thing when signing
/// Dump header with the first signature changed.
#[test]
fn dump_invalid_header_invalid_signature1() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_SIGNATURE1_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature1"));
}

// TODO Check the same thing when signing
/// Dump header with the second signature changed.
#[test]
fn dump_invalid_header_invalid_signature2() {
    let file = create_file(fixtures::INVALID_HEADER_TWO_SIGNATURES_SIGNATURE2_CHANGED);
    let output = test(["dump", "-i", file.path().to_str().unwrap()]);
    assert_eq!(output.exit_code, ExitCode(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("invalid signature2"));
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
