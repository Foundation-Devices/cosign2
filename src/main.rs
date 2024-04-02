// TODO After writing the output file, do another parse() as a sanity check. If
// it fails print an error asking if other processes are writing to the file.

use {colored::Colorize, std::io::Seek};

mod args;

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {e}", "error".bold().red());
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    match args::args()? {
        args::Args::Dump { input } => {
            let input = std::fs::File::open(input).map_err(Error::OpenInputFile)?;
            match cosign2::Header::parse(&input, &[])? {
                Some(header) => {
                    let magic = match header.magic() {
                        cosign2::Magic::Atsama5d27KeyOs => "atsama5d27-keyos",
                    };
                    let timestamp = chrono::DateTime::from_timestamp(header.timestamp().into(), 0)
                        .expect("valid timestamp");
                    println!("{:10} {magic}", "magic".bold());
                    println!(
                        "{:10} {timestamp} ({})",
                        "timestamp".bold(),
                        header.timestamp()
                    );
                    println!("{:10} {}", "date".bold(), header.date());
                    println!("{:10} {}", "version".bold(), header.version());
                    let human_size =
                        humansize::format_size(header.firmware_size(), humansize::BINARY);
                    println!(
                        "{:10} {human_size} ({})",
                        "size".bold(),
                        header.firmware_size()
                    );
                    println!(
                        "{:10} 0x{}",
                        "pubkey1".bold(),
                        match header.pubkey1() {
                            Some(pubkey) => pubkey.to_string(),
                            None => "0".repeat(66),
                        }
                    );
                    let signature1 = match header.signature1() {
                        Some(signature) => signature.serialize_compact(),
                        None => [0; 64],
                    };
                    println!(
                        "{:10} 0x{}",
                        "signature1".bold(),
                        hex::encode(&signature1[..32])
                    );
                    println!("{} {}", " ".repeat(12), hex::encode(&signature1[32..]));
                    println!(
                        "{:10} 0x{}",
                        "pubkey2".bold(),
                        match header.pubkey2() {
                            Some(pubkey) => pubkey.to_string(),
                            None => "0".repeat(66),
                        }
                    );
                    let signature2 = match header.signature2() {
                        Some(signature) => signature.serialize_compact(),
                        None => [0; 64],
                    };
                    println!(
                        "{:10} 0x{}",
                        "signature2".bold(),
                        hex::encode(&signature2[..32])
                    );
                    println!("{} {}", " ".repeat(12), hex::encode(&signature2[32..]));
                }
                None => println!("no header found"),
            }
        }
        args::Args::Sign {
            pubkey: expected_pubkey,
            secret,
            input,
            output,
            version,
            target,
            known_pubkeys,
            developer,
        } => {
            // Check that user is not accidentally signing with the wrong key.
            let pubkey = secret.public_key(&secp256k1::Secp256k1::new());
            if let Some(expected_pubkey) = expected_pubkey {
                if pubkey != expected_pubkey {
                    return Err(Error::KeyMismatch);
                }
            }
            if !known_pubkeys.is_empty() && !known_pubkeys.contains(&pubkey) {
                return Err(Error::UnknownSigner);
            }

            let magic = match target {
                args::Target::Atsama5d27KeyOs => cosign2::Magic::Atsama5d27KeyOs,
            };
            let mut input = std::fs::File::open(input).map_err(Error::OpenInputFile)?;
            let mut output = match output {
                args::Output::InPlace => todo!(),
                args::Output::File(path) => {
                    std::fs::File::create(path).map_err(Error::OpenOutputFile)?
                }
            };

            let header = match cosign2::Header::parse(&input, &known_pubkeys)? {
                // If a header is present, add a second signature.
                Some(mut header) => {
                    header.add_second_signature(&secret)?;
                    header
                }
                // If no header is present, create and sign a new header.
                None => {
                    input
                        .seek(std::io::SeekFrom::Start(0))
                        .map_err(Error::SeekInputFile)?;
                    cosign2::Header::sign_new(
                        magic,
                        version,
                        input
                            .metadata()
                            .map_err(Error::InputFileMetadata)?
                            .len()
                            .try_into()
                            .map_err(|_| Error::Cosign2(cosign2::Error::FirmwareTooLong))?,
                        if developer {
                            cosign2::Signer::Developer(&secret)
                        } else {
                            cosign2::Signer::Trusted(&secret)
                        },
                        &input,
                    )?
                }
            };

            // Write the signed header and firmware to output file.
            header.serialize(&output)?;
            input
                .seek(std::io::SeekFrom::Start(0))
                .map_err(Error::SeekInputFile)?;
            std::io::copy(&mut input, &mut output).map_err(Error::CopyFirmware)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum Error {
    Args(args::Error),
    Cosign2(cosign2::Error),
    KeyMismatch,
    UnknownSigner,
    OpenInputFile(std::io::Error),
    SeekInputFile(std::io::Error),
    OpenOutputFile(std::io::Error),
    InputFileMetadata(std::io::Error),
    CopyFirmware(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Args(e) => write!(f, "{e}"),
            Error::Cosign2(e) => write!(f, "{e}"),
            Error::KeyMismatch => write!(f, "public key does not match secret key"),
            Error::UnknownSigner => write!(f, "signing key is not in known pubkeys list"),
            Error::OpenInputFile(e) => write!(f, "failed to open input file: {e}"),
            Error::OpenOutputFile(e) => write!(f, "failed to open output file: {e}"),
            Error::InputFileMetadata(e) => write!(f, "failed to get input file metadata: {e}"),
            Error::SeekInputFile(e) => write!(f, "failed to seek input file: {e}"),
            Error::CopyFirmware(e) => {
                write!(f, "failed to copy firmware from input to output file: {e}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<args::Error> for Error {
    fn from(e: args::Error) -> Self {
        Error::Args(e)
    }
}

impl From<cosign2::Error> for Error {
    fn from(e: cosign2::Error) -> Self {
        Error::Cosign2(e)
    }
}
