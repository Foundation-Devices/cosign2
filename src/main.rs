// TODO After writing the output file, do another parse() as a sanity check. If
// it fails print an error asking if other processes are writing to the file.

use {
    colored::Colorize,
    std::{
        io::Seek,
        path::{Path, PathBuf},
    },
};

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
                        "{:10} {}",
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
                        "{:10} {}",
                        "signature1".bold(),
                        hex::encode(&signature1[..32])
                    );
                    println!("{} {}", " ".repeat(10), hex::encode(&signature1[32..]));
                    println!(
                        "{:10} {}",
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
                        "{:10} {}",
                        "signature2".bold(),
                        hex::encode(&signature2[..32])
                    );
                    println!("{} {}", " ".repeat(10), hex::encode(&signature2[32..]));
                }
                None => println!("no header found"),
            }
        }
        args::Args::Sign {
            pubkey: expected_pubkey,
            secret,
            input: input_path,
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
            let mut input_options = std::fs::OpenOptions::new();
            input_options.read(true);
            if let args::Output::InPlace = output {
                // When working in-place, the input file will be written to.
                input_options.write(true);
            }
            let mut input = input_options
                .open(&input_path)
                .map_err(Error::OpenInputFile)?;
            let output = match output {
                args::Output::InPlace => OutputFile::InPlace(
                    // When working in-place, first write to a temporary file. The temporary
                    // file will be moved to the input file at the end of the process.
                    tempfile::NamedTempFile::new().map_err(Error::CreateTempFile)?,
                ),
                args::Output::File(path) => OutputFile::File(
                    std::fs::File::create(&path).map_err(Error::OpenOutputFile)?,
                    path.to_owned(),
                ),
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
            header.serialize(output.file())?;
            input
                .seek(std::io::SeekFrom::Start(0))
                .map_err(Error::SeekInputFile)?;
            std::io::copy(&mut input, &mut output.file()).map_err(Error::CopyFirmware)?;

            // When working in-place, the output is actually first written to a temporary
            // file. To achieve the effect of in-place editing, the temporary
            // file must be moved to the input file, replacing it.
            if output.is_in_place() {
                move_file(output.file(), output.path(), &input, &input_path)
                    .map_err(Error::MoveTempFile)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum OutputFile {
    InPlace(tempfile::NamedTempFile),
    File(std::fs::File, PathBuf),
}

impl OutputFile {
    fn file(&self) -> &std::fs::File {
        match self {
            OutputFile::InPlace(file) => file.as_file(),
            OutputFile::File(file, _) => file,
        }
    }

    fn path(&self) -> &Path {
        match self {
            OutputFile::InPlace(file) => file.path(),
            OutputFile::File(_, path) => path,
        }
    }

    fn is_in_place(&self) -> bool {
        matches!(self, OutputFile::InPlace(_))
    }
}

#[derive(Debug)]
enum Error {
    Args(args::Error),
    CopyFirmware(std::io::Error),
    Cosign2(cosign2::Error),
    CreateTempFile(std::io::Error),
    InputFileMetadata(std::io::Error),
    KeyMismatch,
    MoveTempFile(std::io::Error),
    OpenInputFile(std::io::Error),
    OpenOutputFile(std::io::Error),
    SeekInputFile(std::io::Error),
    UnknownSigner,
}

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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Args(e) => write!(f, "{e}"),
            Error::CopyFirmware(e) => {
                write!(f, "failed to copy firmware from input to output file: {e}")
            }
            Error::Cosign2(e) => write!(f, "{e}"),
            Error::CreateTempFile(e) => write!(f, "failed to create temporary file: {e}"),
            Error::InputFileMetadata(e) => write!(f, "failed to get input file metadata: {e}"),
            Error::KeyMismatch => write!(f, "public key does not match secret key"),
            Error::MoveTempFile(e) => write!(f, "failed to move temporary file to output: {e}"),
            Error::OpenInputFile(e) => write!(f, "failed to open input file: {e}"),
            Error::OpenOutputFile(e) => write!(f, "failed to open output file: {e}"),
            Error::SeekInputFile(e) => write!(f, "failed to seek input file: {e}"),
            Error::UnknownSigner => write!(f, "signing key is not in known pubkeys list"),
        }
    }
}

impl std::error::Error for Error {}

fn move_file(
    mut from_file: &std::fs::File,
    from_path: &Path,
    mut to_file: &std::fs::File,
    to_path: &Path,
) -> std::io::Result<()> {
    if std::fs::rename(from_path, to_path).is_err() {
        // If rename fails, the files might be on different filesystems.
        // Fall back to copying and removing the original file.
        from_file.seek(std::io::SeekFrom::Start(0))?;
        to_file.seek(std::io::SeekFrom::Start(0))?;
        std::io::copy(&mut from_file, &mut to_file)?;
        std::fs::remove_file(from_path)?;
    }
    Ok(())
}
