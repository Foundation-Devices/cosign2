use {clap::Parser, sec1::der::Decode, std::path::PathBuf};

mod cli;
mod config;

/// Program arguments loaded from the CLI and config file.
#[derive(Debug, Clone)]
pub enum Args {
    /// Dump the header contents to stdout.
    Dump { input: PathBuf },
    /// Sign a firmware file.
    Sign {
        pubkey: Option<secp256k1::PublicKey>,
        secret: secp256k1::SecretKey,
        input: PathBuf,
        output: Output,
        version: semver::Version,
        target: Target,
        known_pubkeys: Vec<secp256k1::PublicKey>,
        developer: bool,
    },
}

#[derive(Debug, Clone)]
pub enum Output {
    InPlace,
    File(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Atsama5d27KeyOs,
}

pub fn args() -> Result<Args, Error> {
    let cli = cli::Args::parse();
    match cli.command {
        cli::Command::Dump { input: file } => Ok(Args::Dump { input: file }),
        cli::Command::Sign {
            pubkey,
            secret,
            config,
            input,
            in_place,
            output,
            firmware_version,
            developer,
            target,
            known_pubkeys,
        } => {
            let _config = config.map(|c| config::Config::load(&c));
            let pubkey = match pubkey {
                Some(p) => Some(
                    secp256k1::PublicKey::from_slice(
                        &hex::decode(p).map_err(|_| Error::InvalidPubkeyHex)?,
                    )
                    .map_err(Error::InvalidPubkey)?,
                ),
                None => {
                    // TODO try reading from config, return none if missing
                    None
                }
            };
            let secret = match secret {
                Some(s) => {
                    let pem = std::fs::read(s).map_err(Error::ReadPemFile)?;
                    let key = pem::parse(pem)?;
                    if key.tag() != "EC PRIVATE KEY" {
                        return Err(Error::InvalidPemTag(key.tag().to_string()));
                    }
                    let secret = sec1::EcPrivateKey::from_der(key.contents())
                        .map_err(Error::ParseDerContent)?
                        .private_key;
                    secp256k1::SecretKey::from_slice(secret).map_err(Error::InvalidSecretKey)?
                }
                None => {
                    todo!("try reading from config, error if missing")
                }
            };
            if in_place && output.is_some() {
                return Err(Error::InPlaceAndOutputSpecified);
            }
            let output = if in_place {
                Output::InPlace
            } else {
                Output::File(output.unwrap())
            };
            let target = if target == "atsama5d27-keyos" {
                Target::Atsama5d27KeyOs
            } else {
                return Err(Error::InvalidTarget);
            };
            let known_pubkeys = known_pubkeys
                .unwrap_or_default()
                .into_iter()
                .map(|known_pubkey| {
                    hex::decode(&known_pubkey)
                        .map_err(|_| Error::InvalidKnownPubkeyHex(known_pubkey.clone()))
                        .and_then(|p| {
                            secp256k1::PublicKey::from_slice(&p)
                                .map_err(|_| Error::InvalidKnownPubkey(known_pubkey.clone()))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Args::Sign {
                pubkey,
                secret,
                input,
                output,
                version: firmware_version,
                target,
                developer,
                known_pubkeys,
            })
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ReadPemFile(std::io::Error),
    ParsePemFile(pem::PemError),
    ParseDerContent(sec1::der::Error),
    InvalidPemTag(String),
    InvalidPubkey(secp256k1::Error),
    InvalidSecretKey(secp256k1::Error),
    InvalidPubkeyHex,
    InPlaceAndOutputSpecified,
    InvalidTarget,
    InvalidKnownPubkey(String),
    InvalidKnownPubkeyHex(String),
}

impl From<pem::PemError> for Error {
    fn from(e: pem::PemError) -> Self {
        Error::ParsePemFile(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReadPemFile(e) => write!(f, "failed to read PEM file: {e}"),
            Error::ParsePemFile(e) => write!(f, "invalid PEM file: {e}"),
            Error::InvalidPemTag(tag) => {
                write!(f, r#"invalid PEM tag: {tag}, expected "EC PRIVATE KEY""#)
            }
            Error::ParseDerContent(e) => {
                write!(f, "failed to parse DER content inside PEM file: {e}")
            }
            Error::InvalidPubkey(e) => write!(f, "user specified invalid public key: {e}"),
            Error::InvalidSecretKey(e) => write!(f, "user specified invalid secret key: {e}"),
            Error::InvalidPubkeyHex => write!(f, "user specified invalid public key hex"),
            Error::InPlaceAndOutputSpecified => {
                write!(f, "cannot specify both --in-place and --output")
            }
            Error::InvalidTarget => write!(f, "user specified invalid target"),
            Error::InvalidKnownPubkey(pubkey) => {
                write!(f, r#"user specified invalid known public key: "{pubkey}""#)
            }
            Error::InvalidKnownPubkeyHex(pubkey) => {
                write!(
                    f,
                    r#"user specified invalid known public key hex: "{}""#,
                    pubkey
                )
            }
        }
    }
}

impl std::error::Error for Error {}
