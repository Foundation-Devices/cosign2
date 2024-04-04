use {clap::Parser, sec1::der::Decode, std::path::PathBuf};

mod cli;
mod config;

pub use config::Error as ConfigError;

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
            // Load and validate the config.
            let config = config.map(|c| config::Config::load(&c)).transpose()?;
            let config_pubkey = config
                .as_ref()
                .map(|config| {
                    secp256k1::PublicKey::from_slice(
                        &hex::decode(&config.pubkey)
                            .map_err(|_| Error::InvalidPubkeyHexInConfig)?,
                    )
                    .map_err(Error::InvalidPubkeyInConfig)
                })
                .transpose()?;
            let config_secret_path = config
                .as_ref()
                .map(|config| {
                    if !config.secret.is_absolute() {
                        return Err(Error::SecretPathNotAbsoluteInConfig(config.secret.clone()));
                    }
                    Ok(config.secret.clone())
                })
                .transpose()?;
            let config_known_pubkeys = config
                .as_ref()
                .map(|config| {
                    config
                        .known_pubkeys
                        .iter()
                        .map(|known_pubkey| {
                            hex::decode(known_pubkey)
                                .map_err(|_| {
                                    Error::InvalidKnownPubkeyHexInConfig(known_pubkey.clone())
                                })
                                .and_then(|p| {
                                    secp256k1::PublicKey::from_slice(&p).map_err(|_| {
                                        Error::InvalidKnownPubkeyInConfig(known_pubkey.clone())
                                    })
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            let config_target = config
                .as_ref()
                .map(|config| match config.target.as_str() {
                    "atsama5d27-keyos" => Ok(Target::Atsama5d27KeyOs),
                    _ => Err(Error::InvalidTargetInConfig),
                })
                .transpose()?;

            let pubkey = pubkey
                .map(|p| {
                    secp256k1::PublicKey::from_slice(
                        &hex::decode(p).map_err(|_| Error::InvalidPubkeyHex)?,
                    )
                    .map_err(Error::InvalidPubkey)
                })
                .transpose()?
                .or(config_pubkey);
            let secret = secret.or(config_secret_path).ok_or(Error::SecretMissing)?;
            let pem = std::fs::read(secret).map_err(Error::ReadPemFile)?;
            let key = pem::parse(pem)?;
            if key.tag() != "EC PRIVATE KEY" {
                return Err(Error::InvalidPemTag(key.tag().to_string()));
            }
            let secret = sec1::EcPrivateKey::from_der(key.contents())
                .map_err(Error::ParseDerContent)?
                .private_key;
            let secret =
                secp256k1::SecretKey::from_slice(secret).map_err(Error::InvalidSecretKey)?;
            if in_place && output.is_some() {
                return Err(Error::InPlaceAndOutputSpecified);
            }
            let output = if in_place {
                Output::InPlace
            } else {
                Output::File(output.unwrap())
            };
            let target = target
                .map(|t| match t.as_str() {
                    "atsama5d27-keyos" => Ok(Target::Atsama5d27KeyOs),
                    _ => Err(Error::InvalidTarget),
                })
                .transpose()?
                .or(config_target)
                .ok_or(Error::TargetMissing)?;
            let known_pubkeys = known_pubkeys
                .map(|known_pubkeys| {
                    known_pubkeys
                        .into_iter()
                        .map(|known_pubkey| {
                            hex::decode(&known_pubkey)
                                .map_err(|_| Error::InvalidKnownPubkeyHex(known_pubkey.clone()))
                                .and_then(|p| {
                                    secp256k1::PublicKey::from_slice(&p).map_err(|_| {
                                        Error::InvalidKnownPubkey(known_pubkey.clone())
                                    })
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .or(config_known_pubkeys)
                .unwrap_or_default();
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
    Config(ConfigError),
    InPlaceAndOutputSpecified,
    InvalidKnownPubkey(String),
    InvalidKnownPubkeyHex(String),
    InvalidKnownPubkeyHexInConfig(String),
    InvalidKnownPubkeyInConfig(String),
    InvalidPemTag(String),
    InvalidPubkey(secp256k1::Error),
    InvalidPubkeyHex,
    InvalidPubkeyHexInConfig,
    InvalidPubkeyInConfig(secp256k1::Error),
    InvalidSecretKey(secp256k1::Error),
    InvalidTarget,
    InvalidTargetInConfig,
    ParseDerContent(sec1::der::Error),
    ParsePemFile(pem::PemError),
    ReadPemFile(std::io::Error),
    SecretMissing,
    SecretPathNotAbsoluteInConfig(PathBuf),
    TargetMissing,
}

impl From<pem::PemError> for Error {
    fn from(e: pem::PemError) -> Self {
        Error::ParsePemFile(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Error::Config(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(e) => write!(f, "config error: {e}"),
            Error::InPlaceAndOutputSpecified => {
                write!(f, "cannot specify both --in-place and --output (-o)")
            }
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
            Error::InvalidKnownPubkeyHexInConfig(pubkey) => {
                write!(
                    f,
                    r#"config error: config file contains invalid known public key hex: "{pubkey}""#
                )
            }
            Error::InvalidKnownPubkeyInConfig(pubkey) => {
                write!(
                    f,
                    r#"config error: config file contains invalid known public key: "{pubkey}""#
                )
            }
            Error::InvalidPemTag(tag) => {
                write!(f, r#"invalid PEM tag: "{tag}", expected "EC PRIVATE KEY""#)
            }
            Error::InvalidPubkey(e) => write!(f, "user specified invalid public key: {e}"),
            Error::InvalidPubkeyHex => write!(f, "user specified invalid public key hex"),
            Error::InvalidPubkeyHexInConfig => {
                write!(
                    f,
                    "config error: config file contains invalid public key hex"
                )
            }
            Error::InvalidPubkeyInConfig(e) => {
                write!(
                    f,
                    "config error: config file contains invalid public key: {e}"
                )
            }
            Error::InvalidSecretKey(e) => write!(f, "user specified invalid secret key: {e}"),
            Error::InvalidTarget => write!(f, "user specified invalid target"),
            Error::InvalidTargetInConfig => {
                write!(f, "config error: config file contains invalid target")
            }
            Error::ParseDerContent(e) => {
                write!(f, "failed to parse DER content inside PEM file: {e}")
            }
            Error::ParsePemFile(e) => write!(f, "invalid PEM file: {e}"),
            Error::ReadPemFile(e) => write!(f, "failed to read PEM file: {e}"),
            Error::SecretMissing => write!(f, "user did not specify a secret key"),
            Error::SecretPathNotAbsoluteInConfig(path) => {
                write!(
                    f,
                    r#"config error: secret key path is not absolute: "{}""#,
                    path.to_str().unwrap_or("<invalid path>")
                )
            }
            Error::TargetMissing => write!(f, "user did not specify a target"),
        }
    }
}

impl std::error::Error for Error {}
