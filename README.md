# Cosign2

Cosign2 is a Rust library and CLI tool for signing firmware images.
The library part is `#[no_std]` and intended to be used in bootloaders.

TODO Add docs link once the crate is uploaded

## CLI Flags

The following commands are supported:

```
Usage: cosign2 <COMMAND>

Commands:
  dump  Dump the header contents to stdout
  sign  Sign a firmware file
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

The dump command prints header contents to stdout:

```
Dump the header contents to stdout

Usage: cosign2 dump --input <INPUT>

Options:
  -i, --input <INPUT>  The firmware file
  -h, --help           Print help
```

The sign command is used to sign the firmware:

```
Sign a firmware file

Usage: cosign2 sign [OPTIONS] --input <INPUT>

Options:
      --pubkey <PUBKEY>
          The public key in hex, verified against the secret key to avoid accidental signing
      --secret <SECRET>
          Path to PEM-encoded secret key
  -c, --config <CONFIG>
          Path to config file
  -i, --input <INPUT>
          The firmware file
      --in-place
          Update the firmware file in place
  -o, --output <OUTPUT>
          Path to write the signed firmware file
      --firmware-version <FIRMWARE_VERSION>
          Version to write in the header
      --developer
          Developer mode, signs with a single key
      --target <TARGET>
          Target device. Valid values are "atsama5d27-keyos"
      --known-pubkey <KNOWN_PUBKEY>
          Known public keys to accept signatures from, separated by commas
  -h, --help
          Print help
```

## Configuration File

To avoid repeating CLI flags whenever running the tool, the user can specify a config file.
The config file is in TOML has the following format:

```toml
pubkey = "02118f59082b8e26753c1cab1bfead3259344c03312cbb4ff7bdecceb915e92c9b"
secret = "/absolute/path/to/private_key.pem" # NOTE: the path must be absolute
known_pubkeys = ["02118f59082b8e26753c1cab1bfead3259344c03312cbb4ff7bdecceb915e92c9b"]
target = "atsama5d27-keyos"
```

All of the fields are optional. Specifying the same argument in the CLI and in the config
file results in an error.

## Examples

### Sign a Firmware File

```bash
cosign2 sign \
    --secret private-key.pem \
    -i unsigned.img \
    --target atsama5d27-keyos \
    --firmware-version 0.0.121 \
    -o signed.img
```

### Dump the Header Contents

```bash
cosign2 dump -i signed.img
```

### Sign a Firmware File with Config

```bash
cosign2 sign \
    -i unsigned.img \
    --firmware-version 0.0.121 \
    --config my-config-file.toml \
    -o signed.img
```
