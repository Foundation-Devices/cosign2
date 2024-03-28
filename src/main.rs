// TODO Remember Ken wants this:
// - Both Private & Public keys specified on command line (when doing this,
// compare public keys, don't compare the private keys!)
// - Use Semantic Versioning for all version numbers (Rust semver crate)

// TODO After writing the output file, do another parse() as a sanity check. If
// it fails print an error asking if other processes are writing to the file.

// TODO I need CI

// TODO Cargo.lock shouldn't be published with the library, but should be
// committed with the binary, not sure what's the best way to approach this

use {
    cosign2::{PublicKey, SecretKey},
    secp256k1::Secp256k1,
};

fn main() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let bytes = public_key.serialize();
    dbg!(bytes);
    PublicKey::from_slice(&bytes).unwrap();
    println!("Hello, world!");
}
