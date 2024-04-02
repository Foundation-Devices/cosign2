// TODO I think the only two things here would be the public key and the path to
// the PEM file
// And that path should probably be absolute
// TODO Also valid_signers
// TODO And the target

use std::path::Path;

pub struct Config;

impl Config {
    pub fn load(_path: &Path) -> Self {
        todo!()
    }
}
