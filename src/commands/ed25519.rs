use std::path::PathBuf;

use clap::{arg, command, Parser};
use ed25519_dalek::{Digest, Sha512};

use crate::utils::base64_to_bytes;

#[derive(Parser, Debug)]
pub struct Ed25519Cmds {
    #[command(subcommand)]
    cmd: Ed25519Choices,
}

#[derive(Parser, Debug)]
pub enum Ed25519Choices {
    /// Operations on Ed25519 private key
    PrivateKey(PrivateKeyOpts),
}
#[derive(Parser, Debug)]
pub struct PrivateKeyOpts {
    #[arg(
        value_name = "ED25519_PRIVATE_KEY",
        help = "Ed25519 private key in base64 format"
    )]
    pub ed25519_key: String,

    #[arg(long, help = "Return x25519 equivalent private key")]
    pub convert_to_x25519_private_key: bool,
}

pub fn ed25519(opts: Ed25519Cmds) -> Result<(), String> {
    match opts.cmd {
        Ed25519Choices::PrivateKey(opts) => ed25519_sk(opts),
    }
}

fn ed25519_sk(opts: PrivateKeyOpts) -> Result<(), String> {
    let ed25519_private_key = base64_to_bytes(&opts.ed25519_key)?;
    if opts.convert_to_x25519_private_key {
        println!(
            "{}",
            base64::encode(ed25519_sk_to_x25519_sk(&ed25519_private_key))
        );
    }
    Ok(())
}

/// Convert an Ed25519 private key scalar to an X25519 private key.
fn ed25519_sk_to_x25519_sk(ed25519_private_key: &[u8; 32]) -> [u8; 32] {
    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 32] = [0u8; 32];
    h.update(ed25519_private_key);
    let f = h.finalize();
    let slice = f.as_slice();
    hash.copy_from_slice(&slice[0..32]);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64_to_bytes;

    #[test]
    fn test_keypair_seed() {
        let ed25519_private_key =
            base64_to_bytes(&"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let x25519_private_key = ed25519_sk_to_x25519_sk(&ed25519_private_key);
        println!("{}", base64::encode(x25519_private_key));

        assert_eq!(
            base64::encode(x25519_private_key),
            "UEatwduoOIZ7K7v90MNCPli1eXC1JnqQ9XlgkkqH8VY="
        )
    }
}
