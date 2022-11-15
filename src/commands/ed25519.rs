use std::path::PathBuf;

use clap::{arg, command, Parser};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, X25519_BASEPOINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use ed25519_dalek::{Digest, PublicKey, SecretKey, Sha512};

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
    /// Operations on Ed25519 public key
    PublicKey(PublicKeyOpts),
    // TODO: Sign and verify
}
#[derive(Parser, Debug)]
pub struct PrivateKeyOpts {
    #[arg(
        value_name = "ED25519_PRIVATE_KEY",
        help = "Ed25519 32 byte private key seed in base64 format"
    )]
    pub ed25519_key: String,

    #[arg(long, help = "Return x25519 equivalent private key in base64 format")]
    pub convert_to_x25519_private_key: bool,

    #[arg(long, help = "Return ED25519 public key part in base64 format")]
    pub get_public_key: bool,
}

#[derive(Parser, Debug)]
pub struct PublicKeyOpts {
    #[arg(
        value_name = "ED25519_PUBLIC_KEY",
        help = "Ed25519 32 byte public key in base64 format"
    )]
    pub ed25519_key: String,

    #[arg(long, help = "Return x25519 equivalent private key in base64 format")]
    pub convert_to_x25519_public_key: bool,
}
pub fn ed25519(opts: Ed25519Cmds) -> Result<(), String> {
    match opts.cmd {
        Ed25519Choices::PrivateKey(opts) => ed25519_sk(opts),
        Ed25519Choices::PublicKey(opts) => ed25519_pk(opts),
    }
}

fn ed25519_pk(opts: PublicKeyOpts) -> Result<(), String> {
    let ed25519_public_key = base64_to_bytes(&opts.ed25519_key)?;
    if opts.convert_to_x25519_public_key {
        println!(
            "{}",
            base64::encode(ed25519_pk_to_x25519_pk(&ed25519_public_key))
        );
    }
    Ok(())
}

fn ed25519_sk(opts: PrivateKeyOpts) -> Result<(), String> {
    let ed25519_private_key = base64_to_bytes(&opts.ed25519_key)?;

    if opts.get_public_key {
        println!("{}", base64::encode(ed25519_sk_to_pk(&ed25519_private_key)));
        return Ok(());
    }

    if opts.convert_to_x25519_private_key {
        println!(
            "{}",
            base64::encode(ed25519_sk_to_x25519_sk(&ed25519_private_key))
        );
        return Ok(());
    }
    Ok(())
}

/// Get ED25519 Public key from ED25519 private key seed
fn ed25519_sk_to_pk(ed25519_private_key: &[u8; 32]) -> [u8; 32] {
    // secret_to_public function in  https://www.rfc-editor.org/rfc/rfc8032#section-6
    let sk = ed25519_sk_to_x25519_sk(ed25519_private_key);
    let pk = Scalar::from_bits(sk) * ED25519_BASEPOINT_POINT;
    pk.compress().to_bytes()
}

fn ed25519_pk_to_x25519_pk(ed25519_pk: &[u8; 32]) -> [u8; 32] {
    CompressedEdwardsY::from_slice(ed25519_pk)
        .decompress()
        .unwrap()
        .to_montgomery()
        .to_bytes()
}

/// Convert an Ed25519 private key seed to an X25519 private key.
fn ed25519_sk_to_x25519_sk(ed25519_private_key: &[u8; 32]) -> [u8; 32] {
    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 32] = [0u8; 32];
    h.update(ed25519_private_key);
    let f = h.finalize();
    let slice = f.as_slice();
    hash.copy_from_slice(&slice[0..32]);
    // Clamp scalar
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64_to_bytes;

    // RFC8032 Test vectors https://www.rfc-editor.org/rfc/rfc8032#section-7.1
    const ED25519_PRIVATE_KEY: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const ED25519_PUBLIC_KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    // Converted from ed25519 private/public key (not part of test vectors)
    // It's tested in x25519.rs that X25519 private key and public key match
    const X25519_PRIVATE_KEY: &str = "MHyDhk8oM8tCei7xwAoBPP3/J2jZgMCjpSDwBpBN6U8=";
    const X25519_PUBLIC_KEY: &str = "2F4H7CKwrYgVN8L0TWYtGhQ8+DDFespDBdhcepD2ti4=";

    /// Test that ed25519 private key -> public key
    #[test]
    fn test_ed25519_sk_to_pk() {
        let ed25519_private_key = base64_to_bytes(&ED25519_PRIVATE_KEY).unwrap();
        let pub_key = ed25519_sk_to_pk(&ed25519_private_key);
        assert_eq!(&base64::encode(pub_key), &ED25519_PUBLIC_KEY)
    }

    /// Test ed25519 private key -> X25519 private key conversion
    #[test]
    fn test_ed25519_sk_to_x25519_sk() {
        let ed25519_private_key = base64_to_bytes(&ED25519_PRIVATE_KEY).unwrap();
        let x25519_private_key = ed25519_sk_to_x25519_sk(&ed25519_private_key);
        assert_eq!(base64::encode(x25519_private_key), X25519_PRIVATE_KEY)
    }

    /// Test ed25519 public key -> X25519 public key conversion
    #[test]
    fn test_ed25519_pk_to_x25519_pk() {
        let ed25519_public_key = base64_to_bytes(&ED25519_PUBLIC_KEY).unwrap();
        let x25519_pub_key = ed25519_pk_to_x25519_pk(&ed25519_public_key);
        assert_eq!(&base64::encode(x25519_pub_key), &X25519_PUBLIC_KEY)
    }
}
