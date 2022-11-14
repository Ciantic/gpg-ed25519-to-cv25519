use clap::{arg, Parser};
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};
use std::path::PathBuf;

use crate::utils::base64_to_bytes;

#[derive(Parser, Debug)]
pub struct X25519Cmds {
    #[command(subcommand)]
    cmd: X25519Choices,
}

#[derive(Parser, Debug)]
pub enum X25519Choices {
    /// Calculate a shared secret from a public key and ephemeral secret
    Encrypt(EncryptOpts),

    /// Calculate a shared secret from a public key and ephemeral secret
    PrivateKey(PrivateKeyOpts),

    /// Calculate shared secret from private key and ephemeral public key
    Decrypt(DecryptOpts),

    /// Clamp a scalar / private key
    Clamp(ClampScalarOpts),
}

#[derive(Parser, Debug)]
pub struct PrivateKeyOpts {
    #[arg(
        value_name = "X25519_PRIVATE_KEY",
        help = "32 byte private key in base64 format"
    )]
    pub x25519_private_key: String,

    #[arg(long, help = "Return ED25519 public key part in base64 format")]
    pub get_public_key: bool,
}

#[derive(Parser, Debug)]
pub struct ClampScalarOpts {
    #[arg(
        value_name = "X25519_SCALAR",
        help = "32 byte private key candidate or scalar in base64 format"
    )]
    pub x25519_scalar: String,
}

#[derive(Parser, Debug)]
pub struct EncryptOpts {
    #[arg(
        value_name = "X25519_PUBLIC_KEY",
        help = "32 byte public key in base64 format"
    )]
    pub x25519_pub_key: String,

    #[arg(
        value_name = "EPHEMERAL_SECRET",
        help = "32 byte random secret or private key in base64 format"
    )]
    pub secret: String,
}

#[derive(Parser, Debug)]
pub struct DecryptOpts {
    #[arg(
        value_name = "X25519_PRIVATE_KEY",
        help = "32 byte receiver's private key in base64 format"
    )]
    pub x25519_private_key: String,

    #[arg(
        value_name = "EPHEMERAL_PUBLIC_KEY",
        help = "32 byte ephemeral public key in base64 format"
    )]
    pub ephemeral_public_key: String,
}

pub fn x25519(c: X25519Cmds) -> Result<(), String> {
    match c.cmd {
        X25519Choices::Encrypt(opts) => {
            x25519_encrypt(opts).map(|(cipher_pub_key, shared_ecc_key)| {
                println!(
                    "Cipher public key: {}\nShared ECC key: {}",
                    cipher_pub_key, shared_ecc_key
                );
            })
        }
        X25519Choices::Decrypt(opts) => x25519_decrypt(opts).map(|shared_ecc_key| {
            println!("Shared ECC key: {}", shared_ecc_key);
        }),
        X25519Choices::Clamp(opts) => {
            let x25519_clamped = clamp_scalar(base64_to_bytes(&opts.x25519_scalar)?);
            println!("{}", base64::encode(x25519_clamped.to_bytes()));
            Ok(())
        }
        X25519Choices::PrivateKey(opts) => {
            if opts.get_public_key {
                let pub_key = x25519_private_key_to_public_key(&opts.x25519_private_key)?;
                println!("{}", pub_key);
            }
            Ok(())
        }
    }
}

pub fn x25519_private_key_to_public_key(x25519_private_key: &str) -> Result<String, String> {
    let bytes = base64_to_bytes(&x25519_private_key)?;
    let secret = clamp_scalar(bytes);
    let x25519_public_key = secret * X25519_BASEPOINT;
    Ok(base64::encode(x25519_public_key.to_bytes()))
}

pub fn x25519_encrypt(opts: EncryptOpts) -> Result<(String, String), String> {
    let x25519_pub_key = MontgomeryPoint(base64_to_bytes(&opts.x25519_pub_key)?);
    let secret = clamp_scalar(base64_to_bytes(&opts.secret)?);

    let cipher_pub_key = secret * X25519_BASEPOINT;
    let shared_ecc_key = x25519_pub_key * secret;

    Ok((
        base64::encode(cipher_pub_key.to_bytes()),
        base64::encode(shared_ecc_key.to_bytes()),
    ))
}

pub fn x25519_decrypt(opts: DecryptOpts) -> Result<String, String> {
    let x25519_private_key = clamp_scalar(base64_to_bytes(&opts.x25519_private_key)?);
    let ephemeral_public_key = MontgomeryPoint(base64_to_bytes(&opts.ephemeral_public_key)?);

    let shared_ecc_key = ephemeral_public_key * x25519_private_key;

    Ok(base64::encode(shared_ecc_key.to_bytes()))
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC7748 test vectors: https://tools.ietf.org/html/rfc7748#section-6.1

    const BOB_PUBLIC_KEY: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
    const BOB_PRIVATE_KEY: &str = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";
    const ALICE_PUBLIC_KEY: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const ALICE_PRIVATE_KEY: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";

    const SHARED_SECRET: &str = "Sl2dW6TOLeFyjjv0gDUPJeB+IclH0Z4zdvCbPB4WF0I=";

    #[test]
    fn sanity_test_for_ed25519_module() {
        // This tests same values as in ed25519.rs test conversion
        const X25519_PRIVATE_KEY: &str = "MHyDhk8oM8tCei7xwAoBPP3/J2jZgMCjpSDwBpBN6U8=";
        const X25519_PUBLIC_KEY: &str = "2F4H7CKwrYgVN8L0TWYtGhQ8+DDFespDBdhcepD2ti4=";
        let x25519_public_key = x25519_private_key_to_public_key(X25519_PRIVATE_KEY).unwrap();
        assert_eq!(x25519_public_key, X25519_PUBLIC_KEY);
    }

    #[test]
    fn test_x25519_get_public_key() {
        let x25519_public_key = x25519_private_key_to_public_key(BOB_PRIVATE_KEY).unwrap();
        assert_eq!(x25519_public_key, BOB_PUBLIC_KEY);
    }

    /// Alice sends Bob a message, thus she uses Bob's public key and her private key
    #[test]
    fn test_x25519_encrypt() {
        let opts = EncryptOpts {
            x25519_pub_key: BOB_PUBLIC_KEY.to_string(),
            secret: ALICE_PRIVATE_KEY.to_string(),
        };
        let (cipher_pub_key, shared_ecc_key) = x25519_encrypt(opts).unwrap();
        assert_eq!(cipher_pub_key, ALICE_PUBLIC_KEY);
        assert_eq!(shared_ecc_key, SHARED_SECRET);
    }

    /// Bob decrypts a message, thus he uses Alice's public key and his private key
    #[test]
    fn test_x25519_decrypt() {
        let opts = DecryptOpts {
            x25519_private_key: BOB_PRIVATE_KEY.to_string(),
            ephemeral_public_key: ALICE_PUBLIC_KEY.to_string(),
        };
        let shared_ecc_key = x25519_decrypt(opts).unwrap();
        assert_eq!(shared_ecc_key, SHARED_SECRET);
    }
}

// 32 bytes
// 0102030405060708091011121314151617181920212223242526272829303132
