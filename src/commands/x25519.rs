use clap::{arg, Parser};
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct X25519Cmds {
    #[command(subcommand)]
    cmd: X25519Choices,
}

#[derive(Parser, Debug)]
pub enum X25519Choices {
    /// Calculate a shared secret from a public key and ephemeral secret
    Encrypt(EncryptOpts),

    /// Calculate shared secret from private key and ephemeral public key
    Decrypt(DecryptOpts),
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
    }
}

pub fn x25519_encrypt(opts: EncryptOpts) -> Result<(String, String), String> {
    let x25519_pub_key = {
        let key = base64::decode(&opts.x25519_pub_key).map_err(|e| e.to_string())?;
        let mut buf: [u8; 32] = [0; 32];
        buf.copy_from_slice(key.as_slice());
        MontgomeryPoint(buf)
    };
    let secret = {
        let key = base64::decode(&opts.secret).map_err(|e| e.to_string())?;
        let mut buf: [u8; 32] = [0; 32];
        buf.copy_from_slice(key.as_slice());
        clamp_scalar(buf)
    };
    // from from_bytes_mod_order
    // Cipher public key: 0jxltmrWdXoDaT/sUrY8PrsthuZAZYlacomV8U+QfxQ=
    // Shared ECC key: 6NAf2IzBgSAF/s3iGAB158vsGNIK3J70Cli4Q/73JUs=
    //

    let cipher_pub_key = secret * X25519_BASEPOINT;
    let shared_ecc_key = x25519_pub_key * secret;

    Ok((
        base64::encode(cipher_pub_key.to_bytes()),
        base64::encode(shared_ecc_key.to_bytes()),
    ))
}

pub fn x25519_decrypt(opts: DecryptOpts) -> Result<String, String> {
    let x25519_private_key = {
        let key = base64::decode(&opts.x25519_private_key).map_err(|e| e.to_string())?;
        let mut buf: [u8; 32] = [0; 32];
        buf.copy_from_slice(key.as_slice());
        clamp_scalar(buf)
    };
    let ephemeral_public_key = {
        let key = base64::decode(&opts.ephemeral_public_key).map_err(|e| e.to_string())?;
        let mut buf: [u8; 32] = [0; 32];
        buf.copy_from_slice(key.as_slice());
        MontgomeryPoint(buf)
    };

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
