use std::path::PathBuf;

use clap::{arg, command, Parser};
use dryoc::classic::{
    crypto_sign::crypto_sign_seed_keypair,
    crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519,
};

#[derive(Parser, Debug)]
pub struct Ed25519Opts {
    #[arg(value_name = "ED25519_KEY", help = "Ed25519 private key in hex format")]
    pub ed25519_key: String,

    // #[arg(long, help = "Return public key in hex format")]
    // pub get_public_key: bool,
    #[arg(long, help = "Return x25519 equivalent private key")]
    pub convert_to_x25519_private_key: bool,
}

pub fn ed25519(opts: Ed25519Opts) -> Result<(), String> {
    let ed25519_key = hex::decode(&opts.ed25519_key).map_err(|e| e.to_string())?;
    let mut ed25519_key_32: [u8; 32] = [0; 32];
    ed25519_key_32.copy_from_slice(ed25519_key.as_slice());
    // if opts.get_public_key {
    //     // TODO
    // }
    if opts.convert_to_x25519_private_key {
        let (_, secret_key) = crypto_sign_seed_keypair(&ed25519_key_32);
        let mut x25519_key: [u8; 32] = [0; 32];
        crypto_sign_ed25519_sk_to_curve25519(&mut x25519_key, &secret_key);
        println!("{}", hex::encode(x25519_key));
    }
    Ok(())
}
