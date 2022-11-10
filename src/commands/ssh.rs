use std::path::PathBuf;

use clap::{arg, command, Parser};
use ssh_keys::{openssh::parse_private_key, PrivateKey};

#[derive(Parser, Debug)]
pub struct SshOpts {
    #[arg(
        value_name = "SSH_PRIVATE_KEY_FILE",
        help = "SSH private key file in Ed25519 format"
    )]
    pub ssh_file: PathBuf,

    #[arg(short = 's', long, help = "Extract raw private key as base64")]
    pub get_private_key: bool,

    #[arg(short = 'r', long, help = "Extract raw public key as base64")]
    pub get_public_key: bool,

    #[arg(short = 'p', long, help = "Extract SSH public key as base64")]
    pub get_ssh_public_key: bool,

    #[arg(
        short = 'x',
        long,
        help = "Extract raw private and public key as base64."
    )]
    pub get_all: bool,
}

pub fn ssh(opts: SshOpts) -> Result<(), String> {
    let ssh_key = std::fs::read_to_string(&opts.ssh_file).map_err(|e| e.to_string())?;
    let parsed = parse_private_key(&ssh_key).unwrap();
    match parsed.get(0) {
        // SSH private key part contains private key 32 bytes, and copy of public key 32 bytes
        Some(PrivateKey::Ed25519(raw_skpk)) => {
            if opts.get_public_key {
                println!("{}", base64::encode(&raw_skpk[32..]));
            }
            if opts.get_private_key {
                println!("{}", base64::encode(&raw_skpk[..32]));
            }
            if opts.get_ssh_public_key {
                let mut ssh_pk_header = vec![
                    00, 00, 00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31,
                    0x39, 0x00, 0x00, 0x00, 0x20,
                ];
                ssh_pk_header.append(&mut raw_skpk[32..].to_vec());

                println!("ssh-ed25519 {}", base64::encode(&ssh_pk_header));
            }
            Ok(())
        }
        _ => Err("Unsupported key type".into()),
    }
}
