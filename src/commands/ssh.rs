use std::path::PathBuf;

use clap::{arg, command, Parser};

#[derive(Parser, Debug)]
pub struct SshOpts {
    #[arg(
        value_name = "SSH_PRIVATE_KEY_FILE",
        help = "SSH private key file in Ed25519 format"
    )]
    pub ssh_file: PathBuf,

    #[arg(short = 's', long, help = "Extract raw private key as hex")]
    pub extract_private_key: bool,

    #[arg(short = 'p', long, help = "Extract raw public key as hex")]
    pub extract_public_key: bool,

    #[arg(short = 'x', long, help = "Extract raw private and public key as hex.")]
    pub extract: bool,
}
