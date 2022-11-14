extern crate sequoia_openpgp as openpgp;

mod commands;
mod utils;
use clap::{arg, command, Parser, Subcommand};
use commands::{
    ed25519::{self, Ed25519Cmds},
    gpg::{self, GpgCmds},
    ssh::{self, SshOpts},
    x25519::{x25519, X25519Cmds},
};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    version = "0.1",
    arg_required_else_help = true,
    author = "Jari O. O. Pennanen <ciantic@oksidi.com>"
)]
struct Opts {
    #[arg(short, long)]
    verbose: Option<i32>,

    #[command(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// X25519 ECDH encryption, decryption
    X25519(X25519Cmds),

    /// Ed25519 EdDSA key manipulation
    Ed25519(Ed25519Cmds),

    /// Inspect SSH private keys
    Ssh(SshOpts),

    /// Create, modify or inspect GPG private keys
    Gpg(GpgCmds),
}

#[derive(Parser, Debug)]
pub struct Ed25519ToCv25519 {
    #[arg(
        value_name = "INPUT_GPG",
        help = "GPG private key without encryption key"
    )]
    pub gpg_input_file: PathBuf,
    #[arg(value_name = "OUTPUT_GPG", help = "Output GPG private key file")]
    pub gpg_output_file: PathBuf,
}

#[derive(Parser, Debug)]
pub struct SshToGpg {
    #[arg(value_name = "INPUT_GPG", help = "SSH private key")]
    pub ssh_file: PathBuf,
    #[arg(value_name = "OUTPUT_GPG", help = "Output GPG private key file")]
    pub gpg_file: PathBuf,
}

fn main() -> Result<(), String> {
    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Ssh(opts) => ssh::ssh(opts),
        SubCommand::Gpg(opts) => gpg::gpg(opts),
        SubCommand::Ed25519(opts) => ed25519::ed25519(opts),
        SubCommand::X25519(opts) => x25519(opts),
    }
}
