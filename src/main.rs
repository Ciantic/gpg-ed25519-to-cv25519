extern crate sequoia_openpgp as openpgp;

mod commands;
mod utils;
use clap::{arg, command, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version = "0.1", author = "Jari O. O. Pennanen <ciantic@oksidi.com>")]
struct Opts {
    #[arg(short, long)]
    verbose: Option<i32>,

    #[command(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Converts existing ed25519 subkey to cv25519 encryption subkey
    Ed25519ToCv25519(Ed25519ToCv25519),

    /// Convert SSH private key to GPG private key
    SshToGpg(SshToGpg),
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

fn main() -> Result<(), ()> {
    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Ed25519ToCv25519(opts) => {
            crate::commands::ed25519_to_cv25519::convert_gpg_ed25519_to_cv25519(
                opts.gpg_input_file,
                opts.gpg_output_file,
            );
            Ok(())
        }
        SubCommand::SshToGpg(opts) => {
            crate::commands::ssh_to_gpg::ssh_to_gpg(opts.ssh_file, opts.gpg_file);
            Ok(())
        }
    }
}
