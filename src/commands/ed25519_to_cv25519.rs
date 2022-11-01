extern crate sequoia_openpgp as openpgp;

use openpgp::parse::Parse;
use std::path::PathBuf;

pub fn convert_gpg_ed25519_to_cv25519(gpg_input_file: PathBuf, gpg_output_file: PathBuf) {
    let input_file_contents = std::fs::read(gpg_input_file).unwrap();

    let armored_reader = openpgp::armor::Reader::from_bytes(&input_file_contents, None);
    let cert_parser = openpgp::cert::CertParser::from_reader(armored_reader).unwrap();
    let cert = cert_parser.take(1).next().unwrap().unwrap();

    #[cfg(debug)]
    print_keys(&cert);

    let cert = crate::utils::cert_insert_ed25519_as_cv25519(&cert);

    #[cfg(debug)]
    print_keys(&cert);

    let output_armored = crate::utils::export_secret_keys(&cert);
    std::fs::write(gpg_output_file, output_armored).unwrap();
}

// TODO: Tests, error handling
