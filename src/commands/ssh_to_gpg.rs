use std::path::PathBuf;

use crate::utils::cert_insert_ed25519_as_cv25519;
use openpgp::{
    packet::{
        key::SecretParts,
        prelude::Key4,
        signature::{self, SignatureBuilder},
        Key, UserID,
    },
    types::{Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
    Cert, Packet,
};
use ssh_keys::{openssh::parse_private_key, PrivateKey};
extern crate sequoia_openpgp as openpgp;

pub fn ssh_to_gpg(ssh_file: PathBuf, gpg_file: PathBuf) {
    let ssh_file_contents = std::fs::read_to_string(ssh_file).unwrap();
    let parsed = parse_private_key(&ssh_file_contents).unwrap();
    let mut x25519_key: [u8; 32] = [0; 32];
    match parsed.get(0) {
        // SSH private key part contains private key 32 bytes, and copy of public key 32 bytes
        Some(PrivateKey::Ed25519(f)) => {
            let new_private_key = &f[..32];
            x25519_key.copy_from_slice(new_private_key);
        }
        _ => {}
    }

    let primary_key: Key<SecretParts, _> =
        Key4::import_secret_ed25519(&x25519_key, std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .into();
    let primary_key_sig = SignatureBuilder::new(openpgp::types::SignatureType::DirectKey)
        .set_hash_algo(openpgp::types::HashAlgorithm::SHA512)
        .set_signature_creation_time(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .set_features(Features::sequoia())
        .unwrap()
        .set_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_authentication()
                .set_signing(),
        )
        .unwrap()
        .set_key_validity_period(None)
        .unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
        .unwrap()
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
        .unwrap()
        .sign_direct_key(
            &mut primary_key.clone().into_keypair().unwrap(),
            primary_key.parts_as_public(),
        )
        .unwrap();

    let user_id = UserID::from("John O Cron");
    let user_id_sig = signature::SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_primary_userid(true)
        .unwrap()
        .set_features(Features::sequoia())
        .unwrap()
        .set_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_authentication()
                .set_signing(),
        )
        .unwrap()
        .set_key_validity_period(None)
        .unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
        .unwrap()
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
        .unwrap()
        .set_hash_algo(openpgp::types::HashAlgorithm::SHA512)
        .set_signature_creation_time(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .sign_userid_binding(
            &mut primary_key.clone().into_keypair().unwrap(),
            primary_key.parts_as_public(),
            &user_id,
        )
        .unwrap();

    // Add passphrase:
    // subkey.secret_mut().encrypt_in_place("foo");

    let foo = Cert::try_from(vec![
        Packet::SecretKey(primary_key), //
        primary_key_sig.into(),
        Packet::from(user_id),
        user_id_sig.into(),
    ])
    .unwrap();
    let foo = cert_insert_ed25519_as_cv25519(&foo);
    // utils::print_keys(&cert);
    // println!("Foo");
    // crate::utils::print_keys(&foo);
    // println!("{}", crate::utils::export_secret_keys(&foo));

    std::fs::write(gpg_file, crate::utils::export_secret_keys(&foo)).unwrap();
}

#[cfg(test)]
mod tests {

    // This is a test key
    const test_input: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----

    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACBOm6ia6iRBmR5gntmjATYIxZpqg12jOvgc/vex59OQ5wAAAKCTJgtUkyYL
    VAAAAAtzc2gtZWQyNTUxOQAAACBOm6ia6iRBmR5gntmjATYIxZpqg12jOvgc/vex59OQ5w
    AAAEAuyLx0hrtbMlOEedfuvD3bfb+hAxUfOjX7R37xTLKmkE6bqJrqJEGZHmCe2aMBNgjF
    mmqDXaM6+Bz+97Hn05DnAAAAFmphcnBwYUBERVNLVE9QLTE2QVEzMjMBAgMEBQYH
    -----END OPENSSH PRIVATE KEY-----
    ";
    fn test_creation() {}
}

// TODO: Tests, error handling
