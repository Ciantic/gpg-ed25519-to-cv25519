extern crate sequoia_openpgp as openpgp;

use dryoc::classic::{
    crypto_sign::crypto_sign_seed_keypair,
    crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519,
};

use openpgp::{
    armor::{Kind, Writer},
    packet::{
        key::{SecretParts, SubordinateRole},
        prelude::*,
    },
    policy::StandardPolicy,
    serialize::Marshal,
    types::{KeyFlags, SignatureType},
    Cert,
};

pub fn print_keys(cert: &Cert) {
    println!("CRT {} with keyid {}", cert, cert.keyid());
    for k in cert.keys() {
        println!("FPR {} algo {}", k.fingerprint(), k.pk_algo());
        for s in k.signatures() {
            println!("{:?}", s.key_flags());
        }

        if let Some(foo) = k.optional_secret() {
            match foo {
                openpgp::packet::prelude::SecretKeyMaterial::Unencrypted(ref f) => {
                    f.map(|mpis| match mpis {
                        openpgp::crypto::mpi::SecretKeyMaterial::ECDH { scalar } => {
                            println!("ECDH {:?}", scalar.value());
                        }
                        openpgp::crypto::mpi::SecretKeyMaterial::EdDSA { scalar } => {
                            println!("EdDSA {:?} {}", scalar.value(), scalar.value().len());
                        }
                        _ => {
                            println!("Unrecgonized value");
                        }
                    });
                }
                openpgp::packet::prelude::SecretKeyMaterial::Encrypted(f) => {
                    println!("Encrypted can't open {:?}", f);
                }
            }
        }
    }
}

fn get_signing_eddsa_seed_scalar(cert: &Cert) -> Option<[u8; 32]> {
    let mut secretkey: Vec<u8> = Vec::new();
    for k in cert.keys() {
        if let Some(foo) = k.optional_secret() {
            match foo {
                openpgp::packet::prelude::SecretKeyMaterial::Unencrypted(ref f) => {
                    f.map(|mpis| match mpis {
                        openpgp::crypto::mpi::SecretKeyMaterial::EdDSA { scalar } => {
                            secretkey.extend_from_slice(scalar.value());
                        }
                        _ => {}
                    });
                }
                openpgp::packet::prelude::SecretKeyMaterial::Encrypted(f) => {
                    println!("Encrypted, can't open {:?}", f);
                }
            }
        }
    }
    if secretkey.len() > 0 {
        let mut v: [u8; 32] = [0; 32];
        v.copy_from_slice(secretkey.as_slice());
        Some(v)
    } else {
        None
    }
}

pub fn cert_insert_ed25519_as_cv25519(cert: &Cert) -> Cert {
    let secret_scalar = get_signing_eddsa_seed_scalar(&cert).unwrap();
    let (_, secret_key) = crypto_sign_seed_keypair(&secret_scalar);
    let mut x25519_key: [u8; 32] = [0; 32];
    crypto_sign_ed25519_sk_to_curve25519(&mut x25519_key, &secret_key);
    add_cv25519_encryption_key(&cert, &x25519_key).unwrap()
}

/// Add existing X25519 key as encryption
fn add_cv25519_encryption_key(cert: &Cert, x25519_key: &[u8]) -> Option<Cert> {
    let policy = &StandardPolicy::new();
    let flags = KeyFlags::empty().set_storage_encryption();

    // Ensure that cert doesn't have storage key yet
    assert_eq!(
        cert.keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .key_flags(&flags)
            .count(),
        0
    );

    let mut keypair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();

    let subkey: Key<SecretParts, SubordinateRole> =
        Key4::import_secret_cv25519(&x25519_key, None, None, None)
            .unwrap()
            .into();

    let builder = signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_key_flags(flags.clone())
        .unwrap();
    let binding = subkey.bind(&mut keypair, &cert, builder).unwrap();

    let cert2 = cert
        .clone()
        .insert_packets(vec![Packet::from(subkey), binding.into()])
        .unwrap();

    // Ensure that key was added
    assert_eq!(
        cert2
            .keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .key_flags(flags)
            .count(),
        1
    );
    Some(cert2)
}

/// Creates private key block string
///
/// Example:
///
/// ```
/// -----BEGIN PGP PRIVATE KEY BLOCK-----
/// ...
/// -----END PGP PRIVATE KEY BLOCK-----
/// ```
pub fn export_secret_keys(cert: &Cert) -> String {
    let headers = cert.armor_headers();
    let headers: Vec<_> = headers
        .iter()
        .map(|value| ("Comment", value.as_str()))
        .collect();

    let mut writer = Writer::with_headers(Vec::new(), Kind::SecretKey, headers).unwrap();
    cert.as_tsk().serialize(&mut writer).unwrap();
    let buffer = writer.finalize().unwrap();
    String::from_utf8_lossy(&buffer).to_string()
}
