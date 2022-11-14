extern crate sequoia_openpgp as openpgp;

use openpgp::{
    armor::{Kind, Writer},
    serialize::Marshal,
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

pub fn base64_to_bytes(s: &str) -> Result<[u8; 32], String> {
    let value = base64::decode(&s).map_err(|e| e.to_string())?;
    let mut buf: [u8; 32] = [0; 32];
    buf.copy_from_slice(value.as_slice());
    Ok(buf)
}
