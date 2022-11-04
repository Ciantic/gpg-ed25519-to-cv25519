use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use clap::{arg, command, Args, Parser};
use sequoia_openpgp::{
    armor::{Kind, Reader, Writer},
    cert::CertParser,
    crypto::Signer,
    packet::{
        key::{SecretParts, SubordinateRole},
        prelude::Key4,
        signature::SignatureBuilder,
        Key, UserID,
    },
    parse::Parse,
    policy::StandardPolicy,
    serialize::{MarshalInto, Serialize},
    types::{Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
    Cert, Packet,
};

#[derive(Parser, Debug)]
pub struct GpgCmds {
    #[command(subcommand)]
    cmd: GpgOpts,
}

#[derive(Parser, Debug)]
pub enum GpgOpts {
    /// Modify existing GPG private key
    Modify(ModifyOpts),

    /// Create GPG key
    ///
    /// If only user ID is given it generates single ed25519 key with CSEA
    /// capability
    Create(CreateOpts),

    /// Inspect existing GPG private key
    Inspect(InspectOpts),
}

#[derive(Args, Debug)]
pub struct ModifyOpts {
    #[arg(value_name = "GPG_PRIVATE_KEY_FILE", help = "GPG private key filename")]
    pub gpg_file: PathBuf,

    #[arg(short, long, help = "Add ed25519 private key (32 bytes in hex format)")]
    pub ed25519_private_key: Option<String>,

    #[arg(short, long, help = "Capabilities of a new key (CSEA)")]
    pub capabilities: Option<String>,

    #[arg(short = 't', long, help = "Creation timestamp", value_parser = parse_time)]
    pub creation_time: Option<SystemTime>,

    #[arg(
        short,
        long,
        help = "Add x25519 encryption key (32 bytes in hex format)"
    )]
    pub x25519_private_key: Option<String>,

    #[arg(short, long, help = "Output to a file, if not given modifies in place")]
    pub output_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct CreateOpts {
    #[arg(
        value_name = "OUTPUT_FILE",
        help = "Output to a file, if not given outputs to stdout"
    )]
    pub output_file: String,

    #[arg(short, long, help = "User name and email of the new GPG key")]
    pub user_name: Option<String>,

    #[arg(short, long, help = "Add ed25519 private key (32 bytes in hex format)")]
    pub ed25519_private_key: Option<String>,

    #[arg(
        short,
        long,
        help = "Capabilities of a new key (CSE), if only ed25519 is given it's converted to x25519 for E=Encryption capability"
    )]
    pub capabilities: Option<String>,

    #[arg(
        short,
        long,
        help = "Add x25519 encryption key (32 bytes in hex format)"
    )]
    pub x25519_private_key: Option<String>,

    #[arg(short = 't', long, help = "Creation timestamp", value_parser = parse_time)]
    pub creation_time: Option<SystemTime>,
}

#[derive(Args, Debug)]
pub struct InspectOpts {
    #[arg(value_name = "GPG_PRIVATE_KEY_FILE", help = "GPG private key filename")]
    pub gpg_file: PathBuf,

    #[arg(
        short = 's',
        long,
        help = "Get ed25519/x25519 private key as hex with given capabilities (CSEA)"
    )]
    pub private_key_capabilities: Option<String>,

    #[arg(
        short = 'p',
        long,
        help = "Get ed25519/x25519 public key as hex with given capabilities (CSEA)"
    )]
    pub public_key_capabilities: Option<String>,
}

pub fn gpg(opts: GpgCmds) -> Result<(), String> {
    match opts.cmd {
        // Modify existing GPG file
        GpgOpts::Modify(opts) => modify(opts),
        GpgOpts::Create(opts) => create(opts),
        GpgOpts::Inspect(opts) => inspect(opts),
    }
}

fn inspect(opts: InspectOpts) -> Result<(), String> {
    let cert = read_cert_file(&opts.gpg_file)?;

    if let Some(caps) = opts.private_key_capabilities {
        let policy = StandardPolicy::new();
        let flags = caps_to_flags(&caps)?;
        let keys = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .key_flags(&flags);
        for k in keys {
            // println!("FPR {} algo {}", k.fingerprint(), k.pk_algo());
            // for s in k.signatures() {
            //     println!("{:?}", s.key_flags());
            // }

            if let Some(skm) = k.optional_secret() {
                match skm {
                    openpgp::packet::prelude::SecretKeyMaterial::Unencrypted(ref f) => {
                        f.map(|mpis| match mpis {
                            openpgp::crypto::mpi::SecretKeyMaterial::ECDH { scalar } => {
                                println!("{}", hex::encode(scalar.value()));
                                Ok(())
                            }
                            openpgp::crypto::mpi::SecretKeyMaterial::EdDSA { scalar } => {
                                println!("{}", hex::encode(scalar.value()));
                                Ok(())
                            }
                            k => Err(format!("Unsupported private key type {:?}, only ed25519 and cv25519 can be extracted", k).to_string()),
                        })?;
                    }
                    openpgp::packet::prelude::SecretKeyMaterial::Encrypted(_) => {
                        return Err("Encrypted key, can't open".to_string());
                    }
                }
            }
        }
    }

    if let Some(caps) = opts.public_key_capabilities {
        let policy = StandardPolicy::new();
        let flags = caps_to_flags(&caps)?;
        let keys = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .key_flags(&flags);
        for k in keys {
            let mut buf: Vec<u8> = Vec::new();
            buf.resize(4096, 0);
            let size = k
                .mpis()
                .serialize_into(buf.as_mut_slice())
                .map_err(|_| "Failed to serialize key")?;
            buf.resize(size, 0);
            println!("{}", hex::encode(buf));
        }
    }

    Ok(())
}

fn create(opts: CreateOpts) -> Result<(), String> {
    let mut flags = caps_to_flags(&opts.capabilities.unwrap_or_default())?;
    if !flags.for_certification() {
        return Err("Certification is required to create a key".to_string());
    }

    // Do storage encryption separately
    if flags.for_storage_encryption() {
        flags = flags.clear_storage_encryption();
    }

    let creation_time = opts.creation_time.unwrap_or_else(SystemTime::now);
    let ed25519_key_str = opts.ed25519_private_key.unwrap();
    let ed25519_key = hex::decode(ed25519_key_str).map_err(|_| "Unable to decode private key")?;

    let primary_key: Key<SecretParts, _> = Key4::import_secret_ed25519(&ed25519_key, creation_time)
        .unwrap()
        .into();
    let signer = &mut primary_key.clone().into_keypair().unwrap();

    /*
    let primary_key_sig = SignatureBuilder::new(openpgp::types::SignatureType::DirectKey)
        .set_hash_algo(openpgp::types::HashAlgorithm::SHA512)
        .set_signature_creation_time(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .set_features(Features::sequoia())
        .unwrap()
        .set_key_flags(flags)
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
    */
    let user_id = UserID::from(opts.user_name.unwrap_or_default());
    let user_id_sig = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_primary_userid(true)
        .unwrap()
        .set_features(Features::sequoia())
        .unwrap()
        .set_key_flags(flags)
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
        .set_signature_creation_time(creation_time)
        .unwrap()
        .sign_userid_binding(signer, primary_key.parts_as_public(), &user_id)
        .unwrap();

    // Add passphrase:
    // subkey.secret_mut().encrypt_in_place("foo");

    let cert = Cert::try_from(vec![
        Packet::SecretKey(primary_key), //
        Packet::from(user_id),
        // primary_key_sig.into(),
        // Packet::from(user_id),
        user_id_sig.into(),
    ])
    .unwrap();
    let armored = export_secret_keys(&cert);

    if opts.output_file == "-" {
        println!("{}", armored);
    } else {
        std::fs::write(opts.output_file, armored).map_err(|_| "Unable write to file")?;
    }

    Ok(())
}

fn modify(opts: ModifyOpts) -> Result<(), String> {
    let mut cert = read_cert_file(&opts.gpg_file)?;
    let creation_time = opts.creation_time.unwrap_or_else(SystemTime::now);
    let flags = caps_to_flags(&opts.capabilities.unwrap_or_default())?;

    if flags.is_empty() {
        return Err("Capabilities are required".to_string());
    }

    if check_if_cert_contains_capability(&cert, &flags) {
        return Err("Certificate already contains given capability".to_string());
    }

    // Insert given ED25519 key
    if let Some(ed25519_key) = opts.ed25519_private_key {
        println!("Add ed25519 key {:?}", flags);
        let decoded = hex::decode(ed25519_key).map_err(|_| "Unable to decode private key")?;
        if decoded.len() != 32 {
            return Err("Invalid ed25519 private key length".to_string());
        }
        let subkey: Key<SecretParts, SubordinateRole> =
            Key4::import_secret_ed25519(&decoded, creation_time)
                .map_err(|_| "Unable to import ed25519 key")?
                .into();
        cert = add_sub_key(
            &cert,
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(creation_time)
                .unwrap()
                .set_key_flags(flags.clone())
                .map_err(|_| "Unable to build signature")?,
            subkey,
        )?;
    }

    // Insert given X25519 key
    if let Some(x25519_key) = opts.x25519_private_key {
        println!("Add x25519 key");
        let decoded = hex::decode(x25519_key).map_err(|_| "Unable to decode private key")?;
        if decoded.len() != 32 {
            return Err("Invalid x25519 private key length".to_string());
        }
        let subkey: Key<SecretParts, SubordinateRole> =
            Key4::import_secret_cv25519(&decoded, None, None, creation_time)
                .unwrap()
                .into();
        cert = add_sub_key(
            &cert,
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(creation_time)
                .unwrap()
                .set_key_flags(flags.clone())
                .map_err(|_| "Unable to build signature")?,
            subkey,
        )?;
    }

    let armored = export_secret_keys(&cert);
    if let Some(output_file) = opts.output_file {
        if (output_file == "-") || (output_file == "/dev/stdout") {
            println!("{}", armored);
        } else {
            println!("Wrote to file {}", &output_file);
            std::fs::write(output_file, armored).map_err(|_| "Unable to write output file")?;
        }
    } else {
        println!("Wrote to file {}", &opts.gpg_file.to_string_lossy());
        std::fs::write(&opts.gpg_file, armored).map_err(|_| "Unable to write output file")?;
    }

    Ok(())
}

fn read_cert_file(path: &PathBuf) -> Result<Cert, String> {
    let input_file_contents =
        std::fs::read(path).map_err(|_| "Unable to read GPG private key file")?;
    let armored_reader = Reader::from_bytes(&input_file_contents, None);
    let cert_parser =
        CertParser::from_reader(armored_reader).map_err(|_| "Malformed GPG private key file")?;
    let cert = cert_parser.take(1).next().unwrap().unwrap();
    Ok(cert)
}

fn caps_to_flags(caps: &str) -> Result<KeyFlags, String> {
    let mut flags = KeyFlags::empty();

    for cap in caps.chars() {
        match cap {
            'C' => flags = flags.set_certification(),
            'S' => flags = flags.set_signing(),
            'E' => flags = flags.set_storage_encryption(),
            'A' => flags = flags.set_authentication(),
            c => return Err(format!("Invalid capability: {}", c)),
        }
    }

    Ok(flags)
}

fn check_if_cert_contains_capability(cert: &Cert, flags: &KeyFlags) -> bool {
    let policy = StandardPolicy::new();
    cert.keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
        .key_flags(flags)
        .count()
        > 0
}

/*
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
*/

/// Add existing sub key
fn add_sub_key(
    cert: &Cert,
    sigbuilder: SignatureBuilder,
    subkey: Key<SecretParts, SubordinateRole>,
) -> Result<Cert, String> {
    let mut keypair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| "Can't get secrets of the key")?
        .into_keypair()
        .map_err(|_| "Key has passphrase")?;

    let sig = subkey
        .bind(&mut keypair, &cert, sigbuilder)
        .map_err(|_| "Unable to sign subkey")?;

    let cert = cert
        .clone()
        .insert_packets(vec![Packet::from(subkey), sig.into()])
        .map_err(|_| "Unable to insert packets")?;

    Ok(cert)
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
fn export_secret_keys(cert: &Cert) -> String {
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

// parse string to systemtime
fn parse_time(time: &str) -> Result<SystemTime, String> {
    let time = time.parse::<u64>().map_err(|_| "Unable to parse time")?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(time))
}
