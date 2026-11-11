use std::fs;
use std::path::Path;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

fn main() {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Relay Local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Relay");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().expect("ca key");
    let cert = params.self_signed(&key).expect("self-signed ca");

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&dir).expect("fixtures dir");
    fs::write(dir.join("ca-cert.pem"), cert.pem()).expect("write cert");
    fs::write(dir.join("ca-key.pem"), key.serialize_pem()).expect("write key");
    println!("wrote {}", dir.display());
}
