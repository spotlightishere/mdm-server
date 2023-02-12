use rand::rngs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

use super::file::CertificateParamsHelper;
use crate::config::Config;

/// Generates a 2048-bit RSA key.
///
/// Apple writes, in many places throughout MDM documentation, that
/// 2048-bit keys are highly encouraged for compatability.
fn create_rsa_keypair() -> Option<KeyPair> {
    // Due to https://github.com/briansmith/ring/pull/733 we cannot utilize
    // rcgen::KeyPair directly for RSA.
    // We use rsa::RsaPrivateKey instead, converting to DER, and parsing again.
    let private_key =
        RsaPrivateKey::new(&mut rngs::OsRng, 2048).expect("should be able to generate private key");
    let der_form = private_key
        .to_pkcs8_der()
        .expect("should be able to convert private key to DER");
    let keypair =
        rcgen::KeyPair::from_der(der_form.as_bytes()).expect("should be able to parse key");
    Some(keypair)
}

/// Generates a root CA certificate.
pub fn create_root_certificate(config: &Config) -> Certificate {
    let mut cert_params = CertificateParams::default();

    // For our root certificate, a validity of 10 years suits our needs.
    cert_params.set_days_valid(3650);
    cert_params.key_pair = create_rsa_keypair();
    cert_params.alg = &rcgen::PKCS_RSA_SHA256;

    // We'll utilize the configured organization name for subject values.
    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::CommonName, &config.service.root_ca_name);
    cert_name.push(DnType::OrganizationName, &config.service.organization_name);
    cert_params.distinguished_name = cert_name;

    // Ensure we can be used as a certificate authority.
    // We only want one intermediate certificate.
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    Certificate::from_params(cert_params).expect("should be able to generate root CA certificate")
}

/// Generates a general SSL certificate for the configured base domain.
pub fn create_ssl_certificate(config: &Config) -> Certificate {
    let mut cert_params = CertificateParams::default();

    // We'll set our domain name as the CN.
    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::CommonName, &config.service.base_domain);
    cert_name.push(DnType::OrganizationName, &config.service.organization_name);
    cert_params.distinguished_name = cert_name;

    // For our SSL certificate, its validity cannot exceed 825 days
    // if we want any modern Apple platform to mark it as valid.
    // For more information: https://support.apple.com/en-us/HT210176
    cert_params.set_days_valid(825);
    // Per Apple, we must have id-kp-serverAuth applied.
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.subject_alt_names = vec![SanType::DnsName(config.service.base_domain.clone())];
    cert_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    cert_params.key_pair = create_rsa_keypair();
    cert_params.alg = &rcgen::PKCS_RSA_SHA256;
    cert_params.use_authority_key_identifier_extension = true;

    Certificate::from_params(cert_params).expect("should be able to generate SSL certificate")
}
