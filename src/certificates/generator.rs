use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose, RsaKeySize, SanType,
};

use super::file::{CertificateParamsHelper, CertificateStorage};
use crate::config::Config;

/// Generates a 2048-bit RSA key.
///
/// Apple writes, in many places throughout MDM documentation, that
/// 2048-bit keys are highly encouraged for compatability.
fn create_rsa_keypair() -> KeyPair {
    KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_2048)
        .expect("should be able to generate RSA private key")
}

/// Generates a root CA certificate.
fn create_root_cert_params(config: &Config) -> CertificateParams {
    let mut cert_params = CertificateParams::default();

    // For our root certificate, a validity of 10 years suits our needs.
    cert_params.set_days_valid(3650);

    // We'll utilize the configured organization name for subject values.
    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::CommonName, &config.service.root_ca_name);
    cert_name.push(DnType::OrganizationName, &config.service.organization_name);
    cert_params.distinguished_name = cert_name;

    // Ensure we can be used as a certificate authority.
    // We only want one intermediate certificate.
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    cert_params
}

/// Generates CA parameters suitable for signing device certificates.
fn create_device_cert_params(config: &Config) -> CertificateParams {
    let mut cert_params = CertificateParams::default();

    // Similar to our root certificate, a validity of 10 years suits our needs.
    cert_params.set_days_valid(3650);

    // We'll utilize the configured organization name for subject values.
    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::CommonName, &config.service.device_ca_name);
    cert_name.push(DnType::OrganizationName, &config.service.organization_name);
    cert_params.distinguished_name = cert_name;

    // Ensure we can be used as a certificate authority.
    // We do not want any intermediate certificates underneath us.
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    // We'll also need to be permitted for S/MIME signing.
    cert_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    cert_params
}

/// Generates a general SSL certificate for the configured base domain.
fn create_ssl_cert_params(config: &Config) -> CertificateParams {
    let mut cert_params = CertificateParams::default();

    // We'll set our domain name as the CN.
    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::CommonName, &config.service.base_domain);
    cert_name.push(DnType::OrganizationName, &config.service.organization_name);
    cert_params.distinguished_name = cert_name;

    let base_domain = Ia5String::try_from(config.service.base_domain.clone())
        .expect("should be able to format base domain for SSL certificate");

    // For our SSL certificate, its validity cannot exceed 825 days
    // if we want any modern Apple platform to mark it as valid.
    // For more information: https://support.apple.com/en-us/HT210176
    cert_params.set_days_valid(825);
    // Per Apple, we must have id-kp-serverAuth applied.
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.subject_alt_names = vec![SanType::DnsName(base_domain)];
    cert_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    cert_params.use_authority_key_identifier_extension = true;
    cert_params
}

pub fn issue_ca_certificates(config: &Config) {
    // TODO(spotlightishere): All of these paths are within Certificates::load_certs as well.
    // Can we somehow consolidate the two?
    let root_ca_cert_path = config.certificate_path("root_ca_cert.pem");
    let root_ca_key_path = config.certificate_path("root_ca_key.pem");
    let device_ca_cert_path = config.certificate_path("device_ca_cert.pem");
    let device_ca_key_path = config.certificate_path("device_ca_key.pem");
    let ssl_cert_path = config.certificate_path("ssl_cert.pem");
    let ssl_key_path = config.certificate_path("ssl_key.pem");

    // We need to issue three separate certificate types.
    // TODO(spotlightishere): Can we consolidate the signature process somehow?

    /////////////////////////
    // Root CA certificate //
    /////////////////////////
    let root_ca_key = &create_rsa_keypair();
    let root_ca_cert = create_root_cert_params(config)
        .self_signed(root_ca_key)
        .expect("should be able to issue root CA certificate");
    // We sign ourselves.
    root_ca_cert.write_pem(&root_ca_cert_path);
    root_ca_key.write_pem(&root_ca_key_path);

    ///////////////
    // Device CA //
    ///////////////
    // Next, we'll need our device CA, issued by our root CA.
    let device_ca_key = &create_rsa_keypair();
    let device_ca_cert = create_device_cert_params(config)
        .signed_by(device_ca_key, &root_ca_cert, root_ca_key)
        .expect("should be able to issue device CA certificate");
    device_ca_cert.write_pem(&device_ca_cert_path);
    device_ca_key.write_pem(&device_ca_key_path);

    /////////////////////
    // SSL certificate //
    /////////////////////
    // Lastly, we'll generate our SSL certificate. It's similarly issued by our root CA.
    let ssl_key = &create_rsa_keypair();
    let ssl_cert = create_ssl_cert_params(config)
        .signed_by(ssl_key, &root_ca_cert, root_ca_key)
        .expect("should be able to issue SSL certificate");
    ssl_cert.write_pem(&ssl_cert_path);
    ssl_key.write_pem(&ssl_key_path);
}
