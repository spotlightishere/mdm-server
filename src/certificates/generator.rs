use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName,
        },
        X509,
    },
};

use super::file::{build_subject, X509BuilderHelper};
use crate::config::Config;

/// Generates a root CA certificate.
pub fn create_root_certificate(config: &Config) -> Result<(X509, PKey<Private>), ErrorStack> {
    // 2048 bits is strong enough while still being compatible with older devices.
    let rsa = Rsa::generate(2048)?;
    let root_key = PKey::from_rsa(rsa)?;

    // Finally, generate our certificate!
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.generate_serial()?;
    cert_builder.set_pubkey(&root_key)?;
    // For our root certificate, a validity of 10 years suits our needs.
    cert_builder.set_days_valid(3650)?;

    // We'll utilize the configured organization name for subject values.
    let org_name = &config.service.organization_name;
    let cert_name = build_subject(org_name, &format!("{org_name} Root Certificate"))?;
    // We issue ourselves.
    cert_builder.set_subject_name(&cert_name)?;
    cert_builder.set_issuer_name(&cert_name)?;

    // Ensure this can be used as a certificate authority.
    cert_builder.append_extension(BasicConstraints::new().critical().pathlen(0).ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    // Sign, and create!
    cert_builder.set_subject_key_identifier(None)?;
    cert_builder.sign(&root_key, MessageDigest::sha256())?;
    let root_cert = cert_builder.build();

    Ok((root_cert, root_key))
}

/// Generates a general SSL certificate for the configured base domain.
pub fn create_ssl_certificate(
    config: &Config,
    root_ca: &X509,
    root_key: &PKey<Private>,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    // 2048 bits is strong enough while still being compatible with older devices.
    let rsa = Rsa::generate(2048)?;
    let ssl_key = PKey::from_rsa(rsa)?;

    // Finally, generate our certificate!
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.generate_serial()?;
    cert_builder.set_pubkey(&ssl_key)?;
    // For our SSL certificate, its validity cannot exceed 825 days
    // if we want any modern Apple platform to mark it as valid.
    // For more information: https://support.apple.com/en-us/HT210176
    cert_builder.set_days_valid(825)?;

    let root_issuer = Some(root_ca.as_ref());

    // We'll set our domain name as the CN.
    let domain_name = &config.service.base_domain;
    let cert_name = build_subject(&config.service.organization_name, domain_name)?;
    cert_builder.set_subject_name(&cert_name)?;
    // We'll also need to set DNS names.
    cert_builder.append_extension(
        SubjectAlternativeName::new()
            .dns(domain_name)
            .build(&cert_builder.x509v3_context(root_issuer, None))?,
    )?;

    // Our root CA will issue us.
    cert_builder.set_issuer_name(root_ca.issuer_name())?;

    // Ensure that we can be used for SSL.
    cert_builder.append_extension(BasicConstraints::new().build()?)?;
    // Per Apple, we must have id-kp-serverAuth applied.
    cert_builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    // Sign, and create!
    cert_builder.set_subject_key_identifier(root_issuer)?;
    cert_builder.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(root_issuer, None))?,
    )?;

    cert_builder.sign(&root_key, MessageDigest::sha256())?;
    let ssl_cert = cert_builder.build();

    Ok((ssl_cert, ssl_key))
}
