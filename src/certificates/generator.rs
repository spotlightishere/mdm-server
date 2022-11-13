use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509Name, X509NameBuilder, X509,
    },
};

use crate::config::Config;

/// Sets basic information for a certificate, generating an appropriate private key.
pub fn create_base_certificate(
    cert_name: X509Name,
) -> Result<(X509Builder, PKey<Private>), ErrorStack> {
    // 2048 bits is strong enough while still being compatible with older devices.
    let rsa = Rsa::generate(2048)?;
    let cert_key = PKey::from_rsa(rsa)?;

    // The following logic is more or less from
    // https://github.com/sfackler/rust-openssl/blob/2aed206e9b69ba1373c126df09baafcd60c51099/openssl/examples/mk_certs.rs#LL30-L34
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    // Finally, generate our certificate!
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&cert_name)?;
    cert_builder.set_issuer_name(&cert_name)?;
    cert_builder.set_pubkey(&cert_key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    // We'll have the certificate be valid for 10 years.
    let not_after = Asn1Time::days_from_now(3650)?;
    cert_builder.set_not_after(&not_after)?;

    Ok((cert_builder, cert_key))
}

/// Generates a root CA certificate.
pub fn create_root_certificate() -> Result<(X509, PKey<Private>), ErrorStack> {
    // Let's set name properties for our certificate.
    // We'll utilize the configured organization name for values.
    let mut cert_name = X509NameBuilder::new()?;
    let org_name = &Config::service().organization_name;
    cert_name.append_entry_by_text("O", &org_name)?;
    cert_name.append_entry_by_text("CN", &format!("{} Root Certificate", org_name))?;
    let cert_name = cert_name.build();

    // Get a basic certificate to build off of.
    let (mut cert_builder, root_key) = create_base_certificate(cert_name)?;

    // Ensure this can be used as a certificate authority.
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    // Sign, and create!
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&root_key, MessageDigest::sha256())?;
    let root_cert = cert_builder.build();

    Ok((root_cert, root_key))
}

/// Generates a general SSL certificate for the configured base domain.
pub fn create_ssl_certificate(
    root_ca: &X509,
    root_key: &PKey<Private>,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    // We'll need to make sure we set our domain name as the CN.
    let mut cert_name = X509NameBuilder::new()?;
    let org_name = &Config::service().organization_name;
    let domain_name = &Config::service().base_domain;
    cert_name.append_entry_by_text("O", &org_name)?;
    cert_name.append_entry_by_text("CN", &domain_name)?;
    let cert_name = cert_name.build();

    // Get a basic certificate to build off of.
    let (mut cert_builder, ssl_key) = create_base_certificate(cert_name)?;

    // Sign, and create!
    // Our root CA will issue us.
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(&root_ca), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&root_key, MessageDigest::sha256())?;
    let ssl_cert = cert_builder.build();

    Ok((ssl_cert, ssl_key))
}
