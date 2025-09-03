use crate::plist::Plist;
use crate::{app_state::AppState, config::Config};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use der::{
    Any, DecodePem, Encode, Tag,
    asn1::OctetStringRef,
    oid::db::{rfc5911, rfc5912},
};
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, pkcs8::DecodePrivateKey};
use serde::Serialize;
use sha1::Sha1;
use std::fs;
use std::path::Path;
use x509_cert::{Certificate, spki::AlgorithmIdentifierOwned};

use super::generator;

/// Manages certificate generation and signing.
#[derive(Clone, Debug)]
pub struct Certificates {
    pub root_ca_cert: Certificate,
    pub device_ca_cert: Certificate,
    pub device_ca_key: RsaPrivateKey,
    pub ssl_cert: Certificate,
    pub ssl_key: RsaPrivateKey,
}

impl Certificates {
    pub fn load_certs(config: &Config) -> Self {
        let root_ca_cert_path = config.certificate_path("root_ca_cert.pem");
        let root_ca_key_path = config.certificate_path("root_ca_key.pem");
        let device_ca_cert_path = config.certificate_path("device_ca_cert.pem");
        let device_ca_key_path = config.certificate_path("device_ca_key.pem");
        let ssl_cert_path = config.certificate_path("ssl_cert.pem");
        let ssl_key_path = config.certificate_path("ssl_key.pem");

        if !root_ca_key_path.exists() || !root_ca_cert_path.exists() {
            // Regenerate all of our CA certificates.
            generator::issue_ca_certificates(config);
        }

        // Load our certificates, and then we're all set!
        Certificates {
            root_ca_cert: read_cert_pem(&root_ca_cert_path),
            device_ca_cert: read_cert_pem(&device_ca_cert_path),
            device_ca_key: read_key_pem(&device_ca_key_path),
            ssl_cert: read_cert_pem(&ssl_cert_path),
            ssl_key: read_key_pem(&ssl_key_path),
        }
    }

    /// Data signed by the configured SSL certificate, in PKCS#7 format.
    pub fn sign_contents(&self, unsigned_contents: Vec<u8>) -> Vec<u8> {
        let ssl_cert = &self.ssl_cert;
        let ssl_key = &self.ssl_key;

        // Encapsulate our contents.
        let octet_string = OctetStringRef::new(&unsigned_contents)
            .expect("should be able to encode contents as octet string")
            .as_bytes();
        let octet_object = Any::new(Tag::OctetString, octet_string)
            .expect("should be able to encapsulate octet string");

        let content = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: Some(octet_object),
        };

        // We'll be using SHA-1 for backwards compatibility.
        let signer = SigningKey::<Sha1>::new(ssl_key.clone());
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_1,
            parameters: None,
        };

        // If our builder fails, other things are likely misconfigured.
        let signer_info = SignerInfoBuilder::new(
            &signer,
            SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: ssl_cert.tbs_certificate.issuer.clone(),
                serial_number: ssl_cert.tbs_certificate.serial_number.clone(),
            }),
            digest_algorithm.clone(),
            &content,
            None,
        )
        .expect("should be able to create builder");

        let signed_data = SignedDataBuilder::new(&content)
            .add_digest_algorithm(digest_algorithm)
            .expect("should be able to add digest algorithm")
            .add_certificate(CertificateChoices::Certificate(ssl_cert.clone()))
            .expect("should be able to add certificate")
            .add_signer_info(signer_info)
            .expect("should be able to add signer info")
            .build()
            .expect("should be able to sign data for certificate");

        // Lastly, return in DER form.
        signed_data
            .to_der()
            .expect("should be able to convert CMS container to DER form")
    }

    pub fn sign_profile<T: Serialize>(&self, profile: T) -> Response {
        // Let's get our payload contents.
        let profile_xml = match Plist(profile).to_xml() {
            Ok(body) => body,
            Err(err) => {
                // We should not expose this exact error for safety reasons.
                println!("error within xml plist serialization: {err}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                    .into_response();
            }
        };

        // We need to sign this profile.
        let signed_profile = self.sign_contents(profile_xml);

        let headers = [(header::CONTENT_TYPE, "application/x-apple-aspen-config")];
        (headers, signed_profile).into_response()
    }
}

impl AppState {
    // Signs a profile with the current SSL certificate.
    pub fn serve_profile<T: Serialize>(&self, profile: T) -> Response {
        self.certificates.sign_profile(profile)
    }
}

/// Reads a public certificate, in PEM format, from the given path.
pub fn read_cert_pem(cert_path: &Path) -> Certificate {
    let cert_contents = fs::read(cert_path).expect("should be able to read certificate");
    Certificate::from_pem(&cert_contents).expect("should be able to parse certificate")
}

/// Reads a private key, in PEM format, from the given path.
pub fn read_key_pem(key_path: &Path) -> RsaPrivateKey {
    RsaPrivateKey::read_pkcs8_pem_file(key_path).expect("should be able to parse private key")
}
