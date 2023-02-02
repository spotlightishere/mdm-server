use crate::storage::Storage;
use crate::{payloads::Profile, plist::Plist};
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use once_cell::sync::OnceCell;
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack::Stack,
    x509::X509,
};
use serde::Serialize;

use self::file::{PrivateKeyStorage, X509Storage};

mod file;
mod generator;

/// Manages certificate generation and signing.
#[derive(Debug)]
pub struct Certificates {
    root_ca_cert: X509,
    root_ca_key: PKey<Private>,
    pub ssl_cert: X509,
    pub ssl_key: PKey<Private>,
}

static CERTIFICATES: OnceCell<Certificates> = OnceCell::new();

impl Certificates {
    pub fn shared() -> &'static Certificates {
        CERTIFICATES
            .get()
            .expect("certificates were not initialized")
    }

    pub fn issue_if_needed() {
        let root_ca_cert_path = Storage::certificate_path("root_ca_cert.pem");
        let root_ca_key_path = Storage::certificate_path("root_ca_key.pem");
        let ssl_cert_path = Storage::certificate_path("ssl_cert.pem");
        let ssl_key_path = Storage::certificate_path("ssl_key.pem");

        if !root_ca_key_path.exists() || !root_ca_cert_path.exists() {
            // Generate our root CA if one or the other is missing.
            let (ca_cert, ca_key) =
                generator::create_root_certificate().expect("should be able to generate root CA");

            // Finally, write to disk.
            // We'll read these back in a second.
            ca_cert.write_cert_pem(&root_ca_cert_path);
            ca_key.write_key_pem(&root_ca_key_path);

            // Next, we'll generate our SSL certificate.
            // It should be assumed that a new root CA means a new SSL cert should be issued.
            let (ssl_cert, ssl_key) = generator::create_ssl_certificate(&ca_cert, &ca_key)
                .expect("should be able to generate SSL certificate");
            ssl_cert.write_cert_pem(&ssl_cert_path);
            ssl_key.write_key_pem(&ssl_key_path);
        }

        // Load our certificates, and then we're all set!
        let certificates = Certificates {
            root_ca_cert: X509::read_cert_pem(&root_ca_cert_path),
            root_ca_key: PKey::<Private>::read_key_pem(&root_ca_key_path),
            ssl_cert: X509::read_cert_pem(&ssl_cert_path),
            ssl_key: PKey::<Private>::read_key_pem(&ssl_key_path),
        };

        CERTIFICATES
            .set(certificates)
            .expect("should be able to set certificates");
    }
}

/// Data signed by the configured SSL certificate, in PKCS#7 format.
pub fn sign_contents(unsigned_contents: Vec<u8>) -> Vec<u8> {
    let ssl_cert = &Certificates::shared().ssl_cert;
    let ssl_key = &Certificates::shared().ssl_key;
    let empty_certs = Stack::new().expect("should be able to create certificate stack");
    let signed_contents = Pkcs7::sign(
        &ssl_cert,
        &ssl_key,
        &empty_certs,
        &unsigned_contents,
        Pkcs7Flags::BINARY,
    )
    .expect("should be able to sign certificate");

    signed_contents
        .to_der()
        .expect("should be able to convert PKCS7 container to DER form")
}

pub fn sign_profile<T: Serialize>(profile: T) -> Response {
    // Let's get our payload contents.
    let profile_xml = match Plist(profile).to_xml() {
        Ok(body) => body,
        Err(err) => {
            // We should not expose this exact error for safety reasons.
            println!("error within xml plist serialization: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
        }
    };

    // We need to sign this profile.
    let signed_profile = sign_contents(profile_xml);

    let headers = [(header::CONTENT_TYPE, "application/x-apple-aspen-config")];
    (headers, signed_profile).into_response()
}
