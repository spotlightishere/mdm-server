use crate::plist::Plist;
use crate::{app_state::AppState, config::Config};
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use openssl::error::ErrorStack;
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack::Stack,
    x509::{store::X509Store, store::X509StoreBuilder, X509},
};
use serde::Serialize;

use super::file::{PrivateKeyStorage, X509Storage};
use super::generator;

/// Manages certificate generation and signing.
#[derive(Clone, Debug)]
pub struct Certificates {
    pub root_ca_cert: X509,
    pub device_ca_cert: X509,
    pub device_ca_key: PKey<Private>,
    pub ssl_cert: X509,
    pub ssl_key: PKey<Private>,
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
            root_ca_cert: X509::read_cert_pem(&root_ca_cert_path),
            device_ca_cert: X509::read_cert_pem(&device_ca_cert_path),
            device_ca_key: PKey::<Private>::read_key_pem(&device_ca_key_path),
            ssl_cert: X509::read_cert_pem(&ssl_cert_path),
            ssl_key: PKey::<Private>::read_key_pem(&ssl_key_path),
        }
    }

    /// An OpenSSL certificate stack containing our device CA.
    pub fn device_ca_stack(&self) -> Result<Stack<X509>, ErrorStack> {
        let mut ca_stack = Stack::new().expect("should be able to create X509 stack");
        ca_stack.push(self.device_ca_cert.to_owned())?;

        Ok(ca_stack)
    }

    /// An OpenSSL certificate store containing our device and root CAs.
    pub fn device_ca_store(&self) -> Result<X509Store, ErrorStack> {
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(self.device_ca_cert.clone())?;
        ca_store.add_cert(self.root_ca_cert.clone())?;
        let ca_store = ca_store.build();
        Ok(ca_store)
    }

    /// Data signed by the configured SSL certificate, in PKCS#7 format.
    pub fn sign_contents(&self, unsigned_contents: Vec<u8>) -> Vec<u8> {
        let ssl_cert = &self.ssl_cert;
        let ssl_key = &self.ssl_key;
        let empty_certs = Stack::new().expect("should be able to create certificate stack");
        let signed_contents = Pkcs7::sign(
            ssl_cert,
            ssl_key,
            &empty_certs,
            &unsigned_contents,
            Pkcs7Flags::BINARY,
        )
        .expect("should be able to sign certificate");

        signed_contents
            .to_der()
            .expect("should be able to convert PKCS7 container to DER form")
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
