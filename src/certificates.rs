use crate::storage::Storage;
use once_cell::sync::OnceCell;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

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
