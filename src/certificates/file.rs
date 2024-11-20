use der::DecodePem;
use rcgen::{CertificateParams, KeyPair};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::fs;
use std::path::Path;
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate;

pub struct CertificateStorage;

impl CertificateStorage {
    /// Serializes this certificate to the given path in PEM format.
    pub fn write_ca_pem(ca: &rcgen::Certificate, key_path: &Path) {
        let cert_contents = ca.pem();
        fs::write(key_path, cert_contents).expect("should be able to write CA certificate");
    }

    /// Serializes this RSA key to the given path in PEM format.
    pub fn write_key_pem(key: &KeyPair, key_path: &Path) {
        let key_contents = key.serialize_pem();
        fs::write(key_path, key_contents).expect("should be able to write private key");
    }

    /// Reads a public certificate, in PEM format, from the given path.
    pub fn read_cert_pem(cert_path: &Path) -> Certificate {
        let cert_contents = fs::read(cert_path).expect("should be able to read certificate");
        Certificate::from_pem(&cert_contents).expect("should be able to parse certificate")
    }

    /// Reads a private key, in PEM format, from the given path.
    pub fn read_key_pem(key_path: &Path) -> RsaPrivateKey {
        let key_contents =
            fs::read_to_string(key_path).expect("should be able to read private key");
        RsaPrivateKey::from_pkcs8_pem(&key_contents).expect("should be able to parse private key")
    }
}

pub trait CertificateParamsHelper {
    /// Sets the amount of days this certificate should be valid for.
    fn set_days_valid(&mut self, days: i64);
}

impl CertificateParamsHelper for CertificateParams {
    fn set_days_valid(&mut self, days: i64) {
        let current_time = OffsetDateTime::now_utc();
        self.not_before = current_time;
        self.not_after = current_time + Duration::days(days);
    }
}
