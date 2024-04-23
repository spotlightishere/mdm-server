use openssl::{
    pkey::{HasPrivate, PKey, Private},
    x509::X509,
};
use rcgen::{Certificate, CertificateParams, KeyPair};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub trait CertificateStorage {
    /// Serializes this certificate or key to the given path, in PEM format.
    fn write_pem(&self, key_path: &Path);
}

impl CertificateStorage for Certificate {
    fn write_pem(&self, key_path: &Path) {
        let cert_contents = self.pem();
        std::fs::write(key_path, cert_contents).expect("should be able to write CA certificate");
    }
}

impl CertificateStorage for KeyPair {
    fn write_pem(&self, key_path: &Path) {
        let key_contents = self.serialize_pem();
        std::fs::write(key_path, key_contents).expect("should be able to write private key");
    }
}

pub trait X509Storage {
    /// Reads a public certificate, in PEM format, from the given path.
    fn read_cert_pem(cert_path: &Path) -> X509;
}

impl X509Storage for X509 {
    fn read_cert_pem(cert_path: &Path) -> X509 {
        let cert_contents = std::fs::read(cert_path).expect("should be able to read certificate");
        X509::from_pem(&cert_contents).expect("should be able to parse certificate")
    }
}

pub trait PrivateKeyStorage {
    /// Reads a private key, in PEM format, from the given path.
    fn read_key_pem(key_path: &Path) -> PKey<Private>;

    /// Writes this private key to the given path, in PEM format.
    fn write_key_pem(&self, key_path: &Path);
}

impl<T> PrivateKeyStorage for PKey<T>
where
    T: HasPrivate,
{
    fn read_key_pem(key_path: &Path) -> PKey<Private> {
        let key_contents = std::fs::read(key_path).expect("should be able to read private key");
        PKey::private_key_from_pem(&key_contents).expect("should be able to parse private key")
    }

    fn write_key_pem(&self, key_path: &Path) {
        let key_contents = self
            .private_key_to_pem_pkcs8()
            .expect("should be able to get private key");
        std::fs::write(key_path, key_contents).expect("should be able to write private key");
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
