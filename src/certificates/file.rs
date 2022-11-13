use openssl::{
    pkey::{HasPrivate, PKey, Private},
    x509::X509,
};
use std::path::Path;

pub trait X509Storage {
    /// Reads a public certificate, in PEM format, from the given path.
    fn read_cert_pem(cert_path: &Path) -> X509;
    /// Writes this public certificate to the given path, in PEM format.
    fn write_cert_pem(&self, cert_path: &Path);
}

impl X509Storage for X509 {
    fn read_cert_pem(cert_path: &Path) -> X509 {
        let cert_contents = std::fs::read(cert_path).expect("should be able to read certificate");
        X509::from_pem(&cert_contents).expect("should be able to parse certificate")
    }

    fn write_cert_pem(&self, cert_path: &Path) {
        let cert_contents = self.to_pem().expect("should be able to get public key");
        std::fs::write(cert_path, cert_contents).expect("should be able to write certificate");
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
