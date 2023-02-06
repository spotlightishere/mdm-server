use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    pkey::{HasPrivate, PKey, Private},
    x509::{
        extension::SubjectKeyIdentifier, X509Builder, X509Name, X509NameBuilder, X509Ref, X509,
    },
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

pub trait X509BuilderHelper {
    /// Generates a serial number for this certificate.
    fn generate_serial(&mut self) -> Result<(), ErrorStack>;
    /// Sets the amount of days this certificate should be valid for.
    fn set_days_valid(&mut self, days: u32) -> Result<(), ErrorStack>;
    /// Adds the subject key identifier based on given issuer.
    fn set_subject_key_identifier(
        &mut self,
        identifier: Option<&X509Ref>,
    ) -> Result<(), ErrorStack>;
}

impl X509BuilderHelper for X509Builder {
    fn generate_serial(&mut self) -> Result<(), ErrorStack> {
        // The following logic is more or less from
        // https://github.com/sfackler/rust-openssl/blob/2aed206e9b69ba1373c126df09baafcd60c51099/openssl/examples/mk_certs.rs#LL30-L34
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        let serial = serial.to_asn1_integer()?;
        self.set_serial_number(&serial)
    }

    fn set_days_valid(&mut self, days: u32) -> Result<(), ErrorStack> {
        // Our cert begins today...
        let not_before = Asn1Time::days_from_now(0)?;
        self.set_not_before(&not_before)?;
        // ...and ends at the configured time.
        let not_after = Asn1Time::days_from_now(days)?;
        self.set_not_after(&not_after)
    }

    fn set_subject_key_identifier(
        &mut self,
        identifier: Option<&X509Ref>,
    ) -> Result<(), ErrorStack> {
        let identifier =
            SubjectKeyIdentifier::new().build(&self.x509v3_context(identifier, None))?;
        self.append_extension(identifier)
    }
}

/// Creates the configured subject via an X509NameBuilder.
pub fn build_subject(organization_name: &str, common_name: &str) -> Result<X509Name, ErrorStack> {
    let mut cert_name = X509NameBuilder::new()?;
    cert_name.append_entry_by_text("O", organization_name)?;
    cert_name.append_entry_by_text("CN", common_name)?;
    Ok(cert_name.build())
}
