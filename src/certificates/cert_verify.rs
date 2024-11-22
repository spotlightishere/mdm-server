use super::pkcs7_body::Pkcs7Signer;
use crate::AppState;
use axum::extract::FromRef;
use cms::{
    cert::CertificateChoices,
    signed_data::{SignedData, SignerIdentifier},
};
use const_oid::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::DecodePem;
use der::{oid::db::rfc5912, referenced::OwnedToRef, Encode};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
    RsaPublicKey,
};
use sha1::Sha1;
use sha2::Sha256;
use x509_cert::Certificate;

/// Apple writes:
/// "Validate that the device certificate is issued from “Apple iPhone Device CA”, which has the following Base64 encoded PEM data:"
/// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW4
pub const APPLE_IPHONE_DEVICE_CA: &[u8; 1244] = b"-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxLTArBgNVBAMTJEFwcGxlIGlQaG9uZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTAeFw0wNzA0MTYyMjU0NDZaFw0xNDA0MTYyMjU0NDZaMFoxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRUwEwYDVQQLEwxBcHBsZSBp
UGhvbmUxHzAdBgNVBAMTFkFwcGxlIGlQaG9uZSBEZXZpY2UgQ0EwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAPGUSsnquloYYK3Lok1NTlQZaRdZB2bLl+hmmkdf
Rq5nerVKc1SxywT2vTa4DFU4ioSDMVJl+TPhl3ecK0wmsCU/6TKqewh0lOzBSzgd
Z04IUpRai1mjXNeT9KD+VYW7TEaXXm6yd0UvZ1y8Cxi/WblshvcqdXbSGXH0KWO5
JQuvAgMBAAGjgZ4wgZswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFLL+ISNEhpVqedWBJo5zENinTI50MB8GA1UdIwQYMBaAFOc0Ki4i
3jlga7SUzneDYS8xoHw1MDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly93d3cuYXBw
bGUuY29tL2FwcGxlY2EvaXBob25lLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAd13P
Z3pMViukVHe9WUg8Hum+0I/0kHKvjhwVd/IMwGlXyU7DhUYWdja2X/zqj7W24Aq5
7dEKm3fqqxK5XCFVGY5HI0cRsdENyTP7lxSiiTRYj2mlPedheCn+k6T5y0U4Xr40
FXwWb2nWqCF1AgIudhgvVbxlvqcxUm8Zz7yDeJ0JFovXQhyO5fLUHRLCQFssAbf8
B4i8rYYsBUhYTspVJcxVpIIltkYpdIRSIARA49HNvKK4hzjzMS/OhKQpVKw+OCEZ
xptCVeN2pjbdt9uzi175oVo/u6B2ArKAW17u6XEHIdDMOe7cb33peVI6TD15W4MI
pyQPbp8orlXe+tA8JA==
-----END CERTIFICATE-----";

/// Obtains a certificate for the Apple iPhone Device CA.
fn iphone_device_ca() -> Certificate {
    Certificate::from_pem(APPLE_IPHONE_DEVICE_CA).expect("Apple iPhone Device CA should be valid")
}

/// Structure to assist with signature verification.
struct SignatureMetadata {
    pub contents: Vec<u8>,
    pub algorithm: ObjectIdentifier,
}

/// Verifies that the given signature was signed by the given public key.
///
/// As Apple only supports RSA via SCEP at the moment,
/// we will only support RSA-based algorithms as well.
fn verify_signature(
    public_key: RsaPublicKey,
    signature: SignatureMetadata,
    message: &[u8],
) -> Option<()> {
    let given_signature = Signature::try_from(signature.contents.as_ref()).ok()?;

    // Verify that our contents were signed by this signing certificate.
    //
    // As Apple only supports RSA via SCEP at the moment,
    // we will only support RSA-based algorithms as well.
    match signature.algorithm {
        rfc5912::SHA_1_WITH_RSA_ENCRYPTION => {
            // Our digest is a SHA-1 hash over our signedAttrs.
            VerifyingKey::<Sha1>::new(public_key)
                .verify(message, &given_signature)
                .ok()?
        }
        rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            // Our digest is a SHA-256 hash over our signedAttrs.
            VerifyingKey::<Sha256>::new(public_key)
                .verify(message, &given_signature)
                .ok()?
        }
        _ => panic!(
            "Unknown signature algorithm encountered: {}!",
            signature.algorithm
        ),
    }

    Some(())
}

/// Extracts the signing certificate from a CMS envelope.
fn extract_signing_cert(envelope: &SignedData) -> Option<Certificate> {
    // Assume we only have one signer.
    let signer_info = envelope.signer_infos.0.get(0)?;

    // The signer of our contents is specified via the
    // signer identifier in SignerInfo.
    // This should be a certificate within its CertificateSet,
    // matching the issuing information, alongside serial number.
    let SignerIdentifier::IssuerAndSerialNumber(issuer) = &signer_info.sid else {
        return None;
    };
    let signing_certificate = envelope
        .certificates
        .clone()?
        .0
        .into_vec()
        .into_iter()
        .find_map(|x| {
            let CertificateChoices::Certificate(current_cert) = x else {
                return None;
            };
            let tbs_cert = &current_cert.tbs_certificate;

            if tbs_cert.issuer == issuer.issuer && tbs_cert.serial_number == issuer.serial_number {
                Some(current_cert)
            } else {
                None
            }
        })?;

    Some(signing_certificate)
}

/// Verifies that the right-hand potential certificate is signed by
/// the given left-hand verifying certificate.
fn verify_cert_signature(verifying_cert: &Certificate, potential_cert: &Certificate) -> Option<()> {
    let potential_contents = potential_cert.tbs_certificate.to_der().ok()?;

    let verifying_subject = verifying_cert
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let verifying_public_key = RsaPublicKey::try_from(verifying_subject).ok()?;

    let signature = SignatureMetadata {
        contents: potential_cert.signature.as_bytes()?.to_vec(),
        algorithm: potential_cert.signature_algorithm.oid,
    };
    verify_signature(verifying_public_key, signature, &potential_contents)?;

    Some(())
}

/// Attempts to verify an X.509 certificate against our CMS SignedInfo.
/// It returns the signee and contents within the envelope.
fn verify_signing_cert(verifying_cert: Certificate, envelope: &SignedData) -> Option<Vec<u8>> {
    // Before anything else, obtain our envelope's contents.
    let encap_contents = envelope
        .encap_content_info
        .clone()
        .econtent?
        .decode_as::<OctetStringRef>()
        .ok()?
        .as_bytes()
        .to_vec();
    // We're going to assume we only have one signer.
    let signer_info = &envelope.signer_infos.0.get(0)?;

    // Obtain the signer of this envelope via our SignerInfo.
    let signing_certificate = extract_signing_cert(envelope)?;

    // Verify this signing certificate is signed by our given verifiying certicate.
    // If successful, we're given the public key of the potential certificate.
    // (Here, our potential certificate is the extracted signing certificate.)
    verify_cert_signature(&verifying_cert, &signing_certificate)?;

    // If successful, obtain the public key of the signing certificate
    // to use whilst verifying our envelope.
    let signing_subject = signing_certificate
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let signing_public_key = RsaPublicKey::try_from(signing_subject).ok()?;

    // Let's begin verifying our envelope.
    //
    // Per RFC 5652 section 5.4 ("Message Digest Calculation Process"),
    // the signature on a CMS envelope is dependent on signedAttrs existing.
    let digest_contents = match signer_info.signed_attrs.as_ref() {
        Some(signed_attributes) => {
            // If it does, our digest is over the
            // DER-encoded form of signedAttrs.
            signed_attributes.to_der().ok()?
        }
        None => {
            // It if's not present, it's over the value of
            // eContent within encapContentInfo.
            encap_contents.to_vec()
        }
    };

    let envelope_metadata = SignatureMetadata {
        contents: signer_info.signature.as_bytes().to_vec(),
        algorithm: signer_info.signature_algorithm.oid,
    };
    verify_signature(signing_public_key, envelope_metadata, &digest_contents)?;

    // TODO(spotlightishere): Verify message-digest in signedAttrs if necessary

    Some(encap_contents.to_vec())
}

/// Verifies the issuer of this envelope based on its specified
/// SignerInfo against our CA and Apple's iPhone Device CA.
pub fn determine_signing_ca<S>(state: &S, envelope: SignedData) -> Option<(Pkcs7Signer, Vec<u8>)>
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    let state = AppState::from_ref(state);

    // Attempt verification against our CA and Apple's iPhone Device CA.
    //
    // First, attempt against ourselves.
    let server_device_ca = state.certificates.device_ca_cert;
    if let Some(contents) = verify_signing_cert(server_device_ca, &envelope) {
        return Some((Pkcs7Signer::Ourselves, contents));
    }

    // Otherwise, check against Apple's iPhone Device CA.
    let apple_device_ca = iphone_device_ca();
    if let Some(contents) = verify_signing_cert(apple_device_ca, &envelope) {
        return Some((Pkcs7Signer::Apple, contents));
    }

    // Beyond that, we have no idea who the signee is here.
    None
}
