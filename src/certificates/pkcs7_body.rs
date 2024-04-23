use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRef, FromRequest, Request},
    http::StatusCode,
};
use openssl::{
    error::ErrorStack,
    pkcs7::{Pkcs7, Pkcs7Flags},
};

use super::apple_certs::AppleCerts;
use crate::app_state::AppState;

/// The signer of the parsed PKCS#7 envelope.
pub enum Pkcs7Signer {
    Apple,
    Ourselves,
}

/// Our abstraction over Pkcs7 itself.
pub struct Pkcs7Body {
    pub signer: Pkcs7Signer,
    pub envelope: Pkcs7,
    pub contents: Vec<u8>,
}

#[async_trait]
impl<S> FromRequest<S> for Pkcs7Body
where
    Bytes: FromRequest<S>,
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Before we read the body, let's check the content type header.
        // Although this provides no security, it helps to stop invalid requests.
        let Some(content_type) = req.headers().get("Content-Type") else {
            return Err(StatusCode::BAD_REQUEST);
        };
        if content_type != "application/pkcs7-signature" {
            return Err(StatusCode::BAD_REQUEST);
        }

        // We should be POSTed a PKCS#7 envelope.
        let Ok(post_body) = Bytes::from_request(req, state).await else {
            return Err(StatusCode::BAD_REQUEST);
        };

        let Ok(envelope) = Pkcs7::from_der(&post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };

        // First, determine who issued this envelope.
        //
        // TODO: Switching between OpenSSL's PKCS#7 implementation and the
        // Rust pkcs7 crate is extraordinarily messy - we need to refractor.
        // Tracking issue: https://github.com/spotlightishere/mdm-server/issues/1
        let Ok(envelope) = Pkcs7::from_der(&post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };

        // We'll then utilize OpenSSL
        let mut contents = Vec::new();
        let signer = if envelope.apple_ca_issued(&mut contents).is_ok() {
            Pkcs7Signer::Apple
        } else if envelope.our_device_ca_issued(state, &mut contents).is_ok() {
            Pkcs7Signer::Ourselves
        } else {
            // Don't hint that anything certificate-related failed.
            return Err(StatusCode::BAD_REQUEST);
        };

        Ok(Self {
            signer,
            envelope,
            contents,
        })
    }
}

pub trait EnvelopeSigner {
    /// Determine whether this envelope was issued by the Apple iPhone Device CA.
    fn apple_ca_issued(&self, output: &mut Vec<u8>) -> Result<(), ErrorStack>;

    /// Determine whether this envelope was issued by our configured device certificate.
    fn our_device_ca_issued<S>(&self, state: &S, output: &mut Vec<u8>) -> Result<(), ErrorStack>
    where
        S: Send + Sync,
        AppState: FromRef<S>;
}

impl EnvelopeSigner for Pkcs7 {
    fn apple_ca_issued(&self, output: &mut Vec<u8>) -> Result<(), ErrorStack> {
        // Apple's envelope should only be signed by their "Apple iPhone Device CA".
        let ca_stack = AppleCerts::cert_stack()?;
        let ca_store = AppleCerts::cert_store()?;

        // We utilize Pkcs7Flags::NOCHAIN because Apple's certificate
        // does not have S/MIME present under X509v3 Key Usage.
        self.verify(
            &ca_stack,
            &ca_store,
            None,
            Some(output),
            Pkcs7Flags::NOCHAIN,
        )
    }

    fn our_device_ca_issued<S>(&self, state: &S, output: &mut Vec<u8>) -> Result<(), ErrorStack>
    where
        S: Send + Sync,
        AppState: FromRef<S>,
    {
        let state = AppState::from_ref(state);

        // We'll need to extract our certificate.
        let ca_stack = state.certificates.device_ca_stack()?;
        let ca_store = state.certificates.device_ca_store()?;

        // Verify!
        self.verify(
            &ca_stack,
            &ca_store,
            None,
            Some(output),
            Pkcs7Flags::empty(),
        )
    }
}
