use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRef, FromRequest},
    http::{Request, StatusCode},
};
use cms::signed_data::SignedData;
use const_oid::db::rfc5911;
use openssl::{
    error::ErrorStack,
    pkcs7::{Pkcs7, Pkcs7Flags},
};
use rsa::pkcs8::der::{asn1::OctetStringRef, Decode};

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
    pub contents: Vec<u8>,
}

#[async_trait]
impl<S, B> FromRequest<S, B> for Pkcs7Body
where
    Bytes: FromRequest<S, B>,
    B: Send + 'static,
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
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
        println!("huh: {}", hex::encode(&post_body));

        // First, determine who issued this envelope.
        //
        // TODO: There's no reasonable way to natively validate a CA chain
        // within pure Rus. For now, we'll rely on OpenSSL's implementation.
        // Tracking issue: https://github.com/spotlightishere/mdm-server/issues/1
        let Ok(ssl_envelope) = Pkcs7::from_der(&post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };

        let signer = if ssl_envelope.apple_ca_issued().is_ok() {
            Pkcs7Signer::Apple
        } else if ssl_envelope.our_device_ca_issued(&state).is_ok() {
            Pkcs7Signer::Ourselves
        } else {
            // Don't hint that anything certificate-related failed.
            return Err(StatusCode::BAD_REQUEST);
        };
        println!("sig");

        // Next, we use the Rust cms crate to extract its contents.
        let aaa_envelope = SignedData::from_der(&post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let envelope = match aaa_envelope {
            Ok(a) => a,
            Err(wtf) => panic!("wtf: {}", wtf),
        };

        // Our contents should be pkcs7-data.
        if envelope.encap_content_info.econtent_type != rfc5911::ID_DATA {
            return Err(StatusCode::BAD_REQUEST);
        }
        println!("b");

        // As they are, we need to decode the contents as OctetStringRef,
        // and then get their corresponding bytes.
        let Some(encap_contents) = envelope.encap_content_info.econtent else {
            return Err(StatusCode::BAD_REQUEST);
        };
        println!("c");

        let Ok(octet_contents) = encap_contents.decode_as::<OctetStringRef>() else {
            return Err(StatusCode::BAD_REQUEST);
        };
        println!("d");

        let contents = octet_contents.as_bytes().to_vec();

        Ok(Self { signer, contents })
    }
}

pub trait EnvelopeSigner {
    /// Determine whether this envelope was issued by the Apple iPhone Device CA.
    fn apple_ca_issued(&self) -> Result<(), ErrorStack>;

    /// Determine whether this envelope was issued by our configured device certificate.
    fn our_device_ca_issued<S>(&self, state: &S) -> Result<(), ErrorStack>
    where
        S: Send + Sync,
        AppState: FromRef<S>;
}

impl EnvelopeSigner for Pkcs7 {
    fn apple_ca_issued(&self) -> Result<(), ErrorStack> {
        // Apple's envelope should only be signed by their "Apple iPhone Device CA".
        let ca_stack = AppleCerts::cert_stack()?;
        let ca_store = AppleCerts::cert_store()?;

        // We utilize Pkcs7Flags::NOCHAIN because Apple's certificate
        // does not have S/MIME present under X509v3 Key Usage.
        self.verify(&ca_stack, &ca_store, None, None, Pkcs7Flags::NOCHAIN)
    }

    fn our_device_ca_issued<S>(&self, state: &S) -> Result<(), ErrorStack>
    where
        S: Send + Sync,
        AppState: FromRef<S>,
    {
        let state = AppState::from_ref(state);

        // We'll need to extract our certificate.
        let ca_stack = state.certificates.device_ca_stack()?;
        let ca_store = state.certificates.device_ca_store()?;

        // Verify!
        self.verify(&ca_stack, &ca_store, None, None, Pkcs7Flags::empty())
    }
}
