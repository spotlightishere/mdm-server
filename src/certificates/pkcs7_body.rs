use super::{cert_verify::determine_signing_ca, der_transform::parse_der};
use crate::app_state::AppState;
use axum::{
    body::Bytes,
    extract::{FromRef, FromRequest, Request},
    http::StatusCode,
};

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
        let Ok(post_bytes) = Bytes::from_request(req, state).await else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let post_body = post_bytes.to_vec();

        // HACK: Under macOS, the content of our CMS envelope may
        // not have finite lengths. The Rust [`der`] crate currently
        // cannot handle these indefinite BER-style lengths.
        //
        // We may need to to transform our PKCS#7 envelope
        // to have finite lengths specified.
        // A lack of a result means that an error occurred while parsing.
        let Some(envelope) = parse_der(post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };

        // Determine who signed this envelope.
        let Some((signer, contents)) = determine_signing_ca(state, envelope) else {
            // Do not hint we encounter a certificate-related failure.
            return Err(StatusCode::BAD_REQUEST);
        };

        Ok(Self { signer, contents })
    }
}
