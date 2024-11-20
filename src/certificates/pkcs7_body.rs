use super::der_transform::parse_der;
use crate::{app_state::AppState, certificates::apple_certs::iphone_device_ca};
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRef, FromRequest, Request},
    http::StatusCode,
};
use cms::{signed_data::SignerIdentifier, signed_data::SignerInfo};
use der::{asn1::PrintableStringRef, oid::db::rfc4519, referenced::OwnedToRef};
use x509_cert::attr::AttributeTypeAndValue;

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
        let Some((contents, signing_certificate)) = parse_der(post_body) else {
            return Err(StatusCode::BAD_REQUEST);
        };

        // Determine who issued this envelope.
        let Some(signer) = determine_issuer(state, signing_certificate) else {
            // Do not hint we encounter a certificate-related failure.
            return Err(StatusCode::BAD_REQUEST);
        };

        Ok(Self { signer, contents })
    }
}

/// Verifies the issuer of this envelope based on its
/// specified SignerInfo cert.
// TODO(spotlightishere): This is not remotely secure as
// it only checks the last issuer.
// DO NOT use this in a production environment.
fn determine_issuer<S>(state: &S, signer: SignerInfo) -> Option<Pkcs7Signer> where
    S: Send + Sync,
    AppState: FromRef<S>
{
    let state = AppState::from_ref(state);

    // Hackily check via the CN who issued this certificate.
    // We should be given an issuer and serial number.
    let SignerIdentifier::IssuerAndSerialNumber(issuer) = signer.sid else {
        return None;
    };

    // For our intents and purposes, we only have one [`RelativeDistinguishedName`]
    // which contains only a single [`AttributeTypeAndValue`] within.
    // However, we'll merge all specified attributes across all given RDNs.
    let issuer_attributes: Vec<AttributeTypeAndValue> = issuer
        .issuer
        .0
        .iter()
        .flat_map(|x| x.0.clone().into_vec())
        .collect();

    // Find our common name.
    let purported_cn = issuer_attributes
        .into_iter()
        .find(|x| x.oid == rfc4519::COMMON_NAME)?;

    // We should be given a string type of some sort.
    // We've only observed a PrintableString, so let's try this.
    let given_cn_value = purported_cn
        .value
        .owned_to_ref()
        .decode_as::<PrintableStringRef>()
        .ok()?;

    // We'll now determine what signature to match based on string.
    let (signer, expected_certificate) = match given_cn_value.as_str() {
        "Apple iPhone Device CA" => (Pkcs7Signer::Apple, iphone_device_ca()),
        // This isn't a CN we recognize.
        // TODO(spotlightishere): MDM server
        _ => return None,
    };

    // TODO(spotlightishere): Perform actual verification
    println!("Verifying only on name... TODO: please resolve");
    Some(signer)
}
