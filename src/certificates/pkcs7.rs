use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRef, FromRequest},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use openssl::{
    error::ErrorStack,
    pkcs7::{Pkcs7, Pkcs7Flags},
    stack::Stack,
    x509::{store::X509StoreBuilder, verify::X509VerifyFlags},
};
use serde::de::DeserializeOwned;

use super::apple_device_ca::{apple_iphone_ca, apple_iphone_device_ca, apple_root_ca};
use crate::{app_state::AppState, plist::Plist};

/// The signer of the parsed PKCS#7 envelope.
pub enum Pkcs7Signer {
    Apple,
    Ourselves,
}

pub struct Pkcs7Body<T: DeserializeOwned>(pub Pkcs7Signer, pub T);

#[async_trait]
impl<S, B, T> FromRequest<S, B> for Pkcs7Body<T>
where
    Bytes: FromRequest<S, B>,
    B: Send + 'static,
    S: Send + Sync,
    AppState: FromRef<S>,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        // Before we read the body, let's check the content type header.
        // Although this provides no security, it helps to stop invalid requests.
        let Some(content_type) = req.headers().get("Content-Type") else {
            return Err((StatusCode::BAD_REQUEST, "Missing Content-Type").into_response());
        };
        if content_type != "application/pkcs7-signature" {
            return Err((StatusCode::BAD_REQUEST, "Invalid Content-Type").into_response());
        }

        // We should be POSTed a PKCS#7 envelope.
        let post_body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?
            .to_vec();
        let Ok(envelope) = Pkcs7::from_der(&post_body) else {
            return Err((StatusCode::UNAUTHORIZED, "Invalid PKCS#7 envelope").into_response());
        };

        // Before anything else, determine who issued this envelope.
        // We'll also use these functions to extract the contents of this envelope.
        //
        // TODO: This is rather messy - can we refractor?
        let raw_contents = &mut Vec::new();
        let issuer = if apple_ca_issued(&envelope, raw_contents).is_ok() {
            Pkcs7Signer::Apple
        } else if our_root_ca_issued(&envelope, state, raw_contents).is_ok() {
            Pkcs7Signer::Ourselves
        } else {
            // Don't hint that anything certificate-related
            return Err((StatusCode::UNAUTHORIZED).into_response());
        };

        // Now that we've determined the issuer and have extracted its contents,
        // we can serialize to the expected type.
        let Ok(contents) = Plist::<T>::from_xml(raw_contents.to_vec()) else {
            return Err((StatusCode::BAD_REQUEST, "Invalid body contents").into_response());
        };
        Ok(Self(issuer, contents))
    }
}

/// Determine whether this envelope was issued by the Apple iPhone Device CA.
fn apple_ca_issued(envelope: &Pkcs7, sealed_contents: &mut Vec<u8>) -> Result<(), ErrorStack> {
    // Apple's envelope should only be signed by their "Apple iPhone Device CA".
    let mut ca_stack = Stack::new().expect("should be able to create X509 stack");
    ca_stack.push(apple_iphone_device_ca())?;

    // We need to create a X509 store with Apple's three issuing CAs.
    let mut ca_store = X509StoreBuilder::new()?;
    ca_store.add_cert(apple_iphone_device_ca())?;
    ca_store.add_cert(apple_iphone_ca())?;
    ca_store.add_cert(apple_root_ca())?;

    // Then, we must disable its certificate date validity.
    //
    // Apple writes within "Creating a Profile Server for Over-The-Air Enrollment and Configuration":
    // "WARNING: When device certificates signed 'Apple iPhone Device CA' are evaluated
    // their validity dates should be ignored."
    ca_store.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
    let ca_store = ca_store.build();

    // We utilize Pkcs7Flags::NOCHAIN because Apple's certificate
    // does not have S/MIME present under X509v3 Key Usage.
    envelope.verify(
        &ca_stack,
        &ca_store,
        None,
        Some(sealed_contents),
        Pkcs7Flags::NOCHAIN,
    )
}

/// Determine whether this envelope was issued by our configured root certificate.
fn our_root_ca_issued<S>(
    envelope: &Pkcs7,
    state: &S,
    sealed_contents: &mut Vec<u8>,
) -> Result<(), ErrorStack>
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    let mut ca_stack = Stack::new().expect("should be able to create X509 stack");

    // We'll need to extract our certificate.
    let state = AppState::from_ref(state);
    let root_certificate = state.certificates.root_ca_cert;
    ca_stack.push(root_certificate.to_owned())?;

    // We'll also need to add our CA to the verification chain.
    let mut ca_store = X509StoreBuilder::new()?;
    ca_store.add_cert(root_certificate)?;
    let ca_store = ca_store.build();

    // Verify!
    envelope.verify(
        &ca_stack,
        &ca_store,
        None,
        Some(sealed_contents),
        Pkcs7Flags::empty(),
    )
}
