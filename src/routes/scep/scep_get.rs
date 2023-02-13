use axum::{
    extract::{Query, State},
    http::header,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::Private,
    stack::Stack,
};
use serde::Deserialize;

use crate::app_state::AppState;

#[derive(Deserialize)]
/// Standard values passed within query parameters.
/// Per RFC and mdmclient, no others are sent.
pub struct ClientParams {
    pub operation: String,
    // Although not necessary per RFC, message will be set
    // to the value of "Name" within the SCEP payload by mdmclient
    // for GetCACert/GetCACaps.
    pub message: String,
}

/// A budget SCEP implementation. Perhaps more of an approximation of one.
/// This implements RFC 8894: https://datatracker.ietf.org/doc/html/rfc8894
///
/// If this does not work beyond Apple platforms, the authors would like to apologize.
/// However, should you run into this situation, please invest in a proper PKI server.
pub async fn get_op_handler(
    State(state): State<AppState>,
    Query(params): Query<ClientParams>,
) -> Response {
    // As mentioned within ClientParams, our message within the query
    // is the name of our device CA certificate.
    if params.message != state.config.service.device_ca_name {
        return (StatusCode::BAD_REQUEST).into_response();
    }

    // Our operation is specified by a query parameter.
    match params.operation.as_str() {
        "GetCACert" => get_ca_cert(state).await,
        "GetCACaps" => get_ca_caps().await,
        _ => (StatusCode::NOT_FOUND).into_response(),
    }
}

/// Implements GetCACert per section 4.2 of RFC 8894.
pub async fn get_ca_cert(state: AppState) -> Response {
    // Per section 4.2.1.1, we can respond with a single certificate in DER form.
    //
    // However, in our default setup, we have two certificates: our root CA,
    // and our intermediate device CA. Due to this, per section 4.2.1.2, multiple
    // sections must respond with a "degenerate certificates-only CMS SignedData message"
    // as defined within section 3.4.
    let certificates = state.certificates;
    let mut ca_stack = Stack::new().expect("should be able to create X509 stack");
    ca_stack
        .push(certificates.root_ca_cert)
        .expect("should be able to add root CA certificate to stack");
    ca_stack
        .push(certificates.device_ca_cert)
        .expect("should be able to add device CA certificate to stack");

    // If we specify data of None, or provide an empty array to data,
    // we encouter an error within `CMS_final`.
    // To work around this, we specify CMS_PARTIAL.
    // OpenSSL's docs write that `CMS_final` should be called
    // to finalize the structure, but it appears to only deal with data
    // ...which is not ideal, but, avoidable.
    //
    // TODO: This is horrendous - can we manually encode a PKCS#7/CMS
    // body?
    let only_certificates = CmsContentInfo::sign::<Private>(
        None,
        None,
        Some(&ca_stack),
        None,
        CMSOptions::NOSIGS | CMSOptions::DETACHED | CMSOptions::PARTIAL,
    )
    .expect("should be able to create signatureless CMS envelope");
    let der_contents = only_certificates
        .to_der()
        .expect("should be able to encode CMS envelope into DER form");

    (
        [(header::CONTENT_TYPE, "application/x-x509-ca-ra-cert")],
        der_contents,
    )
        .into_response()
}

// Aligns with recommendations within section 3.5.2.
const CA_CAPS: &str = "\
AES
POSTPKIOperation
SCEPStandard
SHA-256
SHA-512
";

/// Implements GetCACaps per section 3.5.1 of RFC 8894.
pub async fn get_ca_caps() -> Response {
    let headers = [(header::CONTENT_TYPE, "text/plain")];
    (headers, CA_CAPS).into_response()
}
