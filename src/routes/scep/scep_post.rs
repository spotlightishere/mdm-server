use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{app_state::AppState, certificates::Pkcs7Body};

#[derive(Deserialize)]
/// Standard values passed within query parameters.
/// For our POST request, we only need operation.
pub struct ClientParams {
    pub operation: String,
}

/// messageTypes per section 3.2.1.2.
enum PKIMessageType {
    CertRep = 3,
    RenewalReq = 17,
    PKCSReq = 19,
    CertPoll = 20,
    GetCert = 21,
    GetCRL = 22,
}

/// A budget SCEP implementation. Perhaps more of an approximation of one.
/// This implements RFC 8894: https://datatracker.ietf.org/doc/html/rfc8894
///
/// This component handles POSTed PKIOperation requests.
/// Per section 4.3: "Note that when used with HTTP POST, the only OPERATION possible
/// is "PKIOperation", so many CAs don't check this value or even notice its absence."
pub async fn post_op_handler(
    State(state): State<AppState>,
    Query(params): Query<ClientParams>,
    envelope: Pkcs7Body,
) -> Response {
    // We are checking the operation out of spite.
    if params.operation != "PKIOperation" {
        return (StatusCode::BAD_REQUEST).into_response();
    }
    // TODO: Handle issuer

    "".into_response()
}
