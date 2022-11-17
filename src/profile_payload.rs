use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

use crate::{certificates::sign_response, payloads::ProfilePayloads, plist::Plist};

#[derive(Clone, Serialize)]
/// A representation of a profile.
pub struct Profile {
    #[serde(rename = "PayloadVersion")]
    pub version: isize,
    #[serde(rename = "PayloadType")]
    pub payload_type: String,
    #[serde(rename = "PayloadIdentifier")]
    pub identifier: String,
    #[serde(rename = "PayloadUUID")]
    pub uuid: Uuid,
    #[serde(rename = "PayloadDisplayName")]
    pub display_name: String,
    #[serde(rename = "PayloadDescription")]
    pub description: String,
    #[serde(rename = "PayloadContent")]
    pub contents: Vec<ProfilePayloads>,
}

impl IntoResponse for Profile {
    fn into_response(self) -> Response {
        // Let's get our payload contents.
        let profile_xml = match Plist(self).to_xml() {
            Ok(body) => body,
            Err(err) => {
                // We should not expose this exact error for safety reasons.
                println!("error within xml plist serialization: {}", err);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                    .into_response();
            }
        };

        // We need to sign this profile.
        let signed_profile = sign_response(profile_xml);

        let headers = [(header::CONTENT_TYPE, "application/x-apple-aspen-config")];
        (headers, signed_profile).into_response()
    }
}
