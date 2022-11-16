use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    stack::Stack,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{certificates::Certificates, plist::Plist};

#[non_exhaustive]
#[derive(Serialize)]
/// Represents the type of a profile.
pub enum ProfileTypes {
    #[serde(rename = "Profile Service")]
    ProfileService,
}

#[derive(Serialize)]
/// A representation of a profile.
pub struct Profile<T>
where
    T: Serialize,
{
    #[serde(rename = "PayloadVersion")]
    pub version: isize,
    #[serde(rename = "PayloadType")]
    pub payload_type: ProfileTypes,
    #[serde(rename = "PayloadIdentifier")]
    pub identifier: String,
    #[serde(rename = "PayloadUUID")]
    pub uuid: Uuid,
    #[serde(rename = "PayloadDisplayName")]
    pub display_name: String,
    #[serde(rename = "PayloadDescription")]
    pub description: String,
    #[serde(rename = "PayloadContent")]
    pub contents: Vec<T>,
}

impl<T> IntoResponse for Profile<T>
where
    T: Serialize,
{
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

        // Next, sign this profile.
        let ssl_cert = &Certificates::shared().ssl_cert;
        let ssl_key = &Certificates::shared().ssl_key;
        let empty_certs = Stack::new().expect("should be able to create certificate stack");
        let signed_profile = Pkcs7::sign(
            &ssl_cert,
            &ssl_key,
            &empty_certs,
            &profile_xml,
            Pkcs7Flags::BINARY,
        )
        .expect("should be able to sign certificate");
        let signed_profile_der = signed_profile
            .to_der()
            .expect("should be able to convert PKCS7 container to DER form");

        let headers = [(header::CONTENT_TYPE, "application/x-apple-aspen-config")];
        (headers, signed_profile_der).into_response()
    }
}
