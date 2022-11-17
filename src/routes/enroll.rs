use crate::certificates::sign_response;
use crate::{config::Config, plist::Plist};
use axum::response::IntoResponse;
use axum::response::Response;
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use uuid::Uuid;

/// Handles the enrollment profile payload.
/// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW17
pub async fn generate_enroll_payload() -> Response {
    let service_config = Config::service();
    // TODO: Persist challenge
    let challenge = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    // TODO: Allow for description configuration
    //
    // This profile is a special case: We cannot return an array of PayloadContent.
    // iOS throws an error. (Curiously, macOS does not.)
    // We encode this ourselves and return the signed response manually.
    let enroll_profile = EnrollProfile {
        version: 1,
        uuid: uuid::Uuid::new_v4(),
        payload_type: "Profile Service".to_string(),
        identifier: format!("{}.profile-service", service_config.base_identifier),
        display_name: format!("{} Enrollment", service_config.organization_name),
        description: format!(
            "Install this profile to enroll into the MDM service for \"{}\".
If you do not recognize this name, please remove this profile.",
            service_config.organization_name
        ),
        contents: EnrollPayload {
            url: format!("https://{}/profile", service_config.base_domain),
            device_attributes: vec!["UDID", "VERSION", "PRODUCT", "SERIAL", "MEID", "IMEI"],
            challenge,
        },
    };

    let enroll_xml = Plist(enroll_profile)
        .to_xml()
        .expect("should be able to create enrollment profile");
    let signed_xml = sign_response(enroll_xml);

    let headers = [("Content-Type", "application/x-apple-aspen-config")];
    (headers, signed_xml).into_response()
}

/// Our custom profile format for enroll.
#[derive(Clone, Serialize)]
pub struct EnrollProfile {
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
    pub contents: EnrollPayload,
}

#[derive(Clone, Serialize)]
pub struct EnrollPayload {
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "DeviceAttributes")]
    pub device_attributes: Vec<&'static str>,
    #[serde(rename = "Challenge")]
    pub challenge: String,
}
