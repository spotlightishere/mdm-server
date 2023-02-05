use crate::app_state::AppState;
use crate::payloads::PayloadType;
use axum::{extract::State, response::Response};
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Serialize)]
/// A stripped-down top-level profile for EnrollPayload.
pub struct EnrollProfile {
    #[serde(rename = "PayloadDescription")]
    pub description: String,
    #[serde(rename = "PayloadDisplayName")]
    pub display_name: String,
    #[serde(rename = "PayloadIdentifier")]
    pub identifier: String,
    #[serde(rename = "PayloadOrganization")]
    pub organization: String,
    #[serde(rename = "PayloadType")]
    pub payload_type: PayloadType,
    #[serde(rename = "PayloadUUID")]
    pub uuid: Uuid,
    #[serde(rename = "PayloadVersion")]
    pub version: isize,
    #[serde(rename = "PayloadContent")]
    pub contents: EnrollPayload,
}

/// Our custom payload format for enroll.
#[derive(Clone, Serialize)]
pub struct EnrollPayload {
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "DeviceAttributes")]
    pub device_attributes: [&'static str; 5],
    #[serde(rename = "Challenge")]
    pub challenge: String,
}

/// Handles the enrollment profile payload.
/// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW17
pub async fn generate_enroll_payload(State(state): State<AppState>) -> Response {
    let service_config = &state.config.service;
    // TODO: Persist challenge
    let challenge = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    // TODO: Allow for description configuration
    //
    // This profile is a special case: The enrollment payload must be the top-level value,
    // i.e. there is no array of PayloadContent.
    // We encode this ourselves and return the signed response manually.
    let enroll_profile = EnrollProfile {
        payload_type: PayloadType::ProfileService,
        identifier: format!("{}.profile-service", service_config.base_identifier),
        organization: service_config.organization_name.to_owned(),
        display_name: format!("{} Enrollment", service_config.organization_name),
        description: format!(
            "Install this profile to enroll into the MDM service for \"{}\".
If you do not recognize this name, please remove this profile.",
            service_config.organization_name
        ),
        uuid: Uuid::new_v4(),
        version: 1,
        contents: EnrollPayload {
            url: format!("https://{}/profile", service_config.base_domain),
            device_attributes: ["UDID", "VERSION", "PRODUCT", "SERIAL", "IMEI"],
            challenge,
        },
    };

    state.sign_profile(enroll_profile)
}
