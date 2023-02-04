use crate::app_state::AppState;
use crate::payloads::{BasePayload, PayloadType};
use axum::{extract::State, response::Response};
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;

/// Our custom profile format for enroll.
#[derive(Clone, Serialize)]
pub struct EnrollProfile {
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "DeviceAttributes")]
    pub device_attributes: Vec<&'static str>,
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
    // This profile is a special case: The enrollment payload must be the top-level value.
    // We encode this ourselves and return the signed response manually.
    let enroll_profile = EnrollProfile {
        base: BasePayload {
            payload_type: PayloadType::ProfileService,
            identifier: format!("{}.profile-service", service_config.base_identifier),
            display_name: Some(format!("{} Enrollment", service_config.organization_name)),
            description: Some(format!(
                "Install this profile to enroll into the MDM service for \"{}\".
    If you do not recognize this name, please remove this profile.",
                service_config.organization_name
            )),
            ..Default::default()
        },
        url: format!("https://{}/profile", service_config.base_domain),
        device_attributes: vec!["UDID", "VERSION", "PRODUCT", "SERIAL", "MEID", "IMEI"],
        challenge,
    };

    state.sign_profile(enroll_profile)
}
