use crate::config::Config;
use crate::profile_payload::{Profile, ProfileTypes};
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;

#[derive(Serialize)]
pub struct EnrollPayload {
    #[serde(rename = "URL")]
    url: String,
    #[serde(rename = "DeviceAttributes")]
    device_attributes: Vec<&'static str>,
    #[serde(rename = "Challenge")]
    challenge: String,
}

/// Handles the enrollment profile payload.
/// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW17
pub async fn generate_enroll_payload() -> Profile<EnrollPayload> {
    let service_config = Config::service();
    // TODO: Persist challenge
    let challenge = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    let payload_content = EnrollPayload {
        url: format!("https://{}/profile", service_config.base_domain),
        device_attributes: vec!["UDID", "VERSION", "PRODUCT", "SERIAL", "MEID", "IMEI"],
        challenge,
    };

    // TODO: Allow for description configuration
    Profile {
        version: 1,
        uuid: uuid::Uuid::new_v4(),
        payload_type: ProfileTypes::ProfileService,
        identifier: format!("{}.profile-service", service_config.base_identifier),
        display_name: format!("{} Enrollment", service_config.organization_name),
        description: format!(
            "Install this profile to enroll into the MDM service for \"{}\".
If you do not recognize this name, please remove this profile.",
            service_config.organization_name
        ),
        content: payload_content,
    }
}
