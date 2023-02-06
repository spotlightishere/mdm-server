use crate::app_state::AppState;
use crate::payloads::{BasePayload, PayloadScope, PayloadType, Profile, RootCertificatePayload};
use axum::extract::State;
use axum::response::Response;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct MDMServiceConfig {
    dep_enrollment_url: String,
    dep_anchor_certs_url: String,
    trust_profile_url: String,
}

// An initial configuration to permit easier access for enrollment.
// See https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
pub async fn create_service_config(State(state): State<AppState>) -> Json<MDMServiceConfig> {
    let host = &state.config.service.base_domain;

    let config = MDMServiceConfig {
        dep_enrollment_url: format!("https://{host}/devicemanagement/mdm/dep_mdm_enroll"),
        dep_anchor_certs_url: format!("https://{host}/devicemanagement/mdm/dep_anchor_certs"),
        trust_profile_url: format!("https://{host}/mdm/trust_profile"),
    };

    Json(config)
}

// Anchor certs
pub async fn get_anchor_certs() -> Json<Vec<String>> {
    // TODO(spotlightishere): Implement
    // We'll need to provide the CA certificate currently providing https
    // so that the device can trust it.
    let certificates = vec!["todo".to_string()];
    Json(certificates)
}

pub async fn create_trust_profile(State(state): State<AppState>) -> Response {
    // Provides the root CA certificate necessary to continue a connection to this server.
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let service_config = &state.config.service;
    let root_ca_contents = state.certificates.root_ca_cert.to_pem().unwrap();

    let trust_profile = Profile {
        base: BasePayload {
            identifier: format!("{}.trust-profile", service_config.base_identifier),
            display_name: Some(format!(
                "Trust Profile for {}",
                service_config.organization_name
            )),
            description: Some(format!(
                "Configures your device to securely connect to the MDM service for \"{}\".",
                service_config.organization_name
            )),
            ..Default::default()
        },
        scope: Some(PayloadScope::System),
        contents: vec![RootCertificatePayload {
            base: BasePayload {
                identifier: format!("{}.trust-profile.root", service_config.base_identifier),
                display_name: Some(format!(
                    "Root Certificate for {}",
                    service_config.organization_name
                )),
                payload_type: PayloadType::CertificateRoot,
                ..Default::default()
            },
            file_name: "root_ca.pem".to_string(),
            certificate: root_ca_contents,
        }],
    };

    state.serve_profile(trust_profile)
}

pub async fn begin_enrollment() -> Json<Vec<String>> {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let certificates = vec!["todo".to_string()];
    Json(certificates)
}
