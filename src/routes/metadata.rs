use crate::plist::Plist;
use axum::extract::Host;
use axum::Json;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct MDMServiceConfig {
    dep_enrollment_url: String,
    dep_anchor_certs_url: String,
    trust_profile_url: String,
}

// An initial configuration to permit easier access for enrollment.
// See https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
pub async fn create_service_config(Host(host): Host) -> Json<MDMServiceConfig> {
    let host = host.as_str();

    let config = MDMServiceConfig {
        dep_enrollment_url: format!("https://{}/devicemanagement/mdm/dep_mdm_enroll", host),
        dep_anchor_certs_url: format!("https://{}/devicemanagement/mdm/dep_anchor_certs", host),
        trust_profile_url: format!("https://{}/mdm/trust_profile", host),
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

pub async fn create_trust_profile() -> Plist<HashMap<String, String>> {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let mut payload = HashMap::new();
    payload.insert("key1".to_string(), "value1".to_string());
    payload.insert("key2".to_string(), "value2".to_string());
    Plist(payload)
}

pub async fn begin_enrollment() -> Json<Vec<String>> {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let certificates = vec!["todo".to_string()];
    Json(certificates)
}
