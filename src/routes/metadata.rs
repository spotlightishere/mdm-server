use crate::plist::plist;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
struct MDMServiceConfig {
    dep_enrollment_url: String,
    dep_anchor_certs_url: String,
    trust_profile_url: String,
}

// An initial configuration to permit easier access for enrollment.
// See https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
pub async fn create_service_config(host: String) -> Result<impl warp::Reply, warp::Rejection> {
    let config = MDMServiceConfig {
        dep_enrollment_url: format!("https://{}/devicemanagement/mdm/dep_mdm_enroll", host),
        dep_anchor_certs_url: format!("https://{}/devicemanagement/mdm/dep_anchor_certs", host),
        trust_profile_url: format!("https://{}/mdm/trust_profile", host),
    };

    Ok(warp::reply::json(&config))
}

// Anchor certs
pub async fn get_anchor_certs() -> Result<impl warp::Reply, warp::Rejection> {
    // TODO(spotlightishere): Implement
    // We'll need to provide the CA certificate currently providing https
    // so that the device can trust it.
    let certificates = vec!["todo"];
    Ok(warp::reply::json(&certificates))
}

pub async fn create_trust_profile() -> Result<impl warp::Reply, warp::Rejection> {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let mut payload = HashMap::new();
    payload.insert("key1", "value1");
    payload.insert("key2", "value2");
    Ok(plist(&payload))
}

pub async fn begin_enrollment() -> Result<impl warp::Reply, warp::Rejection> {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    let certificates = vec!["todo"];
    Ok(warp::reply::json(&certificates))
}
