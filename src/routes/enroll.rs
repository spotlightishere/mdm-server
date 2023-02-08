use crate::app_state::AppState;
use crate::certificates::{Pkcs7Body, Pkcs7Signer};
use crate::database::pending_enrollments::dsl::*;
use crate::database::{pending_enrollments, PendingEnrollment};
use crate::payloads::PayloadType;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use diesel::query_dsl::*;
use diesel::ExpressionMethods;
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
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
    let connection = &mut state.database.connection();
    let service_config = &state.config.service;

    // We'll persist this challenge to identify enrollment later.
    // TODO: Have proper authentication for challenge creation
    let random_challenge = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let enrollment = PendingEnrollment {
        challenge: random_challenge.clone(),
        creation_date: OffsetDateTime::now_utc(),
    };
    diesel::insert_into(pending_enrollments::table)
        .values(&enrollment)
        .execute(connection)
        .expect("error persiting challenge");

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
            challenge: random_challenge,
        },
    };

    state.serve_profile(enroll_profile)
}

#[derive(Deserialize, Debug)]
/// A property list given via its POST body within an PKCS#7 envelope.
pub struct EnrollRequest {
    #[serde(rename = "CHALLENGE")]
    pub challenge: String,
    #[serde(rename = "IMEI")]
    pub imei: String,
    #[serde(rename = "PRODUCT")]
    pub product: String,
    #[serde(rename = "SERIAL")]
    pub serial: String,
    #[serde(rename = "UDID")]
    pub udid: String,
    #[serde(rename = "VERSION")]
    pub device_version: String,
}

pub async fn begin_enrollment(
    State(state): State<AppState>,
    Pkcs7Body(issuer, contents): Pkcs7Body<EnrollRequest>,
) -> Response {
    // TODO(spotlightishere): Implement
    // https://developer.apple.com/documentation/devicemanagement/implementing_device_management/simplifying_mdm_server_administration_for_ios_devices
    match issuer {
        Pkcs7Signer::Apple => {
            println!("Issued by Apple");
        }
        Pkcs7Signer::Ourselves => {
            println!("Issued by ourself");
        }
    }
    println!("Parsed contents: {contents:?}");

    let connection = &mut state.database.connection();
    let results = pending_enrollments
        .filter(challenge.eq(contents.challenge))
        .limit(1)
        .load::<PendingEnrollment>(connection)
        .expect("can query devices");
    if results.len() != 1 {
        return (StatusCode::UNAUTHORIZED).into_response();
    }

    let certificates = vec!["todo".to_string()];
    Json(certificates).into_response()
}
