use crate::app_state::AppState;
use crate::certificates::{Pkcs7Body, Pkcs7Signer};
use crate::database::pending_enrollments::dsl::*;
use crate::database::{PendingEnrollment, pending_enrollments};
use crate::payloads::{BasePayload, PayloadType, Profile, ScepPayload, ScepPayloadContents};
use crate::plist::Plist;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use diesel::ExpressionMethods;
use diesel::query_dsl::*;
use rand::distr::{Alphanumeric, SampleString};
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
    let random_challenge = Alphanumeric.sample_string(&mut rand::rng(), 16);
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

/// Responds to a request to begin enrollment.
/// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW17
pub async fn begin_enrollment(State(state): State<AppState>, envelope: Pkcs7Body) -> Response {
    let service_config = &state.config.service;

    // Now that Pkcs7Body has determined the issuer and have extracted
    // its contents, we can deserialize and handle based on issuer.
    let Ok(contents) = Plist::<EnrollRequest>::from_xml(envelope.contents) else {
        return (StatusCode::BAD_REQUEST).into_response();
    };

    // Ensure we have a pending challenge based on specification.
    let connection = &mut state.database.connection();
    let results = pending_enrollments
        .filter(challenge.eq(&contents.challenge))
        .limit(1)
        .load::<PendingEnrollment>(connection)
        .expect("can query devices");
    if results.len() != 1 {
        return (StatusCode::UNAUTHORIZED).into_response();
    }

    // To give an overview, enrollment can go one of two ways:
    //  - If the supplied PKCS#7 body is signed by Apple, we need to supply SCEP information.
    //    (This occurs initially, immediately after profile installation.)
    //  - If the body is signed by our configured root certificate, we give the device its initial profile.
    //    (This occurs after SCEP provisioning completes.)
    match envelope.signer {
        Pkcs7Signer::Apple => {
            // We'll need to supply a SCEP payload.
            let profile = Profile {
                base: BasePayload {
                    identifier: format!("{}.scep", service_config.base_identifier),
                    display_name: Some("SCEP Payload".to_string()),
                    ..Default::default()
                },
                contents: vec![ScepPayload {
                    base: BasePayload {
                        identifier: format!("{}.scep.config", service_config.base_identifier),
                        payload_type: PayloadType::Scep,
                        ..Default::default()
                    },
                    contents: ScepPayloadContents {
                        // We'll reuse the challenge from MDM.
                        challenge: contents.challenge,
                        key_type: "RSA".to_string(),
                        // 5 is digital signature (1) + key encipherment (5)
                        key_usage: 5,
                        key_size: 2048,
                        name: service_config.device_ca_name.clone(),
                        subject: vec![
                            vec![vec![
                                "O".to_string(),
                                service_config.organization_name.clone(),
                            ]],
                            vec![vec!["CN".to_string(), service_config.base_domain.clone()]],
                        ],
                        // /cgi-bin/pkiclient.exe seems to be standard.
                        url: format!(
                            "https://{}/cgi-bin/pkiclient.exe",
                            service_config.base_domain
                        ),
                    },
                }],
                ..Default::default()
            };
            state.serve_profile(profile)
        }
        Pkcs7Signer::Ourselves => {
            println!("Issued by our root CA");
            "TODO".to_string().into_response()
        }
    }
}
