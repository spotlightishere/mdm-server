use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum ProfilePayloads {
    RootCertificate(RootCertificatePayload),
}

#[derive(Clone, Serialize)]
/// A representation of a profile.
pub struct Profile {
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
    pub contents: Vec<ProfilePayloads>,
}

#[derive(Clone, Serialize)]
pub struct RootCertificatePayload {
    #[serde(rename = "PayloadCertificateFileName")]
    pub file_name: String,
    #[serde(rename = "PayloadContent", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}
