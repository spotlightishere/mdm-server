use optional_value::payload;

use super::BasePayload;

#[payload]
pub struct RootCertificatePayload {
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "PayloadCertificateFileName")]
    pub file_name: String,
    #[serde(rename = "PayloadContent", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}
