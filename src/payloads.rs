use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum ProfilePayloads {
    RootCertificate(RootCertificatePayload),
}

#[derive(Clone, Serialize)]
pub struct RootCertificatePayload {
    #[serde(rename = "PayloadCertificateFileName")]
    pub file_name: String,
    #[serde(rename = "PayloadContent", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}
