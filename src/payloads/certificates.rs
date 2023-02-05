use optional_value::payload;

#[payload]
pub struct RootCertificatePayload {
    #[serde(rename = "PayloadCertificateFileName")]
    pub file_name: String,
    #[serde(rename = "PayloadContent", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}
