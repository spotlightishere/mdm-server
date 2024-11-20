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

#[payload]
pub struct ScepPayload {
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "PayloadContent")]
    pub contents: ScepPayloadContents,
}

#[payload]
/// Represents a SCEP payload. This is abbreviated.
/// https://developer.apple.com/documentation/devicemanagement/scep/payloadcontent
pub struct ScepPayloadContents {
    #[serde(rename = "Challenge")]
    pub challenge: String,
    #[serde(rename = "Key Type")]
    // Key Usage must always be RSA.
    pub key_type: String,
    #[serde(rename = "Key Usage")]
    pub key_usage: i32,
    #[serde(rename = "Keysize")]
    /// Documented to not allow any size larger than 2048 bits.
    pub key_size: i32,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Subject")]
    /// An array of single-element arrays with a single-element array of paired properties.
    /// For example:
    ///   `/C=US/1.2.5.3=Howdy!`
    /// becomes
    /// ```xml
    /// <array>
    ///   <array>
    ///     <array>
    ///       <string>C</string>
    ///       <string>US</string>
    ///     </array>
    ///   </array>
    ///   <array>
    ///     <array>
    ///       <string>1.2.5.3</string>
    ///       <string>Howdy!</string>
    ///     </array>
    ///   </array>
    /// </array>
    /// ```
    ///
    /// There are several shortcuts available for OIDs:
    /// country (C), locality (L), state (ST), organization (O),
    /// organizational unit (OU), and common name (CN).
    // TODO(spotlightishere): It would be nice to make this syntatically nicer.
    pub subject: Vec<Vec<Vec<String>>>,
    #[serde(rename = "URL")]
    pub url: String,
}

impl Default for ScepPayloadContents {
    fn default() -> Self {
        ScepPayloadContents {
            challenge: "".to_string(),
            key_type: "RSA".to_string(),
            // Signing & Encryption
            key_usage: 5,
            key_size: 2048,
            name: "".to_string(),
            subject: vec![],
            url: "".to_string(),
        }
    }
}
