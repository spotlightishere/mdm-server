use optional_value::payload;
use serde::Serialize;
use uuid::Uuid;

use super::PayloadType;

#[payload]
/// Common keys across all payloads.
/// https://developer.apple.com/documentation/devicemanagement/commonpayloadkeys
pub struct BasePayload {
    #[serde(rename = "PayloadDescription")]
    // The description of this payload - user visible.
    pub description: Option<String>,
    #[serde(rename = "PayloadDisplayName")]
    /// The name this payload is displayed as - user visible.
    pub display_name: Option<String>,
    #[serde(rename = "PayloadIdentifier")]
    /// The identifier of this payload, in reverse domain notation.
    pub identifier: String,
    #[serde(rename = "PayloadOrganization")]
    /// The name of the organization this payload represents - user-visible.
    pub organization: Option<String>,
    #[serde(rename = "PayloadType")]
    /// The payload type this payload refers to.
    /// For the top-level payload in a profile, specify "Configuration".
    pub payload_type: PayloadType,
    #[serde(rename = "PayloadUUID")]
    /// Each payload must have a unique UUID.
    /// Persist UUIDs for payloads that you may change in the future.
    pub uuid: Uuid,
    #[serde(rename = "PayloadVersion")]
    /// Every payload's version is typically 1.
    pub version: isize,
}

impl Default for BasePayload {
    /// Creates a profile with common details filled out.
    fn default() -> Self {
        BasePayload {
            description: None,
            display_name: None,
            // Please ensure you set identifier.
            identifier: "".to_string(),
            organization: None,
            // Likewise, please set payload type.
            payload_type: PayloadType::Configuration,
            uuid: uuid::Uuid::new_v4(),
            version: 1,
        }
    }
}

#[payload]
/// A profile - the top-level payload, encapsulating all profiles within.
/// https://developer.apple.com/documentation/devicemanagement/toplevel
pub struct Profile<T>
where
    T: Serialize,
{
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "PayloadContent")]
    pub contents: Vec<T>,
}

impl<T> Default for Profile<T>
where
    T: Serialize,
{
    fn default() -> Self {
        Profile {
            base: BasePayload::default(),
            contents: vec![],
        }
    }
}
