use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "&str")]
pub enum PayloadType {
    Configuration,
    ProfileService,
    CertificateRoot,
    Scep,
}

impl From<PayloadType> for &str {
    fn from(value: PayloadType) -> Self {
        match value {
            PayloadType::Configuration => "Configuration",
            PayloadType::ProfileService => "Profile Service",
            PayloadType::CertificateRoot => "com.apple.security.root",
            PayloadType::Scep => "com.apple.security.scep",
        }
    }
}
