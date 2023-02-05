use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "&str")]
pub enum PayloadType {
    Configuration,
    ProfileService,
    CertificateRoot,
}

impl Into<&str> for PayloadType {
    fn into(self) -> &'static str {
        match self {
            PayloadType::Configuration => "Configuration",
            PayloadType::ProfileService => "Profile Service",
            PayloadType::CertificateRoot => "com.apple.security.root",
        }
    }
}
