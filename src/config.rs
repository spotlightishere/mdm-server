use serde::Deserialize;
use std::{fs, net::IpAddr};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
    pub storage: StorageConfig,
}

#[derive(Clone, Debug, Deserialize)]
/// The raw service config format within
pub struct RawServiceConfig {
    pub bind_address: Option<IpAddr>,
    pub base_domain: String,
    pub base_identifier: String,
    pub organization_name: String,
    pub root_ca_name: Option<String>,
    pub device_ca_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(from = "RawServiceConfig")]
/// Our service config format, but without optionals.
/// This allows for us to fill in defaults for CA names
/// using the deserialized values of the organization's name.
pub struct ServiceConfig {
    pub bind_address: IpAddr,
    pub base_domain: String,
    pub base_identifier: String,
    pub organization_name: String,
    pub root_ca_name: String,
    pub device_ca_name: String,
}

/// Used to allow manipulating CA names to include the organizational name.
impl From<RawServiceConfig> for ServiceConfig {
    fn from(value: RawServiceConfig) -> Self {
        let org_name = &value.organization_name;

        ServiceConfig {
            // Per configuration, we should bind to 127.0.0.1 by default.
            bind_address: value.bind_address.unwrap_or("127.0.0.1".parse().unwrap()),
            base_domain: value.base_domain,
            base_identifier: value.base_identifier,
            organization_name: org_name.clone(),
            root_ca_name: value.root_ca_name.unwrap_or(format!("{org_name} Root CA")),
            device_ca_name: value
                .device_ca_name
                .unwrap_or(format!("{org_name} Device CA")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub certificates_dir: String,
    pub assets_dir: String,
}

/// Used to access options within configuration.
impl Config {
    /// Loads the configuration from the specified path to our shared OnceCell.
    /// Please do not invoke this more than once -- prefer using the config within the shared application state.
    pub fn load_from(path: String) -> Self {
        let contents = fs::read_to_string(path).expect("failed to read configuration");
        toml::from_str(&contents).expect("unable to parse configuration")
    }
}
