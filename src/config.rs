use serde::Deserialize;
use std::{fs, net::IpAddr};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
    pub storage: StorageConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    pub base_domain: String,
    pub base_identifier: String,
    pub organization_name: String,
}

// Per configuration, we should bind to 127.0.0.1 by default.
fn default_bind_address() -> IpAddr {
    "127.0.0.1".parse().unwrap()
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
