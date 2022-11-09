use once_cell::sync::OnceCell;
use serde::Deserialize;
use std::{fs, net::SocketAddr};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,
    pub base_domain: String,
    pub base_identifier: String,
}

// Per configuration, we should bind to 127.0.0.1:8080 by default.
fn default_bind_address() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub assets_dir: String,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

/// Used to access options within configuration.
impl Config {
    /// Retrieves the loaded configuration for this application.
    pub fn shared() -> &'static Config {
        CONFIG.get().expect("config was not initialized")
    }

    /// Retrieves general domain configuration for this application.
    pub fn service() -> &'static ServiceConfig {
        &Config::shared().service
    }

    /// Retrieves storage configuration.
    pub fn storage() -> &'static StorageConfig {
        &Config::shared().storage
    }

    /// Loads the configuration from the specified path to our shared OnceCell.
    /// Please do not invoke this more than once -- instead, access via shared.
    pub fn load_from(path: String) -> () {
        let contents = fs::read_to_string(path).expect("failed to read configuration");
        let config = toml::from_str(&contents).expect("unable to parse configuration");
        CONFIG.set(config).expect("unable to set configuration")
    }
}
