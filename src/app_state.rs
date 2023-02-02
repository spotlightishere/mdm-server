use crate::certificates::Certificates;
use crate::config::Config;
use crate::database::Database;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub certificates: Certificates,
    pub database: Database,
}

impl AppState {
    pub fn with_config(config: Config) -> Self {
        let certificates = Certificates::load_certs(&config);
        let database = Database::open(&config.storage.database_path);

        AppState {
            config,
            certificates,
            database,
        }
    }
}
