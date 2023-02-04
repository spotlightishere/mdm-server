use crate::certificates::Certificates;
use crate::config::Config;
use crate::database::Database;
use crate::plist::Plist;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

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

    // Signs a profile with the current SSL certificate.
    pub fn sign_profile<T: Serialize>(&self, profile: T) -> Response {
        self.certificates.sign_profile(profile)
    }

    // Serves a profile as a normal, unsigned property list.
    pub fn serve_plist<T: Serialize>(&self, profile: T) -> Response {
        Plist(profile).into_response()
    }
}
