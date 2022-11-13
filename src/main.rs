mod certificates;
mod config;
mod database;
mod plist;
mod profile_payload;
mod routes;
mod storage;

use crate::certificates::Certificates;
use crate::config::Config;
use crate::storage::Storage;
use axum_server;
use axum_server::tls_rustls::RustlsConfig;
use std::{env, net::SocketAddr};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    println!("Starting up...");
    // Allow for logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new::<String>(
            "mdm_server=debug,tower_http=debug".into(),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // TODO: Allow for a flag-based way to specify this config path
    let args: Vec<String> = env::args().collect();
    let config_path = match args.get(1) {
        Some(s) => s.clone(),
        None => "./config.toml".to_string(),
    };
    Config::load_from(config_path);

    // Ensure all of our disk storage is present.
    Storage::create_if_needed();
    Certificates::issue_if_needed();

    let ssl_cert_path = Storage::certificate_path("ssl_cert.pem");
    let ssl_key_path = Storage::certificate_path("ssl_key.pem");
    let tls_config = RustlsConfig::from_pem_file(ssl_cert_path, ssl_key_path)
        .await
        .expect("should be able to load SSL certificate and private key");

    // Use the https address configured.
    let https_address = SocketAddr::new(Config::service().bind_address, 443);

    axum_server::bind_rustls(https_address, tls_config)
        .serve(routes::create_routes().into_make_service())
        .await
        .unwrap();
}
