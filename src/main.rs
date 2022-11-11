mod config;
mod database;
mod plist;
mod profile_payload;
mod routes;
mod storage;

use crate::config::Config;
use crate::storage::Storage;
use std::env;
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
    axum::Server::bind(&Config::service().bind_address)
        .serve(routes::create_routes().into_make_service())
        .await
        .unwrap();
}
