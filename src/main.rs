mod config;
mod database;
mod plist;
mod routes;

use crate::config::Config;
use std::env;

#[tokio::main]
async fn main() {
    println!("Starting up...");

    // TODO: Allow for a flag-based way to specify this config path
    let args: Vec<String> = env::args().collect();
    let config_path = match args.get(1) {
        Some(s) => s.clone(),
        None => "./config.toml".to_string(),
    };
    Config::load_from(config_path);

    axum::Server::bind(&Config::service().bind_address)
        .serve(routes::create_routes().into_make_service())
        .await
        .unwrap();
}
