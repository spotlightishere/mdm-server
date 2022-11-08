mod plist;
mod routes;

#[tokio::main]
async fn main() {
    println!("Starting up...");

    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(routes::create_routes().into_make_service())
        .await
        .unwrap();
}
