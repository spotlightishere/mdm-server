mod plist;
mod routes;

#[tokio::main]
async fn main() {
    println!("Starting up...");
    warp::serve(routes::create_routes())
        .run(([127, 0, 0, 1], 8080))
        .await;
}
