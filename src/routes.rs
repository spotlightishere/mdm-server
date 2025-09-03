use axum::Router;
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::app_state::AppState;

mod enroll;
mod metadata;
mod scep;

pub fn create_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/enroll", get(enroll::generate_enroll_payload))
        .route("/profile", post(enroll::begin_enrollment))
        // "/cgi-bin/pkiclient.exe" appears to be a common path.
        .route("/cgi-bin/pkiclient.exe", get(scep::get_op_handler))
        .route("/cgi-bin/pkiclient.exe", post(scep::post_op_handler))
        .route("/MDMServiceConfig", get(metadata::create_service_config))
        .route("/mdm/trust_profile", get(metadata::create_trust_profile))
        .route(
            "/devicemanagement/mdm/dep_anchor_certs",
            get(metadata::get_anchor_certs),
        )
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
}
