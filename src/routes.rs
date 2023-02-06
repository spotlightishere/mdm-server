use axum::routing::get;
use axum::Router;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::app_state::AppState;

mod enroll;
mod metadata;

pub fn create_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/enroll", get(enroll::generate_enroll_payload))
        .route("/MDMServiceConfig", get(metadata::create_service_config))
        .route("/mdm/trust_profile", get(metadata::create_trust_profile))
        .route(
            "/devicemanagement/mdm/dep_mdm_enroll",
            get(metadata::begin_enrollment),
        )
        .route(
            "/devicemanagement/mdm/dep_anchor_certs",
            get(metadata::get_anchor_certs),
        )
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
}
