use axum::routing::get;
use axum::Router;

mod metadata;

pub fn create_routes() -> Router {
    return Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/MDMServiceConfig", get(metadata::create_service_config))
        .route("/mdm/trust_profile", get(metadata::create_trust_profile))
        .route(
            "/devicemanagement/mdm/dep_mdm_enroll",
            get(metadata::begin_enrollment),
        )
        .route(
            "/devicemanagement/mdm/dep_anchor_certs",
            get(metadata::get_anchor_certs),
        );
}
