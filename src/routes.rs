use warp::Filter;

mod metadata;

pub fn create_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let default = warp::path::end().map(|| "Hello, world!");

    // MDMServiceConfig
    let mdm_service_config = warp::path("MDMServiceConfig")
        .and(warp::get())
        .and(warp::header::<String>("host"))
        .and_then(metadata::create_service_config);

    let trust_profile = warp::path!("mdm" / "trust_profile")
        .and(warp::get())
        .and_then(metadata::create_trust_profile);

    // "devicemanagement/mdm" route group
    let device_management = warp::path("devicemanagement")
        .and(warp::path("mdm"))
        .and(warp::get())
        .and(
            (warp::path!("dep_mdm_enroll").and_then(metadata::begin_enrollment))
                .or(warp::path!("dep_anchor_certs").and_then(metadata::get_anchor_certs)),
        );

    default
        .or(mdm_service_config)
        .or(trust_profile)
        .or(device_management)
}
