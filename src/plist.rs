use axum::{
    http::header,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// An XML property list formatted reply.
pub struct Plist<T>(pub T);

impl<T> IntoResponse for Plist<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let mut body = Vec::new();
        match plist::to_writer_xml(&mut body, &self.0) {
            Ok(()) => {
                let headers = [(header::CONTENT_TYPE, "application/xml")];
                (headers, body).into_response()
            }
            Err(err) => {
                // We should not expose this exact error for safety reasons.
                println!("error within xml plist serialization: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}
