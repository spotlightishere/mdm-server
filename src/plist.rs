use serde::Serialize;

pub fn plist<T>(val: &T) -> Plist
where
    T: Serialize,
{
    Plist {
        inner: {
            let mut writer = Vec::with_capacity(128);
            match plist::to_writer_xml(&mut writer, val) {
                Ok(()) => Ok(writer),
                Err(err) => {
                    println!("error within xml plist serialization: {}", err);
                    Err(())
                }
            }
        },
    }
}

/// An XML property list formatted reply.
#[allow(missing_debug_implementations)]
pub struct Plist {
    inner: Result<Vec<u8>, ()>,
}

impl warp::Reply for Plist {
    #[inline]
    fn into_response(self) -> warp::reply::Response {
        match self.inner {
            Ok(body) => {
                let mut res = warp::reply::Response::new(body.into());
                res.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/xml"),
                );
                res
            }
            Err(()) => http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
