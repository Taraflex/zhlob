use crate::{
    cli::{APP_NAME, CLI},
    initable_static,
    proxy::{headers_map_ext::HeaderMapExt, response_ext::BoxedResponse},
};
use bytes::Bytes;
use easy_ext::ext;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use http_mitm_proxy::hyper::{
    self, Response, StatusCode, Version,
    header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, DATE},
};
use hyper::header::HeaderValue;
use std::time::SystemTime;

initable_static! {
    NOBODY_CACHE_CONTROL: HeaderValue = || {
        HeaderValue::from_str(&format!(
            "private, max-age={}, must-revalidate, stale-while-revalidate=604800",
            CLI.cache_max_age
        )).unwrap()
    };
}

#[ext(BytesExt)]
pub impl Bytes {
    fn to_response<S>(self, version: Version, status: StatusCode, mime: S) -> BoxedResponse
    where
        S: Into<Bytes> + AsRef<str>,
    {
        let mut b = Response::builder().version(version).status(status);
        if let Some(headers) = b.headers_mut() {
            match status {
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED => {
                    headers.set_unchecked(DATE, httpdate::fmt_http_date(SystemTime::now()));
                    headers.insert(CACHE_CONTROL, NOBODY_CACHE_CONTROL.clone());
                }
                StatusCode::OK if mime.as_ref().starts_with("text/") => {
                    headers.set(
                        CACHE_CONTROL,
                        "private, max-age=0, must-revalidate, stale-while-revalidate=604800",
                    );
                }
                StatusCode::OK => {
                    headers.set(CACHE_CONTROL, "no-store");
                }
                _ => {}
            }
            if !mime.as_ref().is_empty() {
                match mime.as_ref() {
                    "application/pkix-cert" => headers.set(
                        CONTENT_DISPOSITION,
                        const_str::concat!("attachment; filename=", APP_NAME, "-ca-cert.cer"),
                    ),
                    "application/x-x509-ca-cert" => headers.set(
                        CONTENT_DISPOSITION,
                        const_str::concat!("attachment; filename=", APP_NAME, "-ca-cert.pem"),
                    ),
                    _ => {}
                };
                headers.set_unchecked(CONTENT_TYPE, mime);
            }
        }

        return b.body(self.to_boxed_body()).unwrap();
    }

    fn to_boxed_body(self) -> BoxBody<Bytes, hyper::Error> {
        Full::new(self).map_err(|never| match never {}).boxed()
    }
}
