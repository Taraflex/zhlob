use crate::{
    in_headers, initable_static,
    maybe::UnifiedError,
    proxy::{
        bytes_ext::BytesExt, cert::CERT_PATHS, headers_map_ext::HeaderMapExt,
        response_ext::BoxedResponse,
    },
};
use bytes::Bytes;
use easy_ext::ext;
use hyper::{
    Request, StatusCode,
    header::{ACCEPT, CONNECTION, IF_MODIFIED_SINCE, IF_NONE_MATCH, PROXY_AUTHORIZATION, UPGRADE},
};

initable_static! {
   INSTRUCTION: Bytes = || { Bytes::from(include_str!(concat!(env!("OUT_DIR"), "/install.html"))) };
}

#[ext(RequestExt)]
pub impl<T> Request<T> {
    fn normalize_headers(&mut self) {
        let headers = self.headers_mut();
        if !in_headers!(headers, CONNECTION, *"upgrade"*) {
            headers.remove(CONNECTION);
            headers.remove(UPGRADE);
        }
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove("Proxy-Connection");
        headers.remove("Keep-Alive");
    }
    fn normalize_and_get_accept(&mut self) -> String {
        let headers = self.headers_mut();
        if !in_headers!(headers, CONNECTION, *"upgrade"*) {
            headers.remove(CONNECTION);
            headers.remove(UPGRADE);
        }
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove("Proxy-Connection");
        headers.remove("Keep-Alive");

        let mut accept = String::with_capacity(64);

        for val in headers.get_all(ACCEPT) {
            let Ok(s) = val.to_str() else { continue };

            for part in s.split(',') {
                let part = part.trim_ascii();
                if part.is_empty() {
                    continue;
                }

                if let Some(p) = part.as_bytes().get(0..10) {
                    if p.eq_ignore_ascii_case(b"image/avif")
                        || p.eq_ignore_ascii_case(b"image/heic")
                        || p.eq_ignore_ascii_case(b"image/heif")
                        || p.eq_ignore_ascii_case(b"image/apng")
                    {
                        continue;
                    }
                }

                if !accept.is_empty() {
                    accept.push_str(", ");
                }
                accept.push_str(part);
            }
        }

        if accept.is_empty() {
            accept.push_str("*/*");
        }

        let accept_lower = accept.to_ascii_lowercase();
        headers.set_unchecked(ACCEPT, accept);

        return accept_lower;
    }

    fn skip_if_browser_has_cached(&self, accept: &str) -> Option<BoxedResponse> {
        let h = self.headers();
        if in_headers!(h, IF_NONE_MATCH, "W/\"zhlob-"*)
            || ((h.contains_key(IF_MODIFIED_SINCE) || h.contains_key(IF_NONE_MATCH))
                && matches!(
                    &accept.as_bytes()[..accept.len().min(6)],
                    b"image/" | b"video/" | b"audio/"
                ))
        {
            Some(Bytes::new().to_response(self.version(), StatusCode::NOT_MODIFIED, ""))
        } else {
            None
        }
    }

    fn skip_media_or_favicon(&self, accept: &str) -> Option<BoxedResponse> {
        let is_favicon = {
            let path = self.uri().path();
            if path.len() >= 12 && path[..8].eq_ignore_ascii_case("/favicon") {
                if let Some(dot_pos) = path.rfind('.') {
                    let extension = &path[dot_pos + 1..];
                    extension.eq_ignore_ascii_case("ico")
                        || extension.eq_ignore_ascii_case("png")
                        || extension.eq_ignore_ascii_case("gif")
                } else {
                    false
                }
            } else {
                false
            }
        };

        if is_favicon
            || matches!(
                &accept.as_bytes()[..accept.len().min(6)],
                b"video/" | b"audio/"
            )
        {
            Some(Bytes::new().to_response(self.version(), StatusCode::NO_CONTENT, ""))
        } else {
            None
        }
    }

    fn process_mitm_it(&self) -> Result<Option<BoxedResponse>, UnifiedError> {
        Ok(if self.uri().host() == Some("mitm.it") {
            let req_path = self.uri().path();
            if req_path.contains("-ca-cert") {
                let (path, mime) = if req_path.ends_with("cer") {
                    (&CERT_PATHS.cert_cer_path, "application/pkix-cert")
                } else {
                    (&CERT_PATHS.cert_pem_path, "application/x-x509-ca-cert")
                };
                Some(Bytes::from(std::fs::read(path)?).to_response(
                    self.version(),
                    StatusCode::OK,
                    mime,
                ))
            } else {
                Some(INSTRUCTION.clone().to_response(
                    self.version(),
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                ))
            }
        } else {
            None
        })
    }
}
