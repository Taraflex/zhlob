use crate::{in_headers, proxy::headers_map_ext::HeaderMapExt};
use bytes::Bytes;
use easy_ext::ext;
use http_body_util::combinators::BoxBody;
use hyper::{
    Response, StatusCode, Version,
    header::{
        CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, EXPIRES, PRAGMA,
        PROXY_AUTHENTICATE, TRANSFER_ENCODING, UPGRADE,
    },
};

pub type BoxedResponse = Response<BoxBody<Bytes, hyper::Error>>;

#[ext(ResponseExt)]
pub impl<T> Response<T> {
    fn normalize_headers(&mut self) {
        let status = self.status();
        let ver = self.version();
        let hh = self.headers_mut();

        macro_rules! h_remove {
            ($($item:expr),*) => {
                $(hh.remove($item);)*
            };
        }
        h_remove!(
            //custom headers
            "X-Powered-By",
            "X-Server",
            "X-Served-By",
            "Server",
            "X-AspNet-Version",
            "X-Generator",
            "X-Drupal-Cache",
            "X-Varnish",
            "X-Correlation-ID",
            "X-Debug-Token",
            "X-Debug-Token-Link",
            "X-Runtime",
            "X-VCache-Status",
            "Server-Timing",
            "X-Robots-Tag",
            "X-Cache",
            "X-Cache-Hits",
            "X-Timer",
            //standart
            PRAGMA,
            "Keep-Alive",
            PROXY_AUTHENTICATE
        );

        if status != StatusCode::SWITCHING_PROTOCOLS {
            hh.remove(CONNECTION);
            hh.remove(UPGRADE);
        }

        if in_headers!(hh, CACHE_CONTROL, *"max-age"* ) {
            hh.remove(EXPIRES);
        }

        if hh.contains_key(TRANSFER_ENCODING) {
            if ver != Version::HTTP_11 {
                let te = hh.get_safe(TRANSFER_ENCODING);
                let mut ce = hh.get_safe(CONTENT_ENCODING);
                let mut moved = false;

                for part in te.split(", ") {
                    if matches!(part, "gzip" | "deflate" | "compress") {
                        if !ce.is_empty() {
                            ce.push_str(", ");
                        }
                        ce.push_str(part);
                        moved = true;
                    }
                }

                if moved {
                    hh.set_unchecked(CONTENT_ENCODING, ce);
                    hh.normalize_extra_for_patched_content();
                }
                hh.remove(TRANSFER_ENCODING);
            } else {
                hh.remove(CONTENT_LENGTH);
            }
        }
    }
}
