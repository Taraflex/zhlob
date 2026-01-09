use std::pin::Pin;

use crate::{
    cli::CLI, in_headers, proxy::bytes_ext::BytesExt, proxy::headers_map_ext::HeaderMapExt,
    proxy::response_ext::BoxedResponse,
};
use bytes::Bytes;
use easy_ext::ext;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyStream, StreamBody};
use http_mitm_proxy::futures::future::ready;
use http_mitm_proxy::futures::{Stream, StreamExt, stream};
use hyper::Response;
use hyper::body::{Frame, Incoming};
use hyper::header::{ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH};
use hyper::http::response::Parts;
use hyper::{
    HeaderMap, StatusCode,
    header::{AsHeaderName, CONTENT_TYPE, IntoHeaderName, LOCATION, TRAILER},
};

#[derive(Clone)]
struct MustReChunkified(bool);
#[derive(Clone)]
struct ContentCanBePatched(bool);

#[ext(PartsExt)]
pub impl Parts {
    fn skip_on_proxy_error(&self) -> Option<BoxedResponse> {
        if self.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            Some(
                Bytes::from("Error: Upstream proxy requires authentication.").to_response(
                    self.version,
                    StatusCode::BAD_GATEWAY,
                    "text/plain; charset=utf-8",
                ),
            )
        } else {
            None
        }
    }

    fn skip_media_or_font_or_favicon(&self) -> Option<BoxedResponse> {
        if in_headers!(
            self.headers,
            CONTENT_TYPE,
            "image/x-icon" | "image/vnd.microsoft.icon" |
            "video/"* | "audio/"* |
            "font/"* | "application/font-"* | "application/x-font-"*
        ) {
            Some(Bytes::new().to_response(
                self.version,
                StatusCode::NO_CONTENT,
                self.headers.get_safe(CONTENT_TYPE),
            ))
        } else {
            None
        }
    }

    fn contains_key<K>(&self, key: K) -> bool
    where
        K: AsHeaderName,
    {
        self.headers.contains_key(key)
    }

    fn set<K: IntoHeaderName>(&mut self, key: K, val: &'static str) {
        self.headers.set(key, val);
    }

    fn set_unchecked<K, V>(&mut self, key: K, val: V)
    where
        K: IntoHeaderName,
        V: Into<Bytes>,
    {
        self.headers.set_unchecked(key, val);
    }

    fn remove<K: AsHeaderName>(&mut self, key: K) {
        self.headers.remove(key);
    }

    fn can_be_patched(&mut self, req_headers: Option<&HeaderMap>) -> bool {
        if let Some(m) = self.extensions.get::<ContentCanBePatched>() {
            return m.0;
        }

        let v = !matches!(
            self.status,
            StatusCode::SWITCHING_PROTOCOLS
                | StatusCode::NO_CONTENT
                | StatusCode::RESET_CONTENT
                | StatusCode::NOT_MODIFIED
        ) && !self.contains_key(LOCATION)
            && !self.contains_key(TRAILER)
            && !in_headers!(self.headers, CACHE_CONTROL, *"no-transform"*)
            && req_headers
                .map(|hh| {
                    !hh.contains_key("X-Requested-With")
                        && match hh.get_safe("Sec-Fetch-Dest").as_ref() {
                            "" | "document" | "image" => true,
                            s if s.contains("frame") => true,
                            _ => false,
                        }
                })
                .unwrap_or(true);
        self.extensions.insert(ContentCanBePatched(v));
        v
    }

    fn must_be_rechunkified(&mut self) -> bool {
        if let Some(m) = self.extensions.get::<MustReChunkified>() {
            return m.0;
        }

        let v = CLI.rechunk_html_size > 0
            && self.can_be_patched(None)
            && in_headers!(self.headers, CONTENT_TYPE, "text/html"*)
            && !in_headers!(self.headers, ACCEPT_RANGES, "bytes");

        self.extensions.insert(MustReChunkified(v));
        v
    }

    fn response_from_bytes(mut self, body: Bytes) -> BoxedResponse {
        self.headers.normalize_extra_for_patched_content(true);

        let chunk_size = CLI.rechunk_html_size;

        let len = body.len();
        if len > chunk_size && self.must_be_rechunkified() {
            self.remove(CONTENT_LENGTH);
            Response::from_parts(
                self,
                BoxBody::new(StreamBody::new(stream::iter(
                    (0..len).step_by(chunk_size).map(move |start| {
                        let end = (start + chunk_size).min(len);
                        let chunk = body.slice(start..end);
                        Ok::<_, hyper::Error>(Frame::data(chunk))
                    }),
                ))),
            )
        } else {
            self.set_unchecked(CONTENT_LENGTH, len.to_string());
            Response::from_parts(self, body.to_boxed_body())
        }
    }

    fn response_from_incoming(mut self, body: Incoming) -> BoxedResponse {
        if self.must_be_rechunkified() {
            //for none RANGE responses rechunkify and send as chunked response
            self.response_from_stream(BodyStream::new(body))
        } else {
            Response::from_parts(self, BoxBody::new(body))
        }
    }

    fn response_from_stream<S>(mut self, stream: S) -> BoxedResponse
    where
        S: Stream<Item = Result<Frame<Bytes>, hyper::Error>> + Send + Sync + 'static,
    {
        if self.must_be_rechunkified() {
            let chunk_size = CLI.rechunk_html_size;
            //for none RANGE responses rechunkify and send as chunked response
            self.remove(CONTENT_LENGTH);
            Response::from_parts(
                self,
                BoxBody::new(StreamBody::new(stream.flat_map(move |result| {
                    let s: Pin<
                        Box<dyn Stream<Item = Result<Frame<Bytes>, hyper::Error>> + Send + Sync>,
                    > = match result {
                        Err(e) => Box::pin(stream::once(ready(Err(e)))),
                        Ok(frame) => match frame.into_data() {
                            Err(other) => Box::pin(stream::once(ready(Ok(other)))),
                            Ok(data) => {
                                let len = data.len();
                                if len <= chunk_size {
                                    Box::pin(stream::once(ready(Ok(Frame::data(data)))))
                                } else {
                                    let chunks = (0..len).step_by(chunk_size).map(move |start| {
                                        let end = (start + chunk_size).min(len);
                                        Ok(Frame::data(data.slice(start..end)))
                                    });
                                    Box::pin(stream::iter(chunks))
                                }
                            }
                        },
                    };
                    s
                }))),
            )
        } else {
            Response::from_parts(self, BoxBody::new(StreamBody::new(stream)))
        }
    }
}
