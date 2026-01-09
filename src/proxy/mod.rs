use crate::{
    cancelation_token::CancellationGuard,
    cli::{APP_NAME, CLI},
    dac::DAC,
    highway_semaphore::HighwaySemaphore,
    in_headers, initable_static,
    maybe::UnifiedError,
    processors::{
        compression::CompressionAlgo,
        html::{self},
        webp,
    },
    proxy::{
        bytes_ext::BytesExt,
        cert::{BASE_DIRS, CERT_PATHS, load_root_issuer},
        headers_map_ext::HeaderMapExt,
        mitm::MitmProxy,
        parts_ext::PartsExt,
        request_ext::RequestExt,
        response_ext::{BoxedResponse, ResponseExt},
    },
};
use bytes::{Bytes, BytesMut};
use encoding_rs_io::DecodeReaderBytesBuilder;
use http_body_util::BodyStream;
use http_mitm_proxy::{
    DefaultClient,
    futures::{StreamExt, future::ready, stream},
};
use hyper::{
    Method, Request, StatusCode,
    body::{Frame, Incoming},
    header::{
        CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, PRAGMA, TRANSFER_ENCODING,
    },
};
use hyper_util::service::TowerToHyperService;
use std::{io::Read, time::Duration};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::timeout::ResponseBodyTimeout;

pub mod bytes_ext;
pub mod cert;
pub mod headers_map_ext;
pub mod mitm;
pub mod parts_ext;
pub mod request_ext;
pub mod response_ext;

initable_static! {
   SEM: HighwaySemaphore = || { HighwaySemaphore::new(num_cpus::get()) };
}

macro_rules! up_some {
    ($res:expr) => {
        if let Some(val) = $res {
            return Ok(val);
        }
    };
}

async fn handler(
    mut req: Request<Incoming>,
    client: DefaultClient,
) -> Result<BoxedResponse, UnifiedError> {
    up_some!(req.process_mitm_it()?);

    let accept = req.normalize_and_get_accept();

    let cli = &*CLI;
    
    if cli.fast_304 {
        up_some!(req.skip_if_browser_has_cached(&accept));
    }

    if cli.skip_aux_resources {
        up_some!(req.skip_media_or_favicon(&accept));
    }

    req.normalize_headers();

    let uri = req.uri().to_string();
    let req_method = req.method().clone();
    let req_headers = req.headers().clone();

    let (res, upgrade) = client.send_request(req).await?;
    let (mut parts, body_incoming) = res.into_parts();

    up_some!(parts.skip_on_proxy_error());

    if !parts.contains_key(CACHE_CONTROL) && in_headers!(parts.headers, PRAGMA, "no-cache") {
        parts.set(CACHE_CONTROL, "no-cache");
    }

    if upgrade.is_none() && !matches!(req_method, Method::HEAD | Method::TRACE) {
        // проверка chunked: curl -v -k --http1.1 --proxy http://127.0.0.1:5151 --trace-ascii - http://httpbin.org/stream/5
        let payload_limit: usize = cli.transform_limit;
        let content_length: usize = parts.headers.get_as(CONTENT_LENGTH);
        // can_be_patched проверяем первым чтобы мемоизировать can_be_patched с данными из req_headers 
        if parts.can_be_patched(Some(&req_headers)) && content_length <= payload_limit
        {
            if cli.skip_aux_resources {
                up_some!(parts.skip_media_or_font_or_favicon());
            }

            if (cli.clear_html && in_headers!(parts.headers, CONTENT_TYPE, "text/html"*))
                || (cli.image_scale > 0.0 
                && !accept.starts_with("text/") //browser open in new tab
                && accept.contains("image/webp")
                && in_headers!(
                    parts.headers,
                    CONTENT_TYPE,
                    "image/jpeg"
                        | "image/png"
                        | "image/gif"
                        | "image/webp"
                ))
            {
                if let Some(compression_algo) = CompressionAlgo::from_resp_headers(&parts.headers) {
                    let mut buffer = BytesMut::with_capacity(content_length.max(64 * 1024)); //для content_length == 0 предаллоцируем столько чтобы влезла любая средняя html страница
                    let mut body_stream = BodyStream::new(body_incoming);

                    while let Some(result) = body_stream.next().await {
                        let frame = result?;

                        if let Ok(data) = frame.into_data() {
                            if buffer.len() + data.len() > payload_limit {
                                // ПРЕВЫШЕНИЕ: Склеиваем и выходим
                                let prefix = buffer.freeze();
                                let combined_stream = stream::once(ready(Ok(Frame::data(prefix))))
                                    .chain(stream::once(ready(Ok(Frame::data(data)))))
                                    .chain(body_stream);

                                return Ok(parts.response_from_stream(combined_stream));
                            }
                            buffer.extend_from_slice(&data);
                        } else {
                            // трейлеры или прочие фреймы — для HTML считаем концом данных
                            // на здоровом сервере мы не должны попадать в эту ветку, так как parts.can_be_patched должен пропускать только картинки и документы для вкладок где нет явных заголовков Trailer
                            break;
                        }
                    }
                    let bytes = buffer.freeze();

                    if bytes.is_empty() {
                        parts.remove(TRANSFER_ENCODING);
                        parts.remove(CONTENT_ENCODING);
                        return Ok(parts.response_from_bytes(bytes));
                    }

                    let text_encoding = if in_headers!(parts.headers, CONTENT_TYPE, "image/"*) {
                        None
                    } else {
                        Some(parts.headers.extract_encoding())
                    };

                    let permit = SEM.acquire(text_encoding.is_some()).await?;

                    let (ctoken, _guard) = CancellationGuard::new();
                    macro_rules! c_guard {
                        () => {
                            if ctoken.is_cancelled() {
                                return Err("task canceled".into());
                            }
                        };
                    }

                    let async_load_styles =
                        text_encoding.is_some() && cli.rechunk_html_size > 0 && parts.headers.csp_allow_inline_js_in_attrs();

                    let (result_compression_algo, processed_bytes, content_type_changed) =
                    tokio::task::spawn_blocking(
                        move || -> Result<(CompressionAlgo, bytes::Bytes, bool), UnifiedError> {
                            c_guard!();
                            let _ = permit;

                            if let Some(encoding) = text_encoding {
                                let mut html_reader = DecodeReaderBytesBuilder::new()
                                    .encoding(Some(encoding))
                                    .build(compression_algo.create_decompressor(bytes.as_ref()));

                                c_guard!();

                                let mut html = String::new();

                                Ok(match html_reader.read_to_string(&mut html) {
                                    Ok(_) => {                                      
                                        let patched_html = html::minify(html, async_load_styles, &uri);
                                        c_guard!();
                                        let (_0, _1) = CompressionAlgo::from_req_headers(&req_headers)
                                            .try_compress(patched_html);
                                        (_0, _1, true)
                                    }
                                    Err(e) => {
                                        tracing::warn!("Could not read html '{uri}': {e}");
                                        (compression_algo, bytes.clone(), false)
                                    }
                                })
                            } else {
                                let mut decompressed = Vec::new();

                                let dres = compression_algo
                                    .create_decompressor(bytes.as_ref())
                                    .read_to_end(&mut decompressed)
                                    .map_err(UnifiedError::from);

                                c_guard!();

                                Ok(
                                    match dres.and_then(|_| webp::thumbnail(decompressed)) {
                                        Ok(data) => {
                                            (CompressionAlgo::Uncompressed, Bytes::from(data), true)
                                        }
                                        Err(e) => {
                                            tracing::warn!("Could not optimize image '{uri}': {e}");
                                            (compression_algo, bytes, false)
                                        }
                                    },
                                )
                            }
                        },
                    )
                    .await??;

                    parts.remove(TRANSFER_ENCODING);

                    if content_type_changed {
                        parts.set(
                            CONTENT_TYPE,
                            if text_encoding.is_some() {
                                "text/html; charset=utf-8"
                            } else {
                                "image/webp"
                            },
                        );
                    }
                    if result_compression_algo != CompressionAlgo::Uncompressed {
                        parts.set(CONTENT_ENCODING, result_compression_algo.as_str());
                    } else {
                        parts.remove(CONTENT_ENCODING);
                    }

                    return Ok(parts.response_from_bytes(processed_bytes));
                }
            }
        }
    }
    Ok(parts.response_from_incoming(body_incoming))
}

async fn gracefull_shutdown_handler(
    req: Request<Incoming>,
    client: DefaultClient,
) -> Result<BoxedResponse, UnifiedError> {
    let ver = req.version();

    tokio::select! {
        _ = signal::ctrl_c() => Ok(Bytes::new().to_response(ver, StatusCode::SERVICE_UNAVAILABLE, "")),
        res = handler(req, client.clone()) => res,
    }
}

pub async fn run() -> Result<(), UnifiedError> {
    if let Some(dac_path) = &CLI.dac {
        DAC::init(dac_path)?;
    }
    let db = sled::Config::new()
        .cache_capacity(2 * 1024 * 1024)
        .path(BASE_DIRS.cache_dir().join(APP_NAME).join("certs_db"))
        .open()?;

    let proxy = MitmProxy::new(load_root_issuer()?, db);
    let client = DefaultClient::new();
    let service = TowerToHyperService::new(ResponseBodyTimeout::new(
        ServiceBuilder::new()
            .map_response(|mut res: BoxedResponse| {
                res.normalize_headers();
                res
            })
            .service_fn(move |req: Request<Incoming>| {
                gracefull_shutdown_handler(req, client.clone())
            }),
        Duration::from_secs(30),
    ));

    let server_bind_future = proxy.bind(&CLI.listen, service).await?;

    let (host, port) = &CLI.listen;
    tracing::info!(
        "
    HTTP Proxy is listening on http://{host}:{port}
    Trust this certificate in your browser/system to use HTTPS interception:
        Windows/Android: {}
        Other systems: {}
    Enable proxy http://{host}:{port} in your browser/system and go to http://mitm.it for detailed info.    
",
        CERT_PATHS.cert_cer_path.display(),
        CERT_PATHS.cert_pem_path.display(),
    );

    server_bind_future.await;

    tracing::info!("Server has been shut down.");
    Ok(())
}
