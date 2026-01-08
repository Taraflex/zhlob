use bytes::Bytes;
use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};
use http_mitm_proxy::hyper::{
    HeaderMap,
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, TRANSFER_ENCODING},
};
use std::io::{Read, Write};

use crate::{in_headers, maybe};

#[derive(PartialEq, Clone, Copy)]
pub enum CompressionAlgo {
    Uncompressed,
    Brotli,
    Gzip,
    Deflate,
}

impl CompressionAlgo {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uncompressed => "identity",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    pub fn create_decompressor<'a>(&self, bytes: &'a [u8]) -> Box<dyn Read + 'a> {
        match self {
            CompressionAlgo::Brotli => Box::new(brotli::Decompressor::new(bytes, 4096)),
            CompressionAlgo::Gzip => Box::new(flate2::bufread::GzDecoder::new(bytes)),
            CompressionAlgo::Deflate => Box::new(flate2::bufread::ZlibDecoder::new(bytes)),
            _ => Box::new(bytes),
        }
    }

    pub fn try_compress(self, html: String) -> (CompressionAlgo, Bytes) {
        let raw = html.into_bytes();
        let original_len = raw.len();

        if original_len > 32 {
            let mut compressed = Vec::with_capacity(original_len / 2);

            let result = match self {
                CompressionAlgo::Brotli => {
                    // 10 - 2404 / 9 - 2775 / 8 - 2782 / 6 - 2784 / 5 - 2788 / 4 - 3002 / 3 - 3356
                    let mut w = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 20);
                    maybe! {
                        w.write_all(&raw)?;
                        w.flush()?;
                        (self, 21 /*"Content-Encoding: br\r\n"*/)
                    }
                }
                CompressionAlgo::Gzip => {
                    // 9 - 2841 / 8 - 2864 / 7 - 2865 / 6 - 2876 / 5 - 2881 / 4 - 2902 / 3 - 2958
                    let mut w = GzEncoder::new(&mut compressed, Compression::new(4));
                    maybe! {
                        w.write_all(&raw)?;
                        w.finish()?;
                        (self, 23 /*"Content-Encoding: gzip\r\n"*/)
                    }
                }
                CompressionAlgo::Deflate => {
                    let mut w = ZlibEncoder::new(&mut compressed, Compression::new(4));
                    maybe! {
                        w.write_all(&raw)?;
                        w.finish()?;
                        (self, 26 /*"Content-Encoding: deflate\r\n"*/)
                    }
                }
                _ => None,
            };

            if let Some((algo, overhead)) = result {
                if compressed.len() + overhead < original_len {
                    return (algo, Bytes::from(compressed));
                }
            }
        }

        (CompressionAlgo::Uncompressed, Bytes::from(raw))
    }

    pub fn from_req_headers(headers: &HeaderMap) -> Self {
        if in_headers!(headers, ACCEPT_ENCODING, *"br"*) {
            CompressionAlgo::Brotli
        } else if in_headers!(headers, ACCEPT_ENCODING, *"gzip"*) {
            CompressionAlgo::Gzip
        } else if in_headers!(headers, ACCEPT_ENCODING, *"deflate"*) {
            CompressionAlgo::Deflate
        } else {
            CompressionAlgo::Uncompressed
        }
    }

    pub fn from_resp_headers(headers: &HeaderMap) -> Option<Self> {
        let mut algo = None;

        for name in [TRANSFER_ENCODING, CONTENT_ENCODING] {
            for val in headers.get_all(name) {
                let s = val.to_str().ok()?;
                for part in s.split(',') {
                    let token = part.trim_ascii().to_ascii_lowercase();
                    if token.is_empty() || token == "chunked" || token == "identity" {
                        continue;
                    }

                    if algo.is_some() {
                        return None;
                    }

                    algo = match token.as_ref() {
                        "br" => Some(CompressionAlgo::Brotli),
                        "gzip" => Some(CompressionAlgo::Gzip),
                        "deflate" => Some(CompressionAlgo::Deflate),
                        _ => return None, // Неизвестный алгоритм — сразу вернем None
                    };
                }
            }
        }

        Some(algo.unwrap_or(CompressionAlgo::Uncompressed))
    }
}
