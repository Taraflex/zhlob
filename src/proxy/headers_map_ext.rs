use bytes::Bytes;
use easy_ext::ext;
use encoding_rs::Encoding;
use hyper::{
    HeaderMap,
    header::{
        ACCEPT_RANGES, AsHeaderName, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, DATE,
        ETAG, EXPIRES, HeaderValue, IntoHeaderName, VARY,
    },
};
use std::{str::FromStr, time::SystemTime};

use crate::cli::CLI;

#[macro_export]
macro_rules! in_headers {
    ($headers:expr, $name:expr, $($tokens:tt)+) => {
        $headers.get_all($name).iter().any(|v| {
            // Trim once here for performance
            let s = v.as_bytes().trim_ascii();
            $crate::in_headers!(@inner s, $($tokens)+)
        })
    };

    // --- RECURSIVE CASES ---

    (@inner $s:ident, * $val:literal * | $($tail:tt)+) => {
        $crate::in_headers!(@logic $s, contains, $val) || $crate::in_headers!(@inner $s, $($tail)+)
    };
    (@inner $s:ident, * $val:literal | $($tail:tt)+) => {
        $crate::in_headers!(@logic $s, ends, $val) || $crate::in_headers!(@inner $s, $($tail)+)
    };
    (@inner $s:ident, $val:literal * | $($tail:tt)+) => {
        $crate::in_headers!(@logic $s, starts, $val) || $crate::in_headers!(@inner $s, $($tail)+)
    };
    (@inner $s:ident, $val:literal | $($tail:tt)+) => {
        $crate::in_headers!(@logic $s, eq, $val) || $crate::in_headers!(@inner $s, $($tail)+)
    };

    // --- BASE CASES ---

    (@inner $s:ident, * $val:literal *) => {
        $crate::in_headers!(@logic $s, contains, $val)
    };
    (@inner $s:ident, * $val:literal) => {
        $crate::in_headers!(@logic $s, ends, $val)
    };
    (@inner $s:ident, $val:literal *) => {
        $crate::in_headers!(@logic $s, starts, $val)
    };
    (@inner $s:ident, $val:literal) => {
        $crate::in_headers!(@logic $s, eq, $val)
    };

    // --- CHECK LOGIC ---

    (@logic $s:ident, contains, $val:literal) => {{
        let n = $val.as_bytes();
        n.is_empty() || $s.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
    }};

    (@logic $s:ident, ends, $val:literal) => {{
        let n = $val.as_bytes();
        $s.len() >= n.len() && $s[$s.len() - n.len()..].eq_ignore_ascii_case(n)
    }};

    (@logic $s:ident, starts, $val:literal) => {{
        let n = $val.as_bytes();
        $s.len() >= n.len() && $s[..n.len()].eq_ignore_ascii_case(n)
    }};

    (@logic $s:ident, eq, $val:literal) => {
        $s.eq_ignore_ascii_case($val.as_bytes())
    };
}
#[ext(HeaderMapExt)]
pub impl HeaderMap<HeaderValue> {
    fn set<K: IntoHeaderName>(&mut self, key: K, val: &'static str) {
        self.insert(key, HeaderValue::from_static(val));
    }

    fn set_unchecked<K, V>(&mut self, key: K, val: V)
    where
        K: IntoHeaderName,
        V: Into<Bytes>,
    {
        unsafe {
            let bytes = val.into();
            self.insert(key, HeaderValue::from_maybe_shared_unchecked(bytes));
        }
    }

    fn get_safe<K: AsHeaderName>(&self, key: K) -> String {
        let mut iter = self
            .get_all(key)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(','))
            .map(|s| s.as_bytes().trim_ascii())
            .filter(|b| !b.is_empty());

        let first_bytes = match iter.next() {
            Some(b) => b,
            None => return String::new(),
        };

        let mut result = unsafe { std::str::from_utf8_unchecked(first_bytes).to_owned() };

        for part_bytes in iter {
            result.push_str(", ");
            result.push_str(unsafe { std::str::from_utf8_unchecked(part_bytes) });
        }

        result.make_ascii_lowercase();
        result
    }

    fn get_as<T, K>(&self, key: K) -> T
    where
        T: FromStr + Default,
        K: AsHeaderName,
    {
        self.get(key)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim_ascii().parse().ok())
            .unwrap_or_default()
    }

    fn normalize_extra_for_patched_content(&mut self, change_etag_tag: bool) {
        // Ослабляем ETag: если он есть и не начинается с W/, добавляем префикс
        if change_etag_tag || (self.contains_key(ETAG) && !in_headers!(self, ETAG, "W/"*)) {
            let etag = self
                .get(ETAG)
                .and_then(|e| e.to_str().ok())
                .map(|e| e.trim_ascii().trim_start_matches("W/").trim_matches('"'))
                .unwrap_or("");

            self.set_unchecked(
                ETAG,
                if change_etag_tag {
                    format!("W/\"zhlob-{}\"", etag)
                } else {
                    format!("W/\"{}\"", etag)
                },
            );
        }
        //из-за неоднозначности порядка применения (до TRANSFER_ENCODING: gzip, но после CONTENT_ENCODING: gzip) лучше удалить Content-MD5, так как может быть инвалидирован даже без смены алгоритма сжатия, из-за строгого переноса алгоритма сжатия в CONTENT_ENCODING
        self.remove("Content-MD5");
        self.remove(ACCEPT_RANGES);

        let vary = self.get_safe(VARY);
        if vary.is_empty() {
            self.set(VARY, "accept-encoding");
        } else if !vary.contains("accept-encoding") {
            self.set_unchecked(VARY, format!("accept-encoding, {vary}"));
        }

        // fix CACHE_CONTROL: remove immutability, limit max-age, stale-while-revalidate
        let vis = if in_headers!(self, CACHE_CONTROL, *"private"*) {
            "private"
        } else {
            "public"
        };

        let final_cc = if in_headers!(self, CACHE_CONTROL, *"no-store"*) {
            "no-store".into()
        } else if in_headers!(self, CACHE_CONTROL, *"no-cache"*) {
            format!("{vis}, no-cache")
        } else {
            let mut age = self
                .get_all(CACHE_CONTROL)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .find_map(|p| p.trim_ascii().strip_prefix("max-age="))
                .and_then(|v| v.parse::<i64>().ok());

            let server_date = httpdate::parse_http_date(&self.get_safe(DATE))
                .unwrap_or_else(|_| SystemTime::now());

            if age.is_none() {
                if let Ok(expires_date) = httpdate::parse_http_date(&self.get_safe(EXPIRES)) {
                    age = Some(
                        expires_date
                            .duration_since(server_date)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(-1),
                    )
                }
            }

            let cache_max_age = CLI.cache_max_age as i64;

            let age = if let Some(a) = age { a } else { cache_max_age };

            if age < 0 {
                format!("{vis}, no-cache")
            } else {
                self.set_unchecked(DATE, httpdate::fmt_http_date(server_date));
                format!(
                    "{vis}, max-age={}, must-revalidate, stale-while-revalidate=604800",
                    age.min(cache_max_age)
                )
            }
        };
        self.remove(EXPIRES);
        self.set_unchecked(CACHE_CONTROL, final_cc);
    }

    fn extract_encoding(&self) -> &'static Encoding {
        let label = self
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .and_then(|ct| {
                ct.split(';').find_map(|p| {
                    let (key, val) = p.split_once('=')?;
                    if key.trim_ascii().eq_ignore_ascii_case("charset") {
                        match val.trim_matches(['"', '\'', ' ', '\r', '\n', '\t', '\x0C', '\x0B']) {
                            "" => None,
                            v => Some(v),
                        }
                    } else {
                        None
                    }
                })
            })
            .unwrap_or("utf-8");

        Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::UTF_8)
    }

    fn csp_allow_inline_js_in_attrs(&self) -> bool {
        #[derive(PartialOrd, Ord, Eq, PartialEq, Clone, Copy)]
        enum CspPriority {
            DefaultSrc = 1,
            ScriptSrc = 2,
            ScriptSrcAttr = 3,
        }

        const DIR_ATTR: &str = "script-src-attr";
        const DIR_SCRIPT: &str = "script-src";
        const DIR_DEFAULT: &str = "default-src";

        for val in self.get_all(CONTENT_SECURITY_POLICY) {
            let Ok(s) = val.to_str() else { continue };

            let best_directive = s
                .split(';')
                .map(str::trim_ascii)
                .filter_map(|p| {
                    if p.starts_with(DIR_ATTR) {
                        Some((CspPriority::ScriptSrcAttr, &p[DIR_ATTR.len()..]))
                    } else if p.starts_with(DIR_SCRIPT) {
                        Some((CspPriority::ScriptSrc, &p[DIR_SCRIPT.len()..]))
                    } else if p.starts_with(DIR_DEFAULT) {
                        Some((CspPriority::DefaultSrc, &p[DIR_DEFAULT.len()..]))
                    } else {
                        None
                    }
                })
                .max_by_key(|(prio, _)| *prio);

            if let Some((_, content)) = best_directive {
                let mut has_unsafe_inline = false;

                for word in content.split_ascii_whitespace() {
                    if word.len() < 7 {
                        continue;
                    }

                    match &word[..7] {
                        "'unsafe" => {
                            if word == "'unsafe-inline'" {
                                has_unsafe_inline = true;
                            }
                        }
                        "'strict" => {
                            if word == "'strict-dynamic'" {
                                return false;
                            }
                        }
                        "'nonce-" | "'sha256" | "'sha384" | "'sha512" => return false,
                        _ => {}
                    }
                }

                if !has_unsafe_inline {
                    return false;
                }
            }
        }

        true
    }
}
