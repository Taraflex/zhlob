use crate::{cli::CLI, dac::DAC};
use bytes::Bytes;
use easy_ext::ext;
use encoding_rs::Encoding;
use hyper::{
    HeaderMap,
    header::{
        ACCEPT_RANGES, AsHeaderName, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, DATE,
        ETAG, EXPIRES, HeaderValue, IF_MATCH, IF_NONE_MATCH, IntoHeaderName, VARY,
    },
};
use std::{str::FromStr, time::SystemTime};

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

    fn inject_etag_marker(&mut self) {
        if let Some(value) = self.get(ETAG) {
            let marker = DAC
                .get()
                .map(|(etag_marker, _)| etag_marker.as_bytes())
                .unwrap_or("zhlob~~".as_bytes());

            let etag = value.as_bytes();
            let mut new_etag = Vec::with_capacity(etag.len() + marker.len());

            let mut pos = 0;
            if etag.starts_with(b"W/") {
                new_etag.extend_from_slice(b"W/");
                pos = 2;
            }
            if pos < etag.len() && etag[pos] == b'"' {
                new_etag.push(b'"');
                pos += 1;
            }
            new_etag.extend_from_slice(marker);
            if pos < etag.len() {
                new_etag.extend_from_slice(&etag[pos..]);
            }
            self.set_unchecked(ETAG, new_etag);
        }
    }

    fn strip_etag_marker(&mut self) {
        for name in [IF_MATCH, IF_NONE_MATCH] {
            let mut changed = false;
            let mut out = Vec::new();

            for val in self.get_all(&name) {
                let b = val.as_bytes();
                let mut i = 0;
                let mut last_copy_pos = 0;

                while i < b.len() {
                    // 1. Пропускаем разделители
                    while i < b.len() && (b[i] == b',' || b[i].is_ascii_whitespace()) {
                        i += 1;
                    }

                    // 2. Определяем префикс
                    let prefix_len = if b[i..].starts_with(b"W/\"") {
                        3
                    } else if b[i..].starts_with(b"W/") {
                        2
                    } else if b[i..].starts_with(b"\"") {
                        1
                    } else {
                        0
                    };

                    i += prefix_len;

                    // 3. Поиск и вырезание маркера
                    if i < b.len() && b[i..].starts_with(b"zhlob~") {
                        if let Some(pos) = b[i + 6..].iter().position(|&x| x == b'~') {
                            // Сбрасываем накопленный кусок до начала маркера
                            if i > last_copy_pos {
                                out.extend_from_slice(&b[last_copy_pos..i]);
                            }
                            i += 6 + pos + 1;
                            last_copy_pos = i;
                            changed = true;
                        }
                    }

                    // 4. Пропуск тела ETag до следующего разделителя
                    // i >= 1 гарантировано условием prefix_len > 0
                    let mut in_quotes = prefix_len > 0 && b[i - 1] == b'"';
                    while i < b.len() {
                        if b[i] == b'"' {
                            in_quotes = !in_quotes;
                        }
                        if b[i] == b',' && !in_quotes {
                            break;
                        }
                        i += 1;
                    }
                }

                // Копируем остаток текущего заголовка
                if last_copy_pos < b.len() {
                    out.extend_from_slice(&b[last_copy_pos..]);
                }
                out.extend_from_slice(b", ");
            }

            if changed {
                // Если мы здесь, значит out точно не пуст
                out.truncate(out.len() - 2);
                self.set_unchecked(name, out);
            }
        }
    }

    fn normalize_extra_for_patched_content(&mut self) {
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
