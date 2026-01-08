use std::{borrow::Cow, net::IpAddr, path::PathBuf};

use crate::{UnifiedError, initable_static};
use publicsuffix2::{List, MatchOpts, TypeFilter, options::RAW_NORMALIZER};

initable_static! {
    PS_LIST = |path:&Option<std::path::PathBuf>| -> Result<List, UnifiedError> {
        Ok(if let Some(p) = path {
            if p == &PathBuf::from("-") {
                List::parse(&std::io::read_to_string(std::io::stdin())?)?
            } else {
                List::from_file(p)?
            }
        } else {
            List::default()
        })
    };
}

const ETLD_OPTS_RAW: MatchOpts = MatchOpts {
    wildcard: false,
    normalizer: Some(&RAW_NORMALIZER),
    strict: false,
    types: TypeFilter::Any,
};

pub fn sld(host: &str) -> Option<Cow<'_, str>> {
    PS_LIST::get().sld(host, ETLD_OPTS_RAW)
}

pub struct AdblockFilter<'a> {
    pub domain: &'a str,
    pub sub_without_www: &'a str,
    pub etld_plus_2_without_www: Option<&'a str>,
    pub suffix: &'a str,
}

pub fn prepare_adblock_filter<'a>(mut content: &'a str) -> Option<AdblockFilter<'a>> {
    if content.is_empty() {
        return None;
    }
    content = match content.as_bytes()[0] {
        // h -> https://, http://
        b'h' => {
            if content.starts_with("https://") {
                &content[8..]
            } else if content.starts_with("http://") {
                &content[7..]
            } else {
                content
            }
        }
        // w -> wss://, ws://
        b'w' => {
            if content.starts_with("wss://") {
                &content[6..]
            } else if content.starts_with("ws://") {
                &content[5..]
            } else {
                content
            }
        }
        // / -> //
        b'/' => {
            if content.starts_with("//") {
                &content[2..]
            } else {
                content
            }
        }
        // : -> :// (правила без протокола)
        b':' => {
            if content.starts_with("://") {
                &content[3..]
            } else {
                content
            }
        }
        _ => content,
    };

    let (mut domain, suffix) = match content.find('/') {
        Some(pos) => (&content[..pos], &content[pos..]),
        None => (content, ""),
    };

    if let Some(at_pos) = domain.rfind('@') {
        domain = &domain[at_pos + 1..];
    }

    if !domain.contains(':') && domain.contains('.') && domain.parse::<IpAddr>().is_err() {
        if let Some(etld_plus1_raw) = PS_LIST::get().sld(domain, ETLD_OPTS_RAW) {
            let d_len = domain.len();
            let e1_len = etld_plus1_raw.len();
            let etld_plus1 = &domain[d_len - e1_len..]; // sld c RAW_NORMALIZER не изменит контент, поэтому вместо Cow лучше взять срез от исходных данных, так избежим проблем с борроу чекером

            let sub = domain[0..d_len - e1_len].trim_end_matches('.');

            let (sub_without_www, etld_plus_2_without_www) = if sub.is_empty() {
                (sub, None)
            } else if let Some(stripped) = sub.strip_suffix("www") {
                (stripped.trim_end_matches('.'), Some(etld_plus1))
            } else {
                let e2_start = match domain[..sub.len()].rfind('.') {
                    Some(pos) => pos + 1,
                    None => 0,
                };
                (sub, Some(&domain[e2_start..]))
            };

            return Some(AdblockFilter {
                domain,
                sub_without_www,
                etld_plus_2_without_www,
                suffix,
            });
        }
    }

    None
}
