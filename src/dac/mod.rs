use crate::{
    dac::pattern_type::PatternType, initable_static, maybe,
    processors::js_urls_iterator::JsUrlsIterator, resettable_lazy::ResettableLazy,
};
use daachorse::DoubleArrayAhoCorasick;
use memmap2::Mmap;
use std::{fs::File, path::PathBuf};
use url::{Host, Url};

pub mod generate;
pub mod pattern_type;
pub mod patterns_map;
pub mod psl;

initable_static! {
    DAC = |path: &PathBuf| -> Result<DoubleArrayAhoCorasick<u32>, maybe::UnifiedError> {
        let file = File::open(path)?;
        unsafe {
            let mmap = Mmap::map(&file)?;
            Ok(DoubleArrayAhoCorasick::<u32>::deserialize_unchecked(&mmap).0)
        }
    }
}

pub fn is_match_code(code: &[u8], etld_1_info: &ResettableLazy<'_, Option<UrlBaseInfo>>) -> bool {
    if DAC.get().is_some() {
        for str in JsUrlsIterator::new(code) {
            if is_match_src(str, etld_1_info) {
                return true;
            }
        }
    }
    false
}

fn is_subdomain_or_equal(host: &str, etld_plus1: &str) -> bool {
    host.len() >= etld_plus1.len()
        && host[host.len() - etld_plus1.len()..].eq_ignore_ascii_case(etld_plus1)
        && (host.len() == etld_plus1.len()
            || host.as_bytes()[host.len() - etld_plus1.len() - 1] == b'.')
}

#[derive(Clone)]
pub struct UrlBaseInfo {
    pub etld_plus1: String,
    pub base: Url,
}

pub fn is_match_src<'a>(
    src: &'a [u8],
    etld_1_info: &ResettableLazy<'_, Option<UrlBaseInfo>>,
) -> bool {
    if let Some(dac) = DAC.get() {
        if let Some(url_info) = etld_1_info.get() {
            let Some(url) = maybe!(url_info.base.join(str::from_utf8(src)?)?) else {
                return false;
            };
            let Some(host) = url.host() else {
                return false;
            };
            match host {
                Host::Domain(host) => {
                    let src = url.as_str().to_ascii_lowercase();

                    for m in dac.find_overlapping_iter(&src) {
                        let p = PatternType::from(m.value());
                        if p.is_match(&src, m.start())
                            && (!p.is_third_party()
                                || !is_subdomain_or_equal(host, &url_info.etld_plus1))
                        {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}
