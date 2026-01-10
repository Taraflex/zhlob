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

const fn mix_version_into_hash(body_hash: u64) -> u64 {
    const APP_HASH: u64 =
        xxhash_rust::const_xxh3::xxh3_64_with_seed(env!("CARGO_PKG_VERSION").as_bytes(), 0);

    body_hash
        ^ (APP_HASH
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(body_hash << 6)
            .wrapping_add(body_hash >> 2))
}

initable_static! {
    DAC = |path: &PathBuf| -> Result<(String, DoubleArrayAhoCorasick<u32>), maybe::UnifiedError> {
        let file = File::open(path)?;
        unsafe {
            let mmap = Mmap::map(&file)?;
            if mmap.len() < 20 {
                return Err("DAC file too short".into());
            }
            if !mmap[0..4].eq(&[b'D', b'A', b'C', 1]) {
                return Err("Invalid DAC file format version".into());
            }
            let h3 = mix_version_into_hash(u64::from_le_bytes(mmap[4..12].try_into()?));
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

            Ok((format!("zhlob~{}~", URL_SAFE_NO_PAD.encode(h3.to_le_bytes())), DoubleArrayAhoCorasick::<u32>::deserialize_unchecked(&mmap[12..]).0))
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
    if let Some((_, dac)) = DAC.get() {
        unsafe {
            println!("{}", str::from_utf8_unchecked(src));
        }
        //todo check join with url without protocols like //google.com
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
                            println!(
                                "blocked by rule: {:?} {}",
                                p,
                                src[m.start()..m.end()].to_string()
                            );
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
