use crate::{
    dac::{self, UrlBaseInfo, psl},
    initable_static, maybe,
    resettable_lazy::ResettableLazy,
};
use fastvec::FastVec;
use lol_html::{RewriteStrSettings, comments, element, rewrite_str};
use memchr::memmem::Finder;
use std::cell::RefCell;
use url::Url;

initable_static! {
    FINDER_LOWER: Finder<'static> =|| { Finder::new(b"</script") };
    FINDER_UPPER: Finder<'static> = || { Finder::new(b"</SCRIPT") };
}

pub fn minify<'a>(html: String, csp_allow_inline_js_in_attrs: bool, uri: &'a str) -> String {
    let base_info: RefCell<Option<String>> = None.into();
    let etld_1_info = ResettableLazy::new(|| -> Option<UrlBaseInfo> {
        let url = Url::parse(&uri).ok()?;
        let host = url.host_str()?;

        Some(UrlBaseInfo {
            etld_plus1: psl::sld(host)?.to_string(),
            base: url
                .join(base_info.borrow().as_deref().unwrap_or("./"))
                .unwrap_or(url),
        })
    });

    macro_rules! drop_attrs_except {
        ($el:ident) => {
            let attrs: FastVec<String, 8> = $el.attributes().iter().map(|a| a.name()).collect();
            for attr in attrs {
                $el.remove_attribute(&attr);
            }
        };
        ($el:ident, $pattern:pat) => {
            let attrs: FastVec<String, 8> = $el
                .attributes()
                .iter()
                .filter_map(|a| {
                    if !matches!(a.name_raw(), $pattern) {
                        Some(a.name())
                    } else {
                        None
                    }
                })
                .collect();
            for attr in attrs {
                $el.remove_attribute(&attr);
            }
        };
    }
    let source_bytes: &[u8] = html.as_ref();
    let settings = RewriteStrSettings {
        element_content_handlers: vec![
            element!("base", |el| {
                if base_info.borrow().is_none() {
                    base_info.replace(el.get_attribute("href").or_else(|| Some("./".to_string())));
                    etld_1_info.reset();
                }
                Ok(())
            }),
            element!("meta", |el| {
                let name = el.get_attribute("name");
                let keep = match name.as_deref().unwrap_or("") {
                    "theme-color" => el.has_attribute("media") || el.has_attribute("content"),
                    "referrer" | "viewport" => el.has_attribute("content"),
                    _ => {
                        let equiv = el.get_attribute("http-equiv");
                        let is_forbidden_or_empty_equiv = equiv
                            .as_deref()
                            .map(|e| {
                                e.eq_ignore_ascii_case("X-UA-Compatible")
                                    || e.eq_ignore_ascii_case("Content-Type")
                            })
                            .unwrap_or(true);
                        !is_forbidden_or_empty_equiv && el.has_attribute("content")
                    }
                };

                if keep {
                    drop_attrs_except!(el, b"http-equiv" | b"content" | b"name" | b"media");
                } else {
                    el.remove();
                }
                Ok(())
            }),
            element!("link", move |el| {
                let rel = el.get_attribute("rel").unwrap_or_default();

                if rel.contains("alternate") {
                    el.remove();
                    return Ok(());
                }

                let is_style = rel.contains("stylesheet");
                let like_style =
                    rel == "preload" && el.get_attribute("as").as_deref() == Some("style");

                if rel == "manifest" || like_style || is_style {
                    if !like_style || !csp_allow_inline_js_in_attrs {
                        // на rel="preload" могут висеть js события, их все не перечислить, поэтому не чистим rel="preload"
                        drop_attrs_except!(
                            el,
                            b"rel"
                                | b"href"
                                | b"media"
                                | b"integrity"
                                | b"crossorigin"
                                | b"referrerpolicy"
                                | b"disabled"
                        );
                    }
                    if csp_allow_inline_js_in_attrs && is_style && !el.has_attribute("disabled") {
                        el.set_attribute("rel", "preload")?;
                        el.set_attribute("as", "style")?;
                        el.set_attribute("onload", "this.rel='stylesheet'")?;
                    }
                    let _ = el.set_attribute("fetchpriority", "low");
                } else {
                    el.remove();
                }

                Ok(())
            }),
            element!("script", |el| {
                if let Some(src) = el.attributes().iter().find_map(|attr| {
                    if attr.name_raw() == b"src" {
                        Some(attr.value_raw())
                    } else {
                        None
                    }
                }) {
                    if dac::is_match_src(src, &etld_1_info) {
                        el.remove();
                    }
                } else {
                    let tag_location = el.source_location().bytes();
                    let content_started_at = tag_location.end;

                    if !source_bytes[tag_location].ends_with(b"/>") {
                        let search_area = &source_bytes
                            [content_started_at..source_bytes.len().min(content_started_at + 4096)];
                        let found_offset = FINDER_LOWER
                            .find(search_area)
                            .or_else(|| FINDER_UPPER.find(search_area));

                        if let Some(offset) = found_offset {
                            if dac::is_match_code(&search_area[..offset], &etld_1_info) {
                                el.remove();
                            }
                        }
                    }
                }
                Ok(())
            }),
            element!("table[summary]", |el| {
                el.remove_attribute("summary");
                Ok(())
            }),
            element!("img[decoding]", |el| {
                el.remove_attribute("decoding"); // мы уже радикально жмем картинки
                Ok(())
            }),
            element!("img[loading='eager'], iframe[loading='eager']", |el| {
                el.remove_attribute("loading");
                Ok(())
            }),
            element!("img[srcset]", |el| {
                if let Some(srcset) = el.get_attribute("srcset") {
                    let smallest_url = srcset
                        .split(',')
                        .filter_map(|part| {
                            let mut iter = part.trim_ascii().split_ascii_whitespace();
                            let url = iter.next()?;
                            let descriptor = iter.next();

                            maybe! {
                                let weight = match descriptor {
                                    Some(d) if d.ends_with('w') => d[..d.len() - 1].parse::<u32>()?,
                                    Some(d) if d.ends_with('x') => (d[..d.len() - 1].parse::<f32>()? * 10000.0) as u32,
                                    _ => u32::MAX - 1,
                                };
                                (url, weight)
                            }
                        })
                        .min_by_key(|&(_, weight)| weight)
                        .map(|(url, _)| url);

                    if let Some(url) = smallest_url {
                        let _ = el.set_attribute("src", url);
                    }
                }

                el.remove_attribute("srcset");
                el.remove_attribute("sizes");
                Ok(())
            }),
            element!("a", |el| {
                // Используем битовую маску вместо StackVec.
                // bit 0 (1): ping
                // bit 1 (2): type
                // bit 2 (4): hreflang
                let mut to_remove_mask = 0u8;

                let mut new_href: Option<String> = None;
                let mut new_rel: Option<String> = None;

                for attr in el.attributes().iter() {
                    let name_raw = attr.name_raw();
                    match name_raw {
                        b"href" => {
                            let val = attr.value();
                            if let Some(q_pos) = val.find('?') {
                                let base = &val[..q_pos];
                                let rest = &val[q_pos + 1..];
                                let (query, anchor) = match rest.find('#') {
                                    Some(h_pos) => (&rest[..h_pos], &rest[h_pos..]),
                                    None => (rest, ""),
                                };

                                let mut filtered = String::with_capacity(val.len());
                                let mut first = true;

                                for pair in query.split('&') {
                                    if pair.is_empty() {
                                        continue;
                                    }
                                    let key_end = pair.find('=').unwrap_or(pair.len());
                                    let key = &pair.as_bytes()[..key_end];

                                    let keep = if key.len() < 3 {
                                        !key.is_empty()
                                    } else {
                                        match &key[..3] {
                                            b"utm" => {
                                                !(key.starts_with(b"utm_")
                                                    || key.starts_with(b"utm-"))
                                            }
                                            b"fbc" => !key.starts_with(b"fbclid"),
                                            b"gcl" => !key.starts_with(b"gclid"),
                                            b"ycl" => !key.starts_with(b"yclid"),
                                            b"ysc" => !key.starts_with(b"ysclid"),
                                            b"_ga" | b"_gl" => false,
                                            b"_op" => !key.starts_with(b"_openstat"),
                                            b"rb_" => !key.starts_with(b"rb_clickid"),
                                            _ => true,
                                        }
                                    };

                                    if keep {
                                        if !first {
                                            filtered.push('&');
                                        }
                                        filtered.push_str(pair);
                                        first = false;
                                    }
                                }

                                let mut final_url = String::with_capacity(
                                    base.len() + filtered.len() + anchor.len() + 1,
                                );
                                final_url.push_str(base);
                                if !filtered.is_empty() {
                                    final_url.push('?');
                                    final_url.push_str(&filtered);
                                }
                                final_url.push_str(anchor);
                                new_href = Some(final_url);
                            }
                        }
                        b"rel" => {
                            let val = attr.value();
                            let mut filtered = String::with_capacity(val.len());
                            let mut first = true;
                            for part in val.split_ascii_whitespace() {
                                if part.starts_with("no") {
                                    if !first {
                                        filtered.push(' ');
                                    }
                                    filtered.push_str(part);
                                    first = false;
                                }
                            }
                            new_rel = Some(filtered);
                        }
                        // Применяем формулу: (s[0] >> 2) & 3
                        // p (112) -> 0, t (116) -> 1, h (104) -> 2
                        b"ping" | b"type" | b"hreflang" => {
                            to_remove_mask |= 1 << ((name_raw[0] >> 2) & 3);
                        }
                        _ => {}
                    }
                }

                if let Some(h) = new_href {
                    el.set_attribute("href", &h)?;
                }
                if let Some(r) = new_rel {
                    if r.is_empty() {
                        el.remove_attribute("rel");
                    } else {
                        el.set_attribute("rel", &r)?;
                    }
                }
                if to_remove_mask & 1 != 0 {
                    el.remove_attribute("ping");
                }
                if to_remove_mask & 2 != 0 {
                    el.remove_attribute("type");
                }
                if to_remove_mask & 4 != 0 {
                    el.remove_attribute("hreflang");
                }

                Ok(())
            }),
            element!("noscript, script[type='application/ld+json']", |el| {
                el.remove();
                Ok(())
            }),
            element!(
                "script[type='text/javascript'], style[type='text/css'], link[type='text/css']",
                |el| {
                    if !el.removed() {
                        el.remove_attribute("type");
                    }
                    Ok(())
                }
            ),
            element!("*", |el| {
                if !el.removed() {
                    let to_remove: FastVec<String, 4> = el
                        .attributes()
                        .iter()
                        .filter_map(|a| {
                            if a.name_raw().starts_with(b"aria-") {
                                Some(a.name())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for attr in to_remove {
                        el.remove_attribute(&attr);
                    }
                    el.remove_attribute("itemprop");
                    el.remove_attribute("itemscope");
                    el.remove_attribute("itemtype");
                    el.remove_attribute("role");
                }
                Ok(())
            }),
            comments!("*", |c| {
                c.remove();
                Ok(())
            }),
        ],
        ..Default::default()
    };
    rewrite_str(&html, settings).unwrap_or(html)
}
