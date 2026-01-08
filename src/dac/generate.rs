use crate::{
    cli::Commands,
    dac::{
        pattern_type::PatternType,
        patterns_map::{INNER_SUBDOMAIN_BLACKLIST, PatternsMap},
        psl::prepare_adblock_filter,
    },
    maybe::UnifiedError,
};
use daachorse::DoubleArrayAhoCorasick;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

fn is_valid_domain_part_with_dot(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    if n < 2 || b[n - 1] != b'.' {
        return false;
    }
    for &c in &b[..n - 1] {
        let is_alphanum = (c.wrapping_sub(b'0') < 10) | ((c | 0x20).wrapping_sub(b'a') < 26);
        if !(is_alphanum | (c == b'-')) {
            return false;
        }
    }
    b[0] != b'-' && b[n - 2] != b'-'
}

fn is_valid_script_rule(options: &str) -> Option<bool> {
    let mut has_positive_types = false;
    let mut script_allowed = false;

    let mut get_allowed = false;
    let mut has_positive_methods = false;

    let mut has_third_party = false;

    for opt in options.split(',').map(str::trim_ascii) {
        if opt.is_empty() {
            continue;
        }

        let (key, value) = match opt.find('=') {
            Some(pos) => (opt[..pos].to_ascii_lowercase(), Some(&opt[pos + 1..])),
            None => (opt.to_ascii_lowercase(), None),
        };

        match key.as_ref() {
            "~script"
            | "~all"
            | "badfilter"
            | "~third-party"
            | "~3p"
            | "~strict3p"
            | "~strict-third-party"
            | "first-party"
            | "1p"
            | "strict1p"
            | "strict-first-party"
            | "denyallow"
            | "to"
            | "header"
            | "inline-script"
            | "inline-font"
            | "ipaddress"
            | "permissions"
            | "csp"
            | "removeparam"
            | "redirect"
            | "empty"
            | "mp4"
            | "redirect-rule"
            | "urlskip"
            | "replace"
            | "urltransform"
            | "cookie"
            | "popup"
            | "popunder"
            | "match-case" => return None,
            "domain" | "from" => {
                if let Some(v) = value {
                    if !v.is_empty()
                        && v.split('|')
                            .map(str::trim_ascii)
                            .any(|d| !d.is_empty() && !d.starts_with('~'))
                    {
                        return None;
                    }
                }
                continue;
            }
            "method" => {
                if let Some(v) = value {
                    if v.is_empty() {
                        continue;
                    }

                    for m in v.split('|').map(str::trim_ascii) {
                        if m.is_empty() {
                            continue;
                        }

                        let is_inv = m.starts_with('~');
                        let m_name = if is_inv { &m[1..] } else { m };

                        if m_name.eq_ignore_ascii_case("get") {
                            if is_inv {
                                return None;
                            } else {
                                get_allowed = true;
                            }
                        }
                        if !is_inv {
                            has_positive_methods = true;
                        }
                    }
                }
                continue;
            }
            "third-party" | "3p" | "strict3p" | "strict-third-party" => has_third_party = true,
            "script" | "all" => {
                has_positive_types = true;
                script_allowed = true;
            }
            "image" | "css" | "stylesheet" | "frame" | "subdocument" | "document" | "media"
            | "font" | "ping" | "websocket" | "other" | "object" | "webrtc" | "csp_report"
            | "xmlhttprequest" | "xhr" => has_positive_types = true,
            _ => {}
        }
    }
    if has_positive_types && !script_allowed {
        return None;
    }
    if has_positive_methods && !get_allowed {
        return None;
    }
    Some(has_third_party)
}

pub fn run(args: &Commands) -> Result<(), UnifiedError> {
    match args {
        Commands::Dacgen { dump, inputs, dac } => {
            let dash_path = PathBuf::from("-");

            let mut patterns: BTreeMap<String, u32> = BTreeMap::new();

            for input in inputs {
                let reader: Box<dyn BufRead> = if *input == dash_path {
                    Box::new(BufReader::new(io::stdin()))
                } else {
                    Box::new(BufReader::new(File::open(input)?))
                };

                for line_raw in reader.lines() {
                    let line_raw_trimmed = line_raw?;
                    let mut line = line_raw_trimmed.trim_ascii();

                    if line.is_empty()
                        || line.starts_with('!')
                        || line.starts_with('[')
                        || line.starts_with("@@")
                        || line.contains("##")
                        || line.contains("#@#")
                        || line.contains("#?#")
                    {
                        continue;
                    }

                    let mut third_party = false;
                    //ищем из конца в начало до $ или / , но отрезаем только часть после $ включительно
                    if let Some(pos) = line.rfind(|c: char| c == '/' || c == '$') {
                        if line.as_bytes()[pos] == b'$' {
                            if pos < 1 {
                                continue;
                            }
                            let Some(_third_party) = is_valid_script_rule(&line[pos + 1..]) else {
                                continue;
                            };
                            third_party = _third_party;
                            line = &line[..pos]
                        }
                    }

                    // drop types:
                    // - /regexp/
                    // - ends_with|
                    if (line.ends_with('/') && line.starts_with('/')) || line.ends_with('|') {
                        continue;
                    }

                    let mut exist_caret_at_end = false;
                    loop {
                        if line.ends_with('^') {
                            exist_caret_at_end = true;
                        } else if !line.ends_with('*') {
                            break;
                        }
                        line = &line[..line.len() - 1];
                    }

                    if line.is_empty() || line.contains('*') /* '*' is supported only at end */ || line.contains('^')
                    /* в easylist есть ошибки в фильтрах, поэтому если '^' все еще присутсвует, то это битое правило */ || !line.is_ascii()
                    {
                        continue;
                    }

                    if let Some(substr) = line.strip_prefix("://") {
                        if is_valid_domain_part_with_dot(substr) {
                            unsafe {
                                #[allow(static_mut_refs)]
                                INNER_SUBDOMAIN_BLACKLIST
                                    .insert(substr[0..substr.len() - 1].to_string());
                            }
                            patterns.add_pattern(
                                PatternType::AnyDomainPartBeforeETLD,
                                substr.to_string(),
                            );
                        } else {
                            patterns.add_pattern(
                                PatternType::SlashedStart.with_third_party(third_party),
                                line[1..].to_string(),
                            );
                        }
                    } else if line.starts_with('|') {
                        // Обработка якорей | и ||
                        let (content, domain_starts_with) = if let Some(c) = line.strip_prefix("||")
                        {
                            (c, false)
                        } else {
                            (&line[1..], true) // strip_prefix('|')
                        };

                        if let Some(filter) = prepare_adblock_filter(content) {
                            if patterns.add_shared_subdomain_pattern(filter.sub_without_www) {
                                continue;
                            }

                            let mut suffix = filter.suffix.replace('^', "/"); // для упрощения считаем разделитель слешем 
                            if exist_caret_at_end && !suffix.ends_with('/') {
                                suffix = format!("{suffix}/")
                            }

                            if domain_starts_with {
                                patterns.add_pattern(
                                    PatternType::SlashedStart.with_third_party(third_party),
                                    format!("//{}{suffix}", filter.domain),
                                );
                            } else {
                                // всегда проверяем, что присуттвует хоть один слеш в суффиксе, чтобы привязаться к концу домена
                                // suffix может не содержать / только если он пустой, ибо split_adblock_filter режет по /
                                if suffix.is_empty() {
                                    suffix.push_str("/");
                                }
                                if let Some(etld_2) = filter.etld_plus_2_without_www {
                                    patterns.add_pattern(
                                        PatternType::DomainEndWithDotPrefix
                                            .with_third_party(third_party),
                                        format!(".{etld_2}{suffix}"),
                                    );
                                } else {
                                    patterns.add_pattern(
                                        PatternType::DomainEnd.with_third_party(third_party),
                                        format!("{}{suffix}", filter.domain),
                                    );
                                }
                            }
                        }
                    } else {
                        let line_fixed = line.replace('^', "/"); // для упрощения считаем разделитель слешем
                        if !prepare_adblock_filter(&line_fixed).is_some_and(|f| {
                            patterns.add_shared_subdomain_pattern(f.sub_without_www)
                        }) {
                            patterns.add_pattern(
                                PatternType::Substring.with_third_party(third_party),
                                line_fixed,
                            );
                        }
                    }
                }
            }

            //удаляем проскочивший мусор, что сломает clean overlapping
            patterns.remove(&"".to_string());
            patterns.remove(&"/".to_string());
            patterns.remove(&".".to_string());
            patterns.remove(&"./".to_string());
            patterns.remove(&"//".to_string());

            if patterns.is_empty() {
                return Err("No patterns found.".into());
            }

            macro_rules! timeit {
                ($code:block, $($arg:tt)+) => {{
                    tracing::info!($($arg)+);

                    let start = std::time::Instant::now();
                    let result = $code;
                    let elapsed = start.elapsed();

                    tracing::info!("[Done in {:?}]", elapsed);
                    result.map_err(|e| format!("{:?}", e))?
                }};
            }

            let mut aho_corasik: DoubleArrayAhoCorasick<u32> = timeit!(
                {
                    DoubleArrayAhoCorasick::with_values(
                        patterns.iter().map(|(k, v)| (k.clone(), *v)),
                    )
                },
                "Building DAC for {} patterns",
                patterns.len()
            );

            for (pat, idx) in patterns.clone() {
                for res in aho_corasik.find_overlapping_iter(&pat) {
                    if res.value() > idx {
                        if PatternType::from(res.value()).is_match(&pat, res.start()) {
                            patterns.remove(&pat);
                            break;
                        }
                    }
                }
            }

            aho_corasik = timeit!(
                {
                    DoubleArrayAhoCorasick::with_values(
                        patterns.iter().map(|(k, v)| (k.clone(), *v)),
                    )
                },
                "Rebuild DAC without overlapping for {} patterns",
                patterns.len()
            );

            if let Some(output_list) = dump {
                let writer: Box<dyn Write> = if *output_list == dash_path {
                    Box::new(io::stdout())
                } else {
                    Box::new(File::create(&output_list)?)
                };
                let mut buffered_writer = BufWriter::new(writer);
                for (p, _) in &patterns {
                    writeln!(buffered_writer, "{}", p)?;
                }
                buffered_writer.flush()?;
            }

            drop(patterns);

            {
                let mut writer: Box<dyn Write> = if *dac == dash_path {
                    Box::new(io::stdout())
                } else {
                    Box::new(File::create(&dac)?)
                };
                writer.write_all(&aho_corasik.serialize())?;
                writer.flush()?;
            }

            tracing::info!("Done. Binary DAC: {}", dac.display());

            Ok(())
        } //_ => Err("Unsupported command".into()),
    }
}
