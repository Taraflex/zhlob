use crate::dac::psl::prepare_adblock_filter;

#[derive(PartialEq, PartialOrd, Clone, Copy)]
#[repr(transparent)]
pub struct PatternType(pub(crate) u32);

#[allow(non_upper_case_globals)]
impl PatternType {
    pub const NotThirdParty: PatternType = PatternType(1 << 31); //нужно хранить инвертированное значение, чтобы ThirdParty значения были меньше НЕ ThirdParty
    //
    pub const SlashedStart: PatternType = PatternType(1 << 28);
    pub const DomainEndWithDotPrefix: PatternType = PatternType(2 << 28);
    pub const DomainEnd: PatternType = PatternType(3 << 28); //check [. or //] before
    pub const Substring: PatternType = PatternType(4 << 28);
    pub const AnyDomainPartBeforeETLD: PatternType = PatternType(5 << 28); //check [. or //] before and locate in part before etld (must be always thirdparty)
}

impl PatternType {
    pub fn with_third_party(self, third_party: bool) -> PatternType {
        if third_party {
            PatternType::from(self.0 & !PatternType::NotThirdParty.0)
        } else {
            PatternType::from(self.0 | PatternType::NotThirdParty.0)
        }
    }

    pub fn from(v: u32) -> Self {
        PatternType(v & 0xF0000000)
    }

    pub fn is_third_party(self) -> bool {
        self.0 & PatternType::NotThirdParty.0 == 0
    }

    pub fn is_match(self, src: &str, match_pos: usize) -> bool {
        match self.with_third_party(true) {
            PatternType::SlashedStart => {
                match_pos == 0 || (match_pos > 0 && src.as_bytes()[match_pos - 1] == b':')
            }
            PatternType::DomainEndWithDotPrefix | PatternType::Substring => true,
            kind => {
                let bytes_src = src.as_bytes();
                let has_slashed_prefix = match_pos > 1
                    && bytes_src[match_pos - 1] == b'/'
                    && bytes_src[match_pos - 2] == b'/';
                if has_slashed_prefix || (match_pos > 0 && bytes_src[match_pos - 1] == b'.') {
                    if has_slashed_prefix || kind != PatternType::AnyDomainPartBeforeETLD {
                        return true;
                    }
                    if let Some(filter) = prepare_adblock_filter(src) {
                        let sub = filter.sub_without_www;

                        if !sub.is_empty() {
                            let src_start = src.as_ptr() as usize;
                            let sub_start = sub.as_ptr() as usize;
                            let sub_offset = sub_start - src_start;

                            return match_pos >= sub_offset && match_pos < sub_offset + sub.len();
                        }
                    }
                }
                false
            }
        }
    }
}
