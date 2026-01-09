use fastvec::{AutoVec, autovec};
use memchr::memmem::Finder;

use crate::initable_static;

initable_static!{
    ML_COMMEND_END: Finder<'static> = || { Finder::new(b"*/") };
}

#[inline(always)]
 fn is_likely_url(src: &[u8]) -> bool {
    let len = src.len();
    if len < 8 {
        return false;
    }

    let mut ptr = src.as_ptr();
    let end_ptr = unsafe { ptr.add(len) };

    unsafe {
        let raw_http = ptr.cast::<u32>().read_unaligned();
        // Применяем маску 0x20202020, чтобы перевести все буквы в нижний регистр
        // 'h' (0x68) | 0x20 = 0x68 (уже нижний)
        // 'H' (0x48) | 0x20 = 0x68 (станет нижним)
        if (raw_http | 0x20202020) == 0x70747468 {
            ptr = ptr.add(4);
            if *ptr == b's' {
                ptr = ptr.add(1);
            }
            if ptr >= end_ptr || *ptr != b':' {
                return false;
            }
            ptr = ptr.add(1);
        }

        // 2. Проверка "//"
        if ptr.add(2) > end_ptr || ptr.cast::<u16>().read_unaligned() != 0x2F2F {
            return false;
        }
        ptr = ptr.add(2);

        let host_start_ptr = ptr;
        let mut dot_count = 0;
        let mut last_dot_ptr = std::ptr::null::<u8>();

        // 3. Валидация хоста
        while ptr < end_ptr {
            let b = *ptr;

            if b == b'/' {
                return dot_count > 0 && last_dot_ptr < ptr.offset(-1);
            }

            if b == b'.' {
                if ptr == host_start_ptr || last_dot_ptr == ptr.offset(-1) {
                    return false;
                }
                dot_count += 1;
                last_dot_ptr = ptr;
            } else {
                let is_alphanum =
                    (b.wrapping_sub(b'0') < 10) | ((b | 0x20).wrapping_sub(b'a') < 26);
                if !(is_alphanum | (b == b'-')) {
                    return false;
                }
            }
            ptr = ptr.add(1);
        }
    }
    false
}

/*
use ctor::ctor;
#[ctor]
fn is_likely_url_playground() {
    let cases = vec![
        // Позитивные (должны быть true)
        ("https://google.com/", true),
        ("http://test.ru/path", true),
        ("//sub.domain.tld/js", true),
        ("https://a-b.c-d.com/", true),
        ("http://127.0.0.1/", true),
        ("//static.doubleclick.net/adj/...", true),
        // Негативные: длина
        ("//a.b/", false),
        // Негативные: структура хоста
        ("http://googlecom/", false),   // нет точки
        ("http://.google.com/", false), // точка в начале
        ("http://google..com/", false), // двойная точка
        ("http://google./", false),     // точка в конце хоста
        ("//invalid_char.com/", false), // недопустимый символ '_'
        ("//domain.com:8080/", false),  // двоеточие (твой паттерн его не покрывал)
        // Негативные: протокол и разделители
        ("https:/google.com/", false), // один слеш
        ("https://google.com", false), // нет завершающего слеша (по твоему паттерну)
        ("ftp://google.com/", false),  // не http
        ("http:google.com/", false),   // нет слешей
        //
        ("https://GoOgLe.CoM/", true),
        ("HTTP://MiXeD.CaSe.Ru/path", true),
        ("//Sub-Domain.Tld/js", true),
        ("https://a-B.C-d.CoM/", true),
        ("//Static.Doubleclick.Net/adj/", true),
        // Негативные (должны быть false)
        ("https://GoOgLe.C_M/", false), // '_' запрещен
        ("//Aa.Bb/", true),             // длина < 9 (ровно 8)
        ("http://GOOGLE./", false),     // точка в конце
        ("HTTPS://GOOGLECOM/", false),  // нет точки
    ];

    let mut failed = 0;
    for (url, expected) in cases {
        let result = is_likely_url(url.as_bytes());
        if result != expected {
            println!("FAIL: {} | expected {}, got {}", url, expected, result);
            failed += 1;
        } else {
            println!("OK:   {}", url);
        }
    }

    if failed == 0 {
        println!("\nВсе тесты пройдены успешно!");
    } else {
        println!("\nКоличество ошибок: {}", failed);
    }
}*/

#[inline(always)]
fn is_ident_or_dot_or_whitespace(b: u8) -> bool {
    if b < 123 {
        const MASK: u128 = (1 << b'\t') | (1 << b'\n') | (1 << b'\x0C') | (1 << b'\r') | (1 << b' ') | 
            (1 << b'$')  | (1 << b'.')  |
            (0x3FF << b'0') |        // 0-9
            (0x3FFFFFF << b'A') |    // A-Z (26 бит — это 0x3FFFFFF)
            (1 << b'_')  |
            (0x3FFFFFF << b'a'); // a-z

        return (MASK & (1 << b)) != 0;
    }
    false
}

#[inline(always)]
fn is_ident_or_dot(b: u8) -> bool {
    if b < 123 {
        const MASK: u128 = (1 << b'$')  | (1 << b'.')  |
            (0x3FF << b'0') |        // 0-9
            (0x3FFFFFF << b'A') |    // A-Z (26 бит — это 0x3FFFFFF)
            (1 << b'_')  |
            (0x3FFFFFF << b'a'); // a-z

        return (MASK & (1 << b)) != 0;
    }
    false
}

/*
use ctor::ctor;
#[ctor]
fn is_ident_or_dot_or_whitespace_playground() {
    let mut errors = 0;

    // Эталонная реализация для сравнения (медленная, но понятная)
    fn reference_check(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || b == b'$'
            || b == b'_'
            || b == b'.'
            || matches!(b, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
    }

    println!("Запуск полного теста (0-255)...");

    for b in 0u8..=255u8 {
        let actual = is_ident_or_dot_or_whitespace(b as u8);
        let expected = reference_check(b as u8);

        if actual != expected {
            println!(
                "ОШИБКА: Байт {} (0x{:02X}) | Символ: '{}' | Ожидалось: {}, Получено: {}",
                b, b, b as char, expected, actual
            );
            errors += 1;
        }
    }

    if errors == 0 {
        println!("Успех! Функция на 100% соответствует эталону для всех 256 байт.");
    } else {
        println!("Итого ошибок: {}", errors);
    }
}*/
/*
use ctor::ctor;
#[ctor]
fn playground() {
    const SS: &str = r#"'';"";'\'';"\"";'http://google.com/';
window.i18nFetch = new Promise((res, rej) => {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', '/js/i18n/ru-compiled.json');
            xhr.responseType = 'json';
            xhr.onload = function(e) {
              if (this.status === 200) {
                res({ru: xhr.response});
              } else {
                rej(e);
              }
            };
            xhr.send();
          });    
          
"#;
    for  s in JsUrlsIterator::new(SS.as_bytes()){
        unsafe{
        println!("{}", str::from_utf8_unchecked(s));
        }
    }
}*/

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Script,
    Template,
}

#[derive(Clone, Copy)]
struct Context {
    mode: Mode,
    brace_depth: usize,
    regexp_allowed: bool,
}

pub struct JsUrlsIterator<'a> {
    src: &'a [u8],
    pos: usize,
    stack: AutoVec<Context, 4>,
}

impl<'a> JsUrlsIterator<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            stack: autovec![Context {
                mode: Mode::Script,
                brace_depth: 0,
                regexp_allowed: true,
            }],
        }
    }

    #[inline(always)]
    fn peek_byte(&self) -> u8 {
        if self.pos < self.src.len() {
            self.src[self.pos]
        } else {
            b'\0'
        }
    }
}

impl<'a> Iterator for JsUrlsIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        macro_rules! scan_to {
            ($pattern:pat $(if $guard:expr)? $(,)?) => {{
                let mut found = 0u8;
                while self.pos < self.src.len() {
                    let b = self.src[self.pos];
                    self.pos += 1;
                    #[allow(unreachable_patterns)]
                    match b {
                        b'\\' => { self.pos += 1; }
                        $pattern $(if $guard)? => {
                            found = b;
                            break;
                        }
                        _ => {}
                    }
                }
                found
            }};
        }

        while self.pos < self.src.len() {
            if self.stack.last()?.mode == Mode::Template {
                match scan_to!(b'`' | b'$') {
                    b'`' => {
                        self.stack.pop();
                        self.stack.last()?;
                    }
                    b'$' if self.peek_byte() == b'{' => {
                        self.pos += 1;
                        self.stack.push(Context {
                            mode: Mode::Script,
                            brace_depth: 0,
                            regexp_allowed: true,
                        });
                    }
                    _ => {}
                }
                continue;
            }

            let b = self.src[self.pos];
            self.pos += 1;

            match b {
                b'/' => {
                    if self.pos >= self.src.len() {
                        return None;
                    }
                    match self.src[self.pos] {
                        b'/' => {
                            // line comment
                            self.pos += 1;
                            scan_to!(b'\n');
                        }
                        b'*' => {
                            // multiline comment
                            self.pos += 1;
                            self.pos += ML_COMMEND_END.find(&self.src[self.pos..])? + 2;
                        }
                        _ if self.stack.last()?.regexp_allowed => {
                            // regexp
                            loop {
                                match scan_to!(b'/' | b'[') {
                                    b'/' => break,
                                    b'[' => {
                                        if scan_to!(b']') == 0 {
                                            return None;
                                        }
                                    }
                                    _ => return None,
                                }
                            }
                            self.stack.last_mut()?.regexp_allowed = false;
                        }
                        _ => {
                            // division
                            self.stack.last_mut()?.regexp_allowed = true;
                        }
                    }
                }
                b'{' => {
                    let ctx = self.stack.last_mut()?;
                    ctx.regexp_allowed = true;
                    ctx.brace_depth += 1;
                }
                b'(' | b'[' | b';' | b',' | b'!' | b'=' | b'<' | b'>' | b'+' | b'-' | b'*'
                | b'%' | b'&' | b'|' | b'^' | b'~' | b'?' | b':' => {
                    self.stack.last_mut()?.regexp_allowed = true;
                }
                b')' | b']' => {
                    self.stack.last_mut()?.regexp_allowed = false;
                }
                b'}' => {
                    let ctx = self.stack.last_mut()?;
                    if ctx.brace_depth > 0 {
                        ctx.brace_depth -= 1;
                        ctx.regexp_allowed = false;
                    } else {
                        self.stack.pop();
                        self.stack.last()?;
                    }
                }
                b'`' => {
                    self.stack.push(Context {
                        mode: Mode::Template,
                        brace_depth: 0,
                        regexp_allowed: false,
                    });
                }
                quote @ (b'\'' | b'\"') => {
                    let start = self.pos;
                    let found = match quote {
                        b'\'' => scan_to!(b'\''),
                        b'\"' => scan_to!(b'\"'),
                        _ => unreachable!("quote is always ' or \" due to the guard above"),
                    };
                    if found == 0 {
                        return None;
                    }
                    self.stack.last_mut()?.regexp_allowed = false;
                    let end = self.src.len().min(self.pos - 1);
                    let may_be_url = &self.src[start..end];
                    if is_likely_url(may_be_url) {
                        return Some(may_be_url);
                    }
                }
                _ if is_ident_or_dot(b) => {
                    // захватываем точку чтобы различать случаи, когда используется свойство с именем спец инструкции. прим.:
                    // obj.extends /* тут не может стоять regexp */
                    let start = self.pos - 1;
                    while is_ident_or_dot_or_whitespace(self.peek_byte()) {
                        self.pos += 1;
                    }
                    self.stack.last_mut()?.regexp_allowed = matches!(
                        self.src[start..self.pos].trim_ascii_end(),
                        b"return"
                            | b"await"
                            | b"yield"
                            | b"case"
                            | b"delete"
                            | b"do"
                            | b"else"
                            | b"in"
                            | b"instanceof"
                            | b"new"
                            | b"throw"
                            | b"typeof"
                            | b"void"
                            | b"extends"
                    );
                }
                _ => {
                    if !b.is_ascii_whitespace() {
                        self.stack.last_mut()?.regexp_allowed = false;
                    }
                }
            }
        }
        None
    }
}
