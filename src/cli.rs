use crate::{initable_static, maybe::UnifiedError};
use clap::{
    Parser, Subcommand,
    builder::styling::{self, AnsiColor},
    command,
};
use human_units::{Duration, DurationError, Size};
use std::path::PathBuf;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_NAME_UPPER: &str = const_str::convert_ascii_case!(shouty_snake, APP_NAME);

initable_static! {
    CLI:Cli = || {
        Cli::parse()
    }
}

macro_rules! if_empty {
    ($input:expr, $fallback:expr) => {{
        let input = $input;
        if input.is_empty() { $fallback } else { input }
    }};
}

macro_rules! define_cli {
    (
        pub struct $struct_name:ident {
            $(
                $(#[$doc:meta])*
                $name:ident
                $( ( $t:ty ) => $args:tt )?
                $( => $bool_type:ident )?
                ,
            )*
        }
    ) => {
        #[derive(Parser)]
        #[command(
            name = APP_NAME,
            about = "MITM Proxy with image and HTML optimization",
            styles = styling::Styles::styled()
                .literal(AnsiColor::BrightCyan.on_default())
                .header(AnsiColor::BrightGreen.on_default().underline())
                .usage(AnsiColor::BrightGreen.on_default().underline())
                .placeholder(AnsiColor::BrightYellow.on_default()),
        )]
        pub struct $struct_name {
            $(
                $(#[$doc])*
                // Branch for: name => bool
                $(
                    #[arg(
                        long,
                        env = const_str::concat!(APP_NAME_UPPER, "_", const_str::convert_ascii_case!(shouty_snake, stringify!($name))),
                        default_value_t = true,
                        action = clap::ArgAction::Set,
                        num_args = 0..=1,
                        default_missing_value = "true",
                        value_name = "BOOL",
                        value_parser = clap::builder::BoolishValueParser::new(),
                    )]
                    pub $name: $bool_type,
                )*
                // Branch for: name(type) => (args)
                $(
                    #[arg $args]
                    pub $name: $t,
                )*
            )*

            #[command(subcommand)]
            pub command: Option<Commands>
        }
    };
}

#[derive(Subcommand)]
pub enum Commands {
    /// Compile Adblock patterns to the simplified binary DAC file
    Dacgen {
        /// Path to save the debug plain text patterns list (as they are stored in DAC) (use '-' for stdout)
        #[arg(long)]
        dump: Option<PathBuf>,

        /// Input adblock filters files (use '-' for stdin)
        inputs: Vec<PathBuf>,

        /// Path to save the DAC file (use '-' for stdout)
        #[arg(short, long, default_value = "blocklist.dac")]
        dac: PathBuf,
    },
}

define_cli! {
    pub struct Cli {
        /// Listen address {formats: 127.0.0.1:5151, :5151, http://127.0.0.1, etc.}
        listen((String, u16)) => (
            short = 'L',
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_LISTEN"),
            default_value = "127.0.0.1:5151",
            value_name = "ADDR",
            value_parser = parse_listen_address
        ),

        /// Custom Public Suffix List file (use '-' for stdin)
        psl(Option<PathBuf>) => (
            short,
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_PSL"),
            value_name = "PSL",
            global = true
        ),

        /// DAC binary file
        dac(Option<PathBuf>) => (
            short,
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_DAC")
        ),

        /// Limit "Cache-Control: max-age" for transformed responses
        cache_max_age(u32) => (
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_CACHE_MAX_AGE"),
            default_value = "2h",
            value_name = "DURATION",
            value_parser = parse_duration
        ),

        /// Clear html of advertising scripts and browser-insignificant tags and attributes
        clear_html => bool,

        /// Return 304 Not Modified for media and previously transformed content without upstream requests
        fast_304 => bool,

        /// Skip none cached video, audio, fonts, icons resources
        skip_aux_resources => bool,

        /// Scale images keeping the shorter side within this range (set to 0 to disable image processing) {formats: "96..384", "..768" (1..768), "48.." (48..max_uint32), ".." (1..max_uint32)}
        image_scale(f32) => (
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_IMAGE_SCALE"),
            default_value = "0.5",
            value_name = "FLOAT",
        ),

        /// Scale images keeping the shorter side within this range {formats: "96..384", "..768" (1..768), "48.." (48..max_uint32), ".." (1..max_uint32)}
        image_scale_limit([u32; 2]) => (
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_IMAGE_SCALE_LIMIT"),
            default_value = "96..384",
            value_name = "MIN..MAX",
            value_parser = parse_range
        ),

        /// Rechankify html to speed up partial rendering in browsers (set to 0 to disable chunking)
        rechunk_html_size(usize) => (
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_RECHUNK_HTML_SIZE"),
            default_value = "1360",
            value_name = "SIZE",
            value_parser = parse_size
        ),

        /// html/images larger than this will be proxied as-is without transformation
        transform_limit(usize) => (
            long,
            env = const_str::concat!(APP_NAME_UPPER, "_TRANSFORM_LIMIT"),
            default_value = "5m",
            value_name = "SIZE",
            value_parser = parse_size
        ),

        /// Log level {off, error, warn, info, debug, trace}
        log_level(String) => (
            long,
            env,
            default_value = "info",
            value_name = "LEVEL",
            global = true
        ),
    }
}

fn parse_size(s: &str) -> Result<usize, UnifiedError> {
    Ok(usize::try_from(s.parse::<Size>()?.0)?)
}

fn parse_range(s: &str) -> Result<[u32; 2], UnifiedError> {
    let (s_part, e_part) = s
        .split_once("..")
        .ok_or_else(|| format!("Invalid format '{}'. Use 'MIN..MAX'", s))?;

    let s_val = if_empty!(s_part.trim_ascii(), "1");
    let e_val = if_empty!(e_part.trim_ascii(), &u32::MAX.to_string());

    let start = s_val.parse::<u32>()?;

    let end = e_val.parse::<u32>()?;

    if end < start {
        return Err(format!("MIN ({}) must be <= MAX ({})", start, end).into());
    }

    Ok([start, end])
}

fn parse_duration(s: &str) -> Result<u32, DurationError> {
    s.parse::<Duration>().map(|d| d.as_secs() as u32)
}

fn parse_listen_address(mut input: &str) -> Result<(String, u16), UnifiedError> {
    input = input.trim_ascii();
    let s = input
        .strip_prefix("http://")
        .unwrap_or(input)
        .strip_prefix("://")
        .unwrap_or(input);

    let (host, port) = if let Some((host, port_str)) = s.rsplit_once(':') {
        let port = if_empty!(port_str.trim_ascii(), "5151").parse::<u16>()?;
        (host.trim_ascii().to_string(), port)
    } else {
        (s.trim_ascii().to_string(), 5151u16)
    };

    Ok((if_empty!(host, "127.0.0.1".to_string()), port))
}
