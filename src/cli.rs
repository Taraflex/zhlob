use clap::{ Parser, Subcommand, builder::styling::{self, AnsiColor}, command};
use std::path::PathBuf;
use crate::{initable_static, maybe::UnifiedError};

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_NAME_UPPER: &str = const_str::convert_ascii_case!(shouty_snake, APP_NAME);

initable_static!{
    CLI:Cli = || {
        Cli::parse()
    }
}

macro_rules! if_empty {
    ($input:expr, $fallback:expr) => {{
        let input = $input;
        if input.is_empty() {
            $fallback
        } else {
            input
        }
    }};
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
    }
}

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
pub struct Cli {
    /// Listen address [default: 127.0.0.1:5151]
    /// Supports: 127.0.0.1:5151, :5151, http://127.0.0.1, etc.
    #[arg(
        short = 'L',
        long = "listen",
        env = const_str::concat!(APP_NAME_UPPER, "_LISTEN"),
        default_value = "127.0.0.1:5151",
        value_name = "ADDR",
        value_parser = parse_listen_address 
    )]
    pub listen: (String, u16),

    /// Custom Public Suffix List file (use '-' for stdin)
    #[arg(
        short, 
        long, 
        env = const_str::concat!(APP_NAME_UPPER, "_PSL"),
        value_name = "PSL", 
        global = true
    )]
    pub psl: Option<PathBuf>,

    /// DAC binary file
    #[arg(
        short,
        long, 
        env = const_str::concat!(APP_NAME_UPPER, "_DAC")
    )]
    pub dac: Option<PathBuf>,

    /// Log level (off, error, warn, info, debug, trace)
    #[arg(
        long = "log-level",
        env = const_str::concat!(APP_NAME_UPPER, "_LOG_LEVEL"),
        default_value = "info",
        value_name = "LEVEL",
        global = true
    )]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
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

    Ok((
        if_empty!(host, "127.0.0.1".to_string()),
        port,
    ))
}
