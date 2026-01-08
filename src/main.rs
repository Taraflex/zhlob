use crate::{
    cli::{APP_NAME, CLI},
    dac::psl::PS_LIST,
    maybe::UnifiedError,
};
use enable_ansi_support::enable_ansi_support;
use tracing::{self, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

mod cancelation_token;
mod cli;
mod dac;
mod highway_semaphore;
mod initable_staticts;
mod maybe;
mod processors;
mod proxy;
mod resettable_lazy;

fn main() -> Result<(), UnifiedError> {
    PS_LIST::init(&CLI.psl)?;

    // fix colors in tracing
    let _ = enable_ansi_support();
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_writer(|| std::io::stderr())
        .with_span_events(FmtSpan::ACTIVE)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .parse_lossy(&CLI.log_level),
        )
        .init();

    if let Some(c) = &CLI.command {
        dac::generate::run(c)
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name(const_str::concat!(APP_NAME, "-proxy"))
            .enable_all()
            .build()?
            .block_on(proxy::run())
    }
}
