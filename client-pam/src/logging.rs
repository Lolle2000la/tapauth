//! Logging for the PAM module: journald under systemd, plus a stderr layer when
//! running outside it (systemd already forwards stderr, so both would duplicate).
//!
//! `TAPAUTH_LOG_LEVEL` sets the stderr level (default `warn`);
//! `TAPAUTH_JOURNALD_LOG_LEVEL` the journald level (default `info`).

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

fn make_stderr_layer() -> impl Layer<tracing_subscriber::Registry> {
    let filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));
    tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(filter)
}

pub fn init_logging() {
    let journald_level =
        std::env::var("TAPAUTH_JOURNALD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

    // Every arm installs the subscriber once; `try_init` failing because one is
    // already installed is normal, so the result is ignored.
    if let Ok(journald_layer) = tracing_journald::layer() {
        if std::env::var("JOURNAL_STREAM").is_ok() {
            let filter =
                EnvFilter::try_new(&journald_level).unwrap_or_else(|_| EnvFilter::new("info"));
            let _ = tracing_subscriber::registry()
                .with(journald_layer.with_filter(filter))
                .try_init();
        } else {
            let filter =
                EnvFilter::try_new(&journald_level).unwrap_or_else(|_| EnvFilter::new("info"));
            let _ = tracing_subscriber::registry()
                .with(make_stderr_layer())
                .with(journald_layer.with_filter(filter))
                .try_init();
        }
    } else {
        let _ = tracing_subscriber::registry()
            .with(make_stderr_layer())
            .try_init();
    }
}
