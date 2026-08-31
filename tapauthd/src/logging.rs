//! Logging configuration for tapauthd
//!
//! Logs go to journald (via `tracing-journald`).  When running outside
//! systemd (e.g. manual `cargo run`), a stdout layer is added for
//! terminal visibility.  Under systemd the stdout layer is skipped
//! because systemd already forwards stdout to the journal, avoiding
//! duplicate entries.
//!
//! Environment variables:
//! - `TAPAUTH_LOG_LEVEL`: Controls stdout log level (default: info)
//! - `TAPAUTH_JOURNALD_LOG_LEVEL`: Controls journald log level (default: info)

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub fn init_logging() {
    let stdout_filter = std::env::var("TAPAUTH_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .and_then(|level| EnvFilter::try_new(&level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    // TAPAUTH_DEV_MODE is only meaningful in dev-feature builds (it gates the UDP
    // shim and the PolKit bypass at runtime). Dev runs redirect the daemon's
    // output to a log file, so they want the stdout layer instead of journald.
    // Production binaries have no dev features compiled in and always log to
    // journald, no matter what the environment says.
    #[cfg(any(
        feature = "dev-state-override",
        feature = "dev-udp-loopback",
        feature = "dev-polkit-bypass"
    ))]
    let dev_mode = std::env::var("TAPAUTH_DEV_MODE").is_ok();
    #[cfg(not(any(
        feature = "dev-state-override",
        feature = "dev-udp-loopback",
        feature = "dev-polkit-bypass"
    )))]
    let dev_mode = false;

    if !dev_mode {
        if let Ok(journald_layer) = tracing_journald::layer() {
            let journald_level =
                std::env::var("TAPAUTH_JOURNALD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
            let filter =
                EnvFilter::try_new(&journald_level).unwrap_or_else(|_| EnvFilter::new("info"));
            if std::env::var("JOURNAL_STREAM").is_ok() {
                // Under systemd: journald only, since systemd already forwards
                // stdout to the journal (a stdout layer would duplicate entries).
                tracing_subscriber::registry()
                    .with(journald_layer.with_filter(filter))
                    .init();
            } else {
                // Outside systemd: mirror to stdout for terminal visibility.
                tracing_subscriber::registry()
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_target(false)
                            .with_writer(std::io::stdout)
                            .with_filter(stdout_filter),
                    )
                    .with(journald_layer.with_filter(filter))
                    .init();
            }
            return;
        }
    }

    // Stdout only: journald is unavailable, or this is a dev run
    // (TAPAUTH_DEV_MODE) whose output is redirected to a log file.
    tracing_subscriber::fmt()
        .with_env_filter(stdout_filter)
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();
}
