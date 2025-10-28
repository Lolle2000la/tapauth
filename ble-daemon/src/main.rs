//! TapAuth BLE Daemon
//!
//! A system service that handles BLE authentication requests from PAM modules
//! via D-Bus. This daemon runs persistently with a tokio async runtime and
//! manages BLE advertising and GATT server operations.

mod ble_handler;
mod dbus_interface;

use ble_handler::BleAuthHandler;
use dbus_interface::{AuthRequest, BleServiceImpl};
use shared::{AuthResult, DBUS_OBJECT_PATH, DBUS_SERVICE_NAME};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use zbus::connection;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tracing::info!("TapAuth BLE Daemon starting...");

    // Create BLE authentication handler
    let ble_handler = BleAuthHandler::new().await?;
    tracing::info!("BLE handler initialized");

    // Create channel for authentication requests
    let (auth_tx, mut auth_rx) =
        mpsc::channel::<(AuthRequest, tokio::sync::oneshot::Sender<AuthResult>)>(10);

    // Create broadcast channel for cancellation
    let (cancel_tx, _cancel_rx) = tokio::sync::broadcast::channel::<()>(10);
    let cancel_tx_clone = cancel_tx.clone();

    // Spawn BLE authentication handler task
    let ble_handler = std::sync::Arc::new(ble_handler);
    let ble_handler_clone = ble_handler.clone();
    tokio::spawn(async move {
        tracing::info!("BLE authentication handler task started");
        while let Some((request, response_tx)) = auth_rx.recv().await {
            tracing::info!("Processing authentication request");

            // Subscribe to cancellation for this request
            let mut cancel_rx = cancel_tx_clone.subscribe();

            // Clone handler for the task
            let handler = ble_handler_clone.clone();

            // Spawn a task for this authentication
            let auth_task =
                tokio::spawn(async move { handler.handle_authentication(request).await });

            // Wait for either completion or cancellation
            tokio::select! {
                result = auth_task => {
                    match result {
                        Ok(auth_result) => {
                            if response_tx.send(auth_result).is_err() {
                                tracing::error!("Failed to send authentication result (receiver dropped)");
                            }
                        }
                        Err(e) => {
                            tracing::error!("Authentication task panicked: {}", e);
                            let _ = response_tx.send(AuthResult::Error);
                        }
                    }
                }
                _ = cancel_rx.recv() => {
                    tracing::info!("Authentication cancelled");
                    // The response channel will be dropped, causing the D-Bus call to return with error
                    // This is acceptable - the PAM module will interpret it as cancellation
                }
            }
        }
        tracing::warn!("BLE authentication handler task ending");
    });

    // Set up D-Bus service
    tracing::info!("Registering D-Bus service: {}", DBUS_SERVICE_NAME);
    let service = BleServiceImpl::new(auth_tx, cancel_tx);

    let _connection = connection::Builder::system()?
        .name(DBUS_SERVICE_NAME)?
        .serve_at(DBUS_OBJECT_PATH, service)?
        .build()
        .await?;

    tracing::info!("D-Bus service registered at {}", DBUS_OBJECT_PATH);
    tracing::info!("TapAuth BLE Daemon ready");

    // Keep the daemon running until a shutdown signal is received
    // This ensures proper cleanup when the service is stopped
    shutdown_signal().await;

    tracing::info!("TapAuth BLE Daemon shutting down...");

    // Note: When this function exits, Rust's drop handlers will run:
    // - The D-Bus connection will be dropped, unregistering the service
    // - Any active BLE advertisements will be unregistered
    // - The tokio runtime will shut down all spawned tasks
    // This prevents "zombie" advertisements in bluetoothd

    Ok(())
}

/// Wait for a shutdown signal (SIGTERM, SIGINT, or Ctrl+C)
async fn shutdown_signal() {
    use tokio::signal;

    // Set up signal handlers
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT (Ctrl+C)");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM");
        },
    }
}
