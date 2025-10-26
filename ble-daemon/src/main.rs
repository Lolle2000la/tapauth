//! TapAuth BLE Daemon
//!
//! A system service that handles BLE authentication requests from PAM modules
//! via D-Bus. This daemon runs persistently with a tokio async runtime and
//! manages BLE advertising and GATT server operations.

mod ble_handler;
mod dbus_interface;

use ble_handler::BleAuthHandler;
use dbus_interface::{AuthRequest, BleService};
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

    // Spawn BLE authentication handler task
    let ble_handler = std::sync::Arc::new(ble_handler);
    let ble_handler_clone = ble_handler.clone();
    tokio::spawn(async move {
        tracing::info!("BLE authentication handler task started");
        while let Some((request, response_tx)) = auth_rx.recv().await {
            tracing::info!("Processing authentication request");
            let result = ble_handler_clone.handle_authentication(request).await;
            if response_tx.send(result).is_err() {
                tracing::error!("Failed to send authentication result (receiver dropped)");
            }
        }
        tracing::warn!("BLE authentication handler task ending");
    });

    // Set up D-Bus service
    tracing::info!("Registering D-Bus service: {}", DBUS_SERVICE_NAME);
    let service = BleService::new(auth_tx);

    let _connection = connection::Builder::system()?
        .name(DBUS_SERVICE_NAME)?
        .serve_at(DBUS_OBJECT_PATH, service)?
        .build()
        .await?;

    tracing::info!("D-Bus service registered at {}", DBUS_OBJECT_PATH);
    tracing::info!("TapAuth BLE Daemon ready");

    // Keep the daemon running
    std::future::pending::<()>().await;

    Ok(())
}
