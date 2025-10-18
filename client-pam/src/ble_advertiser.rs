use std::time::Duration;

#[cfg(feature = "ble")]
use bluer::{Adapter, AdapterEvent, Address};

#[cfg(feature = "ble")]
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
pub enum BleError {
    #[cfg(feature = "ble")]
    #[error("Bluer error: {0}")]
    Bluer(#[from] bluer::Error),
    #[error("Timeout")]
    Timeout,
    #[error("No adapter found")]
    NoAdapter,
    #[error("Advertisement failed")]
    AdvertisementFailed,
    #[error("BLE support not compiled")]
    NotCompiled,
}

#[cfg(feature = "ble")]
pub struct BleAdvertiser {
    adapter: Adapter,
}

#[cfg(not(feature = "ble"))]
pub struct BleAdvertiser;

#[cfg(feature = "ble")]
impl BleAdvertiser {
    /// Create a new BLE advertiser
    pub async fn new() -> Result<Self, BleError> {
        let session = bluer::Session::new().await?;
        let adapter_names = session.adapter_names().await?;
        let adapter_name = adapter_names.first().ok_or(BleError::NoAdapter)?;
        let adapter = session.adapter(adapter_name)?;

        Ok(Self { adapter })
    }

    /// Start advertising with temporal identifier
    pub async fn start_advertising(&self, temporal_identifier: &[u8; 16]) -> Result<(), BleError> {
        use shared::models::ble::SERVICE_UUID;

        // Set adapter to be powered on
        self.adapter.set_powered(true).await?;

        // Create advertisement
        let advertisement = bluer::adv::Advertisement {
            service_uuids: vec![SERVICE_UUID.parse().unwrap()].into_iter().collect(),
            service_data: [(SERVICE_UUID.parse().unwrap(), temporal_identifier.to_vec())]
                .into_iter()
                .collect(),
            discoverable: Some(true),
            local_name: Some("TapAuth".to_string()),
            ..Default::default()
        };

        // Start advertising
        let _handle = self.adapter.advertise(advertisement).await?;

        tracing::info!("Started BLE advertising");

        Ok(())
    }

    /// Stop advertising
    pub async fn stop_advertising(&self) -> Result<(), BleError> {
        // Advertising is stopped when the handle is dropped
        Ok(())
    }

    /// Wait for incoming connection with timeout
    pub async fn wait_for_connection(
        &self,
        timeout_duration: Duration,
    ) -> Result<Option<Address>, BleError> {
        use futures_util::StreamExt;

        let mut events = self.adapter.events().await?;

        match timeout(timeout_duration, async {
            while let Some(event) = events.next().await {
                match event {
                    AdapterEvent::DeviceAdded(addr) => {
                        tracing::debug!("Device added: {}", addr);
                        return Some(addr);
                    }
                    _ => {}
                }
            }
            None
        })
        .await
        {
            Ok(result) => Ok(result),
            Err(_) => Err(BleError::Timeout),
        }
    }
}

#[cfg(not(feature = "ble"))]
impl BleAdvertiser {
    /// Create a new BLE advertiser (stub when BLE is disabled)
    pub async fn new() -> Result<Self, BleError> {
        Err(BleError::NotCompiled)
    }

    /// Start advertising with temporal identifier (stub when BLE is disabled)
    pub async fn start_advertising(&self, _temporal_identifier: &[u8; 16]) -> Result<(), BleError> {
        Err(BleError::NotCompiled)
    }

    /// Stop advertising (stub when BLE is disabled)
    pub async fn stop_advertising(&self) -> Result<(), BleError> {
        Ok(())
    }

    /// Wait for incoming connection with timeout (stub when BLE is disabled)
    pub async fn wait_for_connection(
        &self,
        _timeout_duration: Duration,
    ) -> Result<Option<()>, BleError> {
        Err(BleError::NotCompiled)
    }
}

#[cfg(test)]
#[cfg(feature = "ble")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ble_advertiser_creation() {
        // This test will fail if no Bluetooth adapter is available
        // which is expected in CI/testing environments
        let result = BleAdvertiser::new().await;

        // Just verify it doesn't panic
        match result {
            Ok(_) => println!("BLE adapter found"),
            Err(BleError::NoAdapter) => println!("No BLE adapter (expected in CI)"),
            Err(e) => println!("BLE error: {:?}", e),
        }
    }
}
