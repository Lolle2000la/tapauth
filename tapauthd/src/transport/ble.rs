//! BLE transport using direct BlueZ access via D-Bus
//!
//! One static four-characteristic GATT service (`ble-gatt-specification.md` §2)
//! serves both pairing and authentication: `CLIENT_COMMAND`,
//! `SERVER_RESPONSE`, `CLIENT_CONFIRMATION` and `PAIRING` are always registered
//! in that order, so the attribute handles a phone cached during pairing stay
//! valid when it reconnects to authenticate.

use super::{ReceiveResult, Transport, NOTIFY_SETTLE};
use crate::auth_handler::AuthHandlerError as AuthError;
use bluer::adv::Advertisement;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicNotifier, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
    ReqError, Service,
};
use prost::Message;
use shared::config::CskMetadata;
use shared::models::ble::{
    CLIENT_COMMAND_CHAR_UUID, CLIENT_CONFIRMATION_CHAR_UUID, MAX_GATT_PAYLOAD_BYTES,
    PAIRING_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID, SERVICE_UUID,
};
use shared::protocol::messages::{verify_and_decode_payload, DecodedPayload};
use shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce;
use shared::protocol::pb::EncryptedPacket;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, UnboundedReceiver};

/// One paired Server's Ed25519 public key and the signature algorithm it signs
/// wrapper messages with.
///
/// The transport verifies every response frame against these before handing it
/// to the authentication handler, so a write pushed by an unpaired device never
/// ends the wait for a legitimate response.
#[derive(Debug, Clone, Copy)]
pub struct ServerVerifier {
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// `SignatureAlgorithm` value the Server signs with.
    pub signature_algorithm: i32,
}

impl ServerVerifier {
    /// Build a verifier for every paired Server that has a well-formed 32-byte
    /// hex public key. Malformed entries are skipped with a warning: they fail
    /// the same verification on every response, so leaving them out changes no
    /// outcome and keeps the failure visible in the log.
    pub fn from_paired_servers(
        servers: &HashMap<String, shared::config::PairedServer>,
    ) -> Vec<Self> {
        let mut verifiers = Vec::with_capacity(servers.len());
        for server in servers.values() {
            let Ok(bytes) = hex::decode(&server.public_key) else {
                tracing::warn!(
                    "Paired server {} has a non-hex public key; it cannot verify BLE responses",
                    server.name
                );
                continue;
            };
            let Ok(public_key) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                tracing::warn!(
                    "Paired server {} public key is {} bytes, not 32; it cannot verify BLE responses",
                    server.name,
                    bytes.len()
                );
                continue;
            };
            verifiers.push(Self {
                public_key,
                signature_algorithm: server.signature_algorithm as i32,
            });
        }
        verifiers
    }
}

/// The notification session of one characteristic.
///
/// BlueZ hands a [`CharacteristicNotifier`] to the
/// [`CharacteristicNotifyMethod::Fun`] callback when the peer subscribes
/// (CCCD write); it is kept here so `send_cancel`, `send_confirmation` and the
/// pairing channel can notify from outside that callback. A peer that never
/// subscribed leaves the slot empty and falls back to reading the
/// characteristic value, which is why every publish also updates the value.
#[derive(Clone)]
struct Notifier {
    slot: Arc<tokio::sync::Mutex<Option<CharacteristicNotifier>>>,
}

impl Notifier {
    fn new() -> Self {
        Self {
            slot: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Take ownership of the notifier BlueZ created for a new subscription.
    async fn install(&self, notifier: CharacteristicNotifier) {
        *self.slot.lock().await = Some(notifier);
    }

    /// Push `value` to a subscribed peer. Returns whether anything was sent:
    /// `false` means no subscription is open, which is not an error because the
    /// caller also updated the readable value.
    async fn publish(&self, value: Vec<u8>) -> Result<bool, AuthError> {
        let mut slot = self.slot.lock().await;
        let Some(notifier) = slot.as_mut() else {
            return Ok(false);
        };
        notifier
            .notify(value)
            .await
            .map_err(|e| AuthError::BleError(format!("GATT notification failed: {}", e)))?;
        Ok(true)
    }
}

/// Which direction the two write characteristics forward frames to.
///
/// Only the channel of the active phase is created, so a peer that writes to
/// the characteristic the current phase does not use cannot grow a queue
/// nobody drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GattMode {
    /// Post-pairing authentication: frames from `SERVER_RESPONSE_CHAR_UUID`.
    Authentication,
    /// QR-initiated pairing: frames from `PAIRING_CHAR_UUID`.
    Pairing,
}

/// Values and notification handles of the four static characteristics, shared
/// with the BlueZ D-Bus callbacks.
struct GattState {
    /// Readable value of `CLIENT_COMMAND_CHAR_UUID`.
    command_value: Arc<tokio::sync::Mutex<Vec<u8>>>,
    /// Readable value of `CLIENT_CONFIRMATION_CHAR_UUID`.
    confirmation_value: Arc<tokio::sync::Mutex<Vec<u8>>>,
    /// Readable value of `PAIRING_CHAR_UUID`.
    pairing_value: Arc<tokio::sync::Mutex<Vec<u8>>>,
    command_notifier: Notifier,
    confirmation_notifier: Notifier,
    pairing_notifier: Notifier,
}

impl GattState {
    fn new() -> Self {
        Self {
            command_value: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            confirmation_value: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            pairing_value: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            command_notifier: Notifier::new(),
            confirmation_notifier: Notifier::new(),
            pairing_notifier: Notifier::new(),
        }
    }
}

/// Authentication-only state; `None` on a pairing-only transport.
struct AuthState {
    /// 10-byte temporal identifier carried in the advertisement.
    temporal_id: [u8; 10],
    csk: shared::crypto::ClientSymmetricKey,
    /// Paired Servers whose signature may conclude the wait for a response.
    server_verifiers: Vec<ServerVerifier>,
}

/// BLE transport using direct BlueZ access via D-Bus
pub struct BleTransport {
    adapter: bluer::Adapter,
    /// Authentication credentials and policy; `None` when this transport was
    /// created by [`BleTransport::new_for_pairing`].
    auth: Option<AuthState>,
    // Keep advertisement and GATT server alive
    adv_handle: Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
    gatt_handle: Arc<tokio::sync::Mutex<Option<bluer::gatt::local::ApplicationHandle>>>,
    /// Values and notifiers shared with the GATT callbacks.
    gatt: Arc<GattState>,
    /// Frames the peer wrote to `SERVER_RESPONSE_CHAR_UUID`.
    response_rx: tokio::sync::Mutex<Option<UnboundedReceiver<Vec<u8>>>>,
    /// Frames the peer wrote to `PAIRING_CHAR_UUID`.
    pairing_rx: tokio::sync::Mutex<Option<UnboundedReceiver<Vec<u8>>>>,
    // Store all connected devices to disconnect them on cancel
    connected_devices: Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    // Idempotent shutdown flag
    shutdown_started: AtomicBool,
}

/// Parse one of the fixed GATT UUIDs into the type BlueZ expects.
fn parse_uuid(uuid: &str) -> Result<bluer::Uuid, AuthError> {
    uuid.parse()
        .map_err(|e| AuthError::BleError(format!("Invalid UUID {}: {}", uuid, e)))
}

/// Track `addr` so `do_shutdown` can disconnect it explicitly.
async fn track_device(
    adapter: &bluer::Adapter,
    connected_devices: &Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    addr: bluer::Address,
) {
    match adapter.device(addr) {
        Ok(device) => {
            connected_devices.lock().await.insert(addr, device);
        }
        Err(e) => tracing::warn!("Failed to get device object for {}: {}", addr, e),
    }
}

/// A `NOTIFY`-only characteristic definition wired to `notifier`.
fn notify_definition(notifier: Notifier) -> CharacteristicNotify {
    CharacteristicNotify {
        notify: true,
        indicate: false,
        method: CharacteristicNotifyMethod::Fun(Box::new(move |peer_notifier| {
            let notifier = notifier.clone();
            // Resolve as soon as the notifier is stored: the D-Bus StartNotify
            // call is only answered when this future completes, and the peer's
            // CCCD write waits for that answer.
            Box::pin(async move { notifier.install(peer_notifier).await })
        })),
        _non_exhaustive: (),
    }
}

impl BleTransport {
    /// Create a transport for a post-pairing authentication attempt.
    ///
    /// # Arguments
    /// * `temporal_id` - The 10-byte temporal identifier for BLE advertising
    /// * `csk` - Client Symmetric Key (cached at daemon startup)
    /// * `server_verifiers` - Paired Servers whose signature may answer
    pub async fn new(
        temporal_id: [u8; 10],
        csk: shared::crypto::ClientSymmetricKey,
        server_verifiers: Vec<ServerVerifier>,
    ) -> Result<Self, AuthError> {
        let adapter = Self::connect_adapter().await?;
        Ok(Self::from_adapter(
            adapter,
            Some(AuthState {
                temporal_id,
                csk,
                server_verifiers,
            }),
        ))
    }

    /// Construct a transport purely for pairing (no authentication in flight).
    pub async fn new_for_pairing() -> Result<Self, AuthError> {
        let adapter = Self::connect_adapter().await?;
        Ok(Self::from_adapter(adapter, None))
    }

    /// Create the BlueZ session, pick the first adapter and make sure it is on.
    async fn connect_adapter() -> Result<bluer::Adapter, AuthError> {
        tracing::trace!("BleTransport - initializing BlueZ session");
        let session = bluer::Session::new()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to create BlueZ session: {}", e)))?;

        let adapter_names = session
            .adapter_names()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to get adapter names: {}", e)))?;

        let adapter_name = adapter_names
            .first()
            .ok_or_else(|| AuthError::BleError("No Bluetooth adapter found".to_string()))?;

        let adapter = session
            .adapter(adapter_name)
            .map_err(|e| AuthError::BleError(format!("Failed to get adapter: {}", e)))?;

        // Ensure adapter is powered on; attempt to power it if not.
        match adapter.is_powered().await {
            Ok(true) => tracing::trace!("Adapter already powered"),
            Ok(false) => {
                tracing::info!("Bluetooth adapter is off; attempting to power it on");
                if let Err(e) = adapter.set_powered(true).await {
                    tracing::warn!(
                        "Failed to power on Bluetooth adapter ({}); falling back to UDP",
                        e
                    );
                    return Err(AuthError::BleError(
                        "Bluetooth adapter not powered".to_string(),
                    ));
                } else {
                    tracing::info!("Bluetooth adapter powered on successfully");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to query adapter power state ({}); attempting to power on",
                    e
                );
                if let Err(e2) = adapter.set_powered(true).await {
                    tracing::warn!(
                        "Failed to power on Bluetooth adapter after query error ({}); falling back to UDP",
                        e2
                    );
                    return Err(AuthError::BleError(
                        "Bluetooth adapter not powered".to_string(),
                    ));
                }
            }
        }

        Ok(adapter)
    }

    fn from_adapter(adapter: bluer::Adapter, auth: Option<AuthState>) -> Self {
        Self {
            adapter,
            auth,
            adv_handle: Arc::new(tokio::sync::Mutex::new(None)),
            gatt_handle: Arc::new(tokio::sync::Mutex::new(None)),
            gatt: Arc::new(GattState::new()),
            response_rx: tokio::sync::Mutex::new(None),
            pairing_rx: tokio::sync::Mutex::new(None),
            connected_devices: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            shutdown_started: AtomicBool::new(false),
        }
    }

    /// A pairing-only transport cannot authenticate; say so instead of
    /// advertising the wrong service data.
    fn require_auth(&self, operation: &str) -> Result<&AuthState, AuthError> {
        self.auth.as_ref().ok_or_else(|| {
            AuthError::BleError(format!(
                "BLE transport was created for pairing; {} needs an authentication transport",
                operation
            ))
        })
    }

    /// Register the static four-characteristic GATT service, once, for `mode`.
    ///
    /// Both construction paths register the same four characteristics in the
    /// same order, so a phone's cached handles stay valid across the
    /// pairing-to-authentication transition.
    async fn install_gatt(&self, mode: GattMode) -> Result<(), AuthError> {
        let service_uuid = parse_uuid(SERVICE_UUID)?;
        let client_cmd_uuid = parse_uuid(CLIENT_COMMAND_CHAR_UUID)?;
        let server_resp_uuid = parse_uuid(SERVER_RESPONSE_CHAR_UUID)?;
        let client_conf_uuid = parse_uuid(CLIENT_CONFIRMATION_CHAR_UUID)?;
        let pairing_uuid = parse_uuid(PAIRING_CHAR_UUID)?;

        // Only the active phase's write channel is created; the other
        // characteristic stays registered (handles must not shift) but its
        // writes are dropped instead of queued for a reader that never comes.
        let (response_tx, pairing_tx) = match mode {
            GattMode::Authentication => {
                let (tx, rx) = mpsc::unbounded_channel();
                *self.response_rx.lock().await = Some(rx);
                (Some(tx), None)
            }
            GattMode::Pairing => {
                let (tx, rx) = mpsc::unbounded_channel();
                *self.pairing_rx.lock().await = Some(rx);
                (None, Some(tx))
            }
        };

        let adapter = self.adapter.clone();

        // 1. Client Command Characteristic - Server reads auth request, Client
        //    notifies AuthenticationCancel.
        let command_value = self.gatt.command_value.clone();
        let command_notifier = self.gatt.command_notifier.clone();
        let command_adapter = adapter.clone();
        let command_devices = self.connected_devices.clone();
        let client_cmd_char = Characteristic {
            uuid: client_cmd_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |req| {
                    let value = command_value.clone();
                    let adapter = command_adapter.clone();
                    let connected_devices = command_devices.clone();
                    Box::pin(async move {
                        let addr = req.device_address;
                        track_device(&adapter, &connected_devices, addr).await;
                        let bytes = value.lock().await.clone();
                        tracing::debug!(
                            "GATT: Device {} reading client command ({} bytes)",
                            addr,
                            bytes.len()
                        );
                        Ok(bytes)
                    })
                }),
                ..Default::default()
            }),
            notify: Some(notify_definition(command_notifier)),
            ..Default::default()
        };

        // 2. Server Response Characteristic - Server writes response.
        // Use acknowledged writes (write_without_response: false) so the
        // Android device can fragment the encrypted auth payload (> MTU-3)
        // via GATT Prepare/Execute Long Write sequences.
        let response_adapter = adapter.clone();
        let response_devices = self.connected_devices.clone();
        let server_resp_char = Characteristic {
            uuid: server_resp_uuid,
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: false,
                method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                    let response_tx = response_tx.clone();
                    let adapter = response_adapter.clone();
                    let connected_devices = response_devices.clone();
                    Box::pin(async move {
                        let addr = req.device_address;
                        tracing::info!(
                            "GATT: Received server response ({} bytes) from device {}",
                            new_value.len(),
                            addr
                        );
                        track_device(&adapter, &connected_devices, addr).await;
                        // Hand the frame to `receive_response`; a send error only
                        // means nobody is waiting any more.
                        match response_tx {
                            Some(tx) => {
                                if tx.send(new_value).is_err() {
                                    tracing::debug!("GATT: server response dropped, no receiver");
                                }
                            }
                            None => tracing::debug!(
                                "GATT: server response ignored, transport is in the pairing phase"
                            ),
                        }
                        Ok(())
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        // 3. Client Confirmation Characteristic - Server reads or is notified of
        //    the confirmation.
        let confirmation_value = self.gatt.confirmation_value.clone();
        let confirmation_notifier = self.gatt.confirmation_notifier.clone();
        let client_conf_char = Characteristic {
            uuid: client_conf_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_req| {
                    let value = confirmation_value.clone();
                    Box::pin(async move {
                        let bytes = value.lock().await.clone();
                        tracing::debug!(
                            "GATT: Server reading confirmation ({} bytes)",
                            bytes.len()
                        );
                        Ok(bytes)
                    })
                }),
                ..Default::default()
            }),
            notify: Some(notify_definition(confirmation_notifier)),
            ..Default::default()
        };

        // 4. Pairing Channel Characteristic - one PairingPacket frame per write,
        //    notifications in the other direction.
        let pairing_value = self.gatt.pairing_value.clone();
        let pairing_notifier = self.gatt.pairing_notifier.clone();
        let pairing_read_adapter = self.adapter.clone();
        let pairing_read_devices = self.connected_devices.clone();
        let pairing_write_adapter = self.adapter.clone();
        let pairing_write_devices = self.connected_devices.clone();
        let pairing_value_read = pairing_value.clone();
        let pairing_char = Characteristic {
            uuid: pairing_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |req| {
                    let value = pairing_value_read.clone();
                    let adapter = pairing_read_adapter.clone();
                    let connected_devices = pairing_read_devices.clone();
                    Box::pin(async move {
                        let addr = req.device_address;
                        track_device(&adapter, &connected_devices, addr).await;
                        let bytes = value.lock().await.clone();
                        tracing::debug!(
                            "GATT: Device {} reading pairing frame ({} bytes)",
                            addr,
                            bytes.len()
                        );
                        Ok(bytes)
                    })
                }),
                ..Default::default()
            }),
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: false,
                method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                    let pairing_tx = pairing_tx.clone();
                    let adapter = pairing_write_adapter.clone();
                    let connected_devices = pairing_write_devices.clone();
                    Box::pin(async move {
                        let addr = req.device_address;
                        if new_value.len() > MAX_GATT_PAYLOAD_BYTES {
                            tracing::warn!(
                                "GATT: pairing frame from {} is {} bytes, budget is {}; rejecting",
                                addr,
                                new_value.len(),
                                MAX_GATT_PAYLOAD_BYTES
                            );
                            return Err(ReqError::InvalidValueLength);
                        }
                        tracing::debug!(
                            "GATT: Received pairing frame ({} bytes) from device {}",
                            new_value.len(),
                            addr
                        );
                        track_device(&adapter, &connected_devices, addr).await;
                        match pairing_tx {
                            Some(tx) => {
                                if tx.send(new_value).is_err() {
                                    tracing::debug!("GATT: pairing frame dropped, no receiver");
                                }
                            }
                            None => tracing::debug!(
                                "GATT: pairing frame ignored, transport is authenticating"
                            ),
                        }
                        Ok(())
                    })
                })),
                ..Default::default()
            }),
            notify: Some(notify_definition(pairing_notifier)),
            ..Default::default()
        };

        // Create GATT service. The order of this vector fixes every attribute
        // handle, so it must not depend on which flow registered the service.
        let service = Service {
            uuid: service_uuid,
            primary: true,
            characteristics: vec![
                client_cmd_char,
                server_resp_char,
                client_conf_char,
                pairing_char,
            ],
            ..Default::default()
        };

        let app = Application {
            services: vec![service],
            ..Default::default()
        };

        let app_handle = self
            .adapter
            .serve_gatt_application(app)
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to register GATT server: {}", e)))?;

        *self.gatt_handle.lock().await = Some(app_handle);
        tracing::trace!("GATT server registered (4 characteristics)");
        Ok(())
    }

    /// Register the GATT service if it is not up yet.
    async fn ensure_gatt(&self, mode: GattMode) -> Result<(), AuthError> {
        if self.gatt_handle.lock().await.is_some() {
            return Ok(());
        }
        self.install_gatt(mode).await
    }

    /// Advertise `service_data` under `SERVICE_UUID` and keep the handle.
    ///
    /// The 31-byte legacy budget is why `service_uuids` stays unset: the
    /// 128-bit service-data structure plus the flags already fill it.
    async fn start_advertising(&self, service_data: Vec<u8>) -> Result<(), AuthError> {
        let advertisement = Advertisement {
            service_data: [(parse_uuid(SERVICE_UUID)?, service_data)]
                .into_iter()
                .collect(),
            discoverable: Some(true),
            local_name: Some(String::new()),
            // Balanced advertising: faster than default, but not battery-killing
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(200)),
            ..Default::default()
        };

        // Try multiple times to handle "Busy" errors
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.adapter.advertise(advertisement.clone()).await {
                Ok(handle) => {
                    tracing::trace!("BLE advertising started (attempt {})", attempt);
                    *self.adv_handle.lock().await = Some(handle);
                    return Ok(());
                }
                Err(e) => {
                    // Deterministic failure: BlueZ refuses advertisement
                    // registration outright.  The dominant cause is a
                    // BlueZ/kernel version mismatch — bluetoothd < 5.87 sends
                    // extra bytes in MGMT "Add Extended Advertising Data",
                    // which kernels with strict length validation reject with
                    // "Invalid Parameters", surfacing here as
                    // org.bluez.Error.Failed "Failed to register
                    // advertisement".  Retrying cannot succeed, so bail out
                    // immediately with an actionable message.
                    if e.kind == bluer::ErrorKind::Failed
                        && e.message.contains("register advertisement")
                    {
                        tracing::warn!(
                            "BLE advertising is unavailable on this system: {} \
                             (known BlueZ/kernel incompatibility, see \
                             docs/ble-advertisement-bluez-kernel-mismatch.md). \
                             Fix: upgrade BlueZ to >= 5.87 or boot an older kernel. \
                             Falling back to UDP-only for authentication.",
                            e
                        );
                        return Err(AuthError::BleError(format!(
                            "Failed to start BLE advertising: {} \
                             (see docs/ble-advertisement-bluez-kernel-mismatch.md)",
                            e
                        )));
                    }

                    if attempt == MAX_ATTEMPTS {
                        return Err(AuthError::BleError(format!(
                            "Failed to start BLE advertising after {} attempts: {}",
                            MAX_ATTEMPTS, e
                        )));
                    }

                    let is_busy = e.to_string().contains("Busy") || e.to_string().contains("0x0a");
                    if is_busy {
                        tracing::warn!(
                            "BLE advertising is busy, retrying in 150ms (attempt {}/{})",
                            attempt,
                            MAX_ATTEMPTS
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    } else {
                        tracing::warn!(
                            "Failed to start BLE advertising (attempt {}): {}. Retrying...",
                            attempt,
                            e
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        // Unreachable: every path through the loop either returns or retries,
        // and the last attempt returns.
        Err(AuthError::BleError(
            "Failed to start BLE advertising".to_string(),
        ))
    }

    /// Start a QR-initiated pairing session.
    ///
    /// Registers the `PAIRING_CHAR_UUID` write/notify path (as part of the
    /// static four-characteristic service) and advertises the 10-byte
    /// `pairing_adv_id` as `SERVICE_UUID` service data.
    pub async fn start_pairing(&self, adv_id: [u8; 10]) -> Result<PairingBleSession, AuthError> {
        if self.auth.is_some() {
            return Err(AuthError::BleError(
                "start_pairing needs a transport created by new_for_pairing".to_string(),
            ));
        }

        self.ensure_gatt(GattMode::Pairing).await?;

        // Drop a previous advertisement so phones see the new session only.
        if self.adv_handle.lock().await.take().is_some() {
            tracing::trace!("BLE: replaced the previous advertisement");
        }
        self.start_advertising(adv_id.to_vec()).await?;

        let rx = self.pairing_rx.lock().await.take().ok_or_else(|| {
            AuthError::BleError("the pairing channel is already owned by a session".to_string())
        })?;

        Ok(PairingBleSession {
            adv_id,
            adapter: self.adapter.clone(),
            adv_handle: self.adv_handle.clone(),
            gatt_handle: self.gatt_handle.clone(),
            connected_devices: self.connected_devices.clone(),
            rx,
            value: self.gatt.pairing_value.clone(),
            notifier: self.gatt.pairing_notifier.clone(),
        })
    }

    /// Publish an `AuthenticationCancel` on `CLIENT_COMMAND_CHAR_UUID`: the
    /// readable value first (poll fallback), then a notification so a
    /// subscribed phone does not have to sit out its 5 s disconnect grace.
    async fn publish_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        let mut bytes = Vec::new();
        packet
            .encode(&mut bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode cancel: {}", e)))?;

        *self.gatt.command_value.lock().await = bytes.clone();

        match self.gatt.command_notifier.publish(bytes).await? {
            true => tracing::debug!("GATT: AuthenticationCancel notified"),
            false => tracing::debug!("GATT: AuthenticationCancel stored, peer is not subscribed"),
        }

        // `notify` returns once BlueZ accepted the notification; give the
        // controller a moment to transmit it before the link is torn down.
        tokio::time::sleep(NOTIFY_SETTLE).await;
        Ok(())
    }

    /// Static shutdown implementation operating on cloned handles
    #[cfg_attr(test, allow(dead_code))] // test targets don't resolve trait dispatch call paths
    async fn do_shutdown(
        adapter: bluer::Adapter,
        adv_handle: Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
        gatt_handle: Arc<tokio::sync::Mutex<Option<bluer::gatt::local::ApplicationHandle>>>,
        connected_devices: Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    ) -> Result<(), AuthError> {
        // Step 1 - Disconnect all connected BLE devices
        let mut disconnected_count = 0;
        let mut devices_to_disconnect = connected_devices.lock().await;

        let adapter_clone = adapter.clone();

        for addr in devices_to_disconnect.keys() {
            tracing::debug!("Attempting to explicitly disconnect device {}", addr);

            match adapter_clone.device(*addr) {
                Ok(device) => {
                    if let Err(e) = device.disconnect().await {
                        tracing::warn!("Failed to explicitly disconnect device {}: {}", addr, e);
                    } else {
                        tracing::info!("Successfully disconnected device {}", addr);
                        disconnected_count += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to re-fetch device {} for disconnect: {}", addr, e);
                }
            }
        }

        // Clear tracked devices to avoid retaining stale references
        let tracked = devices_to_disconnect.len();
        devices_to_disconnect.clear();
        drop(devices_to_disconnect);

        if disconnected_count > 0 {
            tracing::debug!("Disconnected {} BLE device(s).", disconnected_count);
        } else if tracked > 0 {
            tracing::warn!(
                "Failed to disconnect any of the {} connected BLE device(s).",
                tracked
            );
        } else {
            tracing::trace!("No connected BLE devices to disconnect.");
        }

        // Step 2 - Stop advertising to prevent new connections
        if adv_handle.lock().await.take().is_some() {
            tracing::trace!("BLE advertising stopped.");
        } else {
            tracing::trace!("BLE advertising was not active or already stopped.");
        }

        // Step 3 - Unregister GATT server to remove services
        if gatt_handle.lock().await.take().is_some() {
            tracing::trace!("BLE GATT server unregistered.");
        } else {
            tracing::trace!("BLE GATT server was not active or already stopped.");
        }

        Ok(())
    }
}

impl Transport for BleTransport {
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        let temporal_id = self.require_auth("send_request")?.temporal_id;

        // Only set up once (on first call)
        if self.adv_handle.lock().await.is_some() {
            // Already set up, nothing to do
            return Ok(());
        }

        let send_start = Instant::now();

        // Encode request packet for GATT characteristic
        let mut request_bytes = Vec::new();
        packet
            .encode(&mut request_bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode request: {}", e)))?;

        // The peer reads the request from CLIENT_COMMAND_CHAR_UUID on connect.
        *self.gatt.command_value.lock().await = request_bytes;

        self.ensure_gatt(GattMode::Authentication).await?;
        self.start_advertising(temporal_id.to_vec()).await?;

        tracing::trace!("send_request completed in {:?}", send_start.elapsed());
        Ok(())
    }

    async fn receive_response(
        &self,
        timeout: Duration,
        csk_meta: &CskMetadata,
    ) -> Result<ReceiveResult, AuthError> {
        let auth = self.require_auth("receive_response")?;

        let mut rx_slot = self.response_rx.lock().await;
        let rx = rx_slot.as_mut().ok_or_else(|| {
            AuthError::BleError("send_request must be called before receive_response".to_string())
        })?;

        let deadline = tokio::time::Instant::now() + timeout;
        tracing::trace!("receive_response started, timeout={:?}", timeout);

        loop {
            // Event-driven: the GATT write callback pushes into this channel, so
            // there is no polling interval to wait out.
            let bytes = match tokio::time::timeout_at(deadline, rx.recv()).await {
                // Timeout - no server answered
                Err(_elapsed) => return Ok(ReceiveResult::Timeout),
                // Every sender is gone: the GATT application was unregistered.
                Ok(None) => return Ok(ReceiveResult::Timeout),
                Ok(Some(bytes)) => bytes,
            };

            tracing::trace!("Processing received BLE response ({} bytes)", bytes.len());

            let encrypted_response = match EncryptedPacket::decode(bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "Failed to decode response: {}, waiting for other devices",
                        e
                    );
                    continue;
                }
            };

            let wrapper = match decrypt_encrypted_packet_with_csk_nonce(
                &auth.csk,
                csk_meta.symmetric_algorithm,
                &encrypted_response,
            ) {
                Ok(wrapper) => wrapper,
                Err(e) => {
                    // This exact phrase is asserted by scripts/test-e2e.sh.
                    tracing::warn!(
                        "Failed to decrypt response packet ({} ciphertext bytes): {}; waiting for other devices",
                        encrypted_response.ciphertext.len(),
                        e
                    );
                    continue;
                }
            };

            // Only a grant or denial signed by a paired Server may conclude the
            // wait; the handler still re-verifies before acting on it.
            let mut accepted = false;
            for verifier in &auth.server_verifiers {
                match verify_and_decode_payload(
                    &wrapper,
                    &verifier.public_key,
                    verifier.signature_algorithm,
                ) {
                    Ok(DecodedPayload::AuthGrant(_)) | Ok(DecodedPayload::AuthDenial(_)) => {
                        accepted = true;
                        break;
                    }
                    Ok(other) => {
                        tracing::warn!("Unexpected message type {:?}, waiting", other);
                    }
                    Err(_) => {}
                }
            }
            if !accepted {
                tracing::warn!(
                    "Response signature did not verify against any paired server; waiting for other devices"
                );
                continue;
            }

            // Both grants and denials are verified by auth_handler. A dummy
            // SocketAddr is used because BLE has no IP addresses.
            tracing::trace!("receive_response returning Response");
            let dummy_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
            return Ok(ReceiveResult::Response(encrypted_response, dummy_addr));
        }
    }

    async fn send_confirmation(
        &self,
        packet: &EncryptedPacket,
        _csk_meta: &CskMetadata,
    ) -> Result<(), AuthError> {
        if self.auth.is_none() {
            return Err(AuthError::BleError(
                "BLE transport was created for pairing; it sends no confirmation".to_string(),
            ));
        }

        let mut bytes = Vec::new();
        packet
            .encode(&mut bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode confirmation: {}", e)))?;

        // The readable value is what a peer that polls READ sees.
        *self.gatt.confirmation_value.lock().await = bytes.clone();

        // Notify immediately: waiting for the phone's 500 ms read poll races the
        // ~410 ms Linux teardown, so the confirmation is pushed instead.
        match self.gatt.confirmation_notifier.publish(bytes).await {
            Ok(true) => tracing::debug!("GATT: GrantConfirmation notified"),
            Ok(false) => {
                tracing::debug!("GATT: GrantConfirmation stored, peer is not subscribed")
            }
            Err(e) => tracing::warn!("GATT: failed to notify GrantConfirmation: {}", e),
        }
        Ok(())
    }

    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Real-time AuthenticationCancel over GATT NOTIFY: a subscribed phone
        // aborts the prompt instead of sitting out the 5 s disconnect grace.
        if self.auth.is_some() {
            if let Err(e) = self.publish_cancel(packet).await {
                tracing::warn!("BLE: failed to publish AuthenticationCancel: {}", e);
            }
        }

        // Ensure idempotent scheduling
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            // Determine grace window from env or default 300ms
            let grace_ms: u64 = std::env::var("TAPAUTH_BLE_GRACE_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(300);

            tracing::debug!(
                "BLE transport: send_cancel called, scheduling cleanup in {} ms",
                grace_ms
            );

            let adapter = self.adapter.clone();
            let adv_handle = self.adv_handle.clone();
            let gatt_handle = self.gatt_handle.clone();
            let connected_devices = self.connected_devices.clone();

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(grace_ms)).await;
                if let Err(e) =
                    BleTransport::do_shutdown(adapter, adv_handle, gatt_handle, connected_devices)
                        .await
                {
                    tracing::warn!("BLE delayed shutdown failed: {}", e);
                } else {
                    tracing::debug!("BLE delayed shutdown completed");
                }
            });
        } else {
            tracing::trace!("BLE transport: send_cancel called, but shutdown already scheduled");
        }

        Ok(())
    }

    async fn finalize(&self) -> Result<(), AuthError> {
        // Trigger immediate background shutdown if not yet started
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            tracing::debug!("BLE transport: finalize called, scheduling immediate cleanup");
            let adapter = self.adapter.clone();
            let adv_handle = self.adv_handle.clone();
            let gatt_handle = self.gatt_handle.clone();
            let connected_devices = self.connected_devices.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    BleTransport::do_shutdown(adapter, adv_handle, gatt_handle, connected_devices)
                        .await
                {
                    tracing::warn!("BLE finalize shutdown failed: {}", e);
                } else {
                    tracing::trace!("BLE finalize shutdown completed");
                }
            });
        } else {
            tracing::trace!("BLE transport: finalize called, but shutdown already scheduled");
        }
        Ok(())
    }
}

/// A BLE pairing session: advertises the 10-byte `pairing_adv_id` as service data
/// on `SERVICE_UUID` and exposes `PAIRING_CHAR_UUID` as a framed in/out channel.
///
/// One `PairingPacket` per GATT write/notification; the payload must fit
/// `MAX_GATT_PAYLOAD_BYTES`.
pub struct PairingBleSession {
    adv_id: [u8; 10],
    adapter: bluer::Adapter,
    adv_handle: Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
    gatt_handle: Arc<tokio::sync::Mutex<Option<bluer::gatt::local::ApplicationHandle>>>,
    connected_devices: Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    rx: UnboundedReceiver<Vec<u8>>,
    value: Arc<tokio::sync::Mutex<Vec<u8>>>,
    notifier: Notifier,
}

impl PairingBleSession {
    /// The 10-byte advertisement identifier this session is broadcasting.
    pub fn adv_id(&self) -> [u8; 10] {
        self.adv_id
    }

    /// Next complete frame written by the peer to `PAIRING_CHAR_UUID`.
    ///
    /// `None` once the transport is gone or the GATT application was
    /// unregistered.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Notify the current `PAIRING_CHAR_UUID` value with `frame`.
    ///
    /// The readable value is updated too, so a peer that has not subscribed yet
    /// can still read the frame.
    pub async fn send(&mut self, frame: &[u8]) -> Result<(), AuthError> {
        if frame.len() > MAX_GATT_PAYLOAD_BYTES {
            return Err(AuthError::BleError(format!(
                "pairing frame is {} bytes, BLE GATT budget is {}",
                frame.len(),
                MAX_GATT_PAYLOAD_BYTES
            )));
        }

        *self.value.lock().await = frame.to_vec();

        match self.notifier.publish(frame.to_vec()).await {
            Ok(true) => tracing::debug!("GATT: pairing frame notified ({} bytes)", frame.len()),
            Ok(false) => tracing::debug!(
                "GATT: pairing frame stored ({} bytes), peer is not subscribed",
                frame.len()
            ),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Wait long enough for the frame just published to reach the air.
    ///
    /// [`PairingBleSession::stop`] disconnects the phone and unregisters the GATT
    /// application over the same D-Bus connection, so a notification sent right
    /// before it is dropped by the controller instead of transmitted
    /// ([`NOTIFY_SETTLE`], the same pause `publish_cancel` takes).
    pub async fn settle(&self) {
        tokio::time::sleep(NOTIFY_SETTLE).await;
    }

    /// Stop advertising and unregister the pairing path.
    pub async fn stop(self) {
        tracing::debug!("BLE pairing session {} closed", hex::encode(self.adv_id()));
        if let Err(e) = BleTransport::do_shutdown(
            self.adapter,
            self.adv_handle,
            self.gatt_handle,
            self.connected_devices,
        )
        .await
        {
            tracing::warn!("BLE pairing session shutdown failed: {}", e);
        }
    }
}

impl Drop for BleTransport {
    fn drop(&mut self) {
        // Note: The handles (adv_handle, gatt_handle) will be dropped here
        // automatically by Rust, which cleans up the adv/GATT server.
        tracing::debug!("BLE transport explicitly closed, cleaning up resources.");

        if let Some(mutex) = Arc::get_mut(&mut self.connected_devices) {
            let map = mutex.get_mut();
            let device_count = map.len();

            if device_count > 0 {
                tracing::warn!(
                    "BleTransport dropped with {} connected device(s) still tracked. \
                     Call send_cancel() for explicit cleanup.",
                    device_count
                );
            }
        } else {
            // Devices are still shared, meaning a task might still be running.
            // We can't easily clean up here without a more complex shutdown mechanism.
            tracing::trace!(
                "BleTransport dropped. Handles will be released. \
                Cannot check for connected devices as Arc is still shared."
            );
        }
    }
}
