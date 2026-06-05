use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

use crate::auth_handler::DaemonState;

const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";
const FPRINT_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINT_DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

// ── AuthState: bridge between the D-Bus mock device and the existing auth handler ──

/// D-Bus error types matching the upstream fprintd specification.
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
enum FprintError {
    AlreadyInUse(String),
    ClaimDevice(String),
    Internal(String),
    NoEnrolledPrints(String),
    NoActionInProgress(String),
    PermissionDenied(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

#[derive(Clone)]
pub struct AuthState {
    /// Shared daemon state via RwLock so fprintd always sees the latest
    /// reloaded state after admin mutations (pairing, CSK rotation, etc.).
    pub daemon: Arc<RwLock<Arc<DaemonState>>>,
}

impl AuthState {
    async fn read(&self) -> Arc<DaemonState> {
        self.daemon.read().await.clone()
    }
}

// ── Manager interface ──

pub struct FprintManager {
    device_path: OwnedObjectPath,
}

impl FprintManager {
    fn new() -> Result<Self, zbus::Error> {
        let device_path = OwnedObjectPath::try_from(FPRINT_DEVICE_PATH)
            .map_err(|e| zbus::Error::Failure(format!("invalid device path: {}", e)))?;
        Ok(Self { device_path })
    }
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl FprintManager {
    async fn get_default_device(&self) -> OwnedObjectPath {
        self.device_path.clone()
    }

    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![self.device_path.clone()]
    }
}

// ── Device interface ──

pub struct VirtualFprintDevice {
    auth_state: AuthState,
    connection: zbus::Connection,
    claimed_user: Arc<Mutex<Option<String>>>,
    claimed_owner: Arc<Mutex<Option<String>>>,
    verifying: Arc<Mutex<bool>>,
    cancel_token: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

impl VirtualFprintDevice {
    fn new(auth_state: AuthState, connection: zbus::Connection) -> Self {
        Self {
            auth_state,
            connection,
            claimed_user: Arc::new(Mutex::new(None)),
            claimed_owner: Arc::new(Mutex::new(None)),
            verifying: Arc::new(Mutex::new(false)),
            cancel_token: Arc::new(Mutex::new(None)),
        }
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl VirtualFprintDevice {
    #[zbus(property)]
    async fn name(&self) -> String {
        "TapAuth Virtual Biometric Loop".to_string()
    }

    #[zbus(property, name = "scan-type")]
    async fn scan_type(&self) -> String {
        "press".to_string()
    }

    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        -1
    }

    #[zbus(property, name = "finger-present")]
    async fn finger_present(&self) -> bool {
        false
    }

    #[zbus(property, name = "finger-needed")]
    async fn finger_needed(&self) -> bool {
        let verifying = self.verifying.lock().await;
        *verifying
    }

    async fn list_enrolled_fingers(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: String,
    ) -> Result<Vec<String>, FprintError> {
        let sender = match header.sender() {
            Some(s) => s.clone(),
            None => {
                return Err(FprintError::Internal(
                    "Cannot determine caller identity".to_string(),
                ));
            }
        };
        let caller_uid = resolve_sender_uid(connection, &sender).await?;

        let target_user = if username.is_empty() {
            match self.claimed_user.lock().await.clone() {
                Some(u) => u,
                None => {
                    return Err(FprintError::ClaimDevice(
                        "Device must be claimed before listing enrolled fingers".to_string(),
                    ));
                }
            }
        } else if caller_uid != 0 {
            let target_uid = nix::unistd::User::from_name(&username)
                .map_err(|e| {
                    FprintError::Internal(format!("Failed to query user database: {}", e))
                })?
                .map(|u| u.uid.as_raw())
                .ok_or_else(|| {
                    FprintError::ClaimDevice(format!("User '{}' does not exist", username))
                })?;
            if caller_uid != target_uid {
                return Err(FprintError::PermissionDenied(format!(
                    "Caller is not authorized to list enrolled fingers for '{}'",
                    username
                )));
            }
            username
        } else {
            username
        };

        let state = self.auth_state.read().await;
        let has_authorized = state
            .paired_servers
            .values()
            .any(|s| s.is_user_allowed(&target_user));

        if !has_authorized {
            return Err(FprintError::NoEnrolledPrints(format!(
                "No paired devices configured for user '{}'",
                target_user
            )));
        }
        Ok(vec!["right-index-finger".to_string()])
    }

    async fn claim(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::message::Header<'_>,
        username: String,
    ) -> Result<(), FprintError> {
        let sender = match header.sender() {
            Some(s) => s.clone(),
            None => {
                return Err(FprintError::Internal(
                    "Cannot determine caller identity".to_string(),
                ));
            }
        };

        let caller_uid = resolve_sender_uid(connection, &sender).await?;

        let target_username = if username.is_empty() {
            nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(caller_uid))
                .map_err(|e| {
                    FprintError::Internal(format!(
                        "Failed to query caller UID {}: {}",
                        caller_uid, e
                    ))
                })?
                .ok_or_else(|| {
                    FprintError::Internal(format!("No user entry for UID {}", caller_uid))
                })?
                .name
        } else {
            username
        };

        if caller_uid != 0 {
            let caller_name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(caller_uid))
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_else(|| "unknown".to_string());

            if caller_name != target_username {
                return Err(FprintError::ClaimDevice(format!(
                    "Caller '{}' (UID {}) is not authorized to claim the device for user '{}'",
                    caller_name, caller_uid, target_username
                )));
            }
        }

        let mut claimed = self.claimed_user.lock().await;
        if let Some(ref existing) = *claimed {
            if existing == &target_username {
                return Ok(());
            }
            return Err(FprintError::AlreadyInUse(
                "Device is already claimed".to_string(),
            ));
        }
        *claimed = Some(target_username);
        *self.claimed_owner.lock().await = Some(sender.to_string());
        Ok(())
    }

    async fn release(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = match header.sender() {
            Some(s) => s.to_string(),
            None => {
                return Err(FprintError::Internal(
                    "Cannot determine caller identity".to_string(),
                ));
            }
        };

        let mut claimed = self.claimed_user.lock().await;
        if claimed.is_none() {
            return Err(FprintError::ClaimDevice(
                "Device was not claimed".to_string(),
            ));
        }
        let owner = self.claimed_owner.lock().await;
        if let Some(ref existing_owner) = *owner {
            if existing_owner != &sender {
                return Err(FprintError::ClaimDevice(
                    "Caller is not the owner of the claim".to_string(),
                ));
            }
        }
        drop(owner);

        let v = self.verifying.lock().await;
        if *v {
            return Err(FprintError::AlreadyInUse(
                "Cannot release while verification is in progress".to_string(),
            ));
        }
        drop(v);
        *claimed = None;
        *self.claimed_owner.lock().await = None;
        Ok(())
    }

    async fn verify_start(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        _finger_name: String,
    ) -> Result<(), FprintError> {
        let sender = match header.sender() {
            Some(s) => s.to_string(),
            None => {
                return Err(FprintError::Internal(
                    "Cannot determine caller identity".to_string(),
                ));
            }
        };

        let owner = self.claimed_owner.lock().await;
        match *owner {
            Some(ref existing_owner) => {
                if existing_owner != &sender {
                    return Err(FprintError::ClaimDevice(
                        "Caller is not the owner of the claim".to_string(),
                    ));
                }
            }
            None => {
                return Err(FprintError::ClaimDevice(
                    "Device must be claimed before starting verification".to_string(),
                ));
            }
        }
        drop(owner);
        let state = self.auth_state.read().await;

        if !state.is_healthy() {
            let init_err = state
                .get_init_error()
                .unwrap_or("unknown configuration error");
            tracing::warn!("fprintd verify_start: daemon not healthy: {}", init_err);
            return Err(FprintError::Internal(init_err.to_string()));
        }

        if state.paired_servers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(
                "No paired devices configured".to_string(),
            ));
        }

        let username = {
            let claimed = self.claimed_user.lock().await;
            match claimed.clone() {
                Some(u) => u,
                None => {
                    return Err(FprintError::ClaimDevice(
                        "Device must be claimed before starting verification".to_string(),
                    ));
                }
            }
        };

        let has_authorized = state
            .paired_servers
            .values()
            .any(|s| s.is_user_allowed(&username));
        if !has_authorized {
            return Err(FprintError::NoEnrolledPrints(format!(
                "No paired devices authorized for user '{}'",
                username
            )));
        }

        let connection = self.connection.clone();
        let auth_state = self.auth_state.clone();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        {
            let mut v = self.verifying.lock().await;
            if *v {
                return Err(FprintError::AlreadyInUse(
                    "Verification already in progress".to_string(),
                ));
            }
            *v = true;
            let mut token = self.cancel_token.lock().await;
            *token = Some(cancel_tx);
        }

        let verifying = self.verifying.clone();
        let cancel_token = self.cancel_token.clone();

        let finger_name = if _finger_name == "any" {
            "right-index-finger".to_string()
        } else {
            _finger_name.clone()
        };
        if let Err(e) = connection
            .emit_signal(
                Option::<&str>::None,
                FPRINT_DEVICE_PATH,
                "net.reactivated.Fprint.Device",
                "VerifyFingerSelected",
                &finger_name,
            )
            .await
        {
            tracing::warn!("fprintd: failed to emit VerifyFingerSelected: {}", e);
        }

        tokio::spawn(async move {
            let _ = run_verify(connection, auth_state, username, cancel_rx).await;
            *verifying.lock().await = false;
            *cancel_token.lock().await = None;
        });

        Ok(())
    }

    async fn verify_stop(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = match header.sender() {
            Some(s) => s.to_string(),
            None => {
                return Err(FprintError::Internal(
                    "Cannot determine caller identity".to_string(),
                ));
            }
        };

        let owner = self.claimed_owner.lock().await;
        match *owner {
            Some(ref existing_owner) => {
                if existing_owner != &sender {
                    return Err(FprintError::ClaimDevice(
                        "Caller is not the owner of the claim".to_string(),
                    ));
                }
            }
            None => {
                return Err(FprintError::ClaimDevice(
                    "Device must be claimed before stopping verification".to_string(),
                ));
            }
        }
        drop(owner);
        {
            let claimed = self.claimed_user.lock().await;
            if claimed.is_none() {
                return Err(FprintError::ClaimDevice(
                    "Device must be claimed before stopping verification".to_string(),
                ));
            }
        }

        let mut v = self.verifying.lock().await;
        if !*v {
            return Err(FprintError::NoActionInProgress(
                "No verification in progress".to_string(),
            ));
        }
        *v = false;

        let mut token = self.cancel_token.lock().await;
        if let Some(tx) = token.take() {
            let _ = tx.send(());
        }

        Ok(())
    }

    #[zbus(signal)]
    async fn verify_finger_selected(
        signal_emitter: &zbus::object_server::SignalEmitter<'_>,
        finger_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        signal_emitter: &zbus::object_server::SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

async fn run_verify(
    connection: zbus::Connection,
    auth_state: AuthState,
    username: String,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = auth_state.read().await;
    let session = match crate::auth_handler::AuthSession::new(state, username) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("fprintd: failed to create auth session: {}", e);
            emit_status(&connection, "verify-unknown-error", true).await;
            return Ok(());
        }
    };

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_registry: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let cancel_registry_c = cancel_registry.clone();
    let cancelled_c = cancelled.clone();
    let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = cancel_rx.await;
        cancelled_c.store(true, Ordering::SeqCst);
        let mut reg = cancel_registry_c.lock().await;
        if let Some(tx) = reg.remove("fprintd-verify") {
            let _ = tx.send(());
        }
        let _ = cancel_done_tx.send(());
    });

    let mut auth_fut = Box::pin(session.handle_authenticate(
        None,
        Some("fprintd-verify".to_string()),
        cancel_registry,
    ));

    let result = tokio::select! {
        res = &mut auth_fut => Some(res),
        _ = cancel_done_rx => {
            // Cancel was signaled; grant a 250ms grace period for
            // background transports to clean up before dropping.
            tokio::select! {
                res = &mut auth_fut => Some(res),
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => None,
            }
        }
    };

    if cancelled.load(Ordering::SeqCst) {
        return Ok(());
    }

    let (status, done) = match result {
        Some(Ok(response)) => {
            let outcome = shared::ipc::pb::PamOutcome::try_from(response.outcome);
            match outcome {
                Ok(shared::ipc::pb::PamOutcome::Success) => ("verify-match", true),
                Ok(shared::ipc::pb::PamOutcome::Denied) => ("verify-no-match", true),
                _ => ("verify-unknown-error", true),
            }
        }
        Some(Err(ref e)) => {
            tracing::warn!("fprintd: auth error: {}", e);
            ("verify-unknown-error", true)
        }
        None => {
            return Ok(());
        }
    };

    emit_status(&connection, status, done).await;
    Ok(())
}

async fn emit_status(connection: &zbus::Connection, result: &str, done: bool) {
    if let Err(e) = connection
        .emit_signal(
            Option::<&str>::None,
            FPRINT_DEVICE_PATH,
            "net.reactivated.Fprint.Device",
            "VerifyStatus",
            &(result, done),
        )
        .await
    {
        tracing::error!("fprintd: failed to emit VerifyStatus signal: {}", e);
    }
}

// ── Helpers ──

async fn resolve_sender_uid(
    connection: &zbus::Connection,
    sender: &zbus::names::UniqueName<'_>,
) -> Result<u32, FprintError> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixUser",
            &(sender.to_string(),),
        )
        .await
        .map_err(|e| FprintError::Internal(format!("Failed to query caller UID: {}", e)))?;

    let body = reply.body();
    let uid: u32 = body
        .deserialize()
        .map_err(|e| FprintError::Internal(format!("Failed to parse caller UID: {}", e)))?;

    Ok(uid)
}

// ── Service startup ──

pub async fn start_fprintd_service(
    auth_state: AuthState,
) -> Result<zbus::Connection, Box<dyn std::error::Error>> {
    let connection = zbus::connection::Builder::system()?
        .serve_at(
            FPRINT_MANAGER_PATH,
            FprintManager::new().map_err(|e| format!("fprintd manager init: {}", e))?,
        )
        .map_err(|e| format!("fprintd serve_at manager: {}", e))?
        .build()
        .await
        .map_err(|e| format!("fprintd build: {}", e))?;

    // Register the device object *before* acquiring the well-known name
    // so there is no window where clients see the name without the device.
    connection
        .object_server()
        .at(
            FPRINT_DEVICE_PATH,
            VirtualFprintDevice::new(auth_state, connection.clone()),
        )
        .await
        .map_err(|e| format!("fprintd register device: {}", e))?;

    connection
        .request_name(FPRINT_BUS_NAME)
        .await
        .map_err(|e| format!("fprintd request_name: {}", e))?;

    tracing::info!(
        "Registered fprintd mock at {} and {}",
        FPRINT_MANAGER_PATH,
        FPRINT_DEVICE_PATH
    );

    Ok(connection)
}
