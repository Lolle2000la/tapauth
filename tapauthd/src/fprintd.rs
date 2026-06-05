use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

use crate::auth_handler::DaemonState;

const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";
const FPRINT_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINT_DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

// ── AuthState: bridge between the D-Bus mock device and the existing auth handler ──

#[derive(Clone)]
pub struct AuthState {
    pub daemon: Arc<DaemonState>,
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
    verifying: Arc<Mutex<bool>>,
    cancel_token: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

impl VirtualFprintDevice {
    fn new(auth_state: AuthState, connection: zbus::Connection) -> Self {
        Self {
            auth_state,
            connection,
            claimed_user: Arc::new(Mutex::new(None)),
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
        _username: String,
    ) -> Result<Vec<String>, zbus::fdo::Error> {
        let servers = {
            let arc = self.auth_state.daemon.paired_servers.clone();
            Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone())
        };
        if servers.is_empty() {
            return Err(zbus::fdo::Error::Failed(
                "net.reactivated.Fprint.Error.NoEnrolledPrints".to_string(),
            ));
        }
        Ok(vec!["right-index-finger".to_string()])
    }

    async fn claim(&self, username: String) -> Result<(), zbus::fdo::Error> {
        let mut claimed = self.claimed_user.lock().await;
        if claimed.is_some() {
            return Err(zbus::fdo::Error::Failed(
                "net.reactivated.Fprint.Error.AlreadyInUse".to_string(),
            ));
        }
        *claimed = Some(username);
        Ok(())
    }

    async fn release(&self) -> Result<(), zbus::fdo::Error> {
        let mut claimed = self.claimed_user.lock().await;
        *claimed = None;
        Ok(())
    }

    async fn verify_start(&self, _finger_name: String) -> Result<(), zbus::fdo::Error> {
        let is_healthy = self.auth_state.daemon.is_healthy();
        if !is_healthy {
            let init_err = self
                .auth_state
                .daemon
                .get_init_error()
                .unwrap_or("unknown configuration error");
            tracing::warn!("fprintd verify_start: daemon not healthy: {}", init_err);
            return Err(zbus::fdo::Error::Failed(
                "net.reactivated.Fprint.Error.Internal".to_string(),
            ));
        }

        {
            let mut v = self.verifying.lock().await;
            if *v {
                return Err(zbus::fdo::Error::Failed(
                    "net.reactivated.Fprint.Error.AlreadyInUse".to_string(),
                ));
            }
            *v = true;
        }

        let connection = self.connection.clone();
        let auth_state = self.auth_state.clone();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        {
            let mut token = self.cancel_token.lock().await;
            *token = Some(cancel_tx);
        }

        tokio::spawn(async move {
            let _ = run_verify(connection, auth_state, cancel_rx).await;
        });

        Ok(())
    }

    async fn verify_stop(&self) -> Result<(), zbus::fdo::Error> {
        let mut v = self.verifying.lock().await;
        *v = false;

        let mut token = self.cancel_token.lock().await;
        if let Some(tx) = token.take() {
            let _ = tx.send(());
        }

        Ok(())
    }
}

async fn run_verify(
    connection: zbus::Connection,
    auth_state: AuthState,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let username = {
        let arc = auth_state.daemon.paired_servers.clone();
        let servers = Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone());
        if let Some(first) = servers.values().next() {
            first
                .allowed_users
                .first()
                .cloned()
                .unwrap_or_else(|| "default".to_string())
        } else {
            "default".to_string()
        }
    };

    let session = match crate::auth_handler::AuthSession::new(auth_state.daemon.clone(), username) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("fprintd: failed to create auth session: {}", e);
            emit_status(&connection, "verify-unknown-error", true).await;
            return Ok(());
        }
    };

    let cancel_registry = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let (reg_tx, reg_rx) = tokio::sync::oneshot::channel::<()>();
    {
        let mut reg = cancel_registry.lock().await;
        reg.insert("fprintd-verify".to_string(), reg_tx);
    }

    let auth_fut =
        session.handle_authenticate(None, Some("fprintd-verify".to_string()), cancel_registry);

    let result = tokio::select! {
        res = auth_fut => res,
        _ = cancel_rx => {
            drop(reg_rx);
            Err(crate::auth_handler::AuthHandlerError::Denied)
        }
    };

    let (status, done) = match result {
        Ok(response) => {
            let outcome = shared::ipc::pb::PamOutcome::try_from(response.outcome);
            match outcome {
                Ok(shared::ipc::pb::PamOutcome::Success) => ("verify-match", true),
                Ok(shared::ipc::pb::PamOutcome::Denied) => ("verify-no-match", true),
                _ => ("verify-unknown-error", true),
            }
        }
        Err(ref e) => {
            tracing::warn!("fprintd: auth error: {}", e);
            ("verify-unknown-error", true)
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

// ── Service startup ──

pub async fn start_fprintd_service(
    auth_state: AuthState,
) -> Result<zbus::Connection, Box<dyn std::error::Error>> {
    let connection = zbus::Connection::system().await?;
    connection
        .request_name(FPRINT_BUS_NAME)
        .await
        .map_err(|e| format!("fprintd request_name: {}", e))?;

    connection
        .object_server()
        .at(
            FPRINT_MANAGER_PATH,
            FprintManager::new().map_err(|e| format!("fprintd manager init: {}", e))?,
        )
        .await
        .map_err(|e| format!("fprintd register manager: {}", e))?;

    connection
        .object_server()
        .at(
            FPRINT_DEVICE_PATH,
            VirtualFprintDevice::new(auth_state, connection.clone()),
        )
        .await
        .map_err(|e| format!("fprintd register device: {}", e))?;

    tracing::info!(
        "Registered fprintd mock at {} and {}",
        FPRINT_MANAGER_PATH,
        FPRINT_DEVICE_PATH
    );

    Ok(connection)
}
