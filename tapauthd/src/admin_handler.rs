use crate::auth_handler::DaemonState;
use crate::peer_identity::{check_authorization, resolve_peer};
use shared::ipc::pb as ipc;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::transport::EnabledTransports;

mod device;
mod pairing;
mod response;

use device::{
    handle_get_config, handle_get_daemon_status, handle_get_servers, handle_recover_tpm,
    handle_remove_device, handle_rotate_csk, handle_save_config,
};
use pairing::{
    handle_cancel_pairing, handle_complete_pairing, handle_start_pairing, handle_wait_for_pairing,
};
use response::err_resp;

pub use crate::pairing::PairingState;

/// What one admin arm decided: the reply, and whether it changed daemon state.
///
/// The fact is carried by the type rather than by a boolean beside the reply, so "this request
/// mutates state" is a property of the arm that answers it. A new mutating request has to say
/// [`Handled::Mutated`]; writing [`Handled::Read`] instead is a visible classification error
/// instead of a tuple slot nobody remembered, and the reload itself lives in exactly one `match`
/// ([`settle`]) instead of one boolean per row.
enum Handled {
    /// The request only read state: the in-memory snapshot is still current.
    Read(ipc::AdminResponse),
    /// The request changed on-disk state, so the daemon must reload before the next reader.
    Mutated(ipc::AdminResponse),
}

/// Turn a dispatched request into its reply: reload the daemon exactly once when the arm that
/// answered changed state, and never otherwise.
///
/// This is the single site where the two classes differ, and the `match` is exhaustive, so a third
/// class cannot be added without deciding here what it does to the daemon. `reload` is a parameter
/// rather than a direct call so a unit test can count it.
async fn settle(handled: Handled, reload: impl Future<Output = ()>) -> ipc::AdminResponse {
    match handled {
        Handled::Read(response) => response,
        Handled::Mutated(response) => {
            reload.await;
            response
        }
    }
}

pub async fn handle_admin_request(
    request: ipc::AdminRequest,
    daemon_lock: &RwLock<Arc<DaemonState>>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    caller_pid: i32,
    caller_uid: u32,
) -> ipc::AdminResponse {
    let daemon = daemon_lock.read().await.clone();
    let identity = match resolve_peer(caller_pid, caller_uid) {
        Ok(id) => id,
        Err(e) => return err_resp(ipc::AdminStatus::AdminError, e.to_string()),
    };

    // Daemon-side PolKit authorization: the daemon calls CheckAuthorization
    // using the peer's PID/start-time as the subject.  This is the canonical
    // enforcement point — no client can bypass it by skipping their own
    // PolKit check.  The tapauthd user must be registered as an action owner
    // via org.freedesktop.policykit.owner in the policy file.
    if let Err(e) = check_authorization(&identity).await {
        tracing::warn!(
            "Unauthorized admin request from uid={} (pid={}, user={}): {}",
            identity.uid,
            identity.pid,
            identity.username,
            e
        );
        return err_resp(ipc::AdminStatus::AdminUnauthorized, e.to_string());
    }

    let username = identity.username;

    settle(
        dispatch(request, &daemon, pairing_state, &username).await,
        async {
            let new_daemon = daemon.reload();
            *daemon_lock.write().await = new_daemon;
            tracing::info!("Daemon state reloaded after admin operation");
        },
    )
    .await
}

/// Dispatch one authorized admin request to its handler, naming the class of every arm.
///
/// Each arm says whether the request changed state ([`Handled`]); the reload that follows is
/// [`settle`]'s single job. There is deliberately no `Some(_)` catch-all, so a new payload variant
/// does not compile until it is given a class.
async fn dispatch(
    request: ipc::AdminRequest,
    daemon: &Arc<DaemonState>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    username: &str,
) -> Handled {
    match request.payload {
        Some(ipc::admin_request::Payload::GetServers(_)) => {
            Handled::Read(handle_get_servers(daemon, username).await)
        }
        Some(ipc::admin_request::Payload::StartPairing(_)) => {
            // The toggles are read per request, like `AuthSession::handle_authenticate`
            // does, so a change made in the GUI takes effect on the next attempt
            // without a daemon restart.
            let transports = EnabledTransports::from_config();
            Handled::Read(handle_start_pairing(daemon, pairing_state, transports).await)
        }
        Some(ipc::admin_request::Payload::WaitForPairing(req)) => {
            Handled::Read(handle_wait_for_pairing(pairing_state, req).await)
        }
        Some(ipc::admin_request::Payload::CompletePairing(req)) => {
            Handled::Mutated(handle_complete_pairing(daemon, pairing_state, username, req).await)
        }
        Some(ipc::admin_request::Payload::CancelPairing(req)) => {
            Handled::Read(handle_cancel_pairing(pairing_state, req).await)
        }
        Some(ipc::admin_request::Payload::RemoveDevice(req)) => {
            Handled::Mutated(handle_remove_device(daemon, username, req).await)
        }
        Some(ipc::admin_request::Payload::RotateCsk(_)) => {
            Handled::Mutated(handle_rotate_csk(daemon).await)
        }
        Some(ipc::admin_request::Payload::SaveConfig(req)) => {
            Handled::Mutated(handle_save_config(daemon, req).await)
        }
        Some(ipc::admin_request::Payload::RecoverTpm(_)) => {
            Handled::Mutated(handle_recover_tpm(daemon).await)
        }
        Some(ipc::admin_request::Payload::GetConfig(_)) => {
            Handled::Read(handle_get_config(daemon).await)
        }
        Some(ipc::admin_request::Payload::GetDaemonStatus(_)) => {
            Handled::Read(handle_get_daemon_status(daemon).await)
        }
        None => Handled::Read(err_resp(
            ipc::AdminStatus::AdminError,
            "Empty admin request",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::pairing::cancel_outcome;
    use super::*;

    /// `CancelPairing` after the worker already retired is a success, while a
    /// real failure keeps its error answer.
    ///
    /// The defect this catches: mapping every `request_cancellation` error to the
    /// success reply would report a genuine timeout as "cancelled"; mapping
    /// `Ended` back to an error makes the GUI show "Failed to cancel the pairing
    /// session" for a session that ended by itself — the race the deferred
    /// terminal phase widens, because `is_ended()` only becomes true once the
    /// teardown has finished.
    #[test]
    fn a_cancellation_that_races_teardown_is_a_success_and_a_real_failure_is_not() {
        // The worker answered the cancel.
        let answered = cancel_outcome(Ok(()));
        assert_eq!(answered.status, ipc::AdminStatus::AdminSuccess as i32);
        assert_eq!(answered.error_message, "");
        assert!(matches!(
            answered.payload,
            Some(ipc::admin_response::Payload::CancelPairing(_))
        ));

        // The worker retired between the phase check and the command.
        let raced = cancel_outcome(Err(crate::pairing::PairingError::Ended(
            "the pairing worker is gone".to_string(),
        )));
        assert_eq!(raced.status, ipc::AdminStatus::AdminSuccess as i32);
        assert_eq!(raced.error_message, "");

        // A genuine failure keeps the error answer, with the reason.
        let failed = cancel_outcome(Err(crate::pairing::PairingError::Timeout));
        assert_eq!(failed.status, ipc::AdminStatus::AdminError as i32);
        assert!(
            failed
                .error_message
                .contains("Failed to cancel the pairing session"),
            "unexpected message: {}",
            failed.error_message
        );
        assert!(
            failed.error_message.contains("Timed out"),
            "the reason must survive into the reply: {}",
            failed.error_message
        );
        assert!(failed.payload.is_none());
    }

    /// `StartPairing` must be refused when no transport can work, before anything
    /// is keyed, bound or spawned.
    ///
    /// The defects this catches: `handle_start_pairing` starting a session from a
    /// configuration with the network transport off and BLE unavailable — the
    /// worker then has no socket and no advertisement, so nothing can ever reach
    /// it, `WaitForPairing` holds the GUI until the session expires and the user is
    /// left with a QR code (and a "pairing in progress" handle) that cannot work.
    /// The reply's wording is asserted, not just its status, so a refusal that
    /// reports some other failure does not pass.
    #[tokio::test]
    async fn start_pairing_without_any_transport_is_refused() {
        let daemon = Arc::new(DaemonState {
            config_manager: Arc::new(shared::config::ClientConfigManager::new()),
            paired_servers: Arc::new(std::collections::HashMap::new()),
            keypair: None,
            csk: None,
            hostname: "host".to_string(),
            udp_socket: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            init_error: None,
        });
        let pairing_state: Arc<Mutex<Option<PairingState>>> = Arc::new(Mutex::new(None));

        let refusal = handle_start_pairing(
            &daemon,
            &pairing_state,
            EnabledTransports::new(false, false),
        )
        .await;

        assert_eq!(
            refusal.status,
            ipc::AdminStatus::AdminError as i32,
            "a session with no transport must not be started"
        );
        assert_eq!(
            refusal.error_message, "All transports (BLE and Local Network) are disabled",
            "the refusal must name the cause the way the PAM side does"
        );
        assert!(
            refusal.payload.is_none(),
            "a refused StartPairing must not hand out a QR code or a port"
        );
        assert!(
            pairing_state.lock().await.is_none(),
            "no session may be registered for a configuration nothing can reach"
        );
    }

    /// A mutating request reloads the daemon exactly once, a read-only one never — and the two
    /// classes come from the arm that answered, through [`settle`].
    ///
    /// The defect this catches: a mutating arm written as `Handled::Read` (the old "forgot
    /// `true` in the tuple slot"), so `CompletePairing` persists the device and the daemon keeps
    /// serving the snapshot it built before the pairing, `RemoveDevice` leaves the removed server
    /// able to authenticate, and `SaveConfig`'s transport toggles never reach the next attempt —
    /// with no error anywhere. It also catches the opposite direction: a read that reloads, which
    /// dirties the in-memory snapshot for a request that changed nothing.
    #[tokio::test]
    async fn only_a_mutating_request_reloads_the_daemon() {
        let daemon = Arc::new(DaemonState {
            config_manager: Arc::new(shared::config::ClientConfigManager::new()),
            paired_servers: Arc::new(std::collections::HashMap::new()),
            keypair: None,
            csk: None,
            hostname: "host".to_string(),
            udp_socket: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            init_error: None,
        });
        let pairing_state: Arc<Mutex<Option<PairingState>>> = Arc::new(Mutex::new(None));
        let reloads = std::sync::atomic::AtomicUsize::new(0);
        let count_one_reload = || async {
            reloads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };

        // A read: answered from the in-memory snapshot, so nothing is reloaded.
        let read = dispatch(
            ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::GetDaemonStatus(
                    ipc::GetDaemonStatusRequest {},
                )),
            },
            &daemon,
            &pairing_state,
            "luca",
        )
        .await;
        let read_reply = settle(read, count_one_reload()).await;
        assert_eq!(read_reply.status, ipc::AdminStatus::AdminSuccess as i32);
        assert!(
            matches!(
                read_reply.payload,
                Some(ipc::admin_response::Payload::GetDaemonStatus(_))
            ),
            "the read must be answered by its own handler"
        );
        assert_eq!(
            reloads.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a read-only request must not reload the daemon"
        );

        // A mutation: with no pairing session pending the handler answers an error, and the class
        // is about what the arm does to state, not about whether it succeeded — a failed mutation
        // may still have written something.
        let mutated = dispatch(
            ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::CompletePairing(
                    ipc::CompletePairingRequest { port: 0 },
                )),
            },
            &daemon,
            &pairing_state,
            "luca",
        )
        .await;
        let mutated_reply = settle(mutated, count_one_reload()).await;
        assert_eq!(
            mutated_reply.status,
            ipc::AdminStatus::AdminError as i32,
            "there is no pairing session to complete"
        );
        assert_eq!(
            reloads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a mutating request must reload the daemon exactly once"
        );
    }
}
