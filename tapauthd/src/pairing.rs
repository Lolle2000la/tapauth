//! Unified UDP + BLE pairing session (protocol v2).
//!
//! `admin_handler` owns the IPC surface (`StartPairing` / `WaitForPairing` /
//! `CompletePairing` / `CancelPairing`); this module owns the one running
//! session: the ephemeral dual-stack UDP socket, the BLE pairing advertisement,
//! the retransmission schedule and the `ServerPairingState` handshake machine
//! from `shared::protocol::pairing`.
//!
//! ## Role inversion
//!
//! TapAuth's *Client* is the Linux desktop, so the desktop runs the protocol
//! **Client** half of pairing. That half is named
//! [`ServerPairingState`](shared::protocol::pairing::ServerPairingState) because
//! the v2 messages are framed from the phone's point of view (`PairingInit`
//! carries the phone's keys). Concretely, ours are `handle_init`,
//! `create_confirm_client` and `verify_confirm_server`; the phone drives
//! `ClientPairingSession::{create_init, verify_response, create_confirm_server}`.
//!
//! ## Wire behaviour (`docs/design-documents/protocol/initial-key-exchange.md`)
//!
//! * A retried `PairingInit` is answered from the cached `PairingResponse`
//!   (`ServerPairingState::response`), never re-derived, and refreshes
//!   `peer_addr`: a NAT may have remapped the phone's source port since the last
//!   datagram.
//! * `PairingKeepalive` (phone → desktop, every 1000 ms while the user compares
//!   SAS) carries no payload. It keeps the NAT/SLIRP mapping open, refreshes
//!   `peer_addr`, and is the fastest possible request to re-send the frame that
//!   is currently in flight.
//! * Nothing is ever re-encrypted for a retransmission. `PairingConfirmClient`
//!   and `PairingConfirmServer` draw a fresh nonce per encryption, so a second
//!   encryption would be a different message; both the `PairingResponse` and the
//!   `PairingConfirmClient` are encoded once and re-sent verbatim.
//! * The pairing socket does **not** filter datagrams by source address: the
//!   Android emulator reaches the daemon over QEMU SLIRP NAT (`10.0.2.2:<port>`
//!   arrives as `127.0.0.1:<ephemeral>`), so only the socket's own echo is
//!   dropped (`is_loopback(source) && source.port() == local_port`). Because the
//!   socket is dual-stack an IPv4 loopback peer is reported as `::ffff:127.0.0.1`,
//!   for which std's `Ipv6Addr::is_loopback` is `false` — [`is_loopback_address`]
//!   handles both forms.
//!
//! ## Transport lock
//!
//! The phone races UDP and BLE and the first `PairingInit` that arrives wins; the
//! rule is [`init_disposition`]. The losing transport stays open but is ignored,
//! mirroring the phone's own rule ("whichever transport delivers a valid
//! `PairingResponse` first wins and locks the transport for Steps 3–6; the other
//! transport attempt is cancelled"):
//!
//! | locked | incoming | disposition |
//! | :--- | :--- | :--- |
//! | none | UDP | [`InitDisposition::Accept`] |
//! | none | BLE | [`InitDisposition::Accept`] |
//! | UDP | UDP | [`InitDisposition::Refresh`] (retry: cached response) |
//! | BLE | BLE | [`InitDisposition::Refresh`] (retry: cached response) |
//! | UDP | BLE | [`InitDisposition::Ignore`] |
//! | BLE | UDP | [`InitDisposition::Ignore`] |
//!
//! ## Timing
//!
//! * [`RETRANSMIT_INTERVAL`] — 500 ms between `PairingConfirmClient` retries
//!   (Step 5), overridden by any keepalive ([`transmit_due`]).
//! * [`SCHEDULER_TICK`] — how often the retransmission rule is evaluated. It is
//!   deliberately shorter than the interval so the 500 ms mark is honoured to
//!   within one tick instead of rounding up to a whole interval.
//! * [`SESSION_DEADLINE`] — 120 s for the whole session, from `StartPairing`. It
//!   bounds the human SAS comparison without ever ringing the phone for longer
//!   than `pam_operation_timeout_secs` (default 120 s), and it matches the GUI's
//!   own 120 s IPC read timeout, so a `CompletePairing` that the daemon is still
//!   holding open cannot be cut off by the client first.
//!
//! ## Teardown
//!
//! Every exit path — completion, cancellation, an abort from the phone, expiry —
//! runs [`Session::finish`], which stops the BLE advertisement and only then
//! answers a pending `CompletePairing`/`CancelPairing` IPC call, so a caller that
//! got its answer can rely on the socket and the advertisement being gone.
//! Dropping a [`PairingState`] (the session was superseded) aborts the worker as a
//! backstop; that is the only path that skips the asynchronous teardown, and the
//! BLE session type is expected to stop advertising on drop.

use crate::auth_handler::DaemonState;
use shared::firewall::{FirewallError, FirewallGuard, Protocol as FirewallProtocol};
use shared::protocol::messages::PROTOCOL_VERSION_V2;
use shared::protocol::pairing::{
    decode_pairing_packet, encode_pairing_packet, pairing_session_id, NegotiatedAlgorithms,
    PinnedAlgorithms, ServerPairingState, StartedPairing, PAIRING_SESSION_ID_LEN,
};
use shared::protocol::pb::{
    pairing_packet, PairingAbort, PairingAbortReason, PairingConfirmServer, PairingInit,
    PairingPacket,
};
use shared::protocol::ProtocolError;
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::MissedTickBehavior;

#[cfg(feature = "ble")]
use crate::transport::{BleTransport, PairingBleSession};

/// How long a `PairingConfirmClient` retry waits for the previous one.
pub(crate) const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(500);

/// How often the retransmission rule is evaluated.
pub(crate) const SCHEDULER_TICK: Duration = Duration::from_millis(100);

/// Upper bound on one pairing session, `StartPairing` to conclusion.
pub(crate) const SESSION_DEADLINE: Duration = Duration::from_secs(120);

/// Slack on top of [`SESSION_DEADLINE`] for an IPC caller that waits on the
/// worker: the worker always answers at (or before) the deadline, so this only
/// fires if the worker itself is wedged.
const SESSION_REPLY_TIMEOUT: Duration = Duration::from_secs(135);

/// How long a `CancelPairing` waits for the abort to be sent and the socket to be
/// torn down. Sending one datagram and stopping an advertisement is local work.
const CANCEL_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest pairing frame accepted from either transport. `PairingPacket` stays
/// under 300 bytes (`shared::models::ble::MAX_GATT_PAYLOAD_BYTES` fits it in one
/// notification); anything larger is not a pairing frame.
const MAX_PAIRING_FRAME_LEN: usize = 1024;

/// Depth of the IPC → worker command queue. Only `CompletePairing` and
/// `CancelPairing` are queued, one each in practice.
const COMMAND_QUEUE_LEN: usize = 4;

/// Session counter.
///
/// Every `StartPairing` takes the next value, and a `WaitForPairing` remembers
/// the one it subscribed to: a wait whose session was replaced must not answer
/// the newer session with the older one's SAS.
static PAIRING_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_generation() -> u64 {
    PAIRING_GENERATION.fetch_add(1, Ordering::Relaxed)
}

// ==== Pure session decisions (no sockets, no timers) =========================
//
// The functions below are the whole policy of the session loop in a testable
// form: which transport wins, which frames belong to us, and when a retry goes
// out. `cargo test -p tapauthd` exercises them without opening a socket.

/// Which transport a session is talking over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportKind {
    Udp,
    Ble,
}

/// The live peer of a locked session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Peer {
    Udp(SocketAddr),
    Ble,
}

impl Peer {
    fn kind(self) -> TransportKind {
        match self {
            Peer::Udp(_) => TransportKind::Udp,
            Peer::Ble => TransportKind::Ble,
        }
    }
}

/// What to do with a `PairingInit` for a session that may already be locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitDisposition {
    /// First init of the session: run the handshake and lock this transport.
    Accept,
    /// Retried init on the locked transport: refresh `peer_addr`, re-send the
    /// cached `PairingResponse`.
    Refresh,
    /// Init on the transport that lost the race: drop it.
    Ignore,
}

fn init_disposition(locked: Option<TransportKind>, incoming: TransportKind) -> InitDisposition {
    match locked {
        None => InitDisposition::Accept,
        Some(locked) if locked == incoming => InitDisposition::Refresh,
        Some(_) => InitDisposition::Ignore,
    }
}

/// Whether a decoded frame belongs to this session.
///
/// `decode_pairing_packet` already rejects a truncated or foreign-version
/// envelope; this compares the 16-byte `sid` the QR code committed to. A frame
/// that fails either check is dropped without touching the state machine.
fn frame_matches_session(ours: &[u8; PAIRING_SESSION_ID_LEN], packet: &PairingPacket) -> bool {
    match pairing_session_id(packet) {
        Ok(session_id) => session_id == *ours,
        Err(_) => false,
    }
}

/// Whether a datagram is this socket's own echo.
///
/// The pairing socket is dual-stack, so `127.0.0.1:<port>` may arrive as
/// `::ffff:127.0.0.1:<port>`; both forms must be dropped, and **only** when the
/// source port is the socket's own — a loopback datagram from any other port is
/// the emulator behind QEMU SLIRP NAT and is a legitimate peer.
fn is_self_echo(source: SocketAddr, local_port: u16) -> bool {
    is_loopback_address(source.ip()) && source.port() == local_port
}

/// Whether a source address is loopback, including the IPv4-mapped form.
///
/// The pairing socket is dual-stack, so an IPv4 peer (the Android emulator behind
/// QEMU SLIRP NAT, or the phone on the LAN) shows up as `::ffff:a.b.c.d`. Std's
/// `Ipv6Addr::is_loopback` is `false` for those, so a guard written as plain
/// `ip.is_loopback()` would never match a mapped address — and one written as
/// "drop every local source" would drop the emulator's legitimate datagrams.
fn is_loopback_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ipv4) => ipv4.is_loopback(),
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Whether it is time to (re)send the `PairingConfirmClient`.
///
/// * No send yet → yes: the first provisioning frame goes out immediately once
///   the user confirmed the SAS (Step 5), not one interval later.
/// * A keepalive arrived since the last send → yes: the phone is telling us its
///   mapping is open right now, so this is the cheapest possible retry.
/// * Otherwise → only once [`RETRANSMIT_INTERVAL`] has elapsed, so the phone is
///   not flooded faster than it asked for.
fn transmit_due(last_sent: Option<Instant>, now: Instant, keepalive_received: bool) -> bool {
    match last_sent {
        None => true,
        Some(last_sent) => {
            keepalive_received || now.saturating_duration_since(last_sent) >= RETRANSMIT_INTERVAL
        }
    }
}

/// The wire form of a `PairingAbort`, which the peer authenticates.
///
/// `ServerPairingState::create_abort` tags the abort with `HMAC-SHA256(K_c2s, …)`
/// as soon as the session keys exist, and the phone's `verify_abort` (which checks
/// with `K_c2s`) refuses a tag-less abort at that point — so a cancellation that
/// skipped the tag would be ignored by the phone, which is exactly the silence
/// this path must avoid. Before the keys exist the tag is empty by construction:
/// nobody can authenticate a cancel that early, and the phone may not have
/// created its session yet.
fn abort_frame(
    state: &ServerPairingState,
    session_id: &[u8; PAIRING_SESSION_ID_LEN],
    reason: PairingAbortReason,
) -> Result<Vec<u8>, ProtocolError> {
    let abort = state.create_abort(reason)?;
    encode_pairing_packet(&PairingPacket {
        version: PROTOCOL_VERSION_V2,
        session_id: session_id.to_vec(),
        msg: Some(pairing_packet::Msg::Abort(abort)),
    })
}

/// The protobuf name of an abort reason, for logs.
fn abort_reason_name(reason: i32) -> &'static str {
    match PairingAbortReason::try_from(reason) {
        Ok(reason) => reason.as_str_name(),
        Err(_) => "UNKNOWN",
    }
}

// ==== Session handle ========================================================

/// Observable state of a pairing session, published by the worker.
///
/// `AwaitingSas` is where the session spends the human comparison: it is
/// published as soon as `PairingInit` is accepted and never retracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPhase {
    /// The QR code exists, but no `PairingInit` has matched this session yet.
    AwaitingPhone,
    /// The handshake completed; `sas` is the `"123-456"` display form.
    AwaitingSas(String),
    /// Pairing completed; the server was persisted by the admin handler.
    Finished,
    /// The session ended without a pairing; the string says why.
    Failed(String),
}

/// Why a `CompletePairing`/`CancelPairing` could not be carried out.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("The phone has not connected yet")]
    NotInitiated,
    #[error("Pairing completion is already in progress")]
    AlreadyCompleting,
    #[error("Pairing session ended: {0}")]
    Ended(String),
    #[error("Timed out waiting for the phone to confirm")]
    Timeout,
}

/// What the worker learned while pairing, for the admin handler to persist.
#[derive(Debug, Clone)]
pub struct CompletedPairing {
    /// The phone's static `Ed_S` (32 bytes).
    pub server_public_key: [u8; 32],
    /// The phone's display name, from its `PairingInit`.
    pub server_device_name: String,
    /// The algorithms the handshake selected.
    pub negotiated: NegotiatedAlgorithms,
}

/// Everything the worker needs to run a session. Built by `handle_start_pairing`.
pub(crate) struct SessionSetup {
    /// The handshake machine, already `start`ed (so the QR URL and the BLE
    /// advertisement id come from it).
    pub state: ServerPairingState,
    /// What `ServerPairingState::start` returned.
    pub started: StartedPairing,
    /// The bound pairing socket (`[::]:0`, dual-stack).
    pub udp: UdpSocket,
    /// Its local port, used by the self-echo guard and by the IPC replies.
    pub local_port: u16,
    /// Keeps the pairing firewall rule alive for the life of the session.
    pub firewall_guard: Option<Arc<FirewallGuard>>,
    /// Whether the BLE pairing advertisement should be started.
    pub enable_ble: bool,
    /// The session generation, so a stale `WaitForPairing` cannot answer a newer
    /// session.
    pub generation: u64,
}

/// Control handle of a running pairing session.
///
/// Stored in `ServerState::pending_pairing`; the socket, the advertisement and
/// the state machine live in the background task this handle steers.
pub struct PairingState {
    generation: u64,
    port: u16,
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    phase: watch::Receiver<SessionPhase>,
    commands: mpsc::Sender<SessionCommand>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PairingState {
    fn drop(&mut self) {
        // Backstop only: a handle that is dropped means nobody can steer the
        // session any more (it completed, was cancelled, or was superseded), and
        // its socket and advertisement must not outlive it. The graceful paths
        // call `Session::finish` first, which also stops the advertisement.
        self.task.abort();
    }
}

impl PairingState {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn session_id(&self) -> &[u8; PAIRING_SESSION_ID_LEN] {
        &self.session_id
    }

    /// The current phase, cloned so the caller never holds the watch lock.
    pub(crate) fn phase(&self) -> SessionPhase {
        self.phase.borrow().clone()
    }

    /// A subscription, so a long wait can happen without holding the state lock.
    pub(crate) fn phase_receiver(&self) -> watch::Receiver<SessionPhase> {
        self.phase.clone()
    }

    /// Whether the session is over (its worker may already be gone).
    pub(crate) fn is_ended(&self) -> bool {
        matches!(
            self.phase(),
            SessionPhase::Finished | SessionPhase::Failed(_)
        )
    }

    /// A clone of the worker's command channel.
    ///
    /// The IPC handlers take one of these instead of the whole handle, so a
    /// `CompletePairing` and a `CancelPairing` can be in flight at the same time
    /// without either having to hold (or empty) the pairing-state slot — a cancel
    /// that arrives while a completion waits for the phone still reaches the
    /// worker.
    pub(crate) fn command_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.commands.clone()
    }
}

/// Ask the worker to provision `csk` and wait for the phone's proof.
///
/// The worker retransmits `PairingConfirmClient` every [`RETRANSMIT_INTERVAL`]
/// (and immediately on every keepalive) until `verify_confirm_server` passes, the
/// phone aborts, or the session expires.
pub(crate) async fn request_completion(
    commands: &mpsc::Sender<SessionCommand>,
    csk: [u8; 32],
    username: String,
    client_hostname: String,
) -> Result<CompletedPairing, PairingError> {
    let (reply, response) = oneshot::channel();
    commands
        .send(SessionCommand::Complete(CompleteRequest {
            csk,
            username,
            client_hostname,
            reply,
        }))
        .await
        .map_err(|_| PairingError::Ended("the pairing worker is gone".to_string()))?;

    match tokio::time::timeout(SESSION_REPLY_TIMEOUT, response).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(PairingError::Ended(
            "the pairing worker is gone".to_string(),
        )),
        Err(_) => Err(PairingError::Timeout),
    }
}

/// Send an authenticated abort and tear the session down.
///
/// Returns once the abort has been handed to the transport and the socket and
/// advertisement are gone, so the caller never answers an IPC request while a
/// pairing task is still running.
pub(crate) async fn request_cancellation(
    commands: &mpsc::Sender<SessionCommand>,
) -> Result<(), PairingError> {
    let (reply, confirmation) = oneshot::channel();
    commands
        .send(SessionCommand::Cancel { reply })
        .await
        .map_err(|_| PairingError::Ended("the pairing worker is gone".to_string()))?;

    match tokio::time::timeout(CANCEL_TEARDOWN_TIMEOUT, confirmation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(PairingError::Ended(
            "the pairing worker is gone".to_string(),
        )),
        Err(_) => Err(PairingError::Timeout),
    }
}

impl std::fmt::Debug for PairingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingState")
            .field("generation", &self.generation)
            .field("port", &self.port)
            .field("session_id", &hex::encode(self.session_id))
            .field("phase", &self.phase())
            .finish()
    }
}

/// Bind the ephemeral dual-stack UDP socket the phone sends `PairingInit` to.
///
/// `[::]:0` with `IPV6_V6ONLY = false` so a single socket receives the phone's
/// IPv4 and IPv6 datagrams, and **no** `SO_REUSEPORT`: the port is ephemeral and
/// nothing else should be able to receive (and answer) the pairing frames. An
/// ephemeral port also keeps the pairing socket clear of `daemon.udp_socket`
/// (`udp_port`) when an authentication attempt runs at the same time.
pub(crate) async fn bind_pairing_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(SocketProtocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

/// Open the pairing UDP port in the firewall.
///
/// Test builds continue without a rule when the firewall cannot be programmed
/// (containers/user namespaces without usable `iptables`); production builds
/// abort pairing instead of leaving the ephemeral socket unreachable but open.
#[cfg(feature = "dev-firewall-bypass")]
pub(crate) fn open_pairing_firewall(
    port: u16,
) -> Result<Option<Arc<FirewallGuard>>, FirewallError> {
    match FirewallGuard::new(port, FirewallProtocol::Udp) {
        Ok(guard) => Ok(Some(guard)),
        Err(e) => {
            // NOTE: the "dev-firewall-bypass" token in this message is the only
            // signature the binary scanners can detect for this feature (there is
            // no env var). scripts/ci/check-production-build.sh and
            // scripts/ci/scan-package-artifacts.sh grep for it, and their positive
            // controls fail if it disappears — keep the spelling.
            tracing::warn!(
                "Failed to open firewall port for pairing (continuing anyway; dev-firewall-bypass): {}",
                e
            );
            Ok(None)
        }
    }
}

#[cfg(not(feature = "dev-firewall-bypass"))]
pub(crate) fn open_pairing_firewall(
    port: u16,
) -> Result<Option<Arc<FirewallGuard>>, FirewallError> {
    FirewallGuard::new(port, FirewallProtocol::Udp).map(Some)
}

/// The algorithms an existing CSK is already committed to, if any.
///
/// One multicast broadcast reaches every paired server, so the symmetric and hash
/// algorithms belong to the CSK rather than to a single pairing: re-pairing must
/// negotiate the algorithms the live CSK uses, and `handle_init` refuses a phone
/// that does not offer them (`ProtocolError::UnsupportedAlgorithm`) instead of
/// silently pairing it into a broadcast it cannot decrypt.
///
/// A first pairing has no metadata file, so nothing is pinned. After `RotateCsk`
/// the file exists again with the baseline pair (`ClientConfigManager::rotate_csk`
/// rewrites `CskMetadata::default`), so the baseline is what gets pinned — which
/// selects exactly the same algorithms a fresh negotiation prefers, and only
/// refuses a phone that offers neither.
pub(crate) fn pinned_algorithms(daemon: &Arc<DaemonState>) -> Option<PinnedAlgorithms> {
    if !daemon.config_manager.has_csk_metadata_file() {
        return None;
    }
    let metadata = match daemon.config_manager.load_csk_metadata() {
        Ok(metadata) => metadata,
        Err(e) => {
            tracing::warn!(
                "Could not read the CSK algorithm metadata ({}); pinning the baseline algorithms",
                e
            );
            shared::config::CskMetadata::default()
        }
    };
    Some(PinnedAlgorithms {
        symmetric_algorithm: metadata.symmetric_algorithm,
        hash_algorithm: metadata.hash_algorithm,
    })
}

/// Start the background worker for a prepared session.
pub(crate) fn spawn(setup: SessionSetup) -> PairingState {
    let session_id = *setup.state.session_id();
    let port = setup.local_port;
    let generation = setup.generation;
    let (phase_tx, phase) = watch::channel(SessionPhase::AwaitingPhone);
    let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_LEN);
    let task = tokio::spawn(run_session(setup, phase_tx, command_rx));

    PairingState {
        generation,
        port,
        session_id,
        phase,
        commands,
        task,
    }
}

// ==== Worker ===============================================================

async fn run_session(
    setup: SessionSetup,
    phase: watch::Sender<SessionPhase>,
    commands: mpsc::Receiver<SessionCommand>,
) {
    let session_id = *setup.state.session_id();
    let link = PairingLink::start(setup.started.pairing_adv_id, setup.enable_ble).await;
    let mut session = Session {
        state: setup.state,
        session_id,
        udp: setup.udp,
        local_port: setup.local_port,
        // Held for the life of the session: dropping it closes the firewall rule.
        _firewall_guard: setup.firewall_guard,
        link,
        phase,
        commands,
        peer: None,
        response_frame: None,
        confirm_frame: None,
        provisioning: None,
        completion: None,
        cancel_reply: None,
        server_public_key: None,
        server_device_name: String::new(),
    };

    tracing::info!(
        "Pairing session started: UDP port {}, session {}",
        session.local_port,
        hex::encode(session.session_id)
    );
    session.run().await;
    session.finish().await;
}

/// One awaited event of the session loop.
enum Step {
    /// An admin IPC command (`CompletePairing`, `CancelPairing`).
    Command(SessionCommand),
    /// A frame from the BLE pairing characteristic (`None`: the link closed).
    Ble(Option<Vec<u8>>),
    /// A datagram from the pairing socket.
    Udp(std::io::Result<(usize, SocketAddr)>),
    /// The retransmission scheduler fired.
    Tick,
    /// [`SESSION_DEADLINE`] elapsed.
    Expired,
}

/// Whether the loop keeps running after handling a step.
enum Flow {
    Continue,
    Done,
}

pub(crate) enum SessionCommand {
    Complete(CompleteRequest),
    Cancel { reply: oneshot::Sender<()> },
}

pub(crate) struct CompleteRequest {
    csk: [u8; 32],
    username: String,
    client_hostname: String,
    reply: oneshot::Sender<Result<CompletedPairing, PairingError>>,
}

/// State of an in-flight provisioning: `PairingConfirmClient` going out until the
/// phone proves it received the CSK.
struct Provisioning {
    /// Needed to verify `PairingConfirmServer` (the proof is over `H || csk`).
    csk: [u8; 32],
    /// Answered once the session tears down, with the outcome.
    reply: oneshot::Sender<Result<CompletedPairing, PairingError>>,
    /// When the cached frame last went out, or `None` before the first send.
    last_sent: Option<Instant>,
}

struct Session {
    state: ServerPairingState,
    session_id: [u8; PAIRING_SESSION_ID_LEN],
    udp: UdpSocket,
    local_port: u16,
    _firewall_guard: Option<Arc<FirewallGuard>>,
    link: PairingLink,
    phase: watch::Sender<SessionPhase>,
    commands: mpsc::Receiver<SessionCommand>,
    /// The transport that won the race, and the phone's current address on it.
    peer: Option<Peer>,
    /// The encoded `PairingResponse`, re-sent verbatim on every init retry.
    response_frame: Option<Vec<u8>>,
    /// The encoded `PairingConfirmClient`, re-sent verbatim while provisioning.
    confirm_frame: Option<Vec<u8>>,
    provisioning: Option<Provisioning>,
    /// Outcome to answer a pending `CompletePairing` with, once torn down.
    completion: Option<Result<CompletedPairing, PairingError>>,
    /// Answer for a pending `CancelPairing`, sent once torn down.
    cancel_reply: Option<oneshot::Sender<()>>,
    /// `Ed_S`, captured from the accepted `PairingInit`.
    server_public_key: Option<[u8; 32]>,
    /// The phone's display name, captured from the accepted `PairingInit`.
    server_device_name: String,
}

impl Session {
    async fn run(&mut self) {
        let deadline = tokio::time::sleep(SESSION_DEADLINE);
        tokio::pin!(deadline);
        let mut ticker = tokio::time::interval(SCHEDULER_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut buffer = vec![0u8; MAX_PAIRING_FRAME_LEN];

        loop {
            let step = tokio::select! {
                biased;
                command = self.commands.recv() => match command {
                    Some(command) => Step::Command(command),
                    // Every control handle is gone: nobody can complete or cancel
                    // this session any more.
                    None => break,
                },
                _ = &mut deadline => Step::Expired,
                frame = self.link.recv() => Step::Ble(frame),
                received = self.udp.recv_from(&mut buffer) => Step::Udp(received),
                _ = ticker.tick() => Step::Tick,
            };

            let flow = match step {
                Step::Command(command) => self.on_command(command).await,
                Step::Expired => self.on_expired().await,
                Step::Ble(frame) => self.on_ble(frame).await,
                Step::Udp(Ok((len, source))) => match buffer.get(..len) {
                    Some(frame) => self.on_udp(frame.to_vec(), source).await,
                    None => Flow::Continue,
                },
                Step::Udp(Err(e)) => {
                    tracing::debug!("Pairing UDP receive failed: {}", e);
                    Flow::Continue
                }
                Step::Tick => {
                    self.pump_provisioning(false).await;
                    Flow::Continue
                }
            };

            if let Flow::Done = flow {
                break;
            }
        }
    }

    /// Stop the advertisement and the socket, then answer whoever is waiting.
    async fn finish(mut self) {
        self.link.stop().await;

        if let Some(provisioning) = self.provisioning.take() {
            let outcome = self.completion.take().unwrap_or(Err(PairingError::Ended(
                "pairing session ended before the phone confirmed the CSK".to_string(),
            )));
            let _ = provisioning.reply.send(outcome);
        }
        if let Some(reply) = self.cancel_reply.take() {
            let _ = reply.send(());
        }

        tracing::info!("Pairing session on UDP port {} closed", self.local_port);
    }

    fn publish(&self, phase: SessionPhase) {
        // No receiver left is normal: the GUI may have gone away mid-session.
        let _ = self.phase.send(phase);
    }

    /// End the session, answering a pending `CompletePairing` with `failure`
    /// unless a success was already recorded.
    fn end(&mut self, phase: SessionPhase, failure: Option<PairingError>) -> Flow {
        if self.provisioning.is_some() && self.completion.is_none() {
            self.completion = Some(Err(failure.unwrap_or(PairingError::Ended(
                "pairing session ended before the phone confirmed the CSK".to_string(),
            ))));
        }
        self.publish(phase);
        Flow::Done
    }

    // ---- receive ---------------------------------------------------------

    async fn on_udp(&mut self, frame: Vec<u8>, source: SocketAddr) -> Flow {
        // Only the socket's own echo is dropped: loopback-sourced datagrams are
        // legitimate (Android emulator, QEMU SLIRP NAT), so an `is_local_ip`
        // filter would break emulator pairing.
        if is_self_echo(source, self.local_port) {
            tracing::trace!("Dropping the pairing socket's own datagram (self-echo)");
            return Flow::Continue;
        }
        self.on_frame(frame, Peer::Udp(source)).await
    }

    async fn on_ble(&mut self, frame: Option<Vec<u8>>) -> Flow {
        match frame {
            Some(frame) => self.on_frame(frame, Peer::Ble).await,
            None => {
                // Defensive path: in a live session the sender is owned by the
                // registered GATT application and only dropped by `stop()`, so
                // this is reached only if the app is unregistered behind us.
                tracing::warn!("BLE pairing link closed by the phone");
                if self.peer.map(Peer::kind) == Some(TransportKind::Ble) {
                    // The locked transport is gone: nothing can carry the rest of
                    // the handshake. Over UDP pairing simply continues.
                    return self.end(
                        SessionPhase::Failed("the BLE pairing link closed".to_string()),
                        None,
                    );
                }
                Flow::Continue
            }
        }
    }

    async fn on_frame(&mut self, frame: Vec<u8>, source: Peer) -> Flow {
        let packet = match decode_pairing_packet(&frame) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::debug!(
                    "Dropping an undecodable pairing frame from {:?}: {}",
                    source.kind(),
                    e
                );
                return Flow::Continue;
            }
        };
        if !frame_matches_session(&self.session_id, &packet) {
            tracing::debug!(
                "Dropping a pairing frame from {:?}: it belongs to another session",
                source.kind()
            );
            return Flow::Continue;
        }

        match packet.msg {
            Some(pairing_packet::Msg::Init(init)) => self.on_init(init, source).await,
            Some(pairing_packet::Msg::Keepalive(_)) => self.on_keepalive(source).await,
            Some(pairing_packet::Msg::ConfirmServer(confirm)) => {
                self.on_confirm_server(&confirm).await
            }
            Some(pairing_packet::Msg::Abort(abort)) => self.on_abort(&abort),
            Some(pairing_packet::Msg::Response(_))
            | Some(pairing_packet::Msg::ConfirmClient(_)) => {
                tracing::debug!("Dropping a pairing frame only this desktop sends");
                Flow::Continue
            }
            None => {
                tracing::debug!("Dropping an empty pairing frame");
                Flow::Continue
            }
        }
    }

    // ---- handshake -------------------------------------------------------

    async fn on_init(&mut self, init: PairingInit, source: Peer) -> Flow {
        match init_disposition(self.peer.map(Peer::kind), source.kind()) {
            InitDisposition::Ignore => {
                tracing::debug!(
                    "Ignoring PairingInit over {:?}: the session is locked to {:?}",
                    source.kind(),
                    self.peer.map(Peer::kind)
                );
                return Flow::Continue;
            }
            InitDisposition::Refresh => {
                // A retried PairingInit: the phone resends every 500 ms until it
                // has a response, and a NAT may have remapped its source port, so
                // refresh peer_addr and re-send the cached response verbatim.
                self.peer = Some(source);
                tracing::debug!(
                    "PairingInit retried over {:?}; re-sending the cached PairingResponse",
                    source.kind()
                );
                if let Some(frame) = self.response_frame.clone() {
                    self.send(frame, source).await;
                }
                return Flow::Continue;
            }
            InitDisposition::Accept => {}
        }

        let server_public_key: [u8; 32] = match init.server_ed25519_public_key.as_slice().try_into()
        {
            Ok(key) => key,
            Err(_) => {
                tracing::warn!("Rejecting PairingInit with a malformed Ed_S");
                return self
                    .reject_init(PairingAbortReason::ProtocolError, source)
                    .await;
            }
        };

        let response = match self.state.handle_init(&init) {
            Ok(response) => response.clone(),
            Err(e) => {
                let reason = match e {
                    ProtocolError::UnsupportedAlgorithm => PairingAbortReason::UnsupportedAlgorithm,
                    _ => PairingAbortReason::ProtocolError,
                };
                tracing::warn!(
                    "Rejecting PairingInit ({}); aborting with {}",
                    e,
                    reason.as_str_name()
                );
                return self.reject_init(reason, source).await;
            }
        };

        let frame = match encode_pairing_packet(&PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: self.session_id.to_vec(),
            msg: Some(pairing_packet::Msg::Response(response)),
        }) {
            Ok(frame) => frame,
            Err(e) => {
                tracing::warn!("Failed to encode the PairingResponse: {}", e);
                return self
                    .reject_init(PairingAbortReason::ProtocolError, source)
                    .await;
            }
        };

        self.response_frame = Some(frame);
        self.server_public_key = Some(server_public_key);
        self.server_device_name = init.server_device_name;
        self.peer = Some(source);

        if let Some(sas) = self.state.sas() {
            tracing::info!(
                "PairingInit accepted over {:?} (phone {}); SAS ready for display",
                source.kind(),
                hex::encode(server_public_key)
            );
            self.publish(SessionPhase::AwaitingSas(sas.to_string()));
        }

        if let Some(frame) = self.response_frame.clone() {
            self.send(frame, source).await;
        }
        Flow::Continue
    }

    /// Refuse a `PairingInit` we cannot honour and end the session.
    async fn reject_init(&mut self, reason: PairingAbortReason, source: Peer) -> Flow {
        self.send_abort(source, reason).await;
        self.end(
            SessionPhase::Failed(format!(
                "the phone's pairing request was refused ({})",
                reason.as_str_name()
            )),
            None,
        )
    }

    async fn on_keepalive(&mut self, source: Peer) -> Flow {
        if self.peer.map(Peer::kind) != Some(source.kind()) {
            tracing::trace!(
                "Ignoring PairingKeepalive over {:?}: not the locked transport",
                source.kind()
            );
            return Flow::Continue;
        }
        // Keepalives refresh peer_addr (the phone's NAT port may have changed) and
        // request an immediate retransmission of whatever is in flight.
        self.peer = Some(source);
        if self.provisioning.is_some() {
            self.pump_provisioning(true).await;
        } else if let Some(frame) = self.response_frame.clone() {
            self.send(frame, source).await;
        }
        Flow::Continue
    }

    async fn on_confirm_server(&mut self, confirm: &PairingConfirmServer) -> Flow {
        let Some(csk) = self
            .provisioning
            .as_ref()
            .map(|provisioning| provisioning.csk)
        else {
            tracing::debug!("Ignoring PairingConfirmServer: no CSK was provisioned yet");
            return Flow::Continue;
        };

        if let Err(e) = self.state.verify_confirm_server(confirm, &csk) {
            // A proof that does not verify must not kill the session: the phone
            // may still be settling, and the check is cheap. Keep retransmitting
            // PairingConfirmClient until the deadline (Step 5).
            tracing::warn!(
                "Rejected the phone's PairingConfirmServer ({}); still provisioning the CSK",
                e
            );
            return Flow::Continue;
        }

        let (Some(server_public_key), Some(negotiated)) =
            (self.server_public_key, self.state.negotiated())
        else {
            tracing::warn!("Pairing proved out without a recorded phone identity key");
            return self.end(
                SessionPhase::Failed("pairing completed without a phone identity key".to_string()),
                Some(PairingError::Ended(
                    "pairing completed without a phone identity key".to_string(),
                )),
            );
        };

        // The CSK is provisioned and proven: drop the session keys (and H) now.
        self.state.conclude();
        self.completion = Some(Ok(CompletedPairing {
            server_public_key,
            server_device_name: self.server_device_name.clone(),
            negotiated,
        }));
        tracing::info!(
            "Pairing complete: phone key {}",
            hex::encode(server_public_key)
        );
        self.end(SessionPhase::Finished, None)
    }

    fn on_abort(&mut self, abort: &PairingAbort) -> Flow {
        match self.state.verify_abort(abort) {
            Ok(true) => {
                tracing::info!(
                    "Pairing aborted by the phone ({})",
                    abort_reason_name(abort.reason)
                );
                self.end(
                    SessionPhase::Failed(format!(
                        "the phone aborted the pairing ({})",
                        abort_reason_name(abort.reason)
                    )),
                    None,
                )
            }
            Ok(false) => {
                // A tag-less abort before any key exists authenticates nothing, so
                // it cannot cancel the session.
                tracing::debug!("Ignoring an unauthenticated PairingAbort");
                Flow::Continue
            }
            Err(e) => {
                tracing::warn!("Ignoring a PairingAbort with an invalid auth tag: {}", e);
                Flow::Continue
            }
        }
    }

    async fn on_expired(&mut self) -> Flow {
        tracing::warn!(
            "Pairing session expired after {}s",
            SESSION_DEADLINE.as_secs()
        );
        if let Some(peer) = self.peer {
            self.send_abort(peer, PairingAbortReason::SessionExpired)
                .await;
        }
        self.end(
            SessionPhase::Failed("the pairing session expired".to_string()),
            Some(PairingError::Timeout),
        )
    }

    // ---- admin commands --------------------------------------------------

    async fn on_command(&mut self, command: SessionCommand) -> Flow {
        match command {
            SessionCommand::Complete(request) => self.on_complete(request).await,
            SessionCommand::Cancel { reply } => self.on_cancel(reply).await,
        }
    }

    async fn on_complete(&mut self, request: CompleteRequest) -> Flow {
        if self.provisioning.is_some() {
            let _ = request.reply.send(Err(PairingError::AlreadyCompleting));
            return Flow::Continue;
        }
        let Some(peer) = self.peer else {
            let _ = request.reply.send(Err(PairingError::NotInitiated));
            return Flow::Continue;
        };

        let confirm = match self.state.create_confirm_client(
            &request.csk,
            &request.username,
            &request.client_hostname,
        ) {
            Ok(confirm) => confirm,
            Err(e) => {
                let _ = request.reply.send(Err(e.into()));
                return Flow::Continue;
            }
        };
        let frame = match encode_pairing_packet(&PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: self.session_id.to_vec(),
            msg: Some(pairing_packet::Msg::ConfirmClient(confirm)),
        }) {
            Ok(frame) => frame,
            Err(e) => {
                let _ = request.reply.send(Err(e.into()));
                return Flow::Continue;
            }
        };

        // Encoded exactly once: a retransmission re-sends these bytes (each
        // encryption draws a fresh nonce, so re-encrypting would be a new message).
        self.confirm_frame = Some(frame);
        self.provisioning = Some(Provisioning {
            csk: request.csk,
            reply: request.reply,
            last_sent: None,
        });
        tracing::info!(
            "SAS confirmed: provisioning the CSK to the phone over {:?}",
            peer.kind()
        );
        self.pump_provisioning(false).await;
        Flow::Continue
    }

    async fn on_cancel(&mut self, reply: oneshot::Sender<()>) -> Flow {
        self.cancel_reply = Some(reply);
        let reason = PairingAbortReason::UserRejectedSas;
        match self.peer {
            Some(peer) => {
                tracing::info!(
                    "Cancelling the pairing session: sending {} to the phone",
                    reason.as_str_name()
                );
                self.send_abort(peer, reason).await;
            }
            None => tracing::info!("Cancelling the pairing session before the phone connected"),
        }
        self.state.conclude();
        self.end(
            SessionPhase::Failed("the pairing was cancelled".to_string()),
            None,
        )
    }

    // ---- transmission ----------------------------------------------------

    /// Re-send the cached `PairingConfirmClient` if [`transmit_due`] says so.
    async fn pump_provisioning(&mut self, keepalive_received: bool) {
        let Some(last_sent) = self.provisioning.as_ref().map(|p| p.last_sent) else {
            return;
        };
        let now = Instant::now();
        if !transmit_due(last_sent, now, keepalive_received) {
            return;
        }
        let (Some(frame), Some(peer)) = (self.confirm_frame.clone(), self.peer) else {
            return;
        };
        self.send(frame, peer).await;
        if let Some(provisioning) = self.provisioning.as_mut() {
            provisioning.last_sent = Some(now);
        }
    }

    async fn send(&mut self, frame: Vec<u8>, peer: Peer) {
        match peer {
            Peer::Udp(address) => {
                if let Err(e) = self.udp.send_to(&frame, address).await {
                    tracing::warn!("Failed to send a pairing frame to {}: {}", address, e);
                }
            }
            Peer::Ble => self.link.send(frame).await,
        }
    }

    async fn send_abort(&mut self, peer: Peer, reason: PairingAbortReason) -> bool {
        match abort_frame(&self.state, &self.session_id, reason) {
            Ok(frame) => {
                self.send(frame, peer).await;
                if peer.kind() == TransportKind::Ble {
                    // Teardown follows immediately (`finish` → `PairingLink::stop`
                    // → `device.disconnect()`), so the abort needs the same pause
                    // `publish_cancel` takes before the link goes away; without it
                    // the notification never leaves the controller. The UDP path
                    // has already left the socket at `send_to`.
                    self.link.settle().await;
                }
                true
            }
            Err(e) => {
                tracing::warn!("Failed to build a PairingAbort: {}", e);
                false
            }
        }
    }
}

// ==== BLE half =============================================================
//
// One type for both builds so the session loop reads the same with and without
// the `ble` feature: without it the link is a sink that never yields a frame and
// drops what it is given.

/// The pairing advertisement and its GATT characteristic.
#[cfg(feature = "ble")]
struct PairingLink {
    session: Option<PairingBleSession>,
    /// Set once `recv` reported the link closed, so the loop does not spin on a
    /// closed channel.
    closed: bool,
}

#[cfg(feature = "ble")]
impl PairingLink {
    async fn start(pairing_adv_id: [u8; 10], enable_ble: bool) -> Self {
        if !enable_ble {
            tracing::info!("BLE pairing advertisement disabled by configuration");
            return Self {
                session: None,
                closed: false,
            };
        }

        let transport = match BleTransport::new_for_pairing().await {
            Ok(transport) => transport,
            Err(_) => {
                tracing::warn!("Failed to set up BLE for pairing; pairing over UDP only");
                return Self {
                    session: None,
                    closed: false,
                };
            }
        };

        match transport.start_pairing(pairing_adv_id).await {
            Ok(session) => {
                tracing::info!(
                    "Pairing BLE advertisement started (adv_id {})",
                    hex::encode(pairing_adv_id)
                );
                Self {
                    session: Some(session),
                    closed: false,
                }
            }
            Err(_) => {
                tracing::warn!(
                    "Failed to start the pairing BLE advertisement (adv_id {}); pairing over UDP only",
                    hex::encode(pairing_adv_id)
                );
                Self {
                    session: None,
                    closed: false,
                }
            }
        }
    }

    /// The next frame written to `PAIRING_CHAR_UUID`, or `None` once the link is
    /// gone. Never ready when the session has no BLE half.
    async fn recv(&mut self) -> Option<Vec<u8>> {
        if self.closed {
            return std::future::pending().await;
        }
        match self.session.as_mut() {
            Some(session) => {
                let frame = session.recv().await;
                if frame.is_none() {
                    self.closed = true;
                }
                frame
            }
            None => std::future::pending().await,
        }
    }

    async fn send(&mut self, frame: Vec<u8>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if session.send(&frame).await.is_err() {
            tracing::warn!("Failed to notify the pairing characteristic");
        }
    }

    /// Let the frame just notified reach the air, where the caller is about to
    /// call `stop` (a no-op when this session has no BLE half).
    async fn settle(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.settle().await;
        }
    }

    async fn stop(&mut self) {
        // `stop` consumes the session: it disconnects the peers and unregisters
        // the GATT application.
        if let Some(session) = self.session.take() {
            session.stop().await;
        }
        self.closed = true;
    }
}

/// BLE-less build: pairing runs over UDP only.
#[cfg(not(feature = "ble"))]
struct PairingLink;

#[cfg(not(feature = "ble"))]
impl PairingLink {
    async fn start(_pairing_adv_id: [u8; 10], _enable_ble: bool) -> Self {
        Self
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        std::future::pending().await
    }

    async fn send(&mut self, _frame: Vec<u8>) {}

    async fn settle(&mut self) {}

    async fn stop(&mut self) {}
}

// ==== Tests ================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use shared::crypto::Ed25519KeyPair;
    use shared::protocol::pairing::ClientPairingSession;
    use shared::protocol::pb::PairingKeepalive;
    use std::net::Ipv4Addr;

    const DESKTOP_SEED: [u8; 32] = [0x3C; 32];
    const PHONE_SEED: [u8; 32] = [0x4D; 32];

    fn keepalive_frame(session_id: [u8; PAIRING_SESSION_ID_LEN]) -> PairingPacket {
        PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id.to_vec(),
            msg: Some(pairing_packet::Msg::Keepalive(PairingKeepalive {})),
        }
    }

    /// A desktop and a phone that have completed Steps 1–4, so both hold
    /// `K_c2s`/`K_s2c`/`H`.
    fn paired_states() -> (ServerPairingState, ClientPairingSession) {
        let desktop_identity = Ed25519KeyPair::from_signing_key_bytes(&DESKTOP_SEED).unwrap();
        let (mut desktop, started) = ServerPairingState::start(
            desktop_identity,
            "thinkpad",
            36692,
            Some(Ipv4Addr::new(192, 168, 1, 5)),
            None,
            None,
        )
        .unwrap();

        let mut phone = ClientPairingSession::new(
            started.session_id,
            Ed25519KeyPair::from_signing_key_bytes(&PHONE_SEED).unwrap(),
            "pixel",
        )
        .unwrap();
        let init = phone.create_init().unwrap();
        let response = desktop.handle_init(&init).unwrap().clone();
        phone
            .verify_response(&response, &started.client_x25519_public_key)
            .unwrap();
        (desktop, phone)
    }

    #[test]
    fn retransmit_is_immediate_on_the_first_send_and_on_every_keepalive() {
        let now = Instant::now();
        // Nothing has gone out yet: the first PairingConfirmClient must not wait
        // for an interval.
        assert!(transmit_due(None, now, false));
        // A keepalive says the phone's mapping is open right now, so it overrides
        // the 500 ms spacing even an instant after the previous send.
        assert!(transmit_due(Some(now), now, true));
    }

    #[test]
    fn retransmit_waits_for_the_500ms_interval_without_a_keepalive() {
        let now = Instant::now();
        let sent_499ms_ago = now.checked_sub(Duration::from_millis(499)).unwrap();
        assert!(
            !transmit_due(Some(sent_499ms_ago), now, false),
            "retransmitting inside 500 ms floods the phone"
        );
        let sent_500ms_ago = now.checked_sub(RETRANSMIT_INTERVAL).unwrap();
        assert!(
            transmit_due(Some(sent_500ms_ago), now, false),
            "a 500 ms old PairingConfirmClient is due"
        );
    }

    #[test]
    fn frame_for_another_session_is_rejected_and_our_own_is_accepted() {
        let ours = [0x11u8; PAIRING_SESSION_ID_LEN];
        let another = [0x22u8; PAIRING_SESSION_ID_LEN];

        assert!(frame_matches_session(&ours, &keepalive_frame(ours)));
        assert!(
            !frame_matches_session(&ours, &keepalive_frame(another)),
            "a frame from another session must never reach the state machine"
        );
    }

    #[test]
    fn a_pairing_init_on_the_losing_transport_is_ignored() {
        assert_eq!(
            init_disposition(None, TransportKind::Udp),
            InitDisposition::Accept
        );
        assert_eq!(
            init_disposition(None, TransportKind::Ble),
            InitDisposition::Accept
        );
        assert_eq!(
            init_disposition(Some(TransportKind::Udp), TransportKind::Udp),
            InitDisposition::Refresh
        );
        assert_eq!(
            init_disposition(Some(TransportKind::Ble), TransportKind::Udp),
            InitDisposition::Ignore
        );
        assert_eq!(
            init_disposition(Some(TransportKind::Udp), TransportKind::Ble),
            InitDisposition::Ignore
        );
    }

    #[test]
    fn cancelling_produces_an_abort_the_phone_authenticates() {
        let (desktop, phone) = paired_states();
        let frame = abort_frame(
            &desktop,
            desktop.session_id(),
            PairingAbortReason::UserRejectedSas,
        )
        .unwrap();

        // What the phone actually receives: a valid envelope for this session.
        let packet = decode_pairing_packet(&frame).unwrap();
        assert_eq!(packet.version, PROTOCOL_VERSION_V2);
        assert_eq!(packet.session_id, desktop.session_id().to_vec());

        let Some(pairing_packet::Msg::Abort(abort)) = packet.msg else {
            panic!("expected a PairingAbort, got {:?}", packet.msg);
        };
        assert_eq!(abort.reason, PairingAbortReason::UserRejectedSas as i32);
        assert_eq!(
            abort.auth_tag.len(),
            32,
            "an abort after key agreement must carry the HMAC-SHA256 tag over K_c2s"
        );
        // The phone is the side that authenticates the desktop's abort:
        // its verify_abort checks the tag with K_c2s.
        assert!(
            phone
                .verify_abort(&abort)
                .is_ok_and(|authenticated| authenticated),
            "the phone must accept our abort as authenticated"
        );
    }

    #[test]
    fn tagless_abort_after_key_agreement_is_refused_by_the_phone() {
        let (_desktop, phone) = paired_states();
        // A LAN observer can create a fresh session id but not the tag, so the
        // phone must reject a tag-less abort once the keys exist.
        let spoofed = PairingAbort {
            reason: PairingAbortReason::UserRejectedSas as i32,
            auth_tag: Vec::new(),
        };
        assert!(
            phone.verify_abort(&spoofed).is_err(),
            "a tag-less abort must not cancel a session whose keys exist"
        );
    }

    // ---- The session loop over a real loopback socket -------------------
    //
    // Loopback is a deliberate part of the spec, not a test shortcut: the pairing
    // socket must accept datagrams from `127.0.0.1` (Android emulator / QEMU
    // SLIRP NAT), which is what these two tests exercise end to end.

    /// Bind the pairing socket for the loop-level tests.
    ///
    /// A host without a usable IPv6 stack cannot run them, and a silently skipped
    /// test is a green tick over no coverage, so the failure is fatal unless
    /// `TAPAUTH_SKIP_NO_IPV6=1` says this host is known to lack it.
    async fn pairing_socket() -> Option<(UdpSocket, u16)> {
        let bound = bind_pairing_socket()
            .await
            .and_then(|socket| socket.local_addr().map(|address| (socket, address.port())));
        match bound {
            Ok((socket, port)) => Some((socket, port)),
            Err(e) => {
                assert!(
                    std::env::var_os("TAPAUTH_SKIP_NO_IPV6").is_some(),
                    "cannot bind the dual-stack pairing socket ({e}); this test is the only \
                     end-to-end pairing coverage, so set TAPAUTH_SKIP_NO_IPV6=1 to skip it \
                     deliberately"
                );
                eprintln!("skipping the socket pairing test (TAPAUTH_SKIP_NO_IPV6): {e}");
                None
            }
        }
    }

    async fn send_frame(
        socket: &UdpSocket,
        to: SocketAddr,
        session_id: [u8; PAIRING_SESSION_ID_LEN],
        msg: pairing_packet::Msg,
    ) {
        let frame = encode_pairing_packet(&PairingPacket {
            version: PROTOCOL_VERSION_V2,
            session_id: session_id.to_vec(),
            msg: Some(msg),
        })
        .unwrap();
        socket.send_to(&frame, to).await.unwrap();
    }

    async fn recv_frame(socket: &UdpSocket) -> PairingPacket {
        let mut buffer = vec![0u8; MAX_PAIRING_FRAME_LEN];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
            .await
            .expect("the daemon did not send a pairing frame in time")
            .unwrap();
        decode_pairing_packet(buffer.get(..len).unwrap()).unwrap()
    }

    /// A desktop session plus a phone socket that has already sent `PairingInit`
    /// and verified the `PairingResponse`.
    async fn session_and_verified_phone() -> Option<(
        PairingState,
        ClientPairingSession,
        UdpSocket,
        SocketAddr,
        [u8; PAIRING_SESSION_ID_LEN],
        [u8; 32],
    )> {
        let (udp, port) = pairing_socket().await?;
        let desktop_identity = Ed25519KeyPair::from_signing_key_bytes(&DESKTOP_SEED).unwrap();
        let (state, started) = ServerPairingState::start(
            desktop_identity,
            "thinkpad",
            port,
            Some(Ipv4Addr::LOCALHOST),
            None,
            None,
        )
        .unwrap();
        let session_id = started.session_id;
        let qr_pk = started.client_x25519_public_key;

        let phone_identity = Ed25519KeyPair::from_signing_key_bytes(&PHONE_SEED).unwrap();
        let phone_key = phone_identity.verifying_key_bytes();
        let session = spawn(SessionSetup {
            state,
            started,
            udp,
            local_port: port,
            firewall_guard: None,
            enable_ble: false,
            generation: 0,
        });

        let phone_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let daemon = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut phone = ClientPairingSession::new(session_id, phone_identity, "pixel").unwrap();
        let init = phone.create_init().unwrap();
        send_frame(
            &phone_socket,
            daemon,
            session_id,
            pairing_packet::Msg::Init(init),
        )
        .await;

        let response = match recv_frame(&phone_socket).await.msg {
            Some(pairing_packet::Msg::Response(response)) => response,
            other => panic!("expected a PairingResponse, got {:?}", other),
        };
        phone.verify_response(&response, &qr_pk).unwrap();
        assert_eq!(
            Some(qr_pk),
            response.client_x25519_public_key.as_slice().try_into().ok(),
            "the response must commit to the QR key"
        );

        Some((session, phone, phone_socket, daemon, session_id, phone_key))
    }

    #[test]
    fn the_self_echo_guard_drops_only_the_sockets_own_loopback_datagram() {
        let local_port = 36_692u16;

        // Our own echo, in the plain and the v4-mapped form the dual-stack socket
        // reports for an IPv4 peer.
        assert!(is_self_echo(
            SocketAddr::from((Ipv4Addr::LOCALHOST, local_port)),
            local_port
        ));
        assert!(is_self_echo(
            "[::ffff:127.0.0.1]:36692".parse().unwrap(),
            local_port
        ));
        assert!(is_self_echo("[::1]:36692".parse().unwrap(), local_port));

        // Loopback from another port is the emulator behind QEMU SLIRP NAT: a
        // legitimate peer, so dropping every loopback source breaks pairing.
        assert!(!is_self_echo(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 41_000)),
            local_port
        ));
        assert!(!is_self_echo(
            "[::ffff:127.0.0.1]:41000".parse().unwrap(),
            local_port
        ));

        // A non-loopback source is never our echo, even on the same port.
        assert!(!is_self_echo(
            SocketAddr::from(([192, 168, 1, 5], local_port)),
            local_port
        ));
    }

    /// A session wired to a loopback socket and no BLE half, so the frame
    /// handlers can be driven without the loop or a phone.
    async fn test_session(
        state: ServerPairingState,
        session_id: [u8; PAIRING_SESSION_ID_LEN],
    ) -> (Session, watch::Receiver<SessionPhase>) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_port = udp.local_addr().unwrap().port();
        let (phase, phases) = watch::channel(SessionPhase::AwaitingPhone);
        let (_commands, commands) = mpsc::channel(COMMAND_QUEUE_LEN);
        let session = Session {
            state,
            session_id,
            udp,
            local_port,
            _firewall_guard: None,
            link: PairingLink::start([0u8; 10], false).await,
            phase,
            commands,
            peer: Some(Peer::Udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 41_000)))),
            response_frame: None,
            confirm_frame: None,
            provisioning: None,
            completion: None,
            cancel_reply: None,
            server_public_key: None,
            server_device_name: String::new(),
        };
        (session, phases)
    }

    /// An unauthenticated `PairingAbort` must not end our session, while a
    /// properly tagged one from the phone must.
    ///
    /// The defects this catches: `Session::on_abort` treating `Ok(false)` (a
    /// tag-less abort before any key exists) as an abort — anyone who guesses the
    /// session id from the advertisement could cancel the session — and treating
    /// a refused tag-less abort after key agreement (`Err`) as a real abort.
    #[tokio::test]
    async fn a_tagless_abort_does_not_end_the_session_but_a_tagged_one_does() {
        let tagless = PairingAbort {
            reason: PairingAbortReason::UserRejectedSas as i32,
            auth_tag: Vec::new(),
        };

        // Before key agreement there is nothing to authenticate an abort with, so
        // `verify_abort` reports it as unauthenticated (`Ok(false)`).
        let fresh_identity = Ed25519KeyPair::from_signing_key_bytes(&DESKTOP_SEED).unwrap();
        let (fresh_state, fresh_started) = ServerPairingState::start(
            fresh_identity,
            "thinkpad",
            36_692,
            Some(Ipv4Addr::LOCALHOST),
            None,
            None,
        )
        .unwrap();
        let (mut session, phases) = test_session(fresh_state, fresh_started.session_id).await;
        session.publish(SessionPhase::AwaitingSas("123-456".to_string()));
        assert!(matches!(session.on_abort(&tagless), Flow::Continue));
        assert_eq!(
            phases.borrow().clone(),
            SessionPhase::AwaitingSas("123-456".to_string()),
            "an unauthenticated abort must not cancel the session"
        );

        // After key agreement a tag-less abort is refused outright, and only the
        // phone's own tagged abort ends the session.
        let (desktop, phone) = paired_states();
        let session_id = *desktop.session_id();
        let (mut session, phases) = test_session(desktop, session_id).await;
        session.publish(SessionPhase::AwaitingSas("123-456".to_string()));
        assert!(matches!(session.on_abort(&tagless), Flow::Continue));
        assert_eq!(
            phases.borrow().clone(),
            SessionPhase::AwaitingSas("123-456".to_string()),
            "a spoofed tag-less abort must not end a session whose keys exist"
        );

        let tagged = phone
            .create_abort(PairingAbortReason::UserRejectedSas)
            .unwrap();
        assert!(
            !tagged.auth_tag.is_empty(),
            "the phone tags an abort once the session keys exist"
        );
        assert!(matches!(session.on_abort(&tagged), Flow::Done));
        assert_eq!(
            phases.borrow().clone(),
            SessionPhase::Failed(format!(
                "the phone aborted the pairing ({})",
                PairingAbortReason::UserRejectedSas.as_str_name()
            ))
        );
    }

    #[tokio::test]
    async fn udp_session_answers_the_sas_and_provisions_the_csk() {
        let Some((session, phone, phone_socket, daemon, session_id, phone_key)) =
            session_and_verified_phone().await
        else {
            return;
        };

        // The SAS the IPC `WaitForPairing` reports is the phone's own SAS.
        assert_eq!(
            session.phase(),
            SessionPhase::AwaitingSas(phone.sas().unwrap().to_string())
        );

        let csk = [0x5Au8; 32];
        let commands = session.command_sender();
        let phone_side = tokio::spawn(async move {
            let Some(pairing_packet::Msg::ConfirmClient(confirm)) =
                recv_frame(&phone_socket).await.msg
            else {
                panic!("expected a PairingConfirmClient");
            };
            let provisioned = phone.process_confirm_client(&confirm).unwrap();
            assert_eq!(provisioned.csk, csk.to_vec(), "the CSK must arrive intact");
            assert_eq!(provisioned.username, "luca");
            assert_eq!(provisioned.client_hostname, "thinkpad");
            // The CSK must not travel in cleartext.
            assert!(!confirm
                .encrypted_payload
                .windows(csk.len())
                .any(|window| window == csk));

            let complete = phone.create_confirm_server(&csk).unwrap();
            send_frame(
                &phone_socket,
                daemon,
                session_id,
                pairing_packet::Msg::ConfirmServer(complete),
            )
            .await;
        });

        let completed =
            request_completion(&commands, csk, "luca".to_string(), "thinkpad".to_string())
                .await
                .unwrap();
        phone_side.await.unwrap();

        assert_eq!(
            completed.server_public_key, phone_key,
            "the daemon must report the phone's static key from PairingInit"
        );
        assert_eq!(completed.server_device_name, "pixel");
        assert_eq!(
            completed.negotiated.symmetric_algorithm,
            shared::protocol::pb::SymmetricAlgorithm::Aes256Gcm
        );
        assert_eq!(
            completed.negotiated.hash_algorithm,
            shared::protocol::pb::HashAlgorithm::Sha256
        );
        assert_eq!(session.phase(), SessionPhase::Finished);
    }

    #[tokio::test]
    async fn udp_session_cancel_sends_an_authenticated_abort_to_the_phone() {
        let Some((session, phone, phone_socket, _daemon, _session_id, _phone_key)) =
            session_and_verified_phone().await
        else {
            return;
        };

        request_cancellation(&session.command_sender())
            .await
            .unwrap();

        let abort = match recv_frame(&phone_socket).await.msg {
            Some(pairing_packet::Msg::Abort(abort)) => abort,
            other => panic!("expected a PairingAbort, got {:?}", other),
        };
        assert_eq!(abort.reason, PairingAbortReason::UserRejectedSas as i32);
        assert!(
            phone
                .verify_abort(&abort)
                .is_ok_and(|authenticated| authenticated),
            "the phone must accept the cancellation as authenticated"
        );
        assert_eq!(
            session.phase(),
            SessionPhase::Failed("the pairing was cancelled".to_string())
        );
    }
}
