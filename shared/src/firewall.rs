use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum FirewallError {
    #[error("lock poisoned: {0}")]
    LockPoisoned(String),
    #[error("iptables command failed: {0}")]
    Iptables(String),
    #[error("firewall-cmd failed: {0}")]
    FirewallCmd(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct FirewallGuard {
    port: u16,
    protocol: Protocol,
    /// Set once [`FirewallGuard::close`] has taken responsibility for removing
    /// the rule, so the best-effort [`Drop`] does not shell out a second time.
    closed: AtomicBool,
}

struct PortControl {
    weak: Weak<FirewallGuard>,
    is_open: bool,
}

/// One shared control slot per `(port, protocol)`.
type PortSlot = Arc<Mutex<PortControl>>;

/// Key of the global guard map.
type PortKey = (u16, Protocol);

/// Per-port state, keyed by `(port, protocol)` so the TCP pairing port and the
/// UDP multicast port on the same number never share one `PortControl`.  The
/// global map is locked only briefly to retrieve or insert the
/// `Arc<Mutex<PortControl>>`.  The costly external commands (`iptables`,
/// `firewall-cmd`) run under the per-entry lock only, so concurrent sessions on
/// *different* ports never block each other.
static GUARDS: OnceLock<Mutex<HashMap<PortKey, PortSlot>>> = OnceLock::new();

fn guards() -> &'static Mutex<HashMap<PortKey, PortSlot>> {
    GUARDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get or insert the shared `PortControl` slot for `(port, protocol)`.
///
/// This touches only the global map: it runs **no** external command, so it is
/// safe to call from a test (and from any context that must not spawn
/// `iptables`/`firewall-cmd`). `FirewallGuard::new` performs the actual
/// open/refcount work on the returned slot.
fn reserve_slot(port: u16, protocol: Protocol) -> Result<PortSlot, FirewallError> {
    let mut map = guards()
        .lock()
        .map_err(|e| FirewallError::LockPoisoned(format!("guard map lock poisoned: {}", e)))?;

    Ok(map
        .entry((port, protocol))
        .or_insert_with(|| {
            Arc::new(Mutex::new(PortControl {
                weak: Weak::new(),
                is_open: false,
            }))
        })
        .clone())
}

impl FirewallGuard {
    /// Create a shared `Arc<FirewallGuard>` for the given port and protocol.
    ///
    /// If another caller already holds a live guard for this `(port, protocol)`,
    /// the existing `Arc` is cloned and returned (the port remains open).
    /// Otherwise a new guard is created, the port is opened, and a `Weak` pointer
    /// is stored for future sharing.
    ///
    /// When the last strong reference is dropped, the port is automatically
    /// closed in a background thread/task — no manual ref-counting needed. A
    /// caller that must observe the rule gone calls [`FirewallGuard::close`]
    /// instead, which awaits the removal.
    pub fn new(port: u16, protocol: Protocol) -> Result<Arc<Self>, FirewallError> {
        let port_ctrl = reserve_slot(port, protocol)?;

        let mut ctrl = port_ctrl.lock().map_err(|e| {
            FirewallError::LockPoisoned(format!("port control lock poisoned: {}", e))
        })?;

        if let Some(existing) = ctrl.weak.upgrade() {
            return Ok(existing);
        }

        if !ctrl.is_open {
            open_port(port, protocol)?;
            ctrl.is_open = true;
        }
        let guard = Arc::new(Self {
            port,
            protocol,
            closed: AtomicBool::new(false),
        });
        ctrl.weak = Arc::downgrade(&guard);
        Ok(guard)
    }

    /// Remove this guard's rule now, awaiting the external command.
    ///
    /// [`Drop`] can only *enqueue* the close: the last reference is typically
    /// dropped on a tokio worker, which must not block on `iptables`. A caller
    /// that needs the rule gone before it publishes anything a client can react
    /// to — the pairing session publishing `Finished`/`Failed` — therefore calls
    /// this and awaits it.
    ///
    /// Unlike [`Drop`], the caller is still holding the guard while this runs, so
    /// liveness cannot be the close decision: the guard deregisters itself from
    /// the shared slot first, and the port is closed unless the slot still names
    /// another live guard (another session on the same `(port, protocol)`), whose
    /// rule would be cut off by removing it.
    ///
    /// Idempotent: the first call does the work, a second call is a no-op, and the
    /// [`Drop`] that follows sees the `closed` flag and does not enqueue a second
    /// removal. The blocking subprocess runs on the blocking pool and is awaited,
    /// so a failure is reported here (and logged) rather than detached.
    pub async fn close(&self) -> Result<(), FirewallError> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let (port, protocol) = (self.port, self.protocol);
        match tokio::task::spawn_blocking(move || do_explicit_close(port, protocol)).await {
            // Still shared with another live guard: nothing was removed, so this
            // guard keeps its best-effort drop.
            Ok(CloseDisposition::KeptForAnotherHolder) => {
                self.closed.store(false, Ordering::SeqCst);
                Ok(())
            }
            Ok(CloseDisposition::Closed) => Ok(()),
            Err(e) => Err(FirewallError::Io(std::io::Error::other(format!(
                "the firewall close task failed: {}",
                e
            )))),
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        // [`FirewallGuard::close`] already removed the rule and awaited the
        // subprocess; running the close again would only fail on a rule that is
        // no longer there.
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let (port, protocol) = (self.port, self.protocol);
        // Closing a port shells out to `iptables`/`ufw`/`firewall-cmd`, which
        // blocks until the subprocess exits. The last strong reference is
        // typically dropped on a tokio worker (a pairing session tearing down),
        // so the close runs on the blocking pool and is detached: the subprocess
        // may outlive this drop by the time it takes to spawn it and run.
        //
        // Deferring is safe because `do_drop_close` re-checks the shared slot
        // under its own lock: a guard created before the task runs re-registers
        // the port as open, so the port is not closed underneath a live session.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Dropping the join handle detaches the task.
                handle.spawn_blocking(move || do_drop_close(port, protocol));
            }
            // No runtime (a plain thread, a test): run the close here, exactly as
            // before.
            Err(_) => do_drop_close(port, protocol),
        }
    }
}

/// What [`do_explicit_close`] did, so [`FirewallGuard::close`] can undo its own
/// `closed` flag when it chose not to touch the rule.
enum CloseDisposition {
    /// The rule was removed (or there was nothing left to remove).
    Closed,
    /// Another live guard shares the `(port, protocol)`; the rule stays.
    KeptForAnotherHolder,
}

/// [`FirewallGuard::close`], on the blocking pool.
///
/// The requesting guard is still alive here (it awaits this), so the liveness
/// check [`do_drop_close`] uses would always say "still held". Instead the slot is
/// deregistered first — which is what a later `new` on the same port and a later
/// best-effort drop both observe — and the rule is removed unless another live
/// guard still holds the slot.
fn do_explicit_close(port: u16, protocol: Protocol) -> CloseDisposition {
    let port_ctrl = {
        let map = match guards().lock() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("guard map lock poisoned on close: {}", e);
                return CloseDisposition::Closed;
            }
        };
        match map.get(&(port, protocol)) {
            Some(ctrl) => ctrl.clone(),
            // Never registered (or already deregistered): nothing to remove.
            None => return CloseDisposition::Closed,
        }
    };

    let mut ctrl = match port_ctrl.lock() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("port control lock poisoned on close: {}", e);
            return CloseDisposition::Closed;
        }
    };

    // One strong reference is this guard; more than one means another session
    // still needs the port.
    if Weak::strong_count(&ctrl.weak) > 1 {
        tracing::debug!(
            "Firewall ({}): port {} is still held by another session; leaving the rule open",
            protocol,
            port
        );
        return CloseDisposition::KeptForAnotherHolder;
    }

    ctrl.weak = Weak::new();
    if ctrl.is_open {
        if let Err(e) = close_port(port, protocol) {
            tracing::error!("Failed to close firewall port: {}", e);
        }
        ctrl.is_open = false;
    }
    CloseDisposition::Closed
}

/// Check whether the weak entry is still alive and, if not, close the
/// port.  Uses only the per-entry lock for the close decision so that
/// operations on other ports are never blocked.
fn do_drop_close(port: u16, protocol: Protocol) {
    let port_ctrl = {
        let map = match guards().lock() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("guard map lock poisoned on drop: {}", e);
                return;
            }
        };
        match map.get(&(port, protocol)) {
            Some(ctrl) => ctrl.clone(),
            None => return,
        }
    };

    let mut ctrl = match port_ctrl.lock() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("port control lock poisoned on drop: {}", e);
            return;
        }
    };

    if ctrl.weak.upgrade().is_none() && ctrl.is_open {
        if let Err(e) = close_port(port, protocol) {
            tracing::error!("Failed to close firewall port: {}", e);
        }
        ctrl.is_open = false;
    }
}

pub fn open_port(port: u16, protocol: Protocol) -> Result<(), FirewallError> {
    if is_firewalld_running() {
        add_firewalld_rule(port, protocol)?;
        tracing::info!(
            "Firewall (firewalld): Opened ephemeral port {}/{}",
            port,
            protocol
        );
        return Ok(());
    }

    let result = Command::new("iptables")
        .args([
            "-I",
            "INPUT",
            "1",
            "-p",
            &protocol.to_string(),
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .status();

    match result {
        Ok(status) if status.success() => {
            tracing::info!(
                "Firewall (iptables): Opened ephemeral port {}/{}",
                port,
                protocol
            );
            Ok(())
        }
        Ok(status) => Err(FirewallError::Iptables(format!(
            "command failed with status: {}",
            status
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "Neither firewalld nor iptables found on host; skipping automated port allocation"
            );
            Ok(())
        }
        Err(e) => Err(FirewallError::Io(e)),
    }
}

pub fn close_port(port: u16, protocol: Protocol) -> Result<(), FirewallError> {
    if is_firewalld_running() {
        if let Err(e) = remove_firewalld_rule(port, protocol) {
            return Err(FirewallError::FirewallCmd(format!(
                "Failed to close firewall port {}/{}: {}",
                port, protocol, e
            )));
        } else {
            tracing::info!(
                "Firewall (firewalld): Closed ephemeral port {}/{}",
                port,
                protocol
            );
        }
        return Ok(());
    }

    let result = Command::new("iptables")
        .args([
            "-D",
            "INPUT",
            "-p",
            &protocol.to_string(),
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .status();

    match result {
        Ok(status) if !status.success() => Err(FirewallError::Iptables(format!(
            "iptables -D failed with exit status: {}",
            status
        ))),
        Ok(_) => {
            tracing::info!(
                "Firewall (iptables): Closed ephemeral port {}/{}",
                port,
                protocol
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("iptables binary not found; skipping automated port cleanup");
            Ok(())
        }
        Err(e) => Err(FirewallError::Io(e)),
    }
}

fn is_firewalld_running() -> bool {
    // Capture output: systemd forwards any inherited stdout to the journal,
    // which would pollute `journalctl -u tapauthd` with systemctl's status
    // lines.
    Command::new("systemctl")
        .args(["is-active", "--quiet", "firewalld"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn add_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), FirewallError> {
    run_firewalld_port_action("--add-port", port, protocol)
}

fn remove_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), FirewallError> {
    run_firewalld_port_action("--remove-port", port, protocol)
}

/// Run a firewall-cmd port action and capture its output.
///
/// Output is captured (never inherited): firewall-cmd prints "success" on
/// stdout, which systemd would otherwise forward to the journal under the
/// tapauthd unit name.
fn run_firewalld_port_action(
    action_flag: &str,
    port: u16,
    protocol: Protocol,
) -> Result<(), FirewallError> {
    let output = Command::new("firewall-cmd")
        .args([action_flag, &format!("{}/{}", port, protocol)])
        .output()
        .map_err(|e| {
            FirewallError::FirewallCmd(format!("Failed to execute firewall-cmd: {}", e))
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FirewallError::FirewallCmd(format!(
            "firewall-cmd {} failed with status: {} — stdout: {} — stderr: {}",
            action_flag,
            output.status,
            String::from_utf8_lossy(&output.stdout).trim_end(),
            String::from_utf8_lossy(&output.stderr).trim_end()
        )))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// A high fixed port, outside the ephemeral range the kernel hands out.
    ///
    /// NOTE: `GUARDS` is a process-global map shared by every test in this
    /// binary. `reserve_slot` never opens a port and never spawns a command, so
    /// using it (rather than `FirewallGuard::new`) keeps this test free of
    /// `iptables`/`firewall-cmd` side effects and safe to share.
    const TEST_PORT: u16 = 45_678;

    /// The guard map must be keyed by `(port, protocol)`.
    /// The defect this catches: a TCP and a UDP guard on the same port number
    /// sharing one entry, so dropping the TCP pairing guard would close the UDP
    /// multicast port an authentication attempt is still using (and vice versa).
    #[test]
    fn reserve_slot_separates_protocols_on_the_same_port() {
        let udp = reserve_slot(TEST_PORT, Protocol::Udp).unwrap();
        let tcp = reserve_slot(TEST_PORT, Protocol::Tcp).unwrap();

        assert!(
            !Arc::ptr_eq(&udp, &tcp),
            "TCP and UDP on the same port must not share one slot"
        );

        // Re-reserving the same (port, protocol) yields the same slot.
        let udp_again = reserve_slot(TEST_PORT, Protocol::Udp).unwrap();
        assert!(
            Arc::ptr_eq(&udp, &udp_again),
            "the same (port, protocol) must reuse its slot"
        );

        // Both entries exist, and each maps to its own slot.
        let map = guards().lock().unwrap();
        let udp_entry = map.get(&(TEST_PORT, Protocol::Udp)).unwrap();
        let tcp_entry = map.get(&(TEST_PORT, Protocol::Tcp)).unwrap();
        assert!(Arc::ptr_eq(udp_entry, &udp));
        assert!(Arc::ptr_eq(tcp_entry, &tcp));
        assert!(!Arc::ptr_eq(udp_entry, tcp_entry));
    }

    /// Ports no other test registers, and one per test: `GUARDS` is a
    /// process-global map, so two tests sharing a `(port, protocol)` would each see
    /// the other's registered guard (and its strong count) and fail on an
    /// assertion that is true when the test runs alone.
    ///
    /// NOTE: these tests build a `FirewallGuard` directly (rather than through
    /// `FirewallGuard::new`) and register it in the slot with `is_open = false`,
    /// which is what keeps them free of `iptables`/`firewall-cmd` side effects.
    const CLOSE_TEST_PORT: u16 = 45_679;
    const SHARED_CLOSE_TEST_PORT: u16 = 45_680;

    /// A guard registered in a slot that claims no open rule, so the close
    /// decision is exercised without shelling out.
    fn registered_guard(port: u16, is_open: bool) -> (Arc<FirewallGuard>, PortSlot) {
        let guard = Arc::new(FirewallGuard {
            port,
            protocol: Protocol::Udp,
            closed: AtomicBool::new(false),
        });
        let slot = reserve_slot(port, Protocol::Udp).unwrap();
        {
            let mut ctrl = slot.lock().unwrap();
            ctrl.weak = Arc::downgrade(&guard);
            ctrl.is_open = is_open;
        }
        (guard, slot)
    }

    /// `close()` deregisters the guard before it awaits the removal, so the wait
    /// really sees a port nobody holds.
    ///
    /// The defects this catches: a close that leaves the requesting guard
    /// registered (what `do_drop_close`'s liveness check would see), so the
    /// external command never runs and the close reports success while the port
    /// stays open — the pairing session would then publish `Finished`/`Failed`
    /// with its pairing port still reachable.
    #[tokio::test]
    async fn close_deregisters_the_guard_before_the_rule_is_removed() {
        let (guard, slot) = registered_guard(CLOSE_TEST_PORT, false);
        assert!(
            Arc::ptr_eq(&slot.lock().unwrap().weak.upgrade().unwrap(), &guard),
            "the fixture registers the guard"
        );

        guard.close().await.unwrap();

        // The guard is still alive here — `close` takes `&self` — so a live weak
        // can only mean the slot was never deregistered.
        assert!(
            slot.lock().unwrap().weak.upgrade().is_none(),
            "close must deregister the guard it is closing"
        );
        assert!(guard.closed.load(Ordering::SeqCst));
    }

    /// One holder closing a shared guard must not cut the port out from under the
    /// other holder.
    ///
    /// The defect this catches: `close()` removing a `(port, protocol)` rule that a
    /// second live guard shares — the other session's port goes dark even though it
    /// still needs the rule — and clearing its own `closed` flag decision so the
    /// last holder never closes it either.
    #[tokio::test]
    async fn close_leaves_a_shared_guard_to_its_last_holder() {
        let (guard, slot) = registered_guard(SHARED_CLOSE_TEST_PORT, false);
        let other = Arc::clone(&guard);

        guard.close().await.unwrap();

        assert!(
            slot.lock().unwrap().weak.upgrade().is_some(),
            "a shared guard must stay registered for the remaining holder"
        );
        assert!(
            !other.closed.load(Ordering::SeqCst),
            "a shared guard must keep its drop fallback, or the port is never closed"
        );
        drop(other);
    }
}
