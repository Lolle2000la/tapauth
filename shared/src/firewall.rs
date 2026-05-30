use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Debug, Clone, Copy)]
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

pub struct FirewallGuard {
    port: u16,
    protocol: Protocol,
}

/// Per-port weak-tracking: when a live `Arc<FirewallGuard>` exists for a port,
/// subsequent callers upgrade the `Weak` and share the guard.  When the last
/// strong reference is dropped, `FirewallGuard::drop` closes the port
/// automatically — no manual ref-counting needed.
static GUARDS: OnceLock<Mutex<HashMap<u16, Weak<FirewallGuard>>>> = OnceLock::new();

fn guards() -> &'static Mutex<HashMap<u16, Weak<FirewallGuard>>> {
    GUARDS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl FirewallGuard {
    /// Create a shared `Arc<FirewallGuard>` for the given port.
    ///
    /// If another caller already holds a live guard for this port, the existing
    /// `Arc` is cloned and returned (the port remains open).  Otherwise a new
    /// guard is created, the port is opened, and a `Weak` pointer is stored for
    /// future sharing.
    ///
    /// When the last strong reference is dropped, the port is automatically
    /// closed in a background thread/task — no manual ref-counting needed.
    pub fn new(port: u16, protocol: Protocol) -> Result<Arc<Self>, String> {
        let mut map = guards()
            .lock()
            .map_err(|e| format!("guard map lock poisoned: {}", e))?;

        if let Some(existing) = map.get(&port).and_then(|w| w.upgrade()) {
            return Ok(existing);
        }

        open_port(port, protocol)?;
        let guard = Arc::new(Self { port, protocol });
        map.insert(port, Arc::downgrade(&guard));
        Ok(guard)
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        let port = self.port;
        let protocol = self.protocol;

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || do_drop_close(port, protocol));
        } else {
            std::thread::spawn(move || do_drop_close(port, protocol));
        }
    }
}

/// Called from a background thread/task: check whether the weak entry
/// is still alive and, if not, close the port.  Holding the lock across
/// the check **and** the removal avoids a race with `acquire_guard`.
fn do_drop_close(port: u16, protocol: Protocol) {
    let mut map = match guards().lock() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("guard map lock poisoned on drop: {}", e);
            return;
        }
    };
    if map.get(&port).and_then(|w| w.upgrade()).is_none() && map.remove(&port).is_some() {
        if let Err(e) = close_port(port, protocol) {
            tracing::error!("Failed to close firewall port: {}", e);
        }
    }
}

pub fn open_port(port: u16, protocol: Protocol) -> Result<(), String> {
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
        Ok(status) => Err(format!("iptables command failed with status: {}", status)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "Neither firewalld nor iptables found on host; skipping automated port allocation"
            );
            Ok(())
        }
        Err(e) => Err(format!("Failed to execute iptables: {}", e)),
    }
}

pub fn close_port(port: u16, protocol: Protocol) -> Result<(), String> {
    if is_firewalld_running() {
        if let Err(e) = remove_firewalld_rule(port, protocol) {
            return Err(format!(
                "Failed to close firewall port {}/{}: {}",
                port, protocol, e
            ));
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
        Ok(status) if !status.success() => {
            Err(format!("iptables -D failed with exit status: {}", status))
        }
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
        Err(e) => Err(format!("Failed to execute iptables -D: {}", e)),
    }
}

fn is_firewalld_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "firewalld"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn add_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), String> {
    let status = Command::new("firewall-cmd")
        .args(["--add-port", &format!("{}/{}", port, protocol)])
        .status()
        .map_err(|e| format!("Failed to execute firewall-cmd: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("firewall-cmd failed with status: {}", status))
    }
}

fn remove_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), String> {
    let status = Command::new("firewall-cmd")
        .args(["--remove-port", &format!("{}/{}", port, protocol)])
        .status()
        .map_err(|e| format!("Failed to execute firewall-cmd: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("firewall-cmd failed with status: {}", status))
    }
}
