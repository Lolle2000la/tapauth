use nix::unistd::User;
use zbus::Connection;

const POLKIT_ACTION_ID: &str = "dev.rourunisen.tapauth.config.admin";

#[derive(thiserror::Error, Debug)]
pub enum PeerIdentityError {
    #[error("invalid peer PID {0}")]
    InvalidPid(i32),
    #[error("failed to resolve peer identity")]
    ResolveFailed,
    #[error("cannot read /proc/{pid}/stat: {source}")]
    ProcStatRead {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed /proc/{pid}/stat: {detail}")]
    ProcStatMalformed { pid: i32, detail: String },
    #[error("D-Bus connection failed: {0}")]
    DBusUnavailable(String),
    #[error("authorization denied by PolKit")]
    AuthorizationDenied,
    #[error("PolKit unavailable ({reason}) and caller is not root")]
    PolKitUnavailable { reason: String },
    #[error("PolKit authorization failed: {0}")]
    PolKitError(String),
}

pub struct PeerIdentity {
    #[allow(dead_code)]
    pub pid: i32,
    #[allow(dead_code)]
    pub uid: u32,
    pub username: String,
    pub start_time: u64,
}

pub fn resolve_peer(pid: i32, uid: u32) -> Result<PeerIdentity, PeerIdentityError> {
    if pid <= 0 {
        return Err(PeerIdentityError::InvalidPid(pid));
    }
    let username = User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| {
            tracing::warn!("Failed to resolve UID: {}", e);
            PeerIdentityError::ResolveFailed
        })?
        .ok_or_else(|| {
            tracing::warn!("No user found for UID {uid}");
            PeerIdentityError::ResolveFailed
        })?
        .name;

    let start_time = read_process_start_time(pid)?;

    Ok(PeerIdentity {
        pid,
        uid,
        username,
        start_time,
    })
}

fn read_process_start_time(pid: i32) -> Result<u64, PeerIdentityError> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(&stat_path)
        .map_err(|e| PeerIdentityError::ProcStatRead { pid, source: e })?;

    let comm_end = stat_content
        .rfind(')')
        .ok_or_else(|| PeerIdentityError::ProcStatMalformed {
            pid,
            detail: "no closing parenthesis".to_string(),
        })?;

    let after_comm = &stat_content[comm_end + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    if fields.len() < 20 {
        return Err(PeerIdentityError::ProcStatMalformed {
            pid,
            detail: format!("only {} fields after comm", fields.len()),
        });
    }

    fields
        .get(19)
        .ok_or_else(|| PeerIdentityError::ProcStatMalformed {
            pid,
            detail: "too few fields".to_string(),
        })?
        .parse::<u64>()
        .map_err(|e| PeerIdentityError::ProcStatMalformed {
            pid,
            detail: format!("failed to parse start_time: {}", e),
        })
}

/// Authorize an admin IPC caller via PolKit.
///
/// Uses `CheckAuthorization` with the caller's process as the subject.
/// The tapauthd daemon must be registered as an action owner via the
/// `org.freedesktop.policykit.owner` annotation so it can query
/// authorizations for subjects belonging to other identities.
///
/// Falls back to root-only when PolKit is unavailable.
pub async fn check_authorization(identity: &PeerIdentity) -> Result<(), PeerIdentityError> {
    match check_polkit(identity).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(PeerIdentityError::AuthorizationDenied),
        Err(e @ PeerIdentityError::DBusUnavailable(_)) => {
            tracing::warn!(
                "PolKit unavailable ({}), falling back to root-only check",
                e
            );
            if identity.uid == 0 {
                Ok(())
            } else {
                Err(PeerIdentityError::PolKitUnavailable {
                    reason: format!(
                        "D-Bus unavailable ({}) and caller is not root. \
                         Install PolicyKit or run as root.",
                        e
                    ),
                })
            }
        }
        Err(e) => Err(e),
    }
}

async fn check_polkit(identity: &PeerIdentity) -> Result<bool, PeerIdentityError> {
    let connection = Connection::system()
        .await
        .map_err(|e| PeerIdentityError::DBusUnavailable(format!("{}", e)))?;

    let mut details = std::collections::HashMap::new();
    details.insert(
        "pid".to_string(),
        zbus::zvariant::Value::U32(identity.pid as u32),
    );
    details.insert(
        "start-time".to_string(),
        zbus::zvariant::Value::U64(identity.start_time),
    );
    details.insert("uid".to_string(), zbus::zvariant::Value::U32(identity.uid));

    let reply = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(
                ("unix-process".to_string(), details),
                POLKIT_ACTION_ID,
                std::collections::HashMap::<&str, &str>::new(),
                1u32, // AllowUserInteraction
                "",
            ),
        )
        .await
        .map_err(|e| PeerIdentityError::PolKitError(format!("{}", e)))?;

    let body = reply.body();
    let (is_authorized, _is_challenge, _details): (
        bool,
        bool,
        std::collections::HashMap<String, String>,
    ) = body
        .deserialize()
        .map_err(|e| PeerIdentityError::PolKitError(format!("response parse failed: {}", e)))?;

    Ok(is_authorized)
}
