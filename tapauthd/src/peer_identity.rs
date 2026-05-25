use nix::unistd::User;

const POLKIT_ACTION_ID: &str = "org.tapauth.config.admin";

pub struct PeerIdentity {
    #[allow(dead_code)]
    pub pid: i32,
    #[allow(dead_code)]
    pub uid: u32,
    pub username: String,
    pub start_time: u64,
}

pub fn resolve_peer(pid: i32, uid: u32) -> Result<PeerIdentity, String> {
    if pid <= 0 {
        return Err(format!(
            "Invalid peer PID {} from SO_PEERCRED — expected positive PID",
            pid
        ));
    }
    let username = User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| {
            tracing::warn!("Failed to resolve UID: {}", e);
            "Failed to resolve peer identity".to_string()
        })?
        .ok_or_else(|| {
            tracing::warn!("No user found for UID {uid}");
            "Failed to resolve peer identity".to_string()
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

fn read_process_start_time(pid: i32) -> Result<u64, String> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(&stat_path)
        .map_err(|e| format!("Failed to read {}: {}", stat_path, e))?;

    let comm_end = stat_content
        .rfind(')')
        .ok_or_else(|| format!("Malformed /proc/{}/stat: no closing parenthesis", pid))?;

    let after_comm = &stat_content[comm_end + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    if fields.len() < 20 {
        return Err(format!(
            "Malformed /proc/{}/stat: only {} fields after comm",
            pid,
            fields.len()
        ));
    }

    fields
        .get(19)
        .ok_or_else(|| format!("Malformed /proc/{}/stat: too few fields", pid))?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse start_time from /proc/{}/stat: {}", pid, e))
}

/// Authorize an admin IPC caller via PolKit.
///
/// Uses `CheckAuthorization` with the caller's process as the subject.
/// The tapauthd daemon must be registered as an action owner via the
/// `org.freedesktop.policykit.owner` annotation so it can query
/// authorizations for subjects belonging to other identities.
///
/// Falls back to root-only when PolKit is unavailable.
pub async fn check_authorization(identity: &PeerIdentity) -> Result<(), String> {
    match check_polkit(identity).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Authorization denied by PolKit".to_string()),
        Err(e) => {
            if is_dbus_unavailable(&e) {
                tracing::warn!(
                    "PolKit unavailable ({}), falling back to root-only check",
                    e
                );
                if identity.uid == 0 {
                    Ok(())
                } else {
                    Err(format!(
                        "PolKit unavailable ({}) and caller is not root. \
                         Install PolicyKit or run as root.",
                        e
                    ))
                }
            } else {
                Err(format!("PolKit authorization failed: {}", e))
            }
        }
    }
}

async fn check_polkit(identity: &PeerIdentity) -> Result<bool, String> {
    use zbus::Connection;

    let connection = Connection::system()
        .await
        .map_err(|e| format!("D-Bus unavailable: {}", e))?;

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
        .map_err(|e| format!("PolKit call failed: {}", e))?;

    let body = reply.body();
    let (is_authorized, _is_challenge, _details): (
        bool,
        bool,
        std::collections::HashMap<String, String>,
    ) = body
        .deserialize()
        .map_err(|e| format!("PolKit response parse failed: {}", e))?;

    Ok(is_authorized)
}

fn is_dbus_unavailable(error: &str) -> bool {
    let e = error.to_lowercase();
    e.contains("d-bus unavailable")
        || e.contains("dbus unavailable")
        || e.contains("not found")
        || e.contains("no such")
        || e.contains("serviceunknown")
}
