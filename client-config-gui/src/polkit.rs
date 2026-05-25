use std::collections::HashMap;

const ACTION_ID: &str = "org.tapauth.config.admin";

/// Check whether the current process is authorized for TapAuth admin operations.
///
/// Calls PolicyKit1.CheckAuthorization with `AllowUserInteraction = true` so
/// the desktop's authentication agent can prompt for the user's password.
///
/// Fails closed for unprivileged users: if PolKit is unavailable or returns
/// an error, the caller is denied.  Root (UID 0) bypasses PolKit entirely —
/// the daemon's socket permissions still gate access.
pub async fn authorize_admin_action() -> Result<(), String> {
    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    match try_polkit().await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Authorization denied by authentication agent".to_string()),
        Err(e) => {
            if is_dbus_unavailable(&e) {
                Err(format!(
                    "PolicyKit is not available on this system ({}).\n\
                     Run the TapAuth config GUI as root (sudo) to bypass PolKit, \
                     or install and configure PolicyKit.",
                    e
                ))
            } else {
                Err(format!("PolKit authorization failed: {}", e))
            }
        }
    }
}

async fn try_polkit() -> Result<bool, String> {
    use zbus::Connection;

    let connection = Connection::system()
        .await
        .map_err(|e| format!("D-Bus unavailable: {}", e))?;

    let pid = std::process::id() as u32;
    let start_time = read_self_start_time()?;

    let mut details = HashMap::new();
    details.insert("pid".to_string(), zbus::zvariant::Value::U32(pid));
    details.insert(
        "start-time".to_string(),
        zbus::zvariant::Value::U64(start_time),
    );

    let reply = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(
                ("unix-process".to_string(), details),
                ACTION_ID,
                HashMap::<&str, &str>::new(),
                1u32,
                "",
            ),
        )
        .await
        .map_err(|e| format!("PolKit call failed: {}", e))?;

    let body = reply.body();
    let (is_authorized, _is_challenge, _details): (bool, bool, HashMap<String, String>) = body
        .deserialize()
        .map_err(|e| format!("PolKit response parse failed: {}", e))?;

    Ok(is_authorized)
}

fn is_dbus_unavailable(error: &str) -> bool {
    let e = error.to_lowercase();
    e.contains("d-bus")
        || e.contains("dbus")
        || e.contains("connect")
        || e.contains("not found")
        || e.contains("no such")
        || e.contains("serviceunknown")
}

fn read_self_start_time() -> Result<u64, String> {
    let stat_content = std::fs::read_to_string("/proc/self/stat")
        .map_err(|e| format!("Failed to read /proc/self/stat: {}", e))?;

    let comm_end = stat_content
        .rfind(')')
        .ok_or_else(|| "Malformed /proc/self/stat".to_string())?;

    let after_comm = &stat_content[comm_end + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    fields
        .get(19)
        .ok_or_else(|| "Malformed /proc/self/stat: too few fields".to_string())?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse start_time: {}", e))
}
