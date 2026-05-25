use std::collections::HashMap;

const ACTION_ID: &str = "org.tapauth.config.admin";

/// Check whether the current process is authorized for TapAuth admin operations.
///
/// Calls PolicyKit1.CheckAuthorization with `AllowUserInteraction = true` so
/// the desktop's authentication agent can prompt for the user's password.
/// Falls back to allowing access when PolKit is unavailable (the Unix socket
/// already gates access via group membership).
pub async fn authorize_admin_action() -> Result<(), String> {
    match try_polkit().await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Authorization denied by authentication agent".to_string()),
        Err(e) => {
            tracing::warn!(
                "PolKit unavailable or not configured ({}); allowing access via socket membership",
                e
            );
            Ok(())
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
    // uid is implicitly the caller's uid — omit for self-check

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
                1u32, // AllowUserInteraction
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
