use nix::unistd::User;

const POLKIT_ACTION_ID: &str = "org.tapauth.config.admin";

pub struct PeerIdentity {
    pub pid: i32,
    pub uid: u32,
    pub username: String,
    pub start_time: u64,
}

pub fn resolve_peer(pid: i32, uid: u32) -> Result<PeerIdentity, String> {
    let username = User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| format!("Failed to resolve UID {}: {}", uid, e))?
        .ok_or_else(|| format!("No user found for UID {}", uid))?
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

pub async fn check_authorization(identity: &PeerIdentity) -> Result<(), String> {
    let result = check_polkit_authorization(identity).await;

    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err("Authorization denied by PolKit".to_string()),
        Err(e) => {
            if is_polkit_unavailable(&e) {
                tracing::warn!("PolKit unavailable ({}), falling back to UID==0 check", e);
                if identity.uid == 0 {
                    Ok(())
                } else {
                    Err(format!(
                        "Unauthorized: not root and PolKit unavailable ({})",
                        e
                    ))
                }
            } else {
                Err(e)
            }
        }
    }
}

async fn check_polkit_authorization(identity: &PeerIdentity) -> Result<bool, String> {
    use zbus::Connection;

    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system D-Bus: {}", e))?;

    let subject = build_polkit_subject(identity);

    let reply = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(
                subject,
                POLKIT_ACTION_ID,
                std::collections::HashMap::<&str, &str>::new(),
                1u32,
                "",
            ),
        )
        .await
        .map_err(|e| format!("PolKit CheckAuthorization call failed: {}", e))?;

    let body = reply.body();
    let (is_authorized, _is_challenge, _details): (
        bool,
        bool,
        std::collections::HashMap<String, String>,
    ) = body
        .deserialize()
        .map_err(|e| format!("Failed to deserialize PolKit response: {}", e))?;

    Ok(is_authorized)
}

fn is_polkit_unavailable(error: &str) -> bool {
    let e = error.to_lowercase();
    e.contains("connect")
        || e.contains("not found")
        || e.contains("no such")
        || e.contains("serviceunknown")
}

fn build_polkit_subject(
    identity: &PeerIdentity,
) -> std::collections::HashMap<String, zbus::zvariant::Value<'_>> {
    let mut subject = std::collections::HashMap::new();
    subject.insert(
        "type".to_string(),
        zbus::zvariant::Value::Str("unix-process".into()),
    );
    subject.insert(
        "pid".to_string(),
        zbus::zvariant::Value::U32(identity.pid as u32),
    );
    subject.insert(
        "start-time".to_string(),
        zbus::zvariant::Value::U64(identity.start_time),
    );
    subject.insert(
        "uid".to_string(),
        zbus::zvariant::Value::I32(identity.uid as i32),
    );
    subject
}
