use nix::unistd::User;

pub struct PeerIdentity {
    #[allow(dead_code)]
    pub pid: i32,
    #[allow(dead_code)]
    pub uid: u32,
    pub username: String,
    #[allow(dead_code)]
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
