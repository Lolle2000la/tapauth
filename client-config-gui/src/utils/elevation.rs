use nix::unistd::User;

pub fn get_username() -> String {
    if let Ok(Some(user)) = User::from_uid(nix::unistd::geteuid()) {
        return user.name;
    }
    whoami::username().unwrap_or_else(|_| "unknown".to_string())
}
