use std::env;

pub fn get_username() -> String {
    if let Ok(user) = env::var("USER") {
        return user;
    }
    whoami::username().unwrap_or_else(|_| "unknown".to_string())
}
