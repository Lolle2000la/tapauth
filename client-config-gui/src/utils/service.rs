use tokio::process::Command;

/// Restart the tapauthd systemd service
pub async fn restart_tapauthd_service() -> Result<(), String> {
    tracing::info!("Restarting tapauthd service...");
    
    let output = Command::new("systemctl")
        .arg("restart")
        .arg("tapauthd.service")
        .output()
        .await
        .map_err(|e| format!("Failed to execute systemctl: {}", e))?;

    if output.status.success() {
        tracing::info!("tapauthd service restarted successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let error_msg = format!("Failed to restart tapauthd service: {}", stderr);
        tracing::error!("{}", error_msg);
        Err(error_msg)
    }
}
