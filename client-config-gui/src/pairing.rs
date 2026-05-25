use crate::ipc;

pub async fn start_pairing() -> Result<(String, u16), String> {
    tracing::debug!("Starting pairing via daemon IPC...");
    ipc::start_pairing().await
}

pub async fn wait_for_pairing_connection(port: u16) -> Result<(String, u16), String> {
    tracing::debug!("Waiting for pairing connection via daemon IPC...");
    let (sas_code, port) = ipc::wait_for_pairing(port as u32).await?;
    Ok((sas_code, port))
}

pub async fn complete_pairing(port: u16) -> Result<String, String> {
    tracing::debug!("Completing pairing via daemon IPC...");
    ipc::complete_pairing(port as u32).await
}
