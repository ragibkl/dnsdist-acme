use std::net::SocketAddr;

use tokio::process::{Child, Command};

pub fn spawn_dnsdist(
    tls_enabled: bool,
    backend: SocketAddr,
    port: u16,
) -> Result<Child, anyhow::Error> {
    let child = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND", backend.to_string())
        .env("PORT", port.to_string())
        .arg("--supervised")
        .arg("--disable-syslog")
        .arg("--config")
        .arg("dnsdist.conf")
        .kill_on_drop(true)
        .spawn()?;

    Ok(child)
}

pub async fn run_dnsdist_reload_cert() -> Result<(), anyhow::Error> {
    let res = Command::new("dnsdist")
        .arg("-c")
        .arg("127.0.0.1")
        .arg("-k")
        .arg("miQjUydO7fwUmSDS0hT+2pHC1VqT8vOjfexOyvHKcNA=")
        .arg("-e")
        .arg("reloadAllCertificates()")
        .status()
        .await?;

    tracing::info!("dnsdist reload status: {res}");

    Ok(())
}
