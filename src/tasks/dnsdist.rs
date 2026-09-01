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

/// Reloads the TLS certificates into the running dnsdist via its control socket.
///
/// The console key is taken from `dnsdist.conf` with `-C` rather than passed as
/// `-k <key>`: dnsdist 2.0 no longer accepts a key supplied that way, and `-k`
/// also exposed the key through `ps` to any user on the host. `-C` works on
/// 1.8.x, 1.9.x and 2.0.x alike.
///
/// The same env vars as `spawn_dnsdist` are set because the client evaluates
/// the whole config, and `dnsdist.conf` reads them via `os.getenv`.
pub async fn run_dnsdist_reload_cert(
    tls_enabled: bool,
    backend: SocketAddr,
    port: u16,
) -> Result<(), anyhow::Error> {
    let res = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND", backend.to_string())
        .env("PORT", port.to_string())
        .arg("-C")
        .arg("dnsdist.conf")
        .arg("-c")
        .arg("127.0.0.1")
        .arg("-e")
        .arg("reloadAllCertificates()")
        .status()
        .await?;

    tracing::info!("dnsdist reload status: {res}");

    Ok(())
}
