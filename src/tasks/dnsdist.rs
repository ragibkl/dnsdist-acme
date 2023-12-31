use std::net::SocketAddr;

use tokio::process::Command;

pub async fn run_dnsdist(tls_enabled: bool, backend: SocketAddr, port: u16) {
    let res = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND", backend.to_string())
        .env("PORT", port.to_string())
        .arg("--supervised")
        .arg("--disable-syslog")
        .arg("--config")
        .arg("dnsdist.conf")
        .status()
        .await
        .unwrap();

    tracing::info!("dnsdist status: {res}");
}

pub async fn reload_dnsdist_cert() {
    let res = Command::new("dnsdist")
        .arg("-c")
        .arg("127.0.0.1")
        .arg("-k")
        .arg("miQjUydO7fwUmSDS0hT+2pHC1VqT8vOjfexOyvHKcNA=")
        .arg("-e")
        .arg("reloadAllCertificates()")
        .status()
        .await
        .unwrap();

    tracing::info!("dnsdist reload status: {res}");
}
