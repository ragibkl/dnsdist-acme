use tokio::process::Command;

pub async fn run_dnsdist(tls_enabled: bool, backend_port: u16, port: u16) {
    let res = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND_PORT", backend_port.to_string())
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
