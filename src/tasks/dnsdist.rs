use tokio::process::Command;

pub async fn run_dnsdist() {
    Command::new("dnsdist")
        .arg("--supervised")
        .arg("--disable-syslog")
        .arg("--config")
        .arg("dnsdist.conf")
        .output()
        .await
        .unwrap();
}
