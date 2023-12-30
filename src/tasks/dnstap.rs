use tokio::process::Command;

pub async fn run_dnstap() {
    Command::new("dnstap")
        .arg("-y")
        .arg("-u")
        .arg("dnstap.sock")
        .arg("-a")
        .arg("-w")
        .arg("logs.yaml")
        .output()
        .await
        .unwrap();
}
