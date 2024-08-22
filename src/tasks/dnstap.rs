use tokio::process::{Child, Command};

pub fn spawn_dnstap() -> Result<Child, anyhow::Error> {
    let child = Command::new("dnstap")
        .arg("-y")
        .arg("-u")
        .arg("dnstap.sock")
        .arg("-a")
        .arg("-w")
        .arg("logs.yaml")
        .kill_on_drop(true)
        .spawn()?;

    Ok(child)
}
