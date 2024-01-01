use std::path::PathBuf;

use tokio::process::Command;

pub struct CertbotTask {
    domain: String,
    email: String,
}

impl CertbotTask {
    pub fn new(domain: &str, email: &str) -> Self {
        let domain = domain.to_string();
        let email = email.to_string();
        Self { domain, email }
    }

    pub async fn run(&self) -> Result<(), anyhow::Error> {
        Command::new("certbot")
            .arg("certonly")
            .arg("--standalone")
            .arg("--non-interactive")
            .arg("--agree-tos")
            .arg("--preferred-chain")
            .arg("ISRG Root X1")
            .arg("--domain")
            .arg(&self.domain)
            .arg("--email")
            .arg(&self.email)
            .output()
            .await
            .unwrap();

        let (cert, key) = {
            let dir = PathBuf::from("/etc/letsencrypt/live/").join(&self.domain);
            let cert = dir.join("fullchain.pem");
            let key = dir.join("privkey.pem");
            (cert, key)
        };

        tokio::fs::create_dir_all("./certs").await?;
        tokio::fs::copy(cert, "./certs/fullchain.pem").await?;
        tokio::fs::copy(key, "./certs/privkey.pem").await?;

        Ok(())
    }
}
