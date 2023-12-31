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

    pub async fn run(&self) {
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
            .arg("--dry-run")
            .output()
            .await
            .unwrap();

        let certs_dir = PathBuf::from("/etc/letsencrypt/live/").join(&self.domain);
        let cert_path = certs_dir.join("fullchain.pem");
        let key_path = certs_dir.join("privkey.pem");
        tokio::fs::create_dir_all("./certs").await.unwrap();
        tokio::fs::copy(cert_path, "./certs/fullchain.pem")
            .await
            .unwrap();
        tokio::fs::copy(key_path, "./certs/privkey.pem")
            .await
            .unwrap();
    }

    pub async fn run_update(&self) {
        Command::new("certbot")
            .arg("certonly")
            .arg("--non-interactive")
            .arg("--agree-tos")
            .arg("--preferred-chain")
            .arg("ISRG Root X1")
            .arg("--domain")
            .arg(&self.domain)
            .arg("--email")
            .arg(&self.email)
            .arg("--webroot")
            .arg("./html")
            .arg("--dry-run")
            .output()
            .await
            .unwrap();
    }
}
