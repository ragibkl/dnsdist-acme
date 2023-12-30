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
            .arg("--non-interactive")
            .arg("--agree-tos")
            .arg("--preferred-chain")
            .arg("ISRG Root X1")
            .arg("--domain")
            .arg(&self.domain)
            .arg("--email")
            .arg(&self.email)
            .arg("--webroot")
            .arg("./certs")
            .arg("--dry-run")
            .output()
            .await
            .unwrap();
    }
}
