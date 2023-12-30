mod tasks;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "DnsDist ACME")]
#[command(version)]
#[command(about)]
struct Args {
    /// Sets a custom l istener port
    #[arg(short, long, value_name = "PORT", default_value = "53")]
    port: u16,

    /// Sets a backend port to forward the requests to
    #[arg(short, long, value_name = "PORT", default_value = "1153")]
    backend_port: u16,

    /// If enabled, obtains a tls cert from letsencrypt and enable doh and dot protocols
    #[arg(
        short,
        long,
        env,
        value_name = "TLS_ENABLED",
    )]
    tls_enabled: bool,

    /// Sets the email used for letsencrypt
    #[arg(
        short,
        long,
        env,
        value_name = "TLS_EMAIL",
    )]
    tls_email: Option<String>,

    /// Sets the domain used for letsencrypt
    #[arg(
        short,
        long,
        env,
        value_name = "TLS_DOMAIN",
    )]
    tls_domain: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Hello, world!");

    Ok(())
}
