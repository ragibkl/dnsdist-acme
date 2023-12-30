mod tasks;

use std::net::SocketAddr;

use axum::{routing::get, Router};
use clap::Parser;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_http::services::ServeDir;

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
    #[arg(long, env, value_name = "TLS_ENABLED")]
    tls_enabled: bool,

    /// Sets the email used for letsencrypt
    #[arg(long, env, value_name = "TLS_EMAIL")]
    tls_email: Option<String>,

    /// Sets the domain used for letsencrypt
    #[arg(long, env, value_name = "TLS_DOMAIN")]
    tls_domain: Option<String>,
}

#[axum_macros::debug_handler]
async fn get_logs() -> String {
    "Hello".into()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Hello, world!");

    let app = Router::new()
        .route("/logs", get(get_logs))
        .nest_service("/.well-known/", ServeDir::new("./html/.well-known"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
