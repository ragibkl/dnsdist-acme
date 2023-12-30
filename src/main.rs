mod tasks;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tasks::{dnsdist::run_dnsdist, dnstap::run_dnstap};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_http::services::ServeDir;

use crate::tasks::certbot::CertbotTask;

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
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let tracker = TaskTracker::new();
    let app = Router::new()
        .route("/logs", get(get_logs))
        .nest_service("/.well-known/", ServeDir::new("./html/.well-known"));

    if args.tls_enabled {
        let domain = args.tls_domain.expect("tls_domain is not set");
        let email = args.tls_email.expect("tls_email is not set");

        let certbot = CertbotTask::new(&domain, &email);
        certbot.run().await;

        let certs_dir = PathBuf::from("/etc/letsencrypt/live/").join(&domain);
        let cert_path = certs_dir.join("fullchain.pem");
        let key_path = certs_dir.join("privkey.pem");
        let config = RustlsConfig::from_pem_file(cert_path.as_path(), key_path.as_path()).await?;

        let cloned_config = config.clone();
        tracker.spawn(async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
            axum_server::bind_rustls(addr, cloned_config)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });

        tracker.spawn(run_dnstap());
        tracker.spawn(run_dnsdist(args.tls_enabled, args.backend_port, args.port));

        tracker.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;

                certbot.run().await;
                config
                    .reload_from_pem_file(cert_path.as_path(), key_path.as_path())
                    .await
                    .unwrap();
            }
        });
    } else {
        tracing::info!("Starting http server");
        tracker.spawn(async {
            let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });

        tracing::info!("Starting dnstap");
        tracker.spawn(run_dnstap());

        tracing::info!("Starting dnsdist server");
        tracker.spawn(run_dnsdist(args.tls_enabled, args.backend_port, args.port));
    }

    tracker.close();

    tokio::select! {
        res = tokio::signal::ctrl_c() => match res {
            Ok(()) => {
                tracing::info!("Received shutdown signal");
            }
            Err(err) => {
                tracing::info!("Unable to listen for shutdown signal: {err}");
            }
        },
        _ = tracker.wait() => {
            tracing::info!("Tasks ended prematurely");
        },
    }

    tracing::info!("Exiting");

    std::process::exit(0);
}
