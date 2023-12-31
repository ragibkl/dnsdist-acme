mod handler;
mod tasks;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tasks::{dnsdist::run_dnsdist, dnstap::run_dnstap};
use tokio_util::task::TaskTracker;
use tower_http::services::ServeDir;

use crate::handler::{get_logs, get_logs_api};
use crate::tasks::{certbot::CertbotTask, dnsdist::reload_dnsdist_cert};

#[derive(Parser, Debug)]
#[command(name = "DnsDist ACME")]
#[command(version)]
#[command(about)]
struct Args {
    /// Sets a custom l istener port
    #[arg(long, env, value_name = "PORT", default_value = "53")]
    port: u16,

    /// Sets a backend port to forward the requests to
    #[arg(long, env, value_name = "BACKEND", default_value = "8.8.8.8:53")]
    backend: SocketAddr,

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::info!("args: {args:?}");

    let tracker = TaskTracker::new();
    let app = Router::new()
        .route("/logs", get(get_logs))
        .route("/api/logs", get(get_logs_api))
        .nest_service("/.well-known/", ServeDir::new("./html/.well-known"));

    if args.tls_enabled {
        let domain = args.tls_domain.expect("tls_domain is not set");
        let email = args.tls_email.expect("tls_email is not set");

        let certbot = CertbotTask::new(&domain, &email);

        tracing::info!("certbot renewing certs");
        certbot.run().await;
        tracing::info!("certbot renewing certs. DONE");

        let cert = PathBuf::from("./certs/fullchain.pem");
        let key = PathBuf::from("./certs/privkey.pem");
        let config = RustlsConfig::from_pem_file(cert.as_path(), key.as_path()).await?;

        let cloned_config = config.clone();

        tracing::info!("Starting https server on port 8443");
        tracker.spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
            axum_server::bind_rustls(addr, cloned_config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        });

        tracing::info!("Starting dnstap");
        tracker.spawn(run_dnstap());

        tracing::info!("Starting dnsdist server");
        tracker.spawn(run_dnsdist(args.tls_enabled, args.backend, args.port));

        tracing::info!("Starting certbot auto-update");
        tracker.spawn(async move {
            loop {
                tracing::info!("certbot auto-update sleeping for 1 hour");
                tokio::time::sleep(Duration::from_secs(3600)).await;

                tracing::info!("certbot renewing certs");
                certbot.run().await;
                tracing::info!("certbot renewing certs. DONE");

                tracing::info!("reloading certs for https server");
                config
                    .reload_from_pem_file(cert.as_path(), key.as_path())
                    .await
                    .unwrap();
                tracing::info!("reloading certs for https server. DONE");

                tracing::info!("reloading certs for dnsdist server");
                reload_dnsdist_cert().await;
                tracing::info!("reloading certs for dnsdist server. DONE");
            }
        });
    } else {
        tracing::info!("Starting http server on port 8080");
        tracker.spawn(async {
            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            axum_server::bind(addr)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        });

        // tracing::info!("Starting dnstap");
        // tracker.spawn(run_dnstap());

        // tracing::info!("Starting dnsdist server");
        // tracker.spawn(run_dnsdist(args.tls_enabled, args.backend, args.port));
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
