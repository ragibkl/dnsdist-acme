mod handler;
mod tasks;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{extract::connect_info::IntoMakeServiceWithConnectInfo, routing::get, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_http::services::ServeDir;

use crate::handler::{get_logs, get_logs_api};
use crate::tasks::certbot::CertbotTask;
use crate::tasks::dnsdist::{run_dnsdist_reload_cert, spawn_dnsdist};
use crate::tasks::dnstap::{clear_dnstap_logs, spawn_dnstap};

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

fn make_service() -> IntoMakeServiceWithConnectInfo<Router, SocketAddr> {
    let app = Router::new()
        .route("/logs", get(get_logs))
        .route("/api/logs", get(get_logs_api))
        .nest_service("/.well-known/", ServeDir::new("./html/.well-known"));

    app.into_make_service_with_connect_info::<SocketAddr>()
}

async fn sigint() -> std::io::Result<()> {
    signal(SignalKind::interrupt())?.recv().await;
    Ok(())
}

async fn sigterm() -> std::io::Result<()> {
    signal(SignalKind::terminate())?.recv().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::info!("args: {args:?}");

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    if args.tls_enabled {
        let domain = args.tls_domain.expect("tls_domain is not set");
        let email = args.tls_email.expect("tls_email is not set");

        let certbot = CertbotTask::new(&domain, &email);

        tracing::info!("certbot obtaining certs");
        certbot.run().await?;
        tracing::info!("certbot obtaining certs. DONE");

        let cert = PathBuf::from("./certs/fullchain.pem");
        let key = PathBuf::from("./certs/privkey.pem");
        let config_axum = RustlsConfig::from_pem_file(cert.as_path(), key.as_path()).await?;
        let config_certbot = config_axum.clone();

        tracing::info!("Starting certbot auto-update");
        let cloned_token = token.clone();
        tracker.spawn(async move {
            loop {
                tracing::info!("certbot auto-update sleeping for 1 hour");
                tokio::select! {
                    _ = cloned_token.cancelled() => {
                        tracing::info!("certbot auto-update received cancel signal");
                        return;
                    },
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {
                        tracing::info!("certbot auto-update waking up");
                    },
                }

                tracing::info!("certbot renewing certs");
                if let Err(err) = certbot.run().await {
                    tracing::error!("certbot renewing certs. ERROR: {err}");
                    cloned_token.cancel();
                    return;
                }
                tracing::info!("certbot renewing certs. DONE");

                tracing::info!("reloading certs for https server");
                if let Err(err) = config_certbot
                    .reload_from_pem_file(cert.as_path(), key.as_path())
                    .await
                {
                    tracing::error!("reloading certs for https server. ERROR: {err}");
                    cloned_token.cancel();
                    return;
                }
                tracing::info!("reloading certs for https server. DONE");

                tracing::info!("reloading certs for dnsdist server");
                if let Err(err) = run_dnsdist_reload_cert().await {
                    tracing::error!("reloading certs for dnsdist server. ERROR: {err}");
                    cloned_token.cancel();
                    return;
                }
                tracing::info!("reloading certs for dnsdist server. DONE");
            }
        });

        tracing::info!("Starting https server on port 8443");
        let cloned_token = token.clone();
        tracker.spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
            let handle = Handle::new();
            let server = axum_server::bind_rustls(addr, config_axum).handle(handle.clone());

            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("https server received cancel signal");
                    handle.shutdown();
                },
                _ = server.serve(make_service()) => {
                    tracing::info!("https server ended prematurely");
                    cloned_token.cancel();
                },
            }
        });
    }

    tracing::info!("Starting http server on port 8080");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
        let handle = Handle::new();
        let server = axum_server::bind(addr).handle(handle.clone());

        tokio::select! {
            _ = cloned_token.cancelled() => {
                tracing::info!("http server received cancel signal");
                handle.shutdown();
            },
            _ = server.serve(make_service()) => {
                tracing::info!("http server ended prematurely");
                cloned_token.cancel();
            },
        }
    });

    tracing::info!("Starting dnstap");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        let mut child = match spawn_dnstap() {
            Ok(child) => child,
            Err(err) => {
                tracing::error!("Starting dnstap. ERROR: {err}");
                cloned_token.cancel();
                return;
            }
        };

        tokio::select! {
            _ = cloned_token.cancelled() => {
                tracing::info!("dnstap received cancel signal");
                let _ = child.kill().await;
            },
            _ = child.wait() => {
                tracing::info!("dnstap ended prematurely");
                cloned_token.cancel();
            },
        }
    });

    tracing::info!("Starting dnstap logs-cleanup");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        loop {
            tracing::info!("dnstap logs-cleanup sleeping for 10 minutes");
            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("dnstap logs-cleanup received cancel signal");
                    return;
                },
                _ = tokio::time::sleep(Duration::from_secs(600)) => {
                    tracing::info!("dnstap logs-cleanup waking up");
                },
            }

            tracing::info!("Cleaning logs");
            if let Err(err) = clear_dnstap_logs().await {
                tracing::info!("Cleaning logs. ERROR: {err}");
                cloned_token.cancel();
                return;
            }
            tracing::info!("Cleaning logs. DONE");
        }
    });

    tracing::info!("Starting dnsdist server");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        let mut child = match spawn_dnsdist(args.tls_enabled, args.backend, args.port) {
            Ok(child) => child,
            Err(err) => {
                tracing::error!("Starting dnsdist server. ERROR: {err}");
                cloned_token.cancel();
                return;
            }
        };

        tokio::select! {
            _ = cloned_token.cancelled() => {
                tracing::info!("dnsdist server received cancel signal");
                let _ = child.kill().await;
            },
            _ = child.wait() => {
                tracing::info!("dnsdist server ended prematurely");
                cloned_token.cancel();
            },
        }
    });

    tracker.close();

    tokio::select! {
        res = sigint() => match res {
            Ok(()) => {
                tracing::info!("Received sigint signal");
            }
            Err(err) => {
                tracing::info!("Unable to listen for sigint signal: {err}");
            }
        },
        res = sigterm() => match res {
            Ok(()) => {
                tracing::info!("Received sigterm signal");
            }
            Err(err) => {
                tracing::info!("Unable to listen for sigterm signal: {err}");
            }
        },
        _ = tracker.wait() => {
            tracing::info!("Tasks ended prematurely");
            token.cancel();
        },
    }

    tracing::info!("Shutting down tasks");
    token.cancel();
    tracing::info!("Waiting for tasks to end");
    tracker.wait().await;
    tracing::info!("Exiting");

    Ok(())
}
