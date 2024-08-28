mod handler;
mod logs;
mod tasks;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{extract::connect_info::IntoMakeServiceWithConnectInfo, routing::get, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use clap::Parser;
use handler::AppState;
use logs::{LogsConsumer, QueryLogs, UsageStats};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_http::services::ServeDir;
use tower_http::timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer, TimeoutLayer};

use crate::handler::{get_logs, get_logs_api};
use crate::tasks::certbot::CertbotTask;
use crate::tasks::dnsdist::{run_dnsdist_reload_cert, spawn_dnsdist};
use crate::tasks::dnstap::spawn_dnstap;

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

fn make_service(
    logs_store: QueryLogs,
    usage_stats: UsageStats,
) -> IntoMakeServiceWithConnectInfo<Router, SocketAddr> {
    let app_state = AppState::new(logs_store, usage_stats);

    let app = Router::new()
        .route("/logs", get(get_logs))
        .route("/api/logs", get(get_logs_api))
        .with_state(app_state)
        .nest_service("/.well-known/", ServeDir::new("./html/.well-known"))
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(1)))
        .layer(ResponseBodyTimeoutLayer::new(Duration::from_secs(1)))
        .layer(TimeoutLayer::new(Duration::from_secs(1)));

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

    let logs_store = QueryLogs::default();
    let usage_stats = UsageStats::default();

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
        let cloned_logs_store = logs_store.clone();
        let cloned_usage_stats = usage_stats.clone();
        tracker.spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8443));
            let handle = Handle::new();
            let server = axum_server::bind_rustls(addr, config_axum).handle(handle.clone());

            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("https server received cancel signal");
                    handle.shutdown();
                },
                _ = server.serve(make_service(cloned_logs_store, cloned_usage_stats)) => {
                    tracing::info!("https server ended prematurely");
                    cloned_token.cancel();
                },
            }
        });
    }

    tracing::info!("Starting http server on port 8080");
    let cloned_token = token.clone();
    let cloned_logs_store = logs_store.clone();
    let cloned_usage_stats = usage_stats.clone();
    tracker.spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8080));
        let handle = Handle::new();
        let server = axum_server::bind(addr).handle(handle.clone());

        tokio::select! {
            _ = cloned_token.cancelled() => {
                tracing::info!("http server received cancel signal");
                handle.shutdown();
            },
            _ = server.serve(make_service(cloned_logs_store, cloned_usage_stats)) => {
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

    tracing::info!("Starting logs_consumer read_logs");
    let cloned_token = token.clone();
    let cloned_logs_store = logs_store.clone();
    let cloned_usage_stats = usage_stats.clone();
    tracker.spawn(async move {
        let log_consumer = LogsConsumer::new(cloned_logs_store, cloned_usage_stats);
        loop {
            tracing::info!("logs_consumer read_logs logs-cleanup sleeping for 1 second");
            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("logs_consumer read_logs received cancel signal");
                    return;
                },
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    tracing::info!("logs_consumer read_logs waking up");
                },
            }

            tracing::info!("Reading logs");
            log_consumer.ingest_logs_from_file().await;
            tracing::info!("Reading logs. DONE");
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
