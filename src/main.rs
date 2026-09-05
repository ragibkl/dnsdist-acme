mod handler;
mod logs;
mod tasks;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{extract::connect_info::IntoMakeServiceWithConnectInfo, routing::get, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use clap::Parser;
use handler::AppState;
use logs::{QueryLogs, UsageStats};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use axum::http::StatusCode;
use tower_http::timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer, TimeoutLayer};

use crate::handler::{get_logs, get_logs_api};
use crate::tasks::acme::setup_acme;
use crate::tasks::dnsdist::{ConsoleKey, spawn_dnsdist};
use crate::tasks::dnstap::spawn_dnstap_listener;

#[derive(Parser, Debug)]
#[command(name = "DnsDist ACME")]
#[command(version)]
#[command(about)]
struct Args {
    /// Sets a custom listener port
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

    /// Custom ACME directory URL. Defaults to Let's Encrypt production; the
    /// end-to-end test points this at a local Pebble instance.
    #[arg(long, env, value_name = "ACME_URL")]
    acme_url: Option<String>,

    /// Do not verify the ACME server's own certificate. Only for Pebble.
    #[arg(long, env, value_name = "ACME_INSECURE")]
    acme_insecure: bool,

    /// Directory holding the ACME account key and cached certificates.
    ///
    /// Defaults inside /etc/letsencrypt because deployments already mount a
    /// volume there for certbot, so the cache persists across container
    /// recreation with no compose change. That matters: without a persisted
    /// cache every recreate requests a fresh certificate, and Let's Encrypt
    /// allows only 5 duplicate certificates per hostname per week. Exhaust that
    /// and a node cannot get a certificate -- and since dnsdist is not started
    /// without one, it stops serving DNS entirely.
    #[arg(
        long,
        env,
        value_name = "ACME_CACHE_DIR",
        default_value = "/etc/letsencrypt/acme-cache"
    )]
    acme_cache_dir: String,
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
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(1)))
        .layer(ResponseBodyTimeoutLayer::new(Duration::from_secs(1)))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(1),
        ));

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

    // Copied out so both the certbot auto-update task and the dnsdist task can
    // use them; `args` itself is moved into the latter.
    let tls_enabled = args.tls_enabled;
    let backend = args.backend;
    let port = args.port;

    // Generated once per start and shared by the dnsdist child and the console
    // client that reloads certificates into it -- both derive the key from the
    // same value, so it must not be regenerated per use. Deliberately not in
    // `Args`: it is neither configurable nor loggable.
    let console_key = ConsoleKey::generate()?;

    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    let logs_store = QueryLogs::default();
    let usage_stats = UsageStats::default();

    // Set once dnsdist is up, so a renewal knows there is something to reload.
    let mut dnsdist_running: Option<Arc<AtomicBool>> = None;

    if tls_enabled {
        let domain = args.tls_domain.expect("tls_domain is not set");
        let email = args.tls_email.expect("tls_email is not set");

        tracing::info!("Setting up ACME for {domain}");
        let mut acme = setup_acme(
            domain,
            email,
            args.acme_url,
            args.acme_insecure,
            PathBuf::from(&args.acme_cache_dir),
            PathBuf::from("./certs"),
            tls_enabled,
            backend,
            port,
            console_key.clone(),
            &tracker,
            token.clone(),
        );

        // dnsdist reads its certificate from disk when it starts, so wait for
        // one to exist first. certbot gave us this ordering by blocking; here
        // it is explicit.
        tracing::info!("Waiting for a certificate before starting dnsdist");
        acme.wait_for_cert().await;
        tracing::info!("Certificate available");

        dnsdist_running = Some(acme.dnsdist_running.clone());

        // The Rust HTTPS server takes the ACME resolver directly, so it always
        // serves the current certificate. There is no reload path to forget.
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(acme.resolver.clone());
        let config_axum = RustlsConfig::from_config(Arc::new(server_config));

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

    // Must bind before dnsdist starts: dnsdist connects out to this path, and
    // if nothing is listening it gives up on dnstap for the rest of the run.
    tracing::info!("Starting dnstap listener");
    if let Err(err) = spawn_dnstap_listener(
        PathBuf::from("./dnstap.sock"),
        logs_store.clone(),
        usage_stats.clone(),
        &tracker,
        token.clone(),
    ) {
        tracing::error!("Starting dnstap listener. ERROR: {err}");
        token.cancel();
    }

    // Entries now arrive as dnsdist emits them, so this only expires old ones.
    // It used to run every second because it also did the ingestion, and those
    // two log lines per second were the bulk of the container's output.
    tracing::info!("Starting logs cleanup");
    let cloned_token = token.clone();
    let cloned_logs_store = logs_store.clone();
    let cloned_usage_stats = usage_stats.clone();
    tracker.spawn(async move {
        loop {
            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("logs cleanup received cancel signal");
                    return;
                },
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            }
            cloned_logs_store.remove_expired_logs();
            cloned_usage_stats.remove_old_active_ips();
        }
    });

    tracing::info!("Starting dnsdist server");
    let cloned_token = token.clone();
    tracker.spawn(async move {
        let mut child = match spawn_dnsdist(tls_enabled, backend, port, &console_key) {
            Ok(child) => child,
            Err(err) => {
                tracing::error!("Starting dnsdist server. ERROR: {err}");
                cloned_token.cancel();
                return;
            }
        };

        if let Some(flag) = dnsdist_running {
            flag.store(true, Ordering::SeqCst);
        }

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
