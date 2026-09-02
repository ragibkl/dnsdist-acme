use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use axum::Router;
use futures::StreamExt;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_acme::caches::DirCache;
use rustls_acme::{AccountCache, AcmeConfig, CertCache, ResolvesServerCertAcme, UseChallenge};
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::dnsdist::run_dnsdist_reload_cert;

/// Skips verification of the ACME *server's* certificate. Only for pointing at
/// a local Pebble instance in tests, which signs with an ephemeral CA that is
/// regenerated on every start and therefore trusted by nothing.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Splits the single PEM blob rustls-acme hands to the cache into the two
/// files dnsdist expects.
///
/// The blob is the PKCS#8 private key first, then the certificate chain --
/// see `AcmeState::parse_cert`, which pops block 0 as the key and treats the
/// remainder as the chain.
fn split_pem(pem: &[u8]) -> anyhow::Result<(String, String)> {
    let text = std::str::from_utf8(pem)?;

    let mut blocks: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
        }
    }

    if blocks.len() < 2 {
        anyhow::bail!("expected a private key and at least one certificate, got {} PEM block(s)", blocks.len());
    }

    let key = blocks.remove(0);
    let chain = blocks.concat();
    Ok((key, chain))
}

/// Cert cache that also publishes the certificate for dnsdist.
///
/// dnsdist is a separate process reading PEM files from disk, so unlike the
/// Rust HTTPS server -- which takes the resolver directly -- it needs the
/// credential written out and an explicit reload.
///
/// **Both** `load_cert` and `store_cert` write the files, which is not
/// redundant. rustls-acme calls `store_cert` only for a newly issued
/// certificate: `process_cert(.., cached: true)` returns before reaching it.
/// Writing only on store would leave dnsdist's files stale on every restart
/// that reuses a cached certificate, which is most restarts.
pub struct DnsdistCertCache {
    inner: DirCache<PathBuf>,
    certs_dir: PathBuf,
    /// dnsdist is spawned after the first certificate exists, so there is
    /// nothing to reload until main flips this.
    dnsdist_running: Arc<AtomicBool>,
    reload_args: (bool, SocketAddr, u16),
    /// Signals main that a certificate is on disk and dnsdist can start.
    ready_tx: watch::Sender<bool>,
}

impl DnsdistCertCache {
    async fn publish(&self, pem: &[u8], origin: &str) {
        let (key, chain) = match split_pem(pem) {
            Ok(parts) => parts,
            Err(err) => {
                tracing::error!("acme: cannot split {origin} certificate for dnsdist: {err}");
                return;
            }
        };

        if let Err(err) = tokio::fs::create_dir_all(&self.certs_dir).await {
            tracing::error!("acme: cannot create {}: {err}", self.certs_dir.display());
            return;
        }

        let key_path = self.certs_dir.join("privkey.pem");
        let chain_path = self.certs_dir.join("fullchain.pem");
        if let Err(err) = tokio::fs::write(&key_path, key).await {
            tracing::error!("acme: cannot write {}: {err}", key_path.display());
            return;
        }
        if let Err(err) = tokio::fs::write(&chain_path, chain).await {
            tracing::error!("acme: cannot write {}: {err}", chain_path.display());
            return;
        }
        tracing::info!("acme: wrote {origin} certificate to {}", self.certs_dir.display());

        let _ = self.ready_tx.send(true);

        if !self.dnsdist_running.load(Ordering::SeqCst) {
            tracing::debug!("acme: dnsdist not started yet, skipping reload");
            return;
        }

        let (tls_enabled, backend, port) = self.reload_args;
        match run_dnsdist_reload_cert(tls_enabled, backend, port).await {
            Ok(()) => tracing::info!("acme: reloaded certificates into dnsdist"),
            Err(err) => tracing::error!("acme: reloading certificates into dnsdist failed: {err}"),
        }
    }
}

#[async_trait]
impl CertCache for DnsdistCertCache {
    type EC = std::io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let cached = self.inner.load_cert(domains, directory_url).await?;
        if let Some(pem) = &cached {
            self.publish(pem, "cached").await;
        }
        Ok(cached)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        self.inner.store_cert(domains, directory_url, cert).await?;
        self.publish(cert, "new").await;
        Ok(())
    }
}

#[async_trait]
impl AccountCache for DnsdistCertCache {
    type EA = std::io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        self.inner.load_account(contact, directory_url).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        self.inner.store_account(contact, directory_url, account).await
    }
}

pub struct Acme {
    /// Plugged straight into the Rust HTTPS server, so it needs no reload path.
    pub resolver: Arc<ResolvesServerCertAcme>,
    /// Flip once dnsdist is up, so renewals trigger a reload.
    pub dnsdist_running: Arc<AtomicBool>,
    ready_rx: watch::Receiver<bool>,
}

impl Acme {
    /// Resolves once a certificate is on disk, so dnsdist can be started with
    /// TLS enabled -- preserving the ordering certbot gave us by blocking.
    pub async fn wait_for_cert(&mut self) {
        if *self.ready_rx.borrow() {
            return;
        }
        let _ = self.ready_rx.changed().await;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setup_acme(
    domain: String,
    email: String,
    acme_url: Option<String>,
    acme_insecure: bool,
    acme_cache_dir: PathBuf,
    certs_dir: PathBuf,
    tls_enabled: bool,
    backend: SocketAddr,
    port: u16,
    tracker: &TaskTracker,
    token: CancellationToken,
) -> Acme {
    let (ready_tx, ready_rx) = watch::channel(false);
    let dnsdist_running = Arc::new(AtomicBool::new(false));

    let cache = DnsdistCertCache {
        inner: DirCache::new(acme_cache_dir),
        certs_dir,
        dnsdist_running: dnsdist_running.clone(),
        reload_args: (tls_enabled, backend, port),
        ready_tx,
    };

    let base = if acme_insecure {
        tracing::warn!("ACME_INSECURE=true: not verifying the ACME server's certificate (Pebble mode)");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
        AcmeConfig::new_with_client_config([domain], Arc::new(client_config))
    } else {
        AcmeConfig::new([domain])
    };

    let mut config = base
        .contact_push(format!("mailto:{email}"))
        .cache(cache)
        .challenge_type(UseChallenge::Http01);

    config = match acme_url {
        // A custom directory is how the end-to-end test points at Pebble.
        Some(url) => config.directory(url),
        None => config.directory_lets_encrypt(true),
    };

    let mut state = config.state();
    let resolver = state.resolver();
    let challenge_service = state.http01_challenge_tower_service();

    // Drives issuance and renewal. Individual errors are warnings: a failed
    // renewal is not a reason to stop serving, the existing certificate is
    // still valid, and the state machine retries. Only the stream ending is
    // fatal, because then nothing is driving renewal any more.
    let cloned_token = token.clone();
    tracker.spawn(async move {
        loop {
            tokio::select! {
                event = state.next() => match event {
                    Some(Ok(ok)) => tracing::info!("acme event: {ok:?}"),
                    Some(Err(err)) => tracing::warn!("acme error: {err}. Keeping the existing certificate, will retry."),
                    None => {
                        tracing::error!("acme state stream ended unexpectedly");
                        cloned_token.cancel();
                        return;
                    }
                },
                _ = cloned_token.cancelled() => {
                    tracing::info!("acme task received cancel signal");
                    return;
                }
            }
        }
    });

    // HTTP-01 challenge server. Port 80 is not configurable: Let's Encrypt
    // validates HTTP-01 there and follows redirects only to other port 80
    // hosts. The logs pages stay on 8080/8443 as before.
    let cloned_token = token.clone();
    tracker.spawn(async move {
        // NOTE: `{token}` is axum 0.8 path-parameter syntax; 0.7 spelled it
        // `:token`. Get this wrong for the axum in use and the route matches
        // only a literal segment, every challenge 404s, and issuance fails with
        // no compile-time complaint. The e2e test exists partly to catch it.
        let app = Router::new()
            .route_service("/.well-known/acme-challenge/{token}", challenge_service);
        let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 80));

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                tracing::error!("acme challenge server bind failed on {addr}: {err}");
                cloned_token.cancel();
                return;
            }
        };
        tracing::info!("acme challenge server listening on port 80");

        let shutdown = cloned_token.clone();
        if let Err(err) = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await
        {
            tracing::error!("acme challenge server error: {err}");
            cloned_token.cancel();
        }
    });

    Acme {
        resolver,
        dnsdist_running,
        ready_rx,
    }
}

#[cfg(test)]
mod tests {
    use super::split_pem;

    #[test]
    fn splits_key_from_chain() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n\
                    -----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n";
        let (key, chain) = split_pem(pem).unwrap();
        assert!(key.contains("PRIVATE KEY"));
        assert!(!key.contains("CERTIFICATE"));
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
    }

    #[test]
    fn rejects_a_blob_without_a_chain() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(split_pem(pem).is_err());
    }
}
