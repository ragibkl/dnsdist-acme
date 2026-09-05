use std::fmt;
use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::process::{Child, Command};

/// The dnsdist console key, generated fresh at every start.
///
/// This used to be a literal in `dnsdist.conf`, committed to a public
/// repository. `controlSocket()` is a Lua console -- arbitrary code execution
/// inside the process that terminates TLS and holds the private keys -- and it
/// is TCP-only, so it cannot be moved behind filesystem permissions. Under
/// `network_mode: host` its loopback is the *host's* loopback, reachable by any
/// process on the box. A published key guarding that is worth nothing.
///
/// Generating it per start means the key exists only in this process's memory
/// and in the environment of the two children that need it, and a fresh one
/// every restart bounds the value of ever learning it.
#[derive(Clone)]
pub struct ConsoleKey(String);

impl ConsoleKey {
    /// 32 random bytes, base64-encoded, which is the form `setKey()` expects.
    pub fn generate() -> Result<Self, anyhow::Error> {
        let mut buf = [0u8; 32];
        aws_lc_rs::rand::fill(&mut buf)
            .map_err(|_| anyhow::anyhow!("could not generate a console key"))?;
        Ok(Self(BASE64.encode(buf)))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redacted: `Args` and friends get logged at startup, and the key must not
/// travel with them.
impl fmt::Debug for ConsoleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsoleKey(<redacted>)")
    }
}

pub fn spawn_dnsdist(
    tls_enabled: bool,
    backend: SocketAddr,
    port: u16,
    console_key: &ConsoleKey,
) -> Result<Child, anyhow::Error> {
    let child = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND", backend.to_string())
        .env("PORT", port.to_string())
        .env("CONSOLE_KEY", console_key.as_str())
        .arg("--supervised")
        .arg("--disable-syslog")
        .arg("--config")
        .arg("dnsdist.conf")
        .kill_on_drop(true)
        .spawn()?;

    Ok(child)
}

/// Reloads the TLS certificates into the running dnsdist via its control socket.
///
/// The console key is taken from `dnsdist.conf` with `-C` rather than passed as
/// `-k <key>`: dnsdist 2.0 no longer accepts a key supplied that way, and `-k`
/// also exposed the key through `ps` to any user on the host. `-C` works on
/// 1.8.x, 1.9.x and 2.0.x alike.
///
/// The same env vars as `spawn_dnsdist` are set because the client evaluates
/// the whole config, and `dnsdist.conf` reads them via `os.getenv`. That
/// includes `CONSOLE_KEY`: client and server must derive the same key, which is
/// why it is generated once in `main` and handed to both rather than being
/// generated here.
pub async fn run_dnsdist_reload_cert(
    tls_enabled: bool,
    backend: SocketAddr,
    port: u16,
    console_key: &ConsoleKey,
) -> Result<(), anyhow::Error> {
    let out = Command::new("dnsdist")
        .env("TLS_ENABLED", tls_enabled.to_string())
        .env("BACKEND", backend.to_string())
        .env("PORT", port.to_string())
        .env("CONSOLE_KEY", console_key.as_str())
        .arg("-C")
        .arg("dnsdist.conf")
        .arg("-c")
        .arg("127.0.0.1")
        .arg("-e")
        .arg("reloadAllCertificates()")
        .output()
        .await?;

    // The exit status is not sufficient. dnsdist's console client exits 0 even
    // when it refuses to connect -- a wrong key prints "The currently
    // configured console key is not valid" and still returns success. Trusting
    // the status alone would report a reload that never happened, which is the
    // failure this whole path has to avoid: the new certificate is already on
    // disk, but dnsdist keeps serving the old one from memory until it
    // restarts, so a silent failure here surfaces ~60 days later as an expiry
    // outage with a valid certificate sitting unread beside it.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");

    if !out.status.success() {
        anyhow::bail!(
            "dnsdist console reload exited with {}: {}",
            out.status,
            combined.trim()
        );
    }

    if is_console_failure(&combined) {
        anyhow::bail!("dnsdist console reload rejected: {}", combined.trim());
    }

    tracing::info!("dnsdist reload succeeded");

    Ok(())
}

/// Recognises the console client reporting failure while still exiting 0.
///
/// Matched on substrings because the client has no machine-readable output and
/// no distinguishing exit code. Kept deliberately narrow: anything unrecognised
/// is treated as success, so a future message change makes this miss a failure
/// rather than invent one.
fn is_console_failure(output: &str) -> bool {
    // Two distinct rejections, both observed against dnsdist 2.0.4 and both
    // exiting 0. They share no common substring, so matching one is not enough:
    //
    //   client configured no key -> "The currently configured console key is
    //                                not valid, please configure a valid key
    //                                using the setKey() directive"
    //   client key != server key -> "Connection closed by the server." then
    //                               "...likely indicating a key mismatch."
    const MARKERS: [&str; 6] = [
        "console key is not valid",
        "key mismatch",
        "Connection closed by the server",
        "Unable to connect to remote server",
        "connection refused",
        "Connection refused",
    ];
    MARKERS.iter().any(|m| output.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_key_setkey_will_accept() {
        let key = ConsoleKey::generate().unwrap();
        let raw = BASE64.decode(key.as_str()).expect("must be valid base64");
        assert_eq!(raw.len(), 32, "dnsdist expects a 32-byte key");
    }

    #[test]
    fn each_start_gets_a_different_key() {
        let a = ConsoleKey::generate().unwrap();
        let b = ConsoleKey::generate().unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    /// The exact message dnsdist 2.0.4 prints, captured from a live container,
    /// while still exiting 0.
    #[test]
    fn treats_a_rejected_key_as_failure_despite_exit_zero() {
        assert!(is_console_failure(
            "The currently configured console key is not valid, please configure a valid key using the setKey() directive"
        ));
    }

    /// The other rejection, also captured live: a client key that does not match
    /// the server's. Shares no substring with the message above, which is why
    /// both are matched explicitly.
    #[test]
    fn treats_a_key_mismatch_as_failure_despite_exit_zero() {
        assert!(is_console_failure(
            "Connection closed by the server.\nThe server closed the connection right away, likely indicating a key mismatch. Please check your setKey() directive.\n"
        ));
    }

    #[test]
    fn treats_an_unreachable_console_as_failure() {
        assert!(is_console_failure("Unable to connect to remote server"));
    }

    #[test]
    fn ordinary_console_output_is_not_a_failure() {
        assert!(!is_console_failure(""));
        assert!(!is_console_failure("dnsdist 2.0.4\n"));
        // reloadAllCertificates() prints nothing at all when it works.
        assert!(!is_console_failure("\n"));
    }

    #[test]
    fn debug_does_not_leak_the_key() {
        let key = ConsoleKey::generate().unwrap();
        let shown = format!("{key:?}");
        assert!(!shown.contains(key.as_str()), "key leaked via Debug: {shown}");
    }
}
