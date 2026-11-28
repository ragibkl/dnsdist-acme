//! Receives dnstap directly from dnsdist over a unix socket.
//!
//! This replaces running the `dnstap` binary as a child that appended YAML to
//! `logs.yaml`, which the supervisor then read and truncated once a second.
//! That design lost data two ways:
//!
//!   * anything dnstap appended between the read and the truncate was destroyed
//!     unread, silently and uncounted; and
//!   * a read landing mid-document produced an unparseable fragment, which was
//!     dropped and logged. On sg-dns1 that alone accounted for 834 lost entries
//!     in a couple of hours, roughly 6.6% of ingest ticks.
//!
//! dnsdist already writes to a socket (`newFrameStreamUnixLogger`); the `dnstap`
//! process was only relaying it to disk. Consuming the socket directly removes
//! the file, both races, the child process, and the polling loop.

use std::path::PathBuf;

use tokio::net::{UnixListener, UnixStream};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::logs::{
    Frame, QueryLogs, UsageStats, accept_handshake, is_stop, query_log_from_frame, read_frame,
    send_finish,
};

/// Binds the socket dnsdist will connect to, and serves it until cancelled.
///
/// Must be called before dnsdist is started: dnsdist connects out to this path,
/// and if nothing is listening it logs an error and gives up on dnstap for that
/// run.
pub fn spawn_dnstap_listener(
    socket_path: PathBuf,
    logs_store: QueryLogs,
    usage_stats: UsageStats,
    tracker: &TaskTracker,
    token: CancellationToken,
) -> std::io::Result<()> {
    // A stale socket file from an unclean shutdown would make bind fail.
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("dnstap listener on {}", socket_path.display());

    let cloned_token = token.clone();
    tracker.spawn(async move {
        loop {
            tokio::select! {
                _ = cloned_token.cancelled() => {
                    tracing::info!("dnstap listener received cancel signal");
                    let _ = std::fs::remove_file(&socket_path);
                    return;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            // dnsdist reconnects if the stream drops, so each
                            // connection is handled independently and a failure
                            // on one never stops us accepting the next.
                            let logs = logs_store.clone();
                            let stats = usage_stats.clone();
                            tokio::spawn(async move {
                                if let Err(err) = handle_connection(stream, logs, stats).await {
                                    tracing::warn!("dnstap connection ended: {err}");
                                }
                            });
                        }
                        Err(err) => {
                            tracing::warn!("dnstap accept failed: {err}");
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    logs_store: QueryLogs,
    usage_stats: UsageStats,
) -> std::io::Result<()> {
    accept_handshake(&mut stream).await?;
    tracing::info!("dnstap stream started");

    let mut received: u64 = 0;
    let mut ignored: u64 = 0;

    loop {
        let Some(frame) = read_frame(&mut stream).await? else {
            tracing::info!("dnstap stream closed after {received} entries");
            return Ok(());
        };

        if is_stop(&frame) {
            let _ = send_finish(&mut stream).await;
            tracing::info!("dnstap stream stopped after {received} entries ({ignored} ignored)");
            return Ok(());
        }

        let Frame::Data(payload) = frame else {
            // Control frames other than STOP mid-stream are not expected, but
            // are harmless to skip.
            continue;
        };

        match query_log_from_frame(&payload) {
            Some(log) => {
                usage_stats.touch(&log.ip, log.query_time);
                logs_store.push(log);
                received += 1;
            }
            // dnsdist emits message types we do not log; not an error.
            None => ignored += 1,
        }
    }
}
