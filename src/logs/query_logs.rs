use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use chrono::{Duration, Utc};

use super::QueryLog;

/// How long an entry is kept, and so how much history `/logs` shows.
///
/// **This is a privacy limit, not a memory one. Do not raise it.** `/logs`
/// shows query history to anyone sharing the requester's public IP, which
/// behind CGNAT can be thousands of unrelated subscribers -- that exposure is
/// accepted (it is what makes the page useful without accounts) precisely
/// *because* the window is this short. Ten minutes is long enough to debug a
/// resolution problem while it is happening and short enough that the page is
/// not a browsing history.
///
/// Memory is not the constraint here and never was: at ~226 bytes an entry, ten
/// minutes of the busiest node's entire load is about 5 MB of 992 MB. Anyone
/// tempted to tune this for capacity reasons is solving a problem that does not
/// exist, and would be trading away the reason the exposure above is tolerable.
const MAX_AGE_MINUTES: i64 = 10;

/// `MAX_AGE_MINUTES` for API clients, which expire entries themselves.
pub const WINDOW_SECONDS: i64 = MAX_AGE_MINUTES * 60;

/// Ceiling on the entries held for any one address.
///
/// Deliberately **not** `bancuh-dns`'s `MAX_PER_IP = 1000`. This started at
/// 1000 to match it, and a day on production showed that was the wrong number
/// here: jp-dns1 discarded a steady ~2,100 entries a minute out of ~38 qps of
/// total traffic, so the cap was doing the routine trimming that the ten-minute
/// expiry already does, rather than acting as a backstop.
///
/// The expiry is the real bound on aggregate memory: at ~226 bytes an entry,
/// ten minutes of jp-dns1's entire load is about 5 MB, against 992 MB of RAM
/// and a measured 14 MB RSS. There was never memory pressure to trade history
/// for.
///
/// At 10,000 the cap binds only above ~16.7 qps *sustained by one address*,
/// which is past anything the fleet currently sees from a single source --
/// jp-dns1's heaviest client averages about 12 qps. So it is now insurance
/// against a pathological source rather than a routine trimmer, and ordinary
/// clients keep the full ten minutes the page advertises.
///
/// That last part is the point, not a side effect: the page exists so a real
/// person can debug a resolution problem against `MAX_AGE_MINUTES` of history.
/// A cap low enough to bite ordinary clients silently hands them less history
/// than the page promises, which is the failure this constant is set to avoid.
///
/// Worst case is bounded on both sides: `MaxQPSIPRule` in `dnsdist.conf` holds
/// any single address to 50 qps, so one IP can offer at most ~30,000 entries in
/// a window, of which this keeps 10,000 -- about 2.2 MB.
///
/// The eviction is counted rather than silent. Losing entries without saying so
/// is a failure this code has already had once -- the `logs.yaml` read/truncate
/// race destroyed data with nothing recording it, and only a second, noisier
/// symptom revealed it. That counter is also what measured the paragraph above.
const MAX_PER_IP: usize = 10_000;

#[derive(Debug, Clone)]
pub struct QueryLogs {
    logs_store: Arc<Mutex<HashMap<String, VecDeque<QueryLog>>>>,
    /// Entries discarded by `MAX_PER_IP` since the count was last taken.
    dropped: Arc<AtomicU64>,
    /// The last `seq` handed out.
    ///
    /// Starts at the process start time in microseconds rather than zero, so a
    /// restart never hands out a number a client already has as its `since`.
    /// From zero, a client polling across a restart would see nothing until the
    /// new count overtook its old one. Overtaking the clock would take more
    /// than a million lookups a second, sustained.
    seq: Arc<AtomicU64>,
}

impl Default for QueryLogs {
    fn default() -> Self {
        let start = Utc::now().timestamp_micros().max(0) as u64;
        Self {
            logs_store: Arc::default(),
            dropped: Arc::default(),
            seq: Arc::new(AtomicU64::new(start)),
        }
    }
}

/// What `QueryLogs::get` returns for one address.
#[derive(Debug, Clone, PartialEq)]
pub struct LogsPage {
    /// Newest first.
    pub queries: Vec<QueryLog>,
    /// More entries newer than `since` exist than `limit` let through. The
    /// oldest of them were left out.
    pub truncated: bool,
}

impl QueryLogs {
    pub fn remove_expired_logs(&self) {
        let query_time_cutoff = Utc::now() - Duration::minutes(MAX_AGE_MINUTES);

        let mut logs_store_guard = self.logs_store.lock().unwrap();
        for query_logs in logs_store_guard.values_mut() {
            query_logs.retain(|q| q.query_time > query_time_cutoff);
        }

        logs_store_guard.retain(|_ip, queries| !queries.is_empty());
    }

    /// Records one entry, evicting this address's oldest once the cap is
    /// reached. Ingestion is per-frame as dnstap delivers it, rather than a
    /// batch read from a file every second.
    ///
    /// Entries arrive in the order dnsdist emits them, so the front of the
    /// queue is the oldest and dropping from there keeps the most recent
    /// history -- which is the part a caller of `/logs` is looking for.
    pub fn push(&self, mut log: QueryLog) {
        let mut guard = self.logs_store.lock().unwrap();
        // Taken under the lock, so the order of `seq` within an address's
        // queue is the order of the queue.
        log.seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let entries = guard.entry(log.ip.clone()).or_default();

        while entries.len() >= MAX_PER_IP {
            entries.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }

        entries.push_back(log);
    }

    /// The newest entries for `ip` with a `seq` above `since`, at most `limit`.
    ///
    /// Walks from the newest end and stops at `since` or `limit`, so only the
    /// entries returned are cloned, not the whole queue -- this runs under the
    /// lock that every incoming dnstap frame also takes.
    pub fn get(&self, ip: &str, since: u64, limit: usize) -> LogsPage {
        let guard = self.logs_store.lock().unwrap();
        let Some(entries) = guard.get(ip) else {
            return LogsPage {
                queries: Vec::new(),
                truncated: false,
            };
        };

        let mut newer = entries.iter().rev().take_while(|q| q.seq > since);
        let queries: Vec<QueryLog> = newer.by_ref().take(limit).cloned().collect();
        let truncated = newer.next().is_some();

        LogsPage { queries, truncated }
    }

    /// How many entries the cap has discarded since this was last called, and
    /// resets the count. Called by the cleanup loop so the drops are reported
    /// instead of being invisible.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    fn log_at(ip: &str, secs: i64) -> QueryLog {
        QueryLog {
            ip: ip.to_string(),
            seq: 0,
            query_time: DateTime::from_timestamp(secs, 0).unwrap(),
            name: format!("q{secs}.example"),
            qtype: "A".to_string(),
            rcode: "NOERROR".to_string(),
            blocked: true,
            answers: vec![],
        }
    }

    fn recent(ip: &str, n: usize) -> Vec<QueryLog> {
        let now = Utc::now().timestamp();
        (0..n).map(|i| log_at(ip, now + i as i64)).collect()
    }

    fn all(logs: &QueryLogs, ip: &str) -> Vec<QueryLog> {
        logs.get(ip, 0, usize::MAX).queries
    }

    #[test]
    fn keeps_everything_below_the_cap() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", 10) {
            logs.push(log);
        }

        assert_eq!(all(&logs, "10.0.0.7").len(), 10);
        assert_eq!(logs.take_dropped(), 0);
    }

    /// The point of the cap: a source that will not stop talking must not grow
    /// without limit, and what it keeps must be the newest entries.
    #[test]
    fn the_cap_evicts_the_oldest_and_keeps_the_newest() {
        let logs = QueryLogs::default();
        let over = 50;
        let pushed = recent("10.0.0.7", MAX_PER_IP + over);
        let newest = pushed.last().unwrap().name.clone();
        // The first `over` entries are the ones that should go.
        let oldest_kept = pushed[over].name.clone();
        for log in pushed {
            logs.push(log);
        }

        // Newest first.
        let kept = all(&logs, "10.0.0.7");
        assert_eq!(kept.len(), MAX_PER_IP);
        assert_eq!(kept.first().unwrap().name, newest);
        assert_eq!(kept.last().unwrap().name, oldest_kept);
    }

    #[test]
    fn evictions_are_counted_and_the_count_resets() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", MAX_PER_IP + 5) {
            logs.push(log);
        }

        assert_eq!(logs.take_dropped(), 5);
        assert_eq!(logs.take_dropped(), 0);
    }

    /// The cap is per address, not global -- one loud client must not evict a
    /// quiet one's history.
    #[test]
    fn the_cap_is_per_address() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", MAX_PER_IP + 100) {
            logs.push(log);
        }
        for log in recent("10.0.0.8", 3) {
            logs.push(log);
        }

        assert_eq!(all(&logs, "10.0.0.7").len(), MAX_PER_IP);
        assert_eq!(all(&logs, "10.0.0.8").len(), 3);
    }

    #[test]
    fn expired_entries_are_removed_and_empty_addresses_forgotten() {
        let logs = QueryLogs::default();
        logs.push(log_at("10.0.0.7", 1_700_000_000)); // long past the cutoff
        logs.push(recent("10.0.0.8", 1).pop().unwrap());

        logs.remove_expired_logs();

        assert!(all(&logs, "10.0.0.7").is_empty());
        assert_eq!(all(&logs, "10.0.0.8").len(), 1);
        assert_eq!(logs.logs_store.lock().unwrap().len(), 1);
    }

    #[test]
    fn get_returns_newest_first_with_increasing_seq() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", 3) {
            logs.push(log);
        }

        let page = logs.get("10.0.0.7", 0, 10);
        let seqs: Vec<u64> = page.queries.iter().map(|q| q.seq).collect();
        assert_eq!(seqs.len(), 3);
        assert!(seqs[0] > seqs[1] && seqs[1] > seqs[2], "{seqs:?}");
        assert!(!page.truncated);
    }

    /// The polling contract: `since` is the highest seq the client has, and it
    /// gets exactly the entries after it.
    #[test]
    fn since_returns_only_newer_entries() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", 3) {
            logs.push(log);
        }
        let cursor = logs.get("10.0.0.7", 0, 10).queries[0].seq;

        assert!(logs.get("10.0.0.7", cursor, 10).queries.is_empty());

        for log in recent("10.0.0.7", 2) {
            logs.push(log);
        }
        let page = logs.get("10.0.0.7", cursor, 10);
        assert_eq!(page.queries.len(), 2);
        assert!(page.queries.iter().all(|q| q.seq > cursor));
    }

    #[test]
    fn limit_keeps_the_newest_and_reports_truncation() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", 5) {
            logs.push(log);
        }
        let everything = all(&logs, "10.0.0.7");

        let page = logs.get("10.0.0.7", 0, 2);
        assert_eq!(page.queries, everything[..2].to_vec());
        assert!(page.truncated);

        let page = logs.get("10.0.0.7", 0, 5);
        assert!(!page.truncated, "exactly `limit` left is not truncation");
    }

    /// A restarted process must not reuse numbers an old client holds.
    #[test]
    fn a_new_store_starts_above_an_older_one() {
        let old = QueryLogs::default();
        old.push(recent("10.0.0.7", 1).pop().unwrap());
        let old_seq = all(&old, "10.0.0.7")[0].seq;

        std::thread::sleep(std::time::Duration::from_millis(2));
        let new = QueryLogs::default();
        new.push(recent("10.0.0.7", 1).pop().unwrap());

        assert!(all(&new, "10.0.0.7")[0].seq > old_seq);
    }
}
