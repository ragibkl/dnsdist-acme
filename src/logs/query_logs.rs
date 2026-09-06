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
const MAX_AGE_MINUTES: i64 = 10;

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
/// Worst case is bounded on both sides: `MaxQPSIPRule` in `dnsdist.conf` holds
/// any single address to 50 qps, so one IP can offer at most ~30,000 entries in
/// a window, of which this keeps 10,000 -- about 2.2 MB.
///
/// The eviction is counted rather than silent. Losing entries without saying so
/// is a failure this code has already had once -- the `logs.yaml` read/truncate
/// race destroyed data with nothing recording it, and only a second, noisier
/// symptom revealed it. That counter is also what measured the paragraph above.
const MAX_PER_IP: usize = 10_000;

#[derive(Debug, Clone, Default)]
pub struct QueryLogs {
    logs_store: Arc<Mutex<HashMap<String, VecDeque<QueryLog>>>>,
    /// Entries discarded by `MAX_PER_IP` since the count was last taken.
    dropped: Arc<AtomicU64>,
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
    pub fn push(&self, log: QueryLog) {
        let mut guard = self.logs_store.lock().unwrap();
        let entries = guard.entry(log.ip.clone()).or_default();

        while entries.len() >= MAX_PER_IP {
            entries.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }

        entries.push_back(log);
    }

    pub fn get_logs_for_ip(&self, ip: &str) -> Vec<QueryLog> {
        self.logs_store
            .lock()
            .unwrap()
            .get(ip)
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
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
            query_time: DateTime::from_timestamp(secs, 0).unwrap(),
            question: format!("q{secs}.example. IN A"),
            answers: vec!["0.0.0.0".to_string()],
        }
    }

    fn recent(ip: &str, n: usize) -> Vec<QueryLog> {
        let now = Utc::now().timestamp();
        (0..n).map(|i| log_at(ip, now + i as i64)).collect()
    }

    #[test]
    fn keeps_everything_below_the_cap() {
        let logs = QueryLogs::default();
        for log in recent("10.0.0.7", 10) {
            logs.push(log);
        }

        assert_eq!(logs.get_logs_for_ip("10.0.0.7").len(), 10);
        assert_eq!(logs.take_dropped(), 0);
    }

    /// The point of the cap: a source that will not stop talking must not grow
    /// without limit, and what it keeps must be the newest entries.
    #[test]
    fn the_cap_evicts_the_oldest_and_keeps_the_newest() {
        let logs = QueryLogs::default();
        let over = 50;
        let pushed = recent("10.0.0.7", MAX_PER_IP + over);
        let newest = pushed.last().unwrap().question.clone();
        // The first `over` entries are the ones that should go.
        let oldest_kept = pushed[over].question.clone();
        for log in pushed {
            logs.push(log);
        }

        let kept = logs.get_logs_for_ip("10.0.0.7");
        assert_eq!(kept.len(), MAX_PER_IP);
        assert_eq!(kept.last().unwrap().question, newest);
        assert_eq!(kept.first().unwrap().question, oldest_kept);
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

        assert_eq!(logs.get_logs_for_ip("10.0.0.7").len(), MAX_PER_IP);
        assert_eq!(logs.get_logs_for_ip("10.0.0.8").len(), 3);
    }

    #[test]
    fn expired_entries_are_removed_and_empty_addresses_forgotten() {
        let logs = QueryLogs::default();
        logs.push(log_at("10.0.0.7", 1_700_000_000)); // long past the cutoff
        logs.push(recent("10.0.0.8", 1).pop().unwrap());

        logs.remove_expired_logs();

        assert!(logs.get_logs_for_ip("10.0.0.7").is_empty());
        assert_eq!(logs.get_logs_for_ip("10.0.0.8").len(), 1);
        assert_eq!(logs.logs_store.lock().unwrap().len(), 1);
    }
}
