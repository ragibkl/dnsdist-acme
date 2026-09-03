use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};

use super::QueryLog;

#[derive(Debug, Clone, Default)]
pub struct QueryLogs {
    logs_store: Arc<Mutex<HashMap<String, Vec<QueryLog>>>>,
}

impl QueryLogs {
    pub fn remove_expired_logs(&self) {
        let query_time_cutoff = Utc::now() - Duration::minutes(10);

        let mut logs_store_guard = self.logs_store.lock().unwrap();
        for query_logs in logs_store_guard.values_mut() {
            query_logs.retain(|q| q.query_time > query_time_cutoff);
        }

        logs_store_guard.retain(|_ip, queries| !queries.is_empty());
    }

    /// Records one entry. Ingestion is now per-frame as dnstap delivers it,
    /// rather than a batch read from a file every second.
    pub fn push(&self, log: QueryLog) {
        let mut guard = self.logs_store.lock().unwrap();
        guard.entry(log.ip.clone()).or_default().push(log);
    }

    pub fn get_logs_for_ip(&self, ip: &str) -> Vec<QueryLog> {
        self.logs_store.lock().unwrap().get(ip).cloned().unwrap_or_default()
    }
}
