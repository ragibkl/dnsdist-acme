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
    }

    pub fn merge_logs(&self, logs_hash_map: &HashMap<String, Vec<QueryLog>>) {
        let mut logs_store_guard = self.logs_store.lock().unwrap();
        for (ip, logs) in logs_hash_map.iter() {
            match logs_store_guard.get_mut(ip) {
                Some(existing_logs) => {
                    existing_logs.extend(logs.clone());
                }
                None => {
                    logs_store_guard.insert(ip.to_string(), logs.clone());
                }
            }
        }
    }

    pub fn get_logs_for_ip(&self, ip: &str) -> Vec<QueryLog> {
        match self.logs_store.lock().unwrap().get(ip).cloned() {
            Some(logs) => logs,
            None => Vec::new(),
        }
    }
}
