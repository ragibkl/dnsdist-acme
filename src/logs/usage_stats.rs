use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Clone, Default)]
pub struct UsageStats {
    active_ips: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl UsageStats {
    /// Marks an address active at `seen`.
    pub fn touch(&self, ip: &str, seen: DateTime<Utc>) {
        let mut guard = self.active_ips.lock().unwrap();
        guard
            .entry(ip.to_string())
            .and_modify(|t| *t = seen)
            .or_insert(seen);
    }

    pub fn remove_old_active_ips(&self) {
        let time_cutoff = Utc::now() - Duration::minutes(10);
        let mut active_ips_one_day = self.active_ips.lock().unwrap();
        active_ips_one_day.retain(|_ip, qt| *qt > time_cutoff);
    }

    pub fn get_active_ips(&self) -> usize {
        self.active_ips.lock().unwrap().len()
    }
}
