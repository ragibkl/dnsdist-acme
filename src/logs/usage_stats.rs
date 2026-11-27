use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use jiff::{SignedDuration, Timestamp};

#[derive(Debug, Clone, Default)]
pub struct UsageStats {
    active_ips: Arc<Mutex<HashMap<String, Timestamp>>>,
}

impl UsageStats {
    /// Marks an address active at `seen`.
    pub fn touch(&self, ip: &str, seen: Timestamp) {
        let mut guard = self.active_ips.lock().unwrap();
        guard
            .entry(ip.to_string())
            .and_modify(|t| *t = seen)
            .or_insert(seen);
    }

    pub fn remove_old_active_ips(&self) {
        let time_cutoff = Timestamp::now() - SignedDuration::from_mins(10);
        let mut active_ips = self.active_ips.lock().unwrap();
        active_ips.retain(|_ip, qt| *qt > time_cutoff);
    }

    pub fn get_active_ips(&self) -> usize {
        self.active_ips.lock().unwrap().len()
    }
}
