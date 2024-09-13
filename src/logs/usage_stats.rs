use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};

use super::QueryLog;

#[derive(Debug, Clone, Default)]
pub struct UsageStats {
    active_ips_one_day: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl UsageStats {
    pub fn merge_logs(&self, logs_hash_map: &HashMap<String, Vec<QueryLog>>) {
        let mut last_query_times = self.active_ips_one_day.lock().unwrap().clone();

        for (ip, queries) in logs_hash_map.iter() {
            let Some(last_qt) = queries.last().map(|q| q.query_time) else {
                continue;
            };

            match last_query_times.get_mut(ip) {
                Some(qt) => *qt = last_qt,
                None => {
                    last_query_times.insert(ip.to_string(), last_qt);
                }
            }
        }

        *self.active_ips_one_day.lock().unwrap() = last_query_times;
    }

    pub fn remove_old_query_times(&self) {
        let time_cutoff = Utc::now() - Duration::days(1);
        let mut active_ips_one_day = self.active_ips_one_day.lock().unwrap();
        active_ips_one_day.retain(|_ip, qt| *qt > time_cutoff);
    }

    pub fn get_active_ips_in_last_day(&self) -> usize {
        self.active_ips_one_day.lock().unwrap().len()
    }
}
