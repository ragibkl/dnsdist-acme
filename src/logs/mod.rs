mod query_log;
mod query_logs;
mod usage_stats;

pub use query_log::*;
pub use query_logs::*;
pub use usage_stats::*;

use crate::tasks::dnstap::read_dnstap_logs;

#[derive(Debug, Clone)]
pub struct LogsConsumer {
    logs_store: QueryLogs,
    usage_stats: UsageStats,
}

impl LogsConsumer {
    pub fn new(logs_store: QueryLogs, usage_stats: UsageStats) -> Self {
        Self {
            logs_store,
            usage_stats,
        }
    }

    pub async fn ingest_logs_from_file(&self) {
        tracing::trace!("LogsStore remove_expired_logs");
        self.logs_store.remove_expired_logs();
        tracing::trace!("LogsStore remove_expired_logs. DONE");

        tracing::trace!("LogsStore read_dnstap_logs");
        let content = read_dnstap_logs().await;
        let content_len = content.len();
        tracing::trace!("LogsStore read_dnstap_logs. DONE, content_len={content_len}");

        tracing::trace!("LogsStore extract_query_logs");
        let logs_hash_map = extract_query_logs(&content);
        let logs_hash_map_len = logs_hash_map.len();
        tracing::trace!(
            "LogsStore extract_query_logs. DONE, logs_hash_map_len={logs_hash_map_len}"
        );

        tracing::trace!("LogsStore logs_hash_map");
        self.logs_store.merge_logs(&logs_hash_map);
        self.logs_store.remove_expired_logs();

        self.usage_stats.merge_logs(&logs_hash_map);
        tracing::trace!("LogsStore logs_hash_map. DONE");
    }
}
