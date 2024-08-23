use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::tasks::dnstap::read_dnstap_logs;

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
pub struct RawMessage {
    #[serde(rename = "type")]
    _type: String,

    query_time: String,
    query_address: String,
    response_address: String,
    response_message: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
pub struct RawLog {
    #[serde(rename = "type")]
    _type: String,

    identity: String,
    version: String,
    message: RawMessage,
}

fn parse_query_time(query_time: &str) -> DateTime<Utc> {
    let query_time = query_time.replace("!!timestamp", "").trim().to_string();
    let (query_time, _) =
        NaiveDateTime::parse_and_remainder(&query_time, "%Y-%m-%d %H:%M:%S").unwrap();
    query_time.and_utc()
}

#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct QueryLog {
    ip: String,
    query_time: chrono::DateTime<Utc>,
    question: String,
    answers: Vec<String>,
}

impl From<&RawLog> for QueryLog {
    fn from(raw_log: &RawLog) -> Self {
        let ip = raw_log.message.query_address.to_string();
        let query_time = parse_query_time(&raw_log.message.query_time);
        let response_message = &raw_log.message.response_message;

        let question: String = response_message
            .split('\n')
            .skip_while(|s| *s != ";; QUESTION SECTION:")
            .skip(1)
            .take(1)
            .next()
            .map(|s| s.to_string())
            .unwrap_or_default()
            .replace('\t', "");

        let answers: Vec<String> = response_message
            .split('\n')
            .skip_while(|s| *s != ";; ANSWER SECTION:")
            .skip(1)
            .take_while(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        QueryLog {
            ip,
            query_time,
            question,
            answers,
        }
    }
}

fn extract_query_logs(content: &str) -> HashMap<String, Vec<QueryLog>> {
    let mut logs_store: HashMap<String, Vec<QueryLog>> = HashMap::new();

    for document in serde_yaml::Deserializer::from_str(content) {
        let Ok(raw_log) = RawLog::deserialize(document) else {
            continue;
        };

        let query_log = QueryLog::from(&raw_log);
        match logs_store.get_mut(&query_log.ip) {
            Some(queries) => {
                queries.push(query_log);
            }
            None => {
                logs_store.insert(query_log.ip.to_string(), vec![query_log]);
            }
        }
    }

    logs_store
}

#[derive(Debug, Clone, Default)]
pub struct LogsStore {
    logs_store: Arc<Mutex<HashMap<String, Vec<QueryLog>>>>,
}

impl LogsStore {
    pub fn remove_expired_logs(&self) {
        let query_time_cutoff = Utc::now() - Duration::minutes(10);

        let mut logs_store_guard = self.logs_store.lock().unwrap();
        for query_logs in logs_store_guard.values_mut() {
            query_logs.retain(|q| q.query_time > query_time_cutoff);
        }
    }

    pub fn merge_logs(&self, logs_hash_map: HashMap<String, Vec<QueryLog>>) {
        let mut logs_store_guard = self.logs_store.lock().unwrap();
        for (ip, logs) in logs_hash_map.into_iter() {
            match logs_store_guard.get_mut(&ip) {
                Some(existing_logs) => {
                    existing_logs.extend(logs);
                }
                None => {
                    logs_store_guard.insert(ip, logs);
                }
            }
        }
    }

    pub async fn ingest_logs_from_file(&self) {
        tracing::info!("LogsStore remove_expired_logs");
        self.remove_expired_logs();
        tracing::info!("LogsStore remove_expired_logs. DONE");

        tracing::info!("LogsStore read_dnstap_logs");
        let content = read_dnstap_logs().await;
        tracing::info!("LogsStore read_dnstap_logs. DONE");

        let logs_hash_map = extract_query_logs(&content);

        self.merge_logs(logs_hash_map);
    }

    pub fn get_logs_for_ip(&self, ip: &str) -> Vec<QueryLog> {
        match self.logs_store.lock().unwrap().get(ip).cloned() {
            Some(logs) => logs,
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::TimeZone;

    use crate::logs_store::{parse_query_time, QueryLog};

    use super::extract_query_logs;

    #[test]
    fn test_parse_query_time() {
        let query_time = "!!timestamp 2022-02-26 09:25:07.665010146";
        let output = parse_query_time(query_time);
        let expected = chrono::Utc.with_ymd_and_hms(2022, 2, 26, 9, 25, 7).unwrap();
        assert_eq!(output, expected)
    }

    #[test]
    fn test_extract_queries() {
        let input = r#"
type: MESSAGE
identity: "dns"
version: "dnsdist 1.6.1"
message:
  type: CLIENT_RESPONSE
  query_time: !!timestamp 2022-02-26 09:25:07.665010146
  response_time: !!timestamp 2022-02-26 09:25:10.493649953
  socket_family: INET
  socket_protocol: UDP
  query_address: 127.0.0.1
  response_address: 127.0.0.1
  query_port: 45523
  response_port: 1253
  response_message: |
    ;; opcode: QUERY, status: NOERROR, id: 50897
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
    
    ;; QUESTION SECTION:
    ;zedo.com.	IN	 A
    
    ;; ANSWER SECTION:
    zedo.com.	5	IN	CNAME	null.null-zone.null.
    null.null-zone.null.	86400	IN	A	0.0.0.0
    
    ;; ADDITIONAL SECTION:
    blacklist.	1	IN	SOA	LOCALHOST. named-mgr.example.com.blacklist. 1 3600 900 2592000 7200
        "#
        .trim();

        let expected = HashMap::from([(
            "127.0.0.1".to_string(),
            vec![QueryLog {
                ip: "127.0.0.1".to_string(),
                query_time: chrono::Utc.with_ymd_and_hms(2022, 2, 26, 9, 25, 7).unwrap(),
                question: ";zedo.com.IN A".to_string(),
                answers: vec![
                    "zedo.com.\t5\tIN\tCNAME\tnull.null-zone.null.".to_string(),
                    "null.null-zone.null.\t86400\tIN\tA\t0.0.0.0".to_string(),
                ],
            }],
        )]);

        let output = extract_query_logs(input);
        assert_eq!(output, expected);
    }
}
