use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;

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

#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct Query {
    query_time: chrono::DateTime<Utc>,
    question: String,
    answers: Vec<String>,
}

fn parse_query_time(query_time: &str) -> DateTime<Utc> {
    let query_time = query_time.replace("!!timestamp", "").trim().to_string();
    let (query_time, _) =
        NaiveDateTime::parse_and_remainder(&query_time, "%Y-%m-%d %H:%M:%S").unwrap();
    query_time.and_utc()
}

fn extract_query(raw_log: &RawLog) -> Query {
    let response_message = &raw_log.message.response_message;
    let query_time = parse_query_time(&raw_log.message.query_time);

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

    Query {
        query_time,
        question,
        answers,
    }
}

fn extract_queries(content: &str) -> HashMap<String, Vec<Query>> {
    let mut logs: Vec<RawLog> = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&content) {
        let Ok(log) = RawLog::deserialize(document) else {
            continue;
        };

        logs.push(log);
    }

    let mut logs_store: HashMap<String, Vec<Query>> = HashMap::new();
    for log in logs.into_iter() {
        let ip = log.message.query_address.to_string();
        let query = extract_query(&log);

        match logs_store.get_mut(&ip) {
            Some(queries) => {
                queries.push(query);
            }
            None => {
                logs_store.insert(ip, vec![query]);
            }
        }
    }

    logs_store
}

pub struct LogConsumer {
    logs_store: Arc<Mutex<HashMap<String, Arc<Mutex<Vec<Query>>>>>>,
}

impl LogConsumer {
    pub fn read_logs(&self) {
        let Ok(content) = std::fs::read_to_string("./logs.yaml") else {
            return;
        };
        let _ = std::fs::write("./logs.yaml", "");

        let logs_store = extract_queries(&content);

        for (ip, queries) in logs_store.into_iter() {
            match self.logs_store.lock().unwrap().get(&ip).cloned() {
                Some(val) => {
                    let mut current = val
                        .lock()
                        .unwrap()
                        .clone()
                        .into_iter()
                        .filter(|q| true)
                        .collect::<Vec<_>>();
                    current.extend(queries);
                    *val.lock().unwrap() = current;
                }
                None => {
                    self.logs_store
                        .lock()
                        .unwrap()
                        .insert(ip, Arc::new(Mutex::new(queries)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::TimeZone;

    use crate::log_consumer::{parse_query_time, Query};

    use super::extract_queries;

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
            vec![Query {
                query_time: chrono::Utc.with_ymd_and_hms(2022, 2, 26, 9, 25, 7).unwrap(),
                question: ";zedo.com.IN A".to_string(),
                answers: vec![
                    "zedo.com.\t5\tIN\tCNAME\tnull.null-zone.null.".to_string(),
                    "null.null-zone.null.\t86400\tIN\tA\t0.0.0.0".to_string(),
                ],
            }],
        )]);

        let output = extract_queries(input);
        assert_eq!(output, expected);
    }
}
