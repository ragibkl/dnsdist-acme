use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};

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
        NaiveDateTime::parse_and_remainder(&query_time, "%Y-%m-%d %H:%M:%S").unwrap_or_default();
    query_time.and_utc()
}

#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct QueryLog {
    pub ip: String,
    pub query_time: chrono::DateTime<Utc>,
    pub question: String,
    pub answers: Vec<String>,
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

pub fn extract_query_logs(content: &str) -> HashMap<String, Vec<QueryLog>> {
    let mut logs_store: HashMap<String, Vec<QueryLog>> = HashMap::new();

    let content_parts = content
        .split("\n---\n")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    for part in content_parts {
        let Ok(raw_log) = serde_yaml::from_str::<RawLog>(part) else {
            tracing::info!("extract_query_logs fail to extract part: {part}");
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::TimeZone;

    use super::{extract_query_logs, parse_query_time, QueryLog};

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
