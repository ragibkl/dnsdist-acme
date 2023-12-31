use std::net::SocketAddr;

use axum::{extract::ConnectInfo, response::Html, Json};
use handlebars::Handlebars;
use serde::Deserialize;

// type: MESSAGE
// identity: "dns"
// version: "dnsdist 1.6.1"
// message:
//   type: CLIENT_RESPONSE
//   query_time: !!timestamp 2022-02-26 09:25:07.665010146
//   response_time: !!timestamp 2022-02-26 09:25:10.493649953
//   socket_family: INET
//   socket_protocol: UDP
//   query_address: 127.0.0.1
//   response_address: 127.0.0.1
//   query_port: 45523
//   response_port: 1253
//   response_message: |

static TEMPLATE: &'static str = include_str!("./getLogs.hbs");

#[derive(serde::Deserialize, Debug, Clone)]
pub struct RawMessage {
    #[serde(rename = "type")]
    _type: String,

    query_address: String,
    response_address: String,
    response_message: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct RawLog {
    #[serde(rename = "type")]
    _type: String,

    identity: String,
    version: String,
    message: RawMessage,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct Query {
    question: String,
    answers: Vec<String>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsOutput {
    ip: String,
    queries: Vec<Query>,
}

fn extract(message: &str) -> Query {
    let split: Vec<String> = message.split("\n").map(|s| s.to_string()).collect();

    let question: String = split
        .iter()
        .skip_while(|s| *s != ";; QUESTION SECTION:")
        .skip(1)
        .take(1)
        .next()
        .unwrap()
        .replace("\t", "");

    let answers: Vec<String> = split
        .iter()
        .skip_while(|s| *s != ";; ANSWER SECTION:")
        .skip(1)
        .take_while(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Query { question, answers }
}

async fn load_queries(ip: &str) -> Vec<Query> {
    let content = tokio::fs::read_to_string("./logs.yaml").await.unwrap();

    let mut logs: Vec<RawLog> = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&content) {
        let log: Option<RawLog> = Deserialize::deserialize(document).unwrap();
        if let Some(log) = log {
            logs.push(log);
        }
    }

    logs.iter()
        .filter(|l| l.message.query_address == ip)
        .map(|l| extract(l.message.response_message.as_str()))
        .collect()
}

#[axum_macros::debug_handler]
pub async fn get_logs_api(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Json<GetLogsOutput> {
    tracing::info!("get_logs - addr: {addr}");

    let ip = addr.ip().to_string();
    let queries = load_queries(&ip).await;

    Json(GetLogsOutput { ip, queries })
}

#[axum_macros::debug_handler]
pub async fn get_logs(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    tracing::info!("get_logs - addr: {addr}");

    let ip = addr.ip().to_string();
    let queries = load_queries(&ip).await;

    let reg = Handlebars::new();
    // render without register
    let response = reg
        .render_template(TEMPLATE, &GetLogsOutput { ip, queries })
        .unwrap();

    Html(response)
}
