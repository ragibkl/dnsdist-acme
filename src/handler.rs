use std::net::SocketAddr;

use axum::{extract::ConnectInfo, response::Html, Json};
use handlebars::Handlebars;
use serde::Deserialize;

static GET_LOGS_TEMPLATE: &str = include_str!("./get_logs.hbs");

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug, Clone)]
pub struct RawMessage {
    #[serde(rename = "type")]
    _type: String,

    query_address: String,
    response_address: String,
    response_message: String,
}

#[allow(dead_code)]
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

fn extract_query(response_message: &str) -> Query {
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

    Query { question, answers }
}

async fn load_queries(ip: &str) -> Vec<Query> {
    let content = tokio::fs::read_to_string("./logs.yaml")
        .await
        .unwrap_or_default();

    let mut logs: Vec<RawLog> = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&content) {
        let log: Option<RawLog> = Deserialize::deserialize(document).unwrap_or_default();
        if let Some(log) = log {
            logs.push(log);
        }
    }

    logs.iter()
        .filter(|l| l.message.query_address == ip)
        .map(|l| extract_query(l.message.response_message.as_str()))
        .collect()
}

fn get_ip(addr: SocketAddr) -> String {
    let ip = addr.ip().to_string();
    if ip.starts_with("::ffff:") {
        return ip.replace("::ffff:", "");
    }
    ip
}

#[axum_macros::debug_handler]
pub async fn get_logs_api(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Json<GetLogsOutput> {
    tracing::info!("get_logs_api - addr: {addr}");

    let ip = get_ip(addr);
    let queries = load_queries(&ip).await;

    Json(GetLogsOutput { ip, queries })
}

#[axum_macros::debug_handler]
pub async fn get_logs(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    tracing::info!("get_logs - addr: {addr}");

    let ip = get_ip(addr);
    let queries = load_queries(&ip).await;

    let reg = Handlebars::new();
    let response = reg
        .render_template(GET_LOGS_TEMPLATE, &GetLogsOutput { ip, queries })
        .unwrap();

    Html(response)
}
