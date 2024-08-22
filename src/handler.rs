use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    response::Html,
    Json,
};
use handlebars::Handlebars;

use crate::logs_store::{LogsStore, Query};

static GET_LOGS_TEMPLATE: &str = include_str!("./get_logs.hbs");

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsOutput {
    ip: String,
    queries: Vec<Query>,
}

fn get_ip(addr: SocketAddr) -> String {
    let ip = addr.ip().to_string();
    if ip.starts_with("::ffff:") {
        return ip.replace("::ffff:", "");
    }
    ip
}

#[axum_macros::debug_handler]
pub async fn get_logs_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(logs_store): State<LogsStore>,
) -> Json<GetLogsOutput> {
    tracing::info!("get_logs_api - addr: {addr}");

    let ip = get_ip(addr);
    let queries = logs_store.get_queries_for_ip(&ip);

    Json(GetLogsOutput { ip, queries })
}

#[axum_macros::debug_handler]
pub async fn get_logs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(logs_store): State<LogsStore>,
) -> Html<String> {
    tracing::info!("get_logs - addr: {addr}");

    let ip = get_ip(addr);
    let queries = logs_store.get_queries_for_ip(&ip);

    let reg = Handlebars::new();
    let response = reg
        .render_template(GET_LOGS_TEMPLATE, &GetLogsOutput { ip, queries })
        .unwrap();

    Html(response)
}
