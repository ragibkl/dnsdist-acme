use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    response::Html,
    Json,
};
use handlebars::Handlebars;

use crate::logs::{QueryLog, QueryLogs, UsageStats};

static GET_LOGS_TEMPLATE: &str = include_str!("./get_logs.hbs");

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsApiOutput {
    ip: String,
    queries: Vec<QueryLog>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsOutput {
    ip: String,
    queries: Vec<QueryLog>,
    active_ips_last_day: usize,
}

#[derive(Clone)]
pub struct AppState {
    logs_store: QueryLogs,
    usage_stats: UsageStats,
}

impl AppState {
    pub fn new(logs_store: QueryLogs, usage_stats: UsageStats) -> Self {
        Self {
            logs_store,
            usage_stats,
        }
    }
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
    State(app_state): State<AppState>,
) -> Json<GetLogsApiOutput> {
    tracing::info!("get_logs_api - addr: {addr}");

    let ip = get_ip(addr);
    let queries = app_state.logs_store.get_logs_for_ip(&ip);

    Json(GetLogsApiOutput { ip, queries })
}

#[axum_macros::debug_handler]
pub async fn get_logs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
) -> Html<String> {
    tracing::info!("get_logs - addr: {addr}");

    let ip = get_ip(addr);
    let queries = app_state.logs_store.get_logs_for_ip(&ip);
    let active_ips_last_day = app_state.usage_stats.get_active_ips_in_last_day();

    let reg = Handlebars::new();
    let response = reg
        .render_template(
            GET_LOGS_TEMPLATE,
            &GetLogsOutput {
                ip,
                queries,
                active_ips_last_day,
            },
        )
        .unwrap();

    Html(response)
}
