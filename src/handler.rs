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
    active_ips: usize,
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

/// The client address as a string, with IPv4-mapped IPv6 rendered as plain
/// IPv4.
///
/// Clients reaching a dual-stack listener over IPv4 arrive as `::ffff:a.b.c.d`,
/// and this string is the key that `/logs` looks queries up by, so the two
/// spellings must not produce different keys. `to_canonical` is the operation
/// that means this, rather than editing the formatted string.
fn get_ip(addr: SocketAddr) -> String {
    addr.ip().to_canonical().to_string()
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
    let active_ips = app_state.usage_stats.get_active_ips();

    let reg = Handlebars::new();
    let response = reg
        .render_template(
            GET_LOGS_TEMPLATE,
            &GetLogsOutput {
                ip,
                queries,
                active_ips,
            },
        )
        .unwrap();

    Html(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_of(addr: &str) -> String {
        get_ip(addr.parse().unwrap())
    }

    /// The case that matters: a v4 client on a dual-stack listener must key the
    /// same as the same client seen as plain v4, or `/logs` would show them two
    /// separate histories depending on which socket accepted them.
    #[test]
    fn ipv4_mapped_addresses_render_as_ipv4() {
        assert_eq!(ip_of("[::ffff:203.0.113.7]:443"), "203.0.113.7");
        assert_eq!(ip_of("203.0.113.7:443"), "203.0.113.7");
    }

    #[test]
    fn genuine_ipv6_is_left_alone() {
        assert_eq!(ip_of("[2001:db8::1]:443"), "2001:db8::1");
    }

    /// `::ffff:` is a valid run of hex groups, so a v6 address can contain it
    /// without being v4-mapped. The previous `replace` implementation handled
    /// this correctly too -- its `starts_with` guard meant the substring removal
    /// never ran here, and one `::` per address makes a second occurrence
    /// impossible anyway. Pinned as a regression test, not a fixed bug.
    #[test]
    fn an_ipv6_address_merely_containing_the_prefix_is_not_rewritten() {
        let addr = "[1:2:3:4::ffff:5]:443";
        let got = ip_of(addr);
        assert!(got.contains(':'), "should still be an IPv6 address, got {got}");
        assert_eq!(got, "1:2:3:4::ffff:5");
    }
}
