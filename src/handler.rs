use std::net::SocketAddr;
use std::sync::LazyLock;

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use handlebars::Handlebars;

use crate::logs::{QueryLog, QueryLogs, UsageStats};

static GET_LOGS_TEMPLATE: &str = include_str!("./get_logs.hbs");
const GET_LOGS_TEMPLATE_NAME: &str = "get_logs";

/// Parsed once for the life of the process.
///
/// This used to be a fresh `Handlebars::new()` plus `render_template` on every
/// request, so the template was re-parsed per hit, and the `unwrap` on the
/// result made a template problem a panic *inside a request handler*. The
/// template is `include_str!`-ed, so a parse failure is a build-time mistake
/// rather than anything a request can cause -- and `the_logs_template_renders`
/// below catches it in CI instead of in production.
static REGISTRY: LazyLock<Handlebars<'static>> = LazyLock::new(|| {
    let mut reg = Handlebars::new();
    reg.register_template_string(GET_LOGS_TEMPLATE_NAME, GET_LOGS_TEMPLATE)
        .expect("get_logs.hbs must parse; covered by the_logs_template_renders");
    reg
});

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
) -> Response {
    tracing::info!("get_logs - addr: {addr}");

    let ip = get_ip(addr);
    let queries = app_state.logs_store.get_logs_for_ip(&ip);
    let active_ips = app_state.usage_stats.get_active_ips();

    let data = GetLogsOutput {
        ip,
        queries,
        active_ips,
    };

    match REGISTRY.render(GET_LOGS_TEMPLATE_NAME, &data) {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            // The template is fixed and tested, so reaching this means the data
            // failed to serialize. Answer 500 rather than taking the process
            // down: this handler shares a runtime with the ACME renewal and the
            // dnstap listener.
            tracing::error!("rendering the logs page failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not render the logs page",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    /// Renders the real template with real data. This is what lets the
    /// `expect` in `REGISTRY` be a build-time claim rather than a production
    /// risk -- a template that stopped parsing, or an `{{#each}}` over a field
    /// that no longer exists, fails here.
    #[test]
    fn the_logs_template_renders() {
        let data = GetLogsOutput {
            ip: "203.0.113.7".to_string(),
            queries: vec![QueryLog {
                ip: "203.0.113.7".to_string(),
                query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
                question: "zedo.com. IN A".to_string(),
                answers: vec!["0.0.0.0".to_string()],
            }],
            active_ips: 42,
        };

        let html = REGISTRY.render(GET_LOGS_TEMPLATE_NAME, &data).unwrap();

        assert!(html.contains("203.0.113.7"), "{html}");
        assert!(html.contains("zedo.com."), "{html}");
        assert!(html.contains("0.0.0.0"), "{html}");
        assert!(html.contains("42"), "{html}");
    }

    /// Handlebars escapes `{{ }}` by default, and the page renders a question
    /// name that arrives from the network. Pinned because switching a field to
    /// `{{{ }}}` would silently make it injectable.
    #[test]
    fn query_names_are_html_escaped() {
        let data = GetLogsOutput {
            ip: "203.0.113.7".to_string(),
            queries: vec![QueryLog {
                ip: "203.0.113.7".to_string(),
                query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
                question: "<script>alert(1)</script>. IN A".to_string(),
                answers: vec![],
            }],
            active_ips: 1,
        };

        let html = REGISTRY.render(GET_LOGS_TEMPLATE_NAME, &data).unwrap();

        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

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
