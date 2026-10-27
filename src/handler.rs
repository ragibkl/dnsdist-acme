use std::net::SocketAddr;
use std::sync::LazyLock;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use handlebars::Handlebars;

use crate::logs::{QueryLog, QueryLogs, UsageStats, WINDOW_SECONDS};

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

/// Entries `/api/logs` returns when the caller does not say. Enough for a
/// first look; a polling client asks with `since` after that.
const DEFAULT_LIMIT: usize = 200;
/// Upper bound on `limit`, so one request cannot clone a whole 10,000-entry
/// queue under the store's lock.
const MAX_LIMIT: usize = 1000;
/// The HTML page has no paging, so it shows this many and says when there
/// were more.
const PAGE_LIMIT: usize = 1000;

#[derive(serde::Deserialize, Debug, Default)]
pub struct LogsParams {
    since: Option<u64>,
    limit: Option<usize>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsApiOutput {
    /// TLS_DOMAIN, so a page polling several servers can label the answers.
    server: Option<String>,
    client_ip: String,
    family: &'static str,
    window_seconds: i64,
    /// The `since` to send next: the newest `seq` returned, or the caller's
    /// own `since` when nothing new came back.
    cursor: u64,
    truncated: bool,
    queries: Vec<QueryLog>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetLogsOutput {
    server: Option<String>,
    client_ip: String,
    family: &'static str,
    active_ips: usize,
    window_minutes: i64,
    truncated: bool,
    /// `queries.len()`, which the template cannot compute itself.
    shown: usize,
    queries: Vec<QueryLog>,
}

#[derive(Clone)]
pub struct AppState {
    logs_store: QueryLogs,
    usage_stats: UsageStats,
    server: Option<String>,
}

impl AppState {
    pub fn new(logs_store: QueryLogs, usage_stats: UsageStats, server: Option<String>) -> Self {
        Self {
            logs_store,
            usage_stats,
            server,
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

fn family(addr: SocketAddr) -> &'static str {
    if addr.ip().to_canonical().is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

#[axum_macros::debug_handler]
pub async fn get_logs_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
    Query(params): Query<LogsParams>,
) -> impl IntoResponse {
    tracing::info!("get_logs_api - addr: {addr}");

    let ip = get_ip(addr);
    let since = params.since.unwrap_or(0);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let page = app_state.logs_store.get(&ip, since, limit);
    let cursor = page.queries.first().map_or(since, |q| q.seq);

    // Every answer is specific to the caller's address and changes by the
    // second; nothing in between should keep a copy.
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(GetLogsApiOutput {
            server: app_state.server.clone(),
            client_ip: ip,
            family: family(addr),
            window_seconds: WINDOW_SECONDS,
            cursor,
            truncated: page.truncated,
            queries: page.queries,
        }),
    )
}

#[axum_macros::debug_handler]
pub async fn get_logs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
) -> Response {
    tracing::info!("get_logs - addr: {addr}");

    let ip = get_ip(addr);
    let page = app_state.logs_store.get(&ip, 0, PAGE_LIMIT);
    let active_ips = app_state.usage_stats.get_active_ips();

    let data = GetLogsOutput {
        server: app_state.server.clone(),
        client_ip: ip,
        family: family(addr),
        active_ips,
        window_minutes: WINDOW_SECONDS / 60,
        truncated: page.truncated,
        shown: page.queries.len(),
        queries: page.queries,
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
    use crate::logs::Answer;
    use chrono::{DateTime, Utc};

    fn page_data(queries: Vec<QueryLog>, active_ips: usize) -> GetLogsOutput {
        GetLogsOutput {
            shown: queries.len(),
            server: Some("dns.example.com".to_string()),
            client_ip: "203.0.113.7".to_string(),
            family: "ipv4",
            active_ips,
            window_minutes: 10,
            truncated: false,
            queries,
        }
    }

    /// Renders the real template with real data. This is what lets the
    /// `expect` in `REGISTRY` be a build-time claim rather than a production
    /// risk -- a template that stopped parsing, or an `{{#each}}` over a field
    /// that no longer exists, fails here.
    #[test]
    fn the_logs_template_renders() {
        let data = page_data(
            vec![QueryLog {
                ip: "203.0.113.7".to_string(),
                seq: 1,
                query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
                name: "zedo.com".to_string(),
                qtype: "A".to_string(),
                rcode: "NOERROR".to_string(),
                blocked: true,
                answers: vec![Answer {
                    name: "zedo.com".to_string(),
                    rtype: "A".to_string(),
                    ttl: 60,
                    data: "0.0.0.0".to_string(),
                }],
            }],
            42,
        );

        let html = REGISTRY.render(GET_LOGS_TEMPLATE_NAME, &data).unwrap();

        assert!(html.contains("203.0.113.7"), "{html}");
        assert!(html.contains("zedo.com"), "{html}");
        assert!(html.contains("Blocked"), "{html}");
        assert!(html.contains("42 active addresses"), "{html}");
        assert!(html.contains("dns.example.com"), "{html}");
    }

    /// An answer that resolved shows its records rather than a badge.
    #[test]
    fn resolved_answers_are_listed() {
        let mut q = page_data(vec![], 1).queries;
        q.push(QueryLog {
            ip: "203.0.113.7".to_string(),
            seq: 1,
            query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
            name: "example.com".to_string(),
            qtype: "A".to_string(),
            rcode: "NOERROR".to_string(),
            blocked: false,
            answers: vec![Answer {
                name: "example.com".to_string(),
                rtype: "A".to_string(),
                ttl: 60,
                data: "93.184.215.14".to_string(),
            }],
        });
        let html = REGISTRY
            .render(GET_LOGS_TEMPLATE_NAME, &page_data(q, 1))
            .unwrap();

        assert!(html.contains("A 93.184.215.14"), "{html}");
        assert!(!html.contains(">Blocked<"), "{html}");
    }

    #[test]
    fn a_truncated_page_says_how_many_it_shows() {
        let mut data = page_data(
            vec![QueryLog {
                ip: "203.0.113.7".to_string(),
                seq: 1,
                query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
                name: "example.com".to_string(),
                qtype: "A".to_string(),
                rcode: "NOERROR".to_string(),
                blocked: false,
                answers: vec![],
            }],
            1,
        );
        data.truncated = true;

        let html = REGISTRY.render(GET_LOGS_TEMPLATE_NAME, &data).unwrap();
        assert!(html.contains("Showing the newest 1 only."), "{html}");
    }

    #[test]
    fn an_empty_log_says_so() {
        let html = REGISTRY
            .render(GET_LOGS_TEMPLATE_NAME, &page_data(vec![], 1))
            .unwrap();
        assert!(html.contains("No lookups from 203.0.113.7"), "{html}");
    }

    /// Handlebars escapes `{{ }}` by default, and the page renders a question
    /// name that arrives from the network. Pinned because switching a field to
    /// `{{{ }}}` would silently make it injectable.
    #[test]
    fn query_names_are_html_escaped() {
        let data = page_data(
            vec![QueryLog {
                ip: "203.0.113.7".to_string(),
                seq: 1,
                query_time: DateTime::<Utc>::from_timestamp(1_788_000_000, 0).unwrap(),
                name: "<script>alert(1)</script>".to_string(),
                qtype: "A".to_string(),
                rcode: "NOERROR".to_string(),
                blocked: true,
                answers: vec![Answer {
                    name: "zedo.com".to_string(),
                    rtype: "A".to_string(),
                    ttl: 60,
                    data: "0.0.0.0".to_string(),
                }],
            }],
            1,
        );

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
    fn family_follows_the_canonical_address() {
        assert_eq!(family("[::ffff:203.0.113.7]:443".parse().unwrap()), "ipv4");
        assert_eq!(family("203.0.113.7:443".parse().unwrap()), "ipv4");
        assert_eq!(family("[2001:db8::1]:443".parse().unwrap()), "ipv6");
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
        assert!(
            got.contains(':'),
            "should still be an IPv6 address, got {got}"
        );
        assert_eq!(got, "1:2:3:4::ffff:5");
    }
}
