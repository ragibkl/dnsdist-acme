use chrono::{DateTime, TimeZone, Utc};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;

use super::dnstap_proto::{TYPE_CLIENT_RESPONSE, parse_dnstap};

/// One client lookup, as `/api/logs` returns it.
///
/// Every field is final once the entry is stored: nothing about a lookup changes
/// after the fact, which is what lets a client poll with `since` and simply
/// append. Expiry is the client's job, from `time`.
#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct QueryLog {
    /// The client address. It is the key the store files entries under and the
    /// caller already knows it, so it is not repeated in every entry.
    #[serde(skip)]
    pub ip: String,
    /// Assigned by `QueryLogs::push`, increasing in arrival order. `since` is
    /// compared against this rather than `time`, which has one-second
    /// resolution and can tie.
    pub seq: u64,
    #[serde(rename = "time")]
    pub query_time: DateTime<Utc>,
    /// The name looked up, without the trailing dot.
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: String,
    pub rcode: String,
    pub blocked: bool,
    pub answers: Vec<Answer>,
}

#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct Answer {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: u32,
    pub data: String,
}

/// The mnemonic as dig prints it. hickory's `Display` gives prose such as
/// "Non-Existent Domain", which is not what anyone searches for.
fn rcode_name(code: ResponseCode) -> String {
    match u16::from(code) {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        n => format!("RCODE{n}"),
    }
}

fn trim_root(name: &str) -> String {
    name.strip_suffix('.').filter(|n| !n.is_empty()).unwrap_or(name).to_string()
}

/// Whether bancuh-dns blocked the lookup. It answers a blocked name with
/// 0.0.0.0 or ::, so the lookup is blocked when it has address answers and
/// every one of them is unspecified. A CNAME on the way, as a rewrite gives,
/// does not change that.
fn is_blocked(answers: &[Record]) -> bool {
    let mut any_address = false;
    for record in answers {
        match &record.data {
            RData::A(a) => {
                any_address = true;
                if !a.0.is_unspecified() {
                    return false;
                }
            }
            RData::AAAA(aaaa) => {
                any_address = true;
                if !aaaa.0.is_unspecified() {
                    return false;
                }
            }
            _ => {}
        }
    }
    any_address
}

/// Builds a `QueryLog` from one dnstap frame.
///
/// Returns None when the frame is not something we log: a message type other
/// than CLIENT_RESPONSE, a missing client address, or a DNS payload that will
/// not parse. None is not an error here -- dnsdist emits other message types
/// and we simply ignore them.
///
/// The DNS payload arrives as raw wire format. The previous implementation read
/// dnstap's *text* rendering and recovered fields by slicing on
/// `";; ANSWER SECTION:"`, which meant a partially written record silently
/// produced a malformed entry. Parsing the wire format either succeeds or
/// fails; there is no half-parsed state.
pub fn query_log_from_frame(payload: &[u8]) -> Option<QueryLog> {
    let frame = parse_dnstap(payload)?;
    if frame.message_type != TYPE_CLIENT_RESPONSE {
        return None;
    }

    let ip = frame.query_address?;
    let dns = Message::from_bytes(&frame.response_message).ok()?;

    let (name, qtype) = dns
        .queries
        .first()
        .map(|q| (trim_root(&q.name().to_string()), q.query_type().to_string()))
        .unwrap_or_default();

    let blocked = is_blocked(&dns.answers);
    let answers = dns
        .answers
        .iter()
        .map(|r| Answer {
            name: trim_root(&r.name.to_string()),
            rtype: r.record_type().to_string(),
            ttl: r.ttl,
            data: r.data.to_string(),
        })
        .collect();

    // dnstap reports whole seconds separately from nanoseconds; second
    // resolution is all the ten-minute log window needs.
    let query_time = Utc
        .timestamp_opt(frame.query_time_sec as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);

    Some(QueryLog {
        ip: ip.to_string(),
        seq: 0,
        query_time,
        name,
        qtype,
        rcode: rcode_name(dns.metadata.response_code),
        blocked,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }

    fn key(field: u64, wire: u64) -> Vec<u8> {
        varint((field << 3) | wire)
    }

    fn len_delim(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = key(field, 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    /// A real DNS response, encoded to wire format the same way dnsdist would.
    fn dns_response() -> Vec<u8> {
        let name = Name::from_str("zedo.com.").unwrap();
        let mut msg = Message::response(0, OpCode::Query);
        msg.queries.push(Query::query(name.clone(), RecordType::A));
        msg.answers
            .push(Record::from_rdata(name, 5, RData::A(A::new(0, 0, 0, 0))));
        msg.to_bytes().unwrap()
    }

    fn frame(msg_type: u64, addr: &[u8], secs: u64, dns: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(key(1, 0));
        m.extend(varint(msg_type));
        m.extend(len_delim(4, addr));
        m.extend(key(8, 0));
        m.extend(varint(secs));
        m.extend(len_delim(14, dns));
        len_delim(14, &m)
    }

    #[test]
    fn builds_a_log_entry_from_a_client_response() {
        let f = frame(TYPE_CLIENT_RESPONSE, &[10, 0, 0, 7], 1_788_000_000, &dns_response());
        let log = query_log_from_frame(&f).unwrap();

        assert_eq!(log.ip, "10.0.0.7");
        assert_eq!(log.query_time.timestamp(), 1_788_000_000);
        assert_eq!(log.name, "zedo.com");
        assert_eq!(log.qtype, "A");
        assert_eq!(log.rcode, "NOERROR");
        assert!(log.blocked);
        assert_eq!(
            log.answers,
            vec![Answer {
                name: "zedo.com".to_string(),
                rtype: "A".to_string(),
                ttl: 5,
                data: "0.0.0.0".to_string(),
            }]
        );
    }

    fn response_with(name: &str, answers: Vec<RData>, rcode: ResponseCode) -> Vec<u8> {
        let name = Name::from_str(name).unwrap();
        let mut msg = Message::response(0, OpCode::Query);
        msg.metadata.response_code = rcode;
        msg.queries.push(Query::query(name.clone(), RecordType::A));
        for data in answers {
            msg.answers.push(Record::from_rdata(name.clone(), 60, data));
        }
        msg.to_bytes().unwrap()
    }

    fn log_of(dns: Vec<u8>) -> QueryLog {
        query_log_from_frame(&frame(TYPE_CLIENT_RESPONSE, &[10, 0, 0, 7], 1, &dns)).unwrap()
    }

    #[test]
    fn a_real_address_is_not_blocked() {
        let log = log_of(response_with(
            "example.com.",
            vec![RData::A(A::new(93, 184, 215, 14))],
            ResponseCode::NoError,
        ));
        assert!(!log.blocked);
        assert_eq!(log.answers[0].data, "93.184.215.14");
    }

    #[test]
    fn an_unspecified_ipv6_answer_is_blocked() {
        let log = log_of(response_with(
            "zedo.com.",
            vec![RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 0))],
            ResponseCode::NoError,
        ));
        assert!(log.blocked);
    }

    /// One real address among the answers means the name resolved.
    #[test]
    fn a_mix_of_unspecified_and_real_addresses_is_not_blocked() {
        let log = log_of(response_with(
            "example.com.",
            vec![RData::A(A::new(0, 0, 0, 0)), RData::A(A::new(93, 184, 215, 14))],
            ResponseCode::NoError,
        ));
        assert!(!log.blocked);
    }

    #[test]
    fn rcodes_use_the_dig_mnemonics() {
        let log = log_of(response_with("nope.example.", vec![], ResponseCode::NXDomain));
        assert_eq!(log.rcode, "NXDOMAIN");
        assert!(!log.blocked);
    }

    /// The internal key and the store's sequence number are not the parser's
    /// business, and the address must not be serialized into every entry.
    #[test]
    fn the_client_address_is_not_serialized() {
        let json = serde_json::to_string(&log_of(dns_response())).unwrap();
        assert!(!json.contains("10.0.0.7"), "{json}");
        assert!(json.contains("\"time\""), "{json}");
        assert!(json.contains("\"type\":\"A\""), "{json}");
    }

    #[test]
    fn ignores_message_types_other_than_client_response() {
        // 5 = CLIENT_QUERY, which dnsdist also emits
        let f = frame(5, &[10, 0, 0, 7], 1_788_000_000, &dns_response());
        assert!(query_log_from_frame(&f).is_none());
    }

    #[test]
    fn a_response_with_no_answers_still_logs_the_question() {
        let name = Name::from_str("blocked.example.").unwrap();
        let mut msg = Message::response(0, OpCode::Query);
        msg.queries.push(Query::query(name, RecordType::A));
        let f = frame(TYPE_CLIENT_RESPONSE, &[10, 0, 0, 7], 1, &msg.to_bytes().unwrap());

        let log = query_log_from_frame(&f).unwrap();
        assert_eq!(log.name, "blocked.example");
        assert!(log.answers.is_empty());
        assert!(!log.blocked, "no answer is not the same as blocked");
    }

    #[test]
    fn rejects_a_frame_whose_dns_payload_is_garbage() {
        let f = frame(TYPE_CLIENT_RESPONSE, &[10, 0, 0, 7], 1, b"not a dns message");
        assert!(query_log_from_frame(&f).is_none());
    }

    #[test]
    fn truncated_frames_never_panic() {
        let f = frame(TYPE_CLIENT_RESPONSE, &[10, 0, 0, 7], 1, &dns_response());
        for cut in 1..f.len() {
            let _ = query_log_from_frame(&f[..cut]);
        }
    }
}
