use chrono::{DateTime, TimeZone, Utc};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use super::dnstap_proto::{TYPE_CLIENT_RESPONSE, parse_dnstap};

#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub struct QueryLog {
    pub ip: String,
    pub query_time: DateTime<Utc>,
    pub question: String,
    pub answers: Vec<String>,
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

    let question = dns
        .queries
        .first()
        .map(|q| format!("{} {} {}", q.name(), q.query_class(), q.query_type()))
        .unwrap_or_default();

    let answers = dns.answers.iter().map(|r| r.to_string()).collect();

    // dnstap reports whole seconds separately from nanoseconds; second
    // resolution is all the ten-minute log window needs.
    let query_time = Utc
        .timestamp_opt(frame.query_time_sec as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);

    Some(QueryLog {
        ip: ip.to_string(),
        query_time,
        question,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::A;
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
        assert!(log.question.contains("zedo.com."), "got {}", log.question);
        assert!(log.question.contains('A'), "got {}", log.question);
        assert_eq!(log.answers.len(), 1);
        assert!(log.answers[0].contains("0.0.0.0"), "got {}", log.answers[0]);
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
        assert!(log.question.contains("blocked.example."));
        assert!(log.answers.is_empty());
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
