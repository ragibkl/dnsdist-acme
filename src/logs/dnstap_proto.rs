//! Just enough protobuf to read the five dnstap fields we care about.
//!
//! Deliberately not `prost`: that would mean vendoring dnstap.proto, a build.rs,
//! and `protoc` in the builder image, to decode five fields out of a schema with
//! dozens. Protobuf is designed so unknown fields can be skipped, so a reader
//! this narrow stays correct as the schema grows.
//!
//! Field numbers are from the official dnstap.proto
//! (github.com/dnstap/dnstap.pb):
//!
//! ```text
//! Dnstap.message        = 14  (embedded Message)
//! Message.type          =  1  (enum; CLIENT_RESPONSE = 6)
//! Message.query_address =  4  (bytes; 4 = IPv4, 16 = IPv6)
//! Message.query_time_sec=  8  (uint64)
//! Message.response_message = 14 (bytes; raw DNS wire format)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DNSTAP_FIELD_MESSAGE: u64 = 14;
const MSG_FIELD_TYPE: u64 = 1;
const MSG_FIELD_QUERY_ADDRESS: u64 = 4;
const MSG_FIELD_QUERY_TIME_SEC: u64 = 8;
const MSG_FIELD_RESPONSE_MESSAGE: u64 = 14;

pub const TYPE_CLIENT_RESPONSE: u64 = 6;

#[derive(Debug, Default, PartialEq)]
pub struct DnstapMessage {
    pub message_type: u64,
    pub query_address: Option<IpAddr>,
    pub query_time_sec: u64,
    /// Raw DNS wire format, not the text presentation form the YAML pipeline
    /// used to provide.
    pub response_message: Vec<u8>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.buf.get(self.pos)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.varint()? as usize;
        let end = self.pos.checked_add(len)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Steps over a field we do not care about. Without this, one unfamiliar
    /// field would desynchronise the whole parse.
    fn skip(&mut self, wire_type: u64) -> Option<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => self.pos = self.pos.checked_add(8)?,
            2 => {
                self.bytes()?;
            }
            5 => self.pos = self.pos.checked_add(4)?,
            _ => return None,
        }
        if self.pos > self.buf.len() {
            return None;
        }
        Some(())
    }
}

/// Pulls the embedded Message out of a Dnstap frame, then the fields we use.
/// Returns None on anything malformed rather than panicking -- this parses
/// bytes that arrive over a socket.
pub fn parse_dnstap(payload: &[u8]) -> Option<DnstapMessage> {
    let mut r = Reader::new(payload);
    let mut embedded = None;

    while !r.done() {
        let key = r.varint()?;
        let (field, wire_type) = (key >> 3, key & 0x7);
        if field == DNSTAP_FIELD_MESSAGE && wire_type == 2 {
            embedded = Some(r.bytes()?);
        } else {
            r.skip(wire_type)?;
        }
    }

    parse_message(embedded?)
}

fn parse_message(payload: &[u8]) -> Option<DnstapMessage> {
    let mut r = Reader::new(payload);
    let mut out = DnstapMessage::default();

    while !r.done() {
        let key = r.varint()?;
        let (field, wire_type) = (key >> 3, key & 0x7);
        match (field, wire_type) {
            (MSG_FIELD_TYPE, 0) => out.message_type = r.varint()?,
            (MSG_FIELD_QUERY_TIME_SEC, 0) => out.query_time_sec = r.varint()?,
            (MSG_FIELD_QUERY_ADDRESS, 2) => {
                let raw = r.bytes()?;
                out.query_address = match raw.len() {
                    4 => Some(IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(raw).ok()?,
                    ))),
                    16 => Some(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(raw).ok()?,
                    ))),
                    // Any other length is not an address; drop it rather than
                    // guessing.
                    _ => None,
                };
            }
            (MSG_FIELD_RESPONSE_MESSAGE, 2) => out.response_message = r.bytes()?.to_vec(),
            _ => r.skip(wire_type)?,
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(field: u64, wire: u64) -> Vec<u8> {
        varint((field << 3) | wire)
    }

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

    fn len_delim(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = key(field, 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn sample_message() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(key(MSG_FIELD_TYPE, 0));
        m.extend(varint(TYPE_CLIENT_RESPONSE));
        m.extend(len_delim(MSG_FIELD_QUERY_ADDRESS, &[192, 168, 1, 5]));
        m.extend(key(MSG_FIELD_QUERY_TIME_SEC, 0));
        m.extend(varint(1_788_000_000));
        m.extend(len_delim(MSG_FIELD_RESPONSE_MESSAGE, b"\xab\xcd wire"));
        m
    }

    #[test]
    fn extracts_the_fields_we_use() {
        let frame = len_delim(DNSTAP_FIELD_MESSAGE, &sample_message());
        let got = parse_dnstap(&frame).unwrap();
        assert_eq!(got.message_type, TYPE_CLIENT_RESPONSE);
        assert_eq!(got.query_address, Some("192.168.1.5".parse().unwrap()));
        assert_eq!(got.query_time_sec, 1_788_000_000);
        assert_eq!(got.response_message, b"\xab\xcd wire");
    }

    #[test]
    fn skips_unknown_fields_of_every_wire_type() {
        let mut m = sample_message();
        m.extend(key(99, 0));
        m.extend(varint(7)); // unknown varint
        m.extend(key(98, 1));
        m.extend_from_slice(&[0; 8]); // unknown 64-bit
        m.extend(len_delim(97, b"whatever")); // unknown bytes
        m.extend(key(96, 5));
        m.extend_from_slice(&[0; 4]); // unknown 32-bit

        let frame = len_delim(DNSTAP_FIELD_MESSAGE, &m);
        let got = parse_dnstap(&frame).unwrap();
        assert_eq!(got.query_time_sec, 1_788_000_000);
        assert_eq!(got.response_message, b"\xab\xcd wire");
    }

    #[test]
    fn handles_ipv6_query_addresses() {
        let mut m = Vec::new();
        m.extend(len_delim(MSG_FIELD_QUERY_ADDRESS, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        let got = parse_dnstap(&len_delim(DNSTAP_FIELD_MESSAGE, &m)).unwrap();
        assert_eq!(got.query_address, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn truncated_input_returns_none_rather_than_panicking() {
        let frame = len_delim(DNSTAP_FIELD_MESSAGE, &sample_message());
        for cut in 1..frame.len() {
            let _ = parse_dnstap(&frame[..cut]); // must not panic
        }
    }

    #[test]
    fn a_frame_without_an_embedded_message_is_rejected() {
        let mut f = Vec::new();
        f.extend(len_delim(1, b"identity"));
        assert!(parse_dnstap(&f).is_none());
    }
}
