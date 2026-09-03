//! Minimal Frame Streams reader, enough to receive dnstap from dnsdist.
//!
//! There is no crate for this. `framestream` 0.2.5 provides only an
//! `EncoderWriter` -- it writes the unidirectional flow and has no reader and no
//! control-frame handling at all. dnsdist connects to a unix socket and opens
//! with the *bidirectional* handshake, verified by probing a live dnsdist:
//!
//! ```text
//! 00000000                    escape (marks a control frame)
//! 00000022                    frame length = 34
//! 00000004                    control type = READY
//! 00000001                    field type = CONTENT_TYPE
//! 00000016                    field length = 22
//! "protobuf:dnstap.Dnstap"
//! ```
//!
//! So the exchange we must implement, as the receiving side, is:
//!
//! ```text
//! writer -> READY(content-type)
//! reader -> ACCEPT(content-type)      <- we must send this or nothing follows
//! writer -> START(content-type)
//! writer -> data frame ...            <- dnstap payloads
//! writer -> STOP
//! reader -> FINISH
//! ```
//!
//! Wire format: a 4-byte big-endian length prefixes each data frame. A length of
//! zero is an escape marking a control frame, whose own 4-byte length follows.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CONTROL_ACCEPT: u32 = 0x01;
const CONTROL_START: u32 = 0x02;
const CONTROL_STOP: u32 = 0x03;
const CONTROL_READY: u32 = 0x04;
const CONTROL_FINISH: u32 = 0x05;
const CONTROL_FIELD_CONTENT_TYPE: u32 = 0x01;

pub const DNSTAP_CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// Frames larger than this are refused rather than allocated. dnstap payloads
/// are a DNS message plus a little metadata, so anything approaching this is a
/// bug or a hostile peer rather than a real record.
const MAX_FRAME_LEN: u32 = 256 * 1024;

#[derive(Debug, PartialEq)]
pub enum Frame {
    Control { control_type: u32, content_type: Option<Vec<u8>> },
    Data(Vec<u8>),
}

/// Builds a control frame: escape, length, control type, and an optional
/// content-type field.
pub fn encode_control(control_type: u32, content_type: Option<&[u8]>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&control_type.to_be_bytes());
    if let Some(ct) = content_type {
        payload.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
        payload.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        payload.extend_from_slice(ct);
    }

    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&0u32.to_be_bytes()); // escape
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Parses a control frame payload: a control type, then optional
/// type/length/value fields. Only CONTENT_TYPE is interpreted; anything else is
/// skipped so an unfamiliar field cannot break the stream.
pub fn parse_control(payload: &[u8]) -> io::Result<Frame> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame shorter than its control type",
        ));
    }
    let control_type = u32::from_be_bytes(payload[0..4].try_into().unwrap());

    let mut content_type = None;
    let mut i = 4;
    while i + 8 <= payload.len() {
        let field_type = u32::from_be_bytes(payload[i..i + 4].try_into().unwrap());
        let field_len = u32::from_be_bytes(payload[i + 4..i + 8].try_into().unwrap()) as usize;
        i += 8;
        if i + field_len > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control field runs past the end of the frame",
            ));
        }
        if field_type == CONTROL_FIELD_CONTENT_TYPE {
            content_type = Some(payload[i..i + field_len].to_vec());
        }
        i += field_len;
    }

    Ok(Frame::Control { control_type, content_type })
}

/// Reads one frame. Returns None at a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        // Escape: a control frame, whose own length follows.
        r.read_exact(&mut len_buf).await?;
        let clen = u32::from_be_bytes(len_buf);
        if clen > MAX_FRAME_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "control frame too large"));
        }
        let mut payload = vec![0u8; clen as usize];
        r.read_exact(&mut payload).await?;
        return parse_control(&payload).map(Some);
    }

    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "data frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    Ok(Some(Frame::Data(payload)))
}

/// Completes the bidirectional handshake as the receiving side.
///
/// Returns once START has been seen and data frames may follow. dnsdist sends
/// nothing until it gets ACCEPT, so skipping this hangs rather than failing
/// loudly -- which is why it is a distinct, tested step.
pub async fn accept_handshake<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match read_frame(stream).await? {
            Some(Frame::Control { control_type, .. }) if control_type == CONTROL_READY => {
                stream
                    .write_all(&encode_control(CONTROL_ACCEPT, Some(DNSTAP_CONTENT_TYPE)))
                    .await?;
                stream.flush().await?;
            }
            Some(Frame::Control { control_type, .. }) if control_type == CONTROL_START => {
                return Ok(());
            }
            Some(Frame::Control { control_type, .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected control frame {control_type} during handshake"),
                ));
            }
            Some(Frame::Data(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data frame before START",
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ));
            }
        }
    }
}

/// Acknowledges STOP. Best effort: the peer is already going away.
pub async fn send_finish<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(&encode_control(CONTROL_FINISH, None)).await?;
    w.flush().await
}

pub fn is_stop(frame: &Frame) -> bool {
    matches!(frame, Frame::Control { control_type, .. } if *control_type == CONTROL_STOP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The exact bytes a live dnsdist sends on connecting, captured by probing
    /// the socket. If the handshake ever regresses, this is what catches it.
    const REAL_READY: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, // escape
        0x00, 0x00, 0x00, 0x22, // frame length 34
        0x00, 0x00, 0x00, 0x04, // READY
        0x00, 0x00, 0x00, 0x01, // CONTENT_TYPE
        0x00, 0x00, 0x00, 0x16, // length 22
        b'p', b'r', b'o', b't', b'o', b'b', b'u', b'f', b':', b'd', b'n', b's', b't', b'a', b'p',
        b'.', b'D', b'n', b's', b't', b'a', b'p',
    ];

    #[tokio::test]
    async fn parses_the_ready_frame_dnsdist_actually_sends() {
        let mut c = Cursor::new(REAL_READY.to_vec());
        let frame = read_frame(&mut c).await.unwrap().unwrap();
        assert_eq!(
            frame,
            Frame::Control {
                control_type: CONTROL_READY,
                content_type: Some(DNSTAP_CONTENT_TYPE.to_vec()),
            }
        );
    }

    #[tokio::test]
    async fn reads_a_data_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let mut c = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut c).await.unwrap().unwrap(),
            Frame::Data(b"abc".to_vec())
        );
    }

    #[tokio::test]
    async fn clean_eof_is_not_an_error() {
        let mut c = Cursor::new(Vec::new());
        assert!(read_frame(&mut c).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_an_absurd_frame_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut c = Cursor::new(buf);
        assert!(read_frame(&mut c).await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_control_field_running_past_the_frame() {
        // field claims 999 bytes but the frame ends
        let mut payload = Vec::new();
        payload.extend_from_slice(&CONTROL_READY.to_be_bytes());
        payload.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
        payload.extend_from_slice(&999u32.to_be_bytes());
        assert!(parse_control(&payload).is_err());
    }

    #[tokio::test]
    async fn handshake_answers_ready_with_accept_then_returns_on_start() {
        let mut input = REAL_READY.to_vec();
        input.extend_from_slice(&encode_control(CONTROL_START, Some(DNSTAP_CONTENT_TYPE)));

        // duplex: reads come from `input`, writes are captured
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            client.write_all(&input).await.unwrap();
            let mut got = Vec::new();
            let _ = client.read_buf(&mut got).await;
            // the reply must be an ACCEPT carrying the content type
            assert_eq!(
                parse_control(&got[8..]).unwrap(),
                Frame::Control {
                    control_type: CONTROL_ACCEPT,
                    content_type: Some(DNSTAP_CONTENT_TYPE.to_vec()),
                }
            );
        });

        accept_handshake(&mut server).await.unwrap();
    }
}
