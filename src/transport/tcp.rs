//! TCP transport for TURN (RFC 5766 §2.1) with length-prefixed reassembly.
//!
//! A stream transport coalesces and fragments bytes arbitrarily, so this
//! implementation maintains an internal buffer and reassembles one complete
//! TURN message per [`Transport::receive`] call. The message boundary is
//! recovered from the leading two bytes:
//!
//! * STUN messages (`0x0000..=0x3FFF`): total length is `20 + message_length`,
//!   where `message_length` (the body) is already a multiple of four.
//! * ChannelData frames (`0x4000..=0x7FFF`): wire length is `4 + Length`
//!   rounded up to a 4-byte boundary; padding is REQUIRED over stream
//!   transports per RFC 5766 §11.5 and RFC 8656 §12.4.

use std::sync::Mutex;

use networkframework::client::TcpClient;

use crate::channel::{self, PacketKind};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Read granularity for pulling bytes off the stream.
const READ_CHUNK: usize = 4096;

/// A TCP stream transport to a TURN server with TURN message reassembly.
pub struct TcpTransport {
    socket: TcpClient,
    buffer: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport").finish_non_exhaustive()
    }
}

impl TcpTransport {
    /// Open a plain TCP connection to `host:port`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the connection cannot be established.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let socket = TcpClient::connect(host, port).map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self::from_socket(socket))
    }

    /// Wrap an already-connected [`TcpClient`] (used by the TLS transport).
    #[must_use]
    pub(crate) fn from_socket(socket: TcpClient) -> Self {
        Self {
            socket,
            buffer: Mutex::new(Vec::new()),
        }
    }
}

/// Determine the total on-the-wire length of the first message in `buf`, if a
/// complete message is present.
fn framed_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    let total = match channel::classify(buf) {
        PacketKind::Stun => 20 + declared,
        PacketKind::ChannelData => {
            // ChannelData over a stream transport MUST be padded to a 4-byte
            // boundary (RFC 5766 §11.5, RFC 8656 §12.4). The Length field
            // excludes the padding, so round up to consume it.
            let unpadded = 4 + declared;
            (unpadded + 3) & !3
        }
        PacketKind::Unknown => return Some(0), // signal framing error
    };
    (buf.len() >= total).then_some(total)
}

impl Transport for TcpTransport {
    fn send(&self, data: &[u8]) -> Result<()> {
        self.socket
            .send(data)
            .map_err(|e| Error::Network(e.to_string()))
    }

    fn receive(&self) -> Result<Vec<u8>> {
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| Error::Network("transport buffer poisoned".into()))?;
        loop {
            match framed_len(&buffer) {
                Some(0) => {
                    return Err(Error::Network(
                        "stream framing desynchronized (non-TURN leading bytes)".into(),
                    ))
                }
                Some(total) => {
                    let message = buffer[..total].to_vec();
                    buffer.drain(..total);
                    return Ok(message);
                }
                None => {
                    let chunk = self
                        .socket
                        .receive(READ_CHUNK)
                        .map_err(|e| Error::Network(e.to_string()))?;
                    if chunk.is_empty() {
                        return Err(Error::Network("TCP connection closed by peer".into()));
                    }
                    buffer.extend_from_slice(&chunk);
                }
            }
        }
    }

    fn is_stream(&self) -> bool {
        true
    }
}
