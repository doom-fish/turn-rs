//! Transport abstraction for TURN: UDP (default), TCP, and TLS (RFC 5766 §2.1).
//!
//! A TURN client multiplexes STUN-framed control messages and ChannelData
//! frames over a single connection to the server. This module defines the
//! [`Transport`] trait that abstracts that connection, plus three
//! implementations:
//!
//! * [`udp::UdpTransport`] — datagram transport; each datagram is exactly one
//!   TURN message. This is the default and the path used for live tests.
//! * [`tcp::TcpTransport`] — stream transport with length-prefixed framing and
//!   reassembly, so [`Transport::receive`] still yields one whole TURN message.
//! * [`tls::TlsTransport`] — the same stream framing over a TLS connection
//!   (`turns:`).
//!
//! Over a stream transport, STUN messages are implicitly padded to a 4-byte
//! boundary while ChannelData frames are **not** padded (RFC 5766 §11.5); the
//! reassembler accounts for both.

pub mod tcp;
pub mod tls;
pub mod udp;

use crate::error::Result;

/// A bidirectional TURN transport to a single server.
///
/// Implementations must deliver one complete TURN message (a STUN message or a
/// ChannelData frame) per [`Transport::receive`] call, regardless of how the
/// underlying medium fragments or coalesces bytes.
pub trait Transport: Send + Sync {
    /// Send one already-framed TURN message (STUN message or ChannelData frame).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Network`] if the send fails.
    fn send(&self, data: &[u8]) -> Result<()>;

    /// Receive the next complete TURN message.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Network`] on a transport failure.
    fn receive(&self) -> Result<Vec<u8>>;

    /// Whether this is a stream transport (TCP/TLS). Stream transports do not
    /// pad ChannelData frames (RFC 5766 §11.5).
    fn is_stream(&self) -> bool;
}
