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
//! boundary by the protocol; ChannelData frames are padded by this crate per
//! RFC 5766 §11.5 and RFC 8656 §12.4 (padding REQUIRED on TCP/TLS, permitted
//! on UDP). The reassembler rounds the declared ChannelData `Length` up to a
//! 4-byte boundary to consume the padding.

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

    /// Whether this is a stream transport (TCP/TLS). Reserved for future use
    /// (RFC 6062 `Connect`/`ConnectionBind` flows); ChannelData padding is
    /// now uniform across all transports per RFC 5766 §11.5 / RFC 8656 §12.4.
    fn is_stream(&self) -> bool;
}
