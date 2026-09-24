//! TLS transport for TURN (`turns:`, RFC 5766 §2.1).
//!
//! TLS-over-TCP reuses the exact stream framing and reassembly of
//! [`crate::transport::tcp`]; only the connection setup differs. The underlying
//! `networkframework` TCP client performs the TLS handshake (with SNI from the
//! host) before returning, so once connected the two paths are identical.

use networkframework::client::TcpClient;

use crate::error::{Error, Result};
use crate::transport::tcp::TcpTransport;
use crate::transport::Transport;

/// A TLS-over-TCP stream transport to a TURN server.
#[derive(Debug)]
pub struct TlsTransport {
    inner: TcpTransport,
}

impl TlsTransport {
    /// Open a TLS-wrapped TCP connection to `host:port`, performing the TLS
    /// handshake (server-name indication taken from `host`) before returning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the connection or handshake fails.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let socket =
            TcpClient::connect_tls(host, port).map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self {
            inner: TcpTransport::from_socket(socket),
        })
    }
}

impl Transport for TlsTransport {
    fn send(&self, data: &[u8]) -> Result<()> {
        self.inner.send(data)
    }

    fn receive(&self) -> Result<Vec<u8>> {
        self.inner.receive()
    }

    fn close(&self) {
        self.inner.close();
    }

    fn is_stream(&self) -> bool {
        true
    }
}
