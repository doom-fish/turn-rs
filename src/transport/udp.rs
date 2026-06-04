//! UDP transport for TURN (RFC 5766 default).

use networkframework::udp::UdpClient;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// Maximum UDP datagram size we are willing to receive.
const MAX_DATAGRAM: usize = 1500;

/// A connected-mode UDP transport to a TURN server.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpClient,
}

impl UdpTransport {
    /// Open a connected UDP socket to `host:port`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the socket cannot be opened.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let socket = UdpClient::connect(host, port).map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self { socket })
    }
}

impl Transport for UdpTransport {
    fn send(&self, data: &[u8]) -> Result<()> {
        self.socket
            .send(data)
            .map_err(|e| Error::Network(e.to_string()))
    }

    fn receive(&self) -> Result<Vec<u8>> {
        self.socket
            .receive(MAX_DATAGRAM)
            .map_err(|e| Error::Network(e.to_string()))
    }

    fn is_stream(&self) -> bool {
        false
    }
}
