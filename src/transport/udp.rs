//! UDP transport for TURN (RFC 5766 default).

use networkframework::{Connection, ConnectionParameters, NetworkError};

use crate::error::{Error, Result};
use crate::transport::Transport;

/// Maximum UDP datagram size we are willing to receive.
const MAX_DATAGRAM: usize = 4096;

/// A connected-mode UDP transport to a TURN server.
#[derive(Debug)]
pub struct UdpTransport {
    socket: Connection,
}

impl UdpTransport {
    /// Open a connected UDP socket to `host:port`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the socket cannot be opened.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let parameters = ConnectionParameters::udp().map_err(|e| Error::Network(e.to_string()))?;
        let socket = Connection::connect_with_parameters(host, port, &parameters)
            .map_err(|e| Error::Network(e.to_string()))?;
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
        match self.socket.receive_message(MAX_DATAGRAM) {
            Ok(content) => Ok(content.data),
            Err(NetworkError::MessageTooLarge { .. }) => Ok(Vec::new()),
            Err(e) => Err(Error::Network(e.to_string())),
        }
    }

    fn close(&self) {
        self.socket.force_cancel();
    }

    fn is_stream(&self) -> bool {
        false
    }
}
