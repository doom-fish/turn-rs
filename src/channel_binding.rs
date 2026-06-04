//! Channel-binding tracking with auto-refresh accounting (RFC 5766 §11).
//!
//! A channel binding ties a 16-bit channel number to a specific peer transport
//! address so that data can be exchanged with the compact 4-byte ChannelData
//! header (see [`crate::channel`]). Bindings last 10 minutes from creation or
//! last refresh (RFC 5766 §11.2); the client re-sends `ChannelBind` before then
//! to keep them alive. A binding also implicitly refreshes the corresponding
//! permission.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The fixed channel-binding lifetime (RFC 5766 §11.2): 10 minutes.
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);

/// A single channel binding: a channel number bound to a peer address.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    channel: u16,
    peer: SocketAddr,
    bound_at: Instant,
}

impl ChannelBinding {
    /// Record a freshly created binding of `channel` to `peer`.
    #[must_use]
    pub fn new(channel: u16, peer: SocketAddr) -> Self {
        Self {
            channel,
            peer,
            bound_at: Instant::now(),
        }
    }

    /// The bound channel number (in the `0x4000..=0x7FFF` range).
    #[must_use]
    pub const fn channel(&self) -> u16 {
        self.channel
    }

    /// The peer transport address this channel is bound to.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Reset the lifetime clock after a successful refresh.
    pub fn renew(&mut self) {
        self.bound_at = Instant::now();
    }

    /// Time elapsed since the binding was created or last refreshed.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.bound_at.elapsed()
    }

    /// Whether the binding is at or past its half-life and should be refreshed.
    #[must_use]
    pub fn refresh_due(&self) -> bool {
        self.age() >= CHANNEL_LIFETIME / 2
    }

    /// Whether the binding has fully expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.age() >= CHANNEL_LIFETIME
    }
}
