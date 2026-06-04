//! Allocation state and lifetime/refresh accounting (RFC 5766 §6, §7).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The default allocation lifetime requested and assumed when a server does not
/// specify one (RFC 5766 §6.2 recommends 600 s / 10 minutes).
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// A relayed transport allocation obtained from a TURN server.
///
/// Holds the relayed address(es) the server assigned, the optionally-learned
/// server-reflexive address, and the lifetime accounting used to decide when an
/// auto-refresh is due (half-way through the lifetime, RFC 5766 §6.2 / §7).
#[derive(Debug, Clone)]
pub struct Allocation {
    relayed: SocketAddr,
    relayed_secondary: Option<SocketAddr>,
    mapped: Option<SocketAddr>,
    lifetime: Duration,
    obtained_at: Instant,
}

impl Allocation {
    /// Construct an allocation record from a successful `Allocate` response.
    #[must_use]
    pub fn new(relayed: SocketAddr, mapped: Option<SocketAddr>, lifetime: Duration) -> Self {
        Self {
            relayed,
            relayed_secondary: None,
            mapped,
            lifetime,
            obtained_at: Instant::now(),
        }
    }

    /// Record a second relayed address from a dual-stack allocation (RFC 8656
    /// `ADDITIONAL-ADDRESS-FAMILY`).
    pub fn set_secondary_relayed(&mut self, addr: SocketAddr) {
        self.relayed_secondary = Some(addr);
    }

    /// The primary relayed transport address peers send to.
    #[must_use]
    pub const fn relayed_address(&self) -> SocketAddr {
        self.relayed
    }

    /// The secondary relayed address of a dual-stack allocation, if any.
    #[must_use]
    pub const fn secondary_relayed_address(&self) -> Option<SocketAddr> {
        self.relayed_secondary
    }

    /// The server-reflexive (`XOR-MAPPED-ADDRESS`) address, if the server
    /// reported one.
    #[must_use]
    pub const fn mapped_address(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// The current granted lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// Update the lifetime accounting after a successful `Refresh` (resets the
    /// clock).
    pub fn renew(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
        self.obtained_at = Instant::now();
    }

    /// Time elapsed since the allocation was obtained or last refreshed.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.obtained_at.elapsed()
    }

    /// Whether the allocation has passed its half-life and a refresh is due
    /// (RFC 5766 §6.2 recommends refreshing well before expiry).
    #[must_use]
    pub fn refresh_due(&self) -> bool {
        self.age() >= self.lifetime / 2
    }

    /// Time remaining until the next refresh is due (zero if already due).
    #[must_use]
    pub fn until_refresh(&self) -> Duration {
        (self.lifetime / 2).saturating_sub(self.age())
    }

    /// Whether the allocation has fully expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.age() >= self.lifetime
    }
}
