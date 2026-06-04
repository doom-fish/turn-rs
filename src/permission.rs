//! Permission tracking with auto-refresh accounting (RFC 5766 §8).
//!
//! A permission authorizes a single peer IP address to send relayed data
//! through an allocation. Permissions expire 5 minutes after they are installed
//! or last refreshed (RFC 5766 §8); the client refreshes them before then by
//! re-sending `CreatePermission`. Note that permissions are keyed by IP address
//! only — the port is ignored (RFC 5766 §9).

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// The fixed permission lifetime (RFC 5766 §8): 5 minutes.
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);

/// A single installed permission for a peer IP address.
#[derive(Debug, Clone)]
pub struct Permission {
    ip: IpAddr,
    installed_at: Instant,
}

impl Permission {
    /// Record a freshly installed permission for `ip`.
    #[must_use]
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            installed_at: Instant::now(),
        }
    }

    /// The peer IP this permission authorizes.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Reset the lifetime clock after a successful refresh.
    pub fn renew(&mut self) {
        self.installed_at = Instant::now();
    }

    /// Time elapsed since install or last refresh.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.installed_at.elapsed()
    }

    /// Whether the permission is at or past its half-life and should be
    /// refreshed proactively.
    #[must_use]
    pub fn refresh_due(&self) -> bool {
        self.age() >= PERMISSION_LIFETIME / 2
    }

    /// Whether the permission has fully expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.age() >= PERMISSION_LIFETIME
    }
}
