//! Error type for TURN encoding, decoding, auth, and transport.

use std::fmt;

/// Errors produced while building, parsing, or exchanging TURN messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error bubbled up from the underlying STUN codec.
    Stun(stun::Error),
    /// An underlying network operation failed.
    Network(String),
    /// The transaction timed out without a matching response.
    Timeout,
    /// A TURN URI could not be parsed.
    InvalidUri(String),
    /// The server returned an `ERROR-CODE` response.
    Server {
        /// The combined error code (e.g. `401`, `438`, `486`).
        code: u16,
        /// The human-readable reason phrase.
        reason: String,
    },
    /// The server demanded long-term authentication but no credential was set.
    AuthRequired,
    /// A `401` / `438` challenge was missing its `REALM` or `NONCE`.
    MissingChallenge,
    /// The server kept rejecting an authenticated request (nonce loop).
    AuthFailed,
    /// A required attribute was absent from a success response.
    MissingAttribute(&'static str),
    /// A ChannelData frame was malformed (bad length or channel number).
    BadChannelData(&'static str),
    /// A channel number was outside the valid `0x4000..=0x7FFF` range.
    InvalidChannelNumber(u16),
    /// The requested operation is not valid in the client's current state.
    InvalidState(&'static str),
    /// The requested address family is not supported.
    UnsupportedAddressFamily(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stun(e) => write!(f, "STUN error: {e}"),
            Self::Network(msg) => write!(f, "network error: {msg}"),
            Self::Timeout => f.write_str("TURN transaction timed out"),
            Self::InvalidUri(uri) => write!(f, "invalid TURN URI: {uri}"),
            Self::Server { code, reason } => {
                write!(f, "TURN server error {code}: {reason}")
            }
            Self::AuthRequired => f.write_str("server requires long-term credentials"),
            Self::MissingChallenge => {
                f.write_str("authentication challenge missing REALM or NONCE")
            }
            Self::AuthFailed => f.write_str("authentication failed after nonce refresh"),
            Self::MissingAttribute(what) => write!(f, "response missing attribute: {what}"),
            Self::BadChannelData(what) => write!(f, "malformed ChannelData frame: {what}"),
            Self::InvalidChannelNumber(n) => {
                write!(f, "channel number {n:#06x} out of range 0x4000..=0x7FFF")
            }
            Self::InvalidState(what) => write!(f, "invalid client state: {what}"),
            Self::UnsupportedAddressFamily(family) => {
                write!(f, "unsupported address family: {family:#04x}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stun(e) => Some(e),
            _ => None,
        }
    }
}

impl From<stun::Error> for Error {
    fn from(e: stun::Error) -> Self {
        Self::Stun(e)
    }
}

/// Convenient result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
