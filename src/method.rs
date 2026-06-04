//! TURN method codes (RFC 5766 §13, RFC 8656 §17).
//!
//! TURN methods are ordinary 12-bit STUN methods carried in the STUN message
//! type. This module gives them names and a thin bridge to
//! [`stun::Method`], which models any non-`Binding` method as
//! [`stun::Method::Other`].

use stun::Method as StunMethod;

/// `Allocate` — request a relayed transport address (RFC 5766 §6).
pub const ALLOCATE: u16 = 0x0003;
/// `Refresh` — extend or terminate an allocation (RFC 5766 §7).
pub const REFRESH: u16 = 0x0004;
/// `Send` indication — relay outbound data to a peer (RFC 5766 §10).
pub const SEND: u16 = 0x0006;
/// `Data` indication — receive inbound relayed data (RFC 5766 §10).
pub const DATA: u16 = 0x0007;
/// `CreatePermission` — install a permission for a peer IP (RFC 5766 §9).
pub const CREATE_PERMISSION: u16 = 0x0008;
/// `ChannelBind` — bind a channel number to a peer (RFC 5766 §11).
pub const CHANNEL_BIND: u16 = 0x0009;

/// A TURN method, identified by its 12-bit method code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `Allocate` (`0x003`).
    Allocate,
    /// `Refresh` (`0x004`).
    Refresh,
    /// `Send` (`0x006`).
    Send,
    /// `Data` (`0x007`).
    Data,
    /// `CreatePermission` (`0x008`).
    CreatePermission,
    /// `ChannelBind` (`0x009`).
    ChannelBind,
}

impl Method {
    /// The raw 12-bit method code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Allocate => ALLOCATE,
            Self::Refresh => REFRESH,
            Self::Send => SEND,
            Self::Data => DATA,
            Self::CreatePermission => CREATE_PERMISSION,
            Self::ChannelBind => CHANNEL_BIND,
        }
    }

    /// Resolve a raw 12-bit method code into a known TURN [`Method`].
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            ALLOCATE => Some(Self::Allocate),
            REFRESH => Some(Self::Refresh),
            SEND => Some(Self::Send),
            DATA => Some(Self::Data),
            CREATE_PERMISSION => Some(Self::CreatePermission),
            CHANNEL_BIND => Some(Self::ChannelBind),
            _ => None,
        }
    }

    /// Convert to the underlying [`stun::Method`] used by the message codec.
    #[must_use]
    pub const fn to_stun(self) -> StunMethod {
        StunMethod::Other(self.as_u16())
    }
}

impl From<Method> for StunMethod {
    fn from(method: Method) -> Self {
        method.to_stun()
    }
}
