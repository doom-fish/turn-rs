//! TURN-specific attributes and their value codecs (RFC 5766 §14, RFC 8656).
//!
//! # Layering on `stun-rs`
//!
//! `stun::Attribute` is `#[non_exhaustive]` and cannot be extended from another
//! crate, but it exposes an [`stun::Attribute::Unknown`] variant that preserves
//! any unrecognized attribute's type and raw value bytes verbatim. TURN
//! attributes are therefore layered on top: this module defines a dedicated
//! [`Attribute`] enum for the TURN registry and bridges to STUN by encoding
//! each TURN attribute into an `Unknown { attribute_type, value }`.
//!
//! The two XOR-obfuscated address attributes (`XOR-PEER-ADDRESS`,
//! `XOR-RELAYED-ADDRESS`) use the exact same XOR scheme as
//! `XOR-MAPPED-ADDRESS`. Because `stun-rs` only applies that scheme to the
//! attributes it models, this module re-implements the address codec so that
//! the *value bytes* handed to `Unknown` are already XOR-obfuscated. The XOR
//! key is the message's `magic-cookie || transaction-id`, which the
//! [`crate::client::TurnClient`] controls because it sets the transaction ID
//! explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use stun::Attribute as StunAttribute;

use crate::error::{Error, Result};

/// Attribute type registry (RFC 5766 §14, RFC 6156, RFC 8656).
pub mod types {
    #![allow(missing_docs)]

    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
}

/// The 16-byte XOR key (`magic-cookie || transaction-id`) for a STUN message.
pub type XorKey = [u8; 16];

/// Default `REQUESTED-TRANSPORT` protocol number: UDP (RFC 5766 §14.7).
pub const PROTOCOL_UDP: u8 = 17;

/// Address family value for IPv4 (RFC 5389 §15.1).
const FAMILY_IPV4: u8 = 0x01;
/// Address family value for IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// An address family selector for `REQUESTED-ADDRESS-FAMILY` /
/// `ADDITIONAL-ADDRESS-FAMILY` (RFC 6156 §4.1.1, RFC 8656 §14.7/§14.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4 (`0x01`).
    V4,
    /// IPv6 (`0x02`).
    V6,
}

impl AddressFamily {
    /// The one-byte on-the-wire family value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V4 => FAMILY_IPV4,
            Self::V6 => FAMILY_IPV6,
        }
    }

    /// Resolve a one-byte family value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAddressFamily`] for unknown values.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            FAMILY_IPV4 => Ok(Self::V4),
            FAMILY_IPV6 => Ok(Self::V6),
            other => Err(Error::UnsupportedAddressFamily(other)),
        }
    }
}

/// The `EVEN-PORT` attribute (RFC 5766 §14.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvenPort {
    /// If set, the server reserves the next-higher odd port and returns a
    /// `RESERVATION-TOKEN` for a later allocation (the `R` bit).
    pub reserve_next: bool,
}

/// A single TURN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// `CHANNEL-NUMBER` — the 16-bit channel a `ChannelBind` targets.
    ChannelNumber(u16),
    /// `LIFETIME` — the desired or granted allocation lifetime, in seconds.
    Lifetime(u32),
    /// `XOR-PEER-ADDRESS` — a peer's transport address (XOR-obfuscated).
    XorPeerAddress(SocketAddr),
    /// `DATA` — relayed application data.
    Data(Vec<u8>),
    /// `XOR-RELAYED-ADDRESS` — the relayed transport address (XOR-obfuscated).
    XorRelayedAddress(SocketAddr),
    /// `REQUESTED-ADDRESS-FAMILY` — the address family requested for the relay.
    RequestedAddressFamily(AddressFamily),
    /// `EVEN-PORT` — request an even relayed port (optionally reserving the
    /// next-higher port).
    EvenPort(EvenPort),
    /// `REQUESTED-TRANSPORT` — the transport protocol number (UDP = 17).
    RequestedTransport(u8),
    /// `DONT-FRAGMENT` — set the DF bit on relayed UDP datagrams.
    DontFragment,
    /// `RESERVATION-TOKEN` — an 8-byte token from a prior `EVEN-PORT` reserve.
    ReservationToken([u8; 8]),
    /// `ADDITIONAL-ADDRESS-FAMILY` — request a dual-stack allocation (RFC 8656).
    AdditionalAddressFamily(AddressFamily),
}

impl Attribute {
    /// The 16-bit type code of this attribute.
    #[must_use]
    pub const fn attribute_type(&self) -> u16 {
        match self {
            Self::ChannelNumber(_) => types::CHANNEL_NUMBER,
            Self::Lifetime(_) => types::LIFETIME,
            Self::XorPeerAddress(_) => types::XOR_PEER_ADDRESS,
            Self::Data(_) => types::DATA,
            Self::XorRelayedAddress(_) => types::XOR_RELAYED_ADDRESS,
            Self::RequestedAddressFamily(_) => types::REQUESTED_ADDRESS_FAMILY,
            Self::EvenPort(_) => types::EVEN_PORT,
            Self::RequestedTransport(_) => types::REQUESTED_TRANSPORT,
            Self::DontFragment => types::DONT_FRAGMENT,
            Self::ReservationToken(_) => types::RESERVATION_TOKEN,
            Self::AdditionalAddressFamily(_) => types::ADDITIONAL_ADDRESS_FAMILY,
        }
    }

    /// Encode this attribute's value bytes (no type/length/padding).
    ///
    /// `key` is the message XOR key, used only by the XOR address attributes.
    #[must_use]
    pub fn encode_value(&self, key: &XorKey) -> Vec<u8> {
        match self {
            Self::ChannelNumber(channel) => {
                let mut out = Vec::with_capacity(4);
                out.extend_from_slice(&channel.to_be_bytes());
                out.extend_from_slice(&[0, 0]); // RFFU
                out
            }
            Self::Lifetime(secs) => secs.to_be_bytes().to_vec(),
            Self::XorPeerAddress(addr) | Self::XorRelayedAddress(addr) => {
                encode_xor_addr(*addr, key)
            }
            Self::Data(bytes) => bytes.clone(),
            Self::RequestedAddressFamily(family) | Self::AdditionalAddressFamily(family) => {
                vec![family.as_u8(), 0, 0, 0]
            }
            Self::EvenPort(even) => vec![if even.reserve_next { 0x80 } else { 0x00 }],
            Self::RequestedTransport(protocol) => vec![*protocol, 0, 0, 0],
            Self::DontFragment => Vec::new(),
            Self::ReservationToken(token) => token.to_vec(),
        }
    }

    /// Bridge this attribute into a [`stun::Attribute`] for inclusion in a STUN
    /// message, pre-encoding (and XOR-obfuscating, where needed) its value.
    #[must_use]
    pub fn to_stun(&self, key: &XorKey) -> StunAttribute {
        StunAttribute::Unknown {
            attribute_type: self.attribute_type(),
            value: self.encode_value(key),
        }
    }

    /// Decode a TURN attribute from its type, raw (still XOR-obfuscated) value
    /// bytes, and the message XOR key.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the value is malformed for its declared type.
    pub fn decode(attribute_type: u16, value: &[u8], key: &XorKey) -> Result<Self> {
        match attribute_type {
            types::CHANNEL_NUMBER => {
                if value.len() < 2 {
                    return Err(Error::Stun(stun::Error::MalformedAttribute(
                        "CHANNEL-NUMBER too short",
                    )));
                }
                Ok(Self::ChannelNumber(u16::from_be_bytes([
                    value[0], value[1],
                ])))
            }
            types::LIFETIME => Ok(Self::Lifetime(decode_u32(value, "LIFETIME")?)),
            types::XOR_PEER_ADDRESS => Ok(Self::XorPeerAddress(decode_xor_addr(value, key)?)),
            types::XOR_RELAYED_ADDRESS => Ok(Self::XorRelayedAddress(decode_xor_addr(value, key)?)),
            types::DATA => Ok(Self::Data(value.to_vec())),
            types::REQUESTED_ADDRESS_FAMILY => {
                Ok(Self::RequestedAddressFamily(decode_family(value)?))
            }
            types::ADDITIONAL_ADDRESS_FAMILY => {
                Ok(Self::AdditionalAddressFamily(decode_family(value)?))
            }
            types::EVEN_PORT => {
                let reserve_next = value.first().is_some_and(|b| b & 0x80 != 0);
                Ok(Self::EvenPort(EvenPort { reserve_next }))
            }
            types::REQUESTED_TRANSPORT => {
                let protocol =
                    *value
                        .first()
                        .ok_or(Error::Stun(stun::Error::MalformedAttribute(
                            "REQUESTED-TRANSPORT empty",
                        )))?;
                Ok(Self::RequestedTransport(protocol))
            }
            types::DONT_FRAGMENT => Ok(Self::DontFragment),
            types::RESERVATION_TOKEN => {
                let token: [u8; 8] = value.try_into().map_err(|_| {
                    Error::Stun(stun::Error::MalformedAttribute(
                        "RESERVATION-TOKEN must be 8 bytes",
                    ))
                })?;
                Ok(Self::ReservationToken(token))
            }
            other => Err(Error::Stun(stun::Error::MalformedAttribute(
                turn_type_name(other),
            ))),
        }
    }

    /// Try to interpret a decoded [`stun::Attribute`] as a TURN attribute.
    ///
    /// Returns `Ok(None)` for STUN attributes that `stun-rs` already models
    /// (e.g. `REALM`, `NONCE`, `ERROR-CODE`); those are handled directly by the
    /// client. Returns `Ok(Some(_))` for an `Unknown` whose type is in the TURN
    /// registry.
    ///
    /// # Errors
    ///
    /// Propagates decode errors for malformed TURN attribute values.
    pub fn from_stun(attr: &StunAttribute, key: &XorKey) -> Result<Option<Self>> {
        match attr {
            StunAttribute::Unknown {
                attribute_type,
                value,
            } if is_turn_attribute(*attribute_type) => {
                Ok(Some(Self::decode(*attribute_type, value, key)?))
            }
            _ => Ok(None),
        }
    }
}

/// Returns `true` if `attribute_type` belongs to the TURN registry.
#[must_use]
pub const fn is_turn_attribute(attribute_type: u16) -> bool {
    matches!(
        attribute_type,
        types::CHANNEL_NUMBER
            | types::LIFETIME
            | types::XOR_PEER_ADDRESS
            | types::DATA
            | types::XOR_RELAYED_ADDRESS
            | types::REQUESTED_ADDRESS_FAMILY
            | types::EVEN_PORT
            | types::REQUESTED_TRANSPORT
            | types::DONT_FRAGMENT
            | types::RESERVATION_TOKEN
            | types::ADDITIONAL_ADDRESS_FAMILY
    )
}

/// Build the 16-byte XOR key from a 12-byte transaction ID and the STUN magic
/// cookie.
#[must_use]
pub fn xor_key(transaction_id: &[u8; 12]) -> XorKey {
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
    key[4..16].copy_from_slice(transaction_id);
    key
}

/// Encode an XOR-obfuscated address value (shared by `XOR-PEER-ADDRESS` and
/// `XOR-RELAYED-ADDRESS`; identical scheme to `XOR-MAPPED-ADDRESS`).
fn encode_xor_addr(addr: SocketAddr, key: &XorKey) -> Vec<u8> {
    let xport = addr.port() ^ u16::from_be_bytes([key[0], key[1]]);
    let mut out = Vec::with_capacity(20);
    out.push(0); // reserved
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&xport.to_be_bytes());
            let mut octets = v4.octets();
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            out.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&xport.to_be_bytes());
            let mut octets = v6.octets();
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            out.extend_from_slice(&octets);
        }
    }
    out
}

/// Decode an XOR-obfuscated address value.
fn decode_xor_addr(value: &[u8], key: &XorKey) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(Error::Stun(stun::Error::MalformedAttribute(
            "XOR address too short",
        )));
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ u16::from_be_bytes([key[0], key[1]]);
    match family {
        FAMILY_IPV4 => {
            let raw: [u8; 4] = value
                .get(4..8)
                .ok_or(Error::Stun(stun::Error::MalformedAttribute(
                    "IPv4 address truncated",
                )))?
                .try_into()
                .expect("slice is 4 bytes");
            let mut octets = raw;
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            let raw: [u8; 16] = value
                .get(4..20)
                .ok_or(Error::Stun(stun::Error::MalformedAttribute(
                    "IPv6 address truncated",
                )))?
                .try_into()
                .expect("slice is 16 bytes");
            let mut octets = raw;
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(Error::UnsupportedAddressFamily(other)),
    }
}

/// Decode a `REQUESTED-ADDRESS-FAMILY` / `ADDITIONAL-ADDRESS-FAMILY` value.
fn decode_family(value: &[u8]) -> Result<AddressFamily> {
    let family = *value
        .first()
        .ok_or(Error::Stun(stun::Error::MalformedAttribute(
            "address-family attribute empty",
        )))?;
    AddressFamily::from_u8(family)
}

/// Decode a big-endian `u32` value.
fn decode_u32(value: &[u8], what: &'static str) -> Result<u32> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| {
        Error::Stun(stun::Error::MalformedAttribute(match what {
            "LIFETIME" => "LIFETIME must be 4 bytes",
            _ => "expected 4-byte value",
        }))
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Map a TURN attribute type to a stable static name for error messages.
const fn turn_type_name(attribute_type: u16) -> &'static str {
    match attribute_type {
        types::CHANNEL_NUMBER => "CHANNEL-NUMBER",
        types::LIFETIME => "LIFETIME",
        types::XOR_PEER_ADDRESS => "XOR-PEER-ADDRESS",
        types::DATA => "DATA",
        types::XOR_RELAYED_ADDRESS => "XOR-RELAYED-ADDRESS",
        types::REQUESTED_ADDRESS_FAMILY => "REQUESTED-ADDRESS-FAMILY",
        types::EVEN_PORT => "EVEN-PORT",
        types::REQUESTED_TRANSPORT => "REQUESTED-TRANSPORT",
        types::DONT_FRAGMENT => "DONT-FRAGMENT",
        types::RESERVATION_TOKEN => "RESERVATION-TOKEN",
        types::ADDITIONAL_ADDRESS_FAMILY => "ADDITIONAL-ADDRESS-FAMILY",
        _ => "unrecognized TURN attribute",
    }
}
