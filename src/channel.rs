//! ChannelData message framing (RFC 5766 §11.4, §11.5).
//!
//! Once a channel is bound with `ChannelBind`, a client and server may exchange
//! application data using a compact 4-byte header instead of full STUN framing:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Channel Number        |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Application Data                        |
//! |                             ....                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The first two bytes (the channel number) also disambiguate a ChannelData
//! frame from a STUN message on a shared transport: STUN messages start with
//! the two most-significant bits clear (`0x0000..=0x3FFF`, see RFC 5389 §6),
//! whereas valid TURN channel numbers fall in `0x4000..=0x7FFF`
//! (RFC 5766 §11).

use crate::error::{Error, Result};

/// The lowest valid channel number (RFC 5766 §11).
pub const MIN_CHANNEL: u16 = 0x4000;
/// The highest valid channel number reserved for ChannelData.
pub const MAX_CHANNEL: u16 = 0x7FFF;
/// Length of the ChannelData header in bytes.
pub const HEADER_LEN: usize = 4;

/// Returns `true` if `channel` is in the valid ChannelData range
/// `0x4000..=0x7FFF` (RFC 5766 §11).
#[must_use]
pub const fn is_valid_channel(channel: u16) -> bool {
    channel >= MIN_CHANNEL && channel <= MAX_CHANNEL
}

/// Classifies the first two bytes of a TURN packet on a shared transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// A STUN-framed message (first two bits clear, `0x0000..=0x3FFF`).
    Stun,
    /// A ChannelData frame (`0x4000..=0x7FFF`).
    ChannelData,
    /// Neither (`>= 0x8000`); reserved/invalid for TURN.
    Unknown,
}

/// Classify a received TURN packet by its leading channel-number field.
///
/// This is the demultiplexing step a client must run on every inbound packet
/// when STUN messages and ChannelData frames share one socket.
#[must_use]
pub fn classify(bytes: &[u8]) -> PacketKind {
    if bytes.len() < 2 {
        return PacketKind::Unknown;
    }
    let leading = u16::from_be_bytes([bytes[0], bytes[1]]);
    if leading <= 0x3FFF {
        PacketKind::Stun
    } else if leading <= 0x7FFF {
        PacketKind::ChannelData
    } else {
        PacketKind::Unknown
    }
}

/// ChannelData framing helpers.
pub struct ChannelData;

impl ChannelData {
    /// Encode a ChannelData frame.
    ///
    /// The frame is always padded with zero bytes to a 4-byte boundary. Padding
    /// is **REQUIRED** over stream transports (TCP / TLS-over-TCP) per RFC 5766
    /// §11.5 and RFC 8656 §12.4, and is permitted (RECOMMENDED) over datagram
    /// transports (UDP). The `Length` field always records the *unpadded*
    /// payload length, so the receiver discards trailing padding regardless of
    /// transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChannelNumber`] if `channel` is outside
    /// `0x4000..=0x7FFF`.
    pub fn encode(channel: u16, payload: &[u8]) -> Result<Vec<u8>> {
        if !is_valid_channel(channel) {
            return Err(Error::InvalidChannelNumber(channel));
        }
        let len = u16::try_from(payload.len())
            .map_err(|_| Error::BadChannelData("payload exceeds 65535 bytes"))?;
        let padding = (4 - (payload.len() % 4)) % 4;
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + padding);
        out.extend_from_slice(&channel.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        out.extend(std::iter::repeat_n(0u8, padding));
        Ok(out)
    }

    /// Decode a ChannelData frame, returning the channel number and a borrow of
    /// the payload (without header or padding).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadChannelData`] if the frame is truncated or the
    /// declared length runs past the buffer, or
    /// [`Error::InvalidChannelNumber`] if the channel is out of range.
    pub fn decode(bytes: &[u8]) -> Result<(u16, &[u8])> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::BadChannelData("frame shorter than 4-byte header"));
        }
        let channel = u16::from_be_bytes([bytes[0], bytes[1]]);
        if !is_valid_channel(channel) {
            return Err(Error::InvalidChannelNumber(channel));
        }
        let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let payload = bytes
            .get(HEADER_LEN..HEADER_LEN + len)
            .ok_or(Error::BadChannelData("declared length exceeds frame"))?;
        Ok((channel, payload))
    }
}
