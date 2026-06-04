//! Tests for ChannelData framing, decoding, and STUN/ChannelData
//! demultiplexing.

use turn::channel::{classify, is_valid_channel, PacketKind, MAX_CHANNEL, MIN_CHANNEL};
use turn::ChannelData;

#[test]
fn encode_decode_roundtrip() {
    let payload = b"the quick brown fox";
    let frame = ChannelData::encode(0x4000, payload).expect("encode");
    let (channel, decoded) = ChannelData::decode(&frame).expect("decode");
    assert_eq!(channel, 0x4000);
    assert_eq!(decoded, payload);
}

#[test]
fn header_layout() {
    let frame = ChannelData::encode(0x4001, b"abcd").expect("encode");
    // Channel number (big-endian) then length (big-endian) then payload.
    assert_eq!(&frame[0..2], &0x4001u16.to_be_bytes());
    assert_eq!(&frame[2..4], &4u16.to_be_bytes());
    assert_eq!(&frame[4..8], b"abcd");
}

#[test]
fn rejects_invalid_channel_number() {
    // 0x0000-0x3FFF is reserved for STUN; ChannelData must be 0x4000-0x7FFF.
    assert!(ChannelData::encode(0x3FFF, b"x").is_err());
    assert!(ChannelData::encode(0x8000, b"x").is_err());
}

#[test]
fn valid_channel_range() {
    assert!(!is_valid_channel(MIN_CHANNEL - 1));
    assert!(is_valid_channel(MIN_CHANNEL));
    assert!(is_valid_channel(MAX_CHANNEL));
    assert!(!is_valid_channel(MAX_CHANNEL + 1));
}

#[test]
fn classify_distinguishes_stun_from_channeldata() {
    // First two bits zero -> STUN.
    let stun = [0x00u8, 0x01, 0x00, 0x00];
    assert_eq!(classify(&stun), PacketKind::Stun);

    // 0x40.. -> ChannelData.
    let frame = ChannelData::encode(0x4000, b"hi").expect("encode");
    assert_eq!(classify(&frame), PacketKind::ChannelData);

    // 0x80.. and above is neither.
    let unknown = [0x80u8, 0x00, 0x00, 0x00];
    assert_eq!(classify(&unknown), PacketKind::Unknown);
}

#[test]
fn classify_empty_is_unknown() {
    assert_eq!(classify(&[]), PacketKind::Unknown);
}

#[test]
fn decode_truncated_fails() {
    // Declares 8 bytes of payload but provides none.
    let bad = [0x40u8, 0x00, 0x00, 0x08];
    assert!(ChannelData::decode(&bad).is_err());
}

#[test]
fn decode_empty_payload() {
    let frame = ChannelData::encode(0x4000, b"").expect("encode");
    let (channel, payload) = ChannelData::decode(&frame).expect("decode");
    assert_eq!(channel, 0x4000);
    assert!(payload.is_empty());
}
