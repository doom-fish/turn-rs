//! ChannelData padding rules per this crate's transport model: datagram
//! transports (UDP) pad each frame to a 4-byte boundary, while stream
//! transports (TCP/TLS) emit the frame without trailing padding because the
//! framing is recovered from the explicit `Length` field (RFC 5766 §11.5).

use turn::ChannelData;

#[test]
fn udp_pads_to_four_byte_boundary() {
    // 1-byte payload -> header(4) + payload(1) + padding(3) = 8.
    let frame = ChannelData::encode(0x4000, b"x").expect("encode");
    assert_eq!(frame.len(), 8);
    // Length field still reports the unpadded payload length.
    assert_eq!(&frame[2..4], &1u16.to_be_bytes());
    // Padding bytes are zero.
    assert_eq!(&frame[5..8], &[0, 0, 0]);
}

#[test]
fn udp_padding_for_each_residue() {
    // payload_len % 4 == 0 -> no padding needed.
    assert_eq!(ChannelData::encode(0x4000, b"abcd").unwrap().len(), 8);
    // residue 1 -> +3
    assert_eq!(ChannelData::encode(0x4000, b"abcde").unwrap().len(), 12);
    // residue 2 -> +2
    assert_eq!(ChannelData::encode(0x4000, b"abcdef").unwrap().len(), 12);
    // residue 3 -> +1
    assert_eq!(ChannelData::encode(0x4000, b"abcdefg").unwrap().len(), 12);
}

#[test]
fn tcp_does_not_pad() {
    // 1-byte payload -> header(4) + payload(1) = 5, no padding.
    let frame = ChannelData::encode_stream(0x4000, b"x").expect("encode_stream");
    assert_eq!(frame.len(), 5);
    assert_eq!(&frame[2..4], &1u16.to_be_bytes());
}

#[test]
fn tcp_length_independent_of_alignment() {
    for n in 0..16usize {
        let payload = vec![0xABu8; n];
        let frame = ChannelData::encode_stream(0x4000, &payload).expect("encode_stream");
        assert_eq!(
            frame.len(),
            4 + n,
            "stream frame must be exactly header + payload"
        );
    }
}

#[test]
fn both_decode_to_same_payload() {
    let payload = b"five!"; // 5 bytes, triggers padding on UDP
    let udp = ChannelData::encode(0x4000, payload).expect("encode");
    let tcp = ChannelData::encode_stream(0x4000, payload).expect("encode_stream");
    assert_ne!(udp.len(), tcp.len());

    let (_, udp_payload) = ChannelData::decode(&udp).expect("decode udp");
    let (_, tcp_payload) = ChannelData::decode(&tcp).expect("decode tcp");
    assert_eq!(udp_payload, payload);
    assert_eq!(tcp_payload, payload);
}
