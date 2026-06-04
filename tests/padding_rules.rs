//! ChannelData padding rules per RFC 5766 §11.5 and RFC 8656 §12.4. Every
//! ChannelData frame is padded with zero bytes to a 4-byte boundary, because
//! padding is REQUIRED over stream transports (TCP / TLS-over-TCP) and is
//! permitted (RECOMMENDED) over UDP. The `Length` field always records the
//! unpadded payload length so the receiver can discard trailing padding
//! regardless of transport.

use turn::ChannelData;

#[test]
fn always_pads_to_four_byte_boundary() {
    // 1-byte payload -> header(4) + payload(1) + padding(3) = 8.
    let frame = ChannelData::encode(0x4000, b"x").expect("encode");
    assert_eq!(frame.len(), 8);
    // Length field still reports the unpadded payload length.
    assert_eq!(&frame[2..4], &1u16.to_be_bytes());
    // Padding bytes are zero.
    assert_eq!(&frame[5..8], &[0, 0, 0]);
}

#[test]
fn padding_for_each_residue() {
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
fn length_field_excludes_padding() {
    for n in 0..16usize {
        let payload = vec![0xABu8; n];
        let frame = ChannelData::encode(0x4000, &payload).expect("encode");
        let declared_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(
            declared_len, n,
            "Length field must always equal the unpadded payload length"
        );
        let expected_total = 4 + n + ((4 - (n % 4)) % 4);
        assert_eq!(frame.len(), expected_total, "frame must be 4-byte aligned");
    }
}

#[test]
fn decoder_recovers_payload_independent_of_padding() {
    let payload = b"five!"; // 5 bytes, triggers 3 bytes of padding.
    let frame = ChannelData::encode(0x4000, payload).expect("encode");
    assert_eq!(frame.len(), 12);

    let (_, decoded) = ChannelData::decode(&frame).expect("decode");
    assert_eq!(decoded, payload);
}
