//! Bind a channel and round-trip a ChannelData frame, entirely offline.
//!
//! This shows the ChannelData framing used on the data path once a channel is
//! bound (RFC 5766 §11.4): a 4-byte header (channel number + length) followed by
//! the application payload. It also demonstrates the first-byte
//! STUN-vs-ChannelData demultiplexing used by a TURN client's receive loop.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 02_channel_data
//! ```

use turn::channel::{classify, PacketKind};
use turn::ChannelData;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    let channel = 0x4000;
    let payload = b"relayed application payload";

    // Datagram framing (UDP): padded to a 4-byte boundary.
    let datagram = ChannelData::encode(channel, payload).expect("encode");
    println!("ChannelData (UDP, padded), {} bytes:", datagram.len());
    println!("  {}", hex(&datagram));

    // Stream framing (TCP/TLS): no trailing padding.
    let stream = ChannelData::encode_stream(channel, payload).expect("encode_stream");
    println!("ChannelData (TCP, unpadded), {} bytes:", stream.len());
    println!("  {}", hex(&stream));

    let (decoded_channel, decoded_payload) = ChannelData::decode(&datagram).expect("decode");
    assert_eq!(decoded_channel, channel);
    assert_eq!(decoded_payload, payload);
    println!(
        "\nDecoded channel 0x{decoded_channel:04x}, {} payload bytes.",
        decoded_payload.len()
    );

    // Demultiplexing: the first byte distinguishes STUN (0x00-0x3F) from
    // ChannelData (0x40-0x7F).
    println!("\nDemux:");
    println!("  channel frame -> {:?}", classify(&datagram));
    let stun_like = [0x00u8, 0x01, 0x00, 0x00];
    println!("  STUN message  -> {:?}", classify(&stun_like));
    assert_eq!(classify(&datagram), PacketKind::ChannelData);
    assert_eq!(classify(&stun_like), PacketKind::Stun);
}
