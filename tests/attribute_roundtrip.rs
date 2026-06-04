//! Round-trip tests for the TURN attribute codec, including the XOR-obfuscated
//! address attributes layered on `stun::Attribute::Unknown`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use turn::attribute::{xor_key, PROTOCOL_UDP};
use turn::{AddressFamily, Attribute, EvenPort};

fn roundtrip(attr: &Attribute) -> Attribute {
    let tid = [0x11u8; 12];
    let key = xor_key(&tid);
    let stun = attr.to_stun(&key);
    Attribute::from_stun(&stun, &key)
        .expect("decode ok")
        .expect("is a turn attribute")
}

#[test]
fn xor_peer_address_ipv4_roundtrip() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 49152);
    let attr = Attribute::XorPeerAddress(addr);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn xor_peer_address_ipv6_roundtrip() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        3478,
    );
    let attr = Attribute::XorPeerAddress(addr);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn xor_relayed_address_roundtrip() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)), 50000);
    let attr = Attribute::XorRelayedAddress(addr);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn channel_number_roundtrip() {
    let attr = Attribute::ChannelNumber(0x4001);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn lifetime_roundtrip() {
    let attr = Attribute::Lifetime(600);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn requested_transport_roundtrip() {
    let attr = Attribute::RequestedTransport(PROTOCOL_UDP);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn data_roundtrip() {
    let attr = Attribute::Data(b"relayed payload".to_vec());
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn requested_address_family_roundtrip() {
    let attr = Attribute::RequestedAddressFamily(AddressFamily::V6);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn even_port_roundtrip() {
    let attr = Attribute::EvenPort(EvenPort { reserve_next: true });
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn dont_fragment_roundtrip() {
    let attr = Attribute::DontFragment;
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn reservation_token_roundtrip() {
    let attr = Attribute::ReservationToken([1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(roundtrip(&attr), attr);
}

#[test]
fn xor_obfuscation_actually_changes_bytes() {
    // The encoded XOR-PEER-ADDRESS value must differ from the plain address,
    // proving the magic-cookie/transaction-id XOR is applied.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 49152);
    let key = xor_key(&[0x22u8; 12]);
    let value = Attribute::XorPeerAddress(addr).encode_value(&key);
    // Family byte (0x00 0x01) is not XORed; the port/address are.
    assert_eq!(&value[0..2], &[0x00, 0x01]);
    assert_ne!(&value[2..4], &49152u16.to_be_bytes());
}
