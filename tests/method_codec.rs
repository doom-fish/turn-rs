//! Tests for TURN method encoding and the request message structure.

use stun::{Class, Message, TransactionId};
use turn::attribute::{xor_key, PROTOCOL_UDP};
use turn::{Attribute, Method};

fn build(method: Method, attrs: &[Attribute]) -> Vec<u8> {
    let tid = TransactionId::random();
    let key = xor_key(tid.as_bytes());
    let mut builder = Message::builder(method.to_stun(), Class::Request).transaction_id(tid);
    for attr in attrs {
        builder = builder.attribute(attr.to_stun(&key));
    }
    builder.build_and_encode()
}

#[test]
fn method_constants() {
    assert_eq!(Method::Allocate.as_u16(), 0x0003);
    assert_eq!(Method::Refresh.as_u16(), 0x0004);
    assert_eq!(Method::Send.as_u16(), 0x0006);
    assert_eq!(Method::Data.as_u16(), 0x0007);
    assert_eq!(Method::CreatePermission.as_u16(), 0x0008);
    assert_eq!(Method::ChannelBind.as_u16(), 0x0009);
}

#[test]
fn method_from_u16_roundtrip() {
    for m in [
        Method::Allocate,
        Method::Refresh,
        Method::Send,
        Method::Data,
        Method::CreatePermission,
        Method::ChannelBind,
    ] {
        assert_eq!(Method::from_u16(m.as_u16()), Some(m));
    }
    assert_eq!(Method::from_u16(0x0fff), None);
}

#[test]
fn allocate_request_decodes() {
    let bytes = build(
        Method::Allocate,
        &[
            Attribute::RequestedTransport(PROTOCOL_UDP),
            Attribute::Lifetime(600),
        ],
    );
    let message = Message::decode(&bytes).expect("decode");
    assert_eq!(message.method(), Method::Allocate.to_stun());
    assert_eq!(message.class(), Class::Request);
}

#[test]
fn refresh_request_decodes() {
    let bytes = build(Method::Refresh, &[Attribute::Lifetime(0)]);
    let message = Message::decode(&bytes).expect("decode");
    assert_eq!(message.method(), Method::Refresh.to_stun());
    assert_eq!(message.class(), Class::Request);
}

#[test]
fn create_permission_request_decodes() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 0);
    let bytes = build(Method::CreatePermission, &[Attribute::XorPeerAddress(peer)]);
    let message = Message::decode(&bytes).expect("decode");
    assert_eq!(message.method(), Method::CreatePermission.to_stun());
}

#[test]
fn channel_bind_request_decodes() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 49152);
    let bytes = build(
        Method::ChannelBind,
        &[
            Attribute::ChannelNumber(0x4000),
            Attribute::XorPeerAddress(peer),
        ],
    );
    let message = Message::decode(&bytes).expect("decode");
    assert_eq!(message.method(), Method::ChannelBind.to_stun());
    assert_eq!(message.class(), Class::Request);
}
