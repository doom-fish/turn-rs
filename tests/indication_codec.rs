use std::net::SocketAddr;

use stun::{Attribute as StunAttribute, Class, Message, TransactionId};
use turn::attribute::xor_key;
use turn::indication::{decode_data, encode_send};
use turn::{Attribute, Error, Method};

fn peer() -> SocketAddr {
    "203.0.113.9:4444".parse().unwrap()
}

fn data_indication(attributes: &[StunAttribute], tid: TransactionId) -> Message {
    let mut builder =
        Message::builder(Method::Data.to_stun(), Class::Indication).transaction_id(tid);
    for attribute in attributes {
        builder = builder.attribute(attribute.clone());
    }
    Message::decode(&builder.build_and_encode().unwrap()).unwrap()
}

#[test]
fn send_indication_carries_peer_and_data() {
    let bytes = encode_send(peer(), b"hello").unwrap();
    let message = Message::decode(&bytes).unwrap();
    assert_eq!(message.method(), Method::Send.to_stun());
    assert_eq!(message.class(), Class::Indication);
    let key = xor_key(message.transaction_id().as_bytes());
    let attributes: Vec<Attribute> = message
        .attributes()
        .iter()
        .filter_map(|a| Attribute::from_stun(a, &key).unwrap())
        .collect();
    assert_eq!(
        attributes,
        vec![
            Attribute::XorPeerAddress(peer()),
            Attribute::Data(b"hello".to_vec())
        ]
    );
    assert_eq!(decode_data(&message).unwrap(), None);
}

#[test]
fn data_indication_yields_peer_and_payload() {
    let tid = TransactionId::from_bytes([7; 12]);
    let key = xor_key(tid.as_bytes());
    let message = data_indication(
        &[
            Attribute::XorPeerAddress(peer()).to_stun(&key),
            Attribute::Data(b"relayed".to_vec()).to_stun(&key),
        ],
        tid,
    );
    assert_eq!(
        decode_data(&message).unwrap(),
        Some((peer(), b"relayed".to_vec()))
    );
}

#[test]
fn data_indication_without_data_is_ignored() {
    let tid = TransactionId::from_bytes([8; 12]);
    let key = xor_key(tid.as_bytes());
    let message = data_indication(&[Attribute::XorPeerAddress(peer()).to_stun(&key)], tid);
    assert_eq!(decode_data(&message).unwrap(), None);
}

#[test]
fn data_indication_with_a_malformed_peer_is_rejected() {
    let tid = TransactionId::from_bytes([9; 12]);
    let key = xor_key(tid.as_bytes());
    let message = data_indication(
        &[
            StunAttribute::Unknown {
                attribute_type: turn::attribute::types::XOR_PEER_ADDRESS,
                value: vec![0, 1, 2],
            },
            Attribute::Data(b"x".to_vec()).to_stun(&key),
        ],
        tid,
    );
    assert!(matches!(decode_data(&message), Err(Error::Stun(_))));
}
