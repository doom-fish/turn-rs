use std::net::SocketAddr;

use stun::{Class, Message, TransactionId};

use crate::attribute::{self, Attribute};
use crate::error::Result;
use crate::method::Method;

pub fn encode_send(peer: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let tid = TransactionId::try_random()?;
    let key = attribute::xor_key(tid.as_bytes());
    Ok(Message::builder(Method::Send.to_stun(), Class::Indication)
        .transaction_id(tid)
        .attribute(Attribute::XorPeerAddress(peer).to_stun(&key))
        .attribute(Attribute::Data(payload.to_vec()).to_stun(&key))
        .build_and_encode()?)
}

pub fn decode_data(message: &Message) -> Result<Option<(SocketAddr, Vec<u8>)>> {
    if message.method() != Method::Data.to_stun() || message.class() != Class::Indication {
        return Ok(None);
    }
    let key = attribute::xor_key(message.transaction_id().as_bytes());
    let mut peer = None;
    let mut data = None;
    for attr in message.attributes() {
        match Attribute::from_stun(attr, &key)? {
            Some(Attribute::XorPeerAddress(addr)) if peer.is_none() => peer = Some(addr),
            Some(Attribute::Data(bytes)) if data.is_none() => data = Some(bytes),
            _ => {}
        }
    }
    Ok(peer.zip(data))
}
