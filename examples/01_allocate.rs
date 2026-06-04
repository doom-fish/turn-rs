//! Build a TURN `Allocate` request offline and print its encoded bytes.
//!
//! This demonstrates the message and attribute codec without any network
//! access: it constructs an authenticated `Allocate` request (as it would look
//! *after* the `401` challenge) with `REQUESTED-TRANSPORT`, `LIFETIME`, and a
//! `MESSAGE-INTEGRITY` over the long-term key, then decodes it back.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 01_allocate
//! ```

use stun::auth::long_term_key;
use stun::{Attribute as StunAttribute, Class, Message, TransactionId};
use turn::attribute::{xor_key, PROTOCOL_UDP};
use turn::{Attribute, Method};

fn hex_dump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{:04x}: {}", i * 16, hex.join(" "));
    }
}

fn main() {
    let (username, realm, password) = ("doomfish", "example.org", "s3cr3t");
    let nonce = "f//499k954d6OL34v5vfQDrg";
    let key = long_term_key(username, realm, password);

    // A fixed transaction ID determines the XOR key for any XOR-* attributes.
    let tid = TransactionId::random();
    let xk = xor_key(tid.as_bytes());

    let request = Message::builder(Method::Allocate.to_stun(), Class::Request)
        .transaction_id(tid)
        .attribute(Attribute::RequestedTransport(PROTOCOL_UDP).to_stun(&xk))
        .attribute(Attribute::Lifetime(600).to_stun(&xk))
        .attribute(StunAttribute::Username(username.to_owned()))
        .attribute(StunAttribute::Realm(realm.to_owned()))
        .attribute(StunAttribute::Nonce(nonce.to_owned()))
        .with_message_integrity_sha1(&key)
        .build();

    let bytes = request.encode();
    println!("Allocate request ({} bytes):", bytes.len());
    hex_dump(&bytes);

    let decoded = Message::decode(&bytes).expect("decode");
    decoded
        .verify_message_integrity(&key)
        .expect("MESSAGE-INTEGRITY verifies");

    println!(
        "\nMethod:  {:?}",
        Method::from_u16(decoded.method().as_u16())
    );
    println!("Class:   {:?}", decoded.class());
    println!("Decoded round trip OK; long-term integrity verified.");
}
