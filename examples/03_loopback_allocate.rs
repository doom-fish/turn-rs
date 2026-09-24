use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use stun::auth::long_term_key;
use stun::{Attribute as StunAttribute, Class, ErrorCode, Message};
use turn::attribute::xor_key;
use turn::{AllocateOptions, Attribute, Credential, Method, TurnClient, TurnUri};

const USER: &str = "alice";
const PASSWORD: &str = "s3cr3t";
const REALM: &str = "loopback.example";
const NONCE: &str = "example-nonce";

fn respond(request: &Message, peer: SocketAddr) -> stun::Result<Vec<u8>> {
    let key = long_term_key(USER, REALM, PASSWORD);
    let tid = *request.transaction_id();
    if request.verify_message_integrity(&key).is_err() {
        return Message::builder(request.method(), Class::ErrorResponse)
            .transaction_id(tid)
            .attribute(StunAttribute::ErrorCode(ErrorCode::new(
                401,
                "Unauthorized",
            )))
            .attribute(StunAttribute::Realm(REALM.to_owned()))
            .attribute(StunAttribute::Nonce(NONCE.to_owned()))
            .build_and_encode();
    }
    let xor = xor_key(tid.as_bytes());
    let mut builder =
        Message::builder(request.method(), Class::SuccessResponse).transaction_id(tid);
    if request.method() == Method::Allocate.to_stun() {
        let relayed: SocketAddr = "192.0.2.10:50000".parse().expect("valid literal");
        builder = builder
            .attribute(Attribute::XorRelayedAddress(relayed).to_stun(&xor))
            .attribute(StunAttribute::XorMappedAddress(peer))
            .attribute(Attribute::Lifetime(600).to_stun(&xor));
    }
    builder
        .with_message_integrity_sha1(&key)
        .with_fingerprint()
        .build_and_encode()
}

fn serve(socket: &UdpSocket) {
    let mut buf = [0u8; 2048];
    while let Ok((n, peer)) = socket.recv_from(&mut buf) {
        let Ok(request) = Message::decode(&buf[..n]) else {
            continue;
        };
        if request.class() != Class::Request {
            continue;
        }
        if let Ok(response) = respond(&request, peer) {
            let _ = socket.send_to(&response, peer);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();
    thread::spawn(move || serve(&socket));

    let uri: TurnUri = format!("turn:127.0.0.1:{port}").parse()?;
    let mut client = TurnClient::connect(uri, Credential::long_term(USER, "", PASSWORD))?;
    let allocation = client.allocate(&AllocateOptions::default())?;
    println!("relayed address: {}", allocation.relayed_address());
    if let Some(mapped) = allocation.mapped_address() {
        println!("mapped address:  {mapped}");
    }
    println!("lifetime:        {:?}", allocation.lifetime());
    println!("realm:           {:?}", client.auth_state().realm());

    client.close(Duration::from_secs(2))?;
    println!("allocation released");
    Ok(())
}
