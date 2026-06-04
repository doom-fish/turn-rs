//! Live end-to-end TURN allocation against a real server.
//!
//! This example is **disabled unless** `TURN_LIVE_TESTS=1` is set, because it
//! needs a reachable TURN server and valid long-term credentials. It exercises
//! the full client path against a TURN/STUN relay used by WebRTC peers and other
//! ICE-compliant endpoints.
//!
//! Configure with environment variables:
//!
//! ```sh
//! TURN_LIVE_TESTS=1 \
//! TURN_URL=turn:turn.example.org:3478 \
//! TURN_USER=alice \
//! TURN_REALM=example.org \
//! TURN_PASS=s3cr3t \
//! cargo run --example 03_live_allocate
//! ```

use std::time::Duration;

use turn::{AllocateOptions, Credential, TurnClient, TurnUri};

fn main() {
    if std::env::var("TURN_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!(
            "skipping: set TURN_LIVE_TESTS=1 (and TURN_URL/TURN_USER/TURN_REALM/TURN_PASS) to run"
        );
        return;
    }

    let url = std::env::var("TURN_URL").expect("TURN_URL");
    let user = std::env::var("TURN_USER").expect("TURN_USER");
    let realm = std::env::var("TURN_REALM").unwrap_or_default();
    let pass = std::env::var("TURN_PASS").expect("TURN_PASS");

    let uri: TurnUri = url.parse().expect("parse TURN_URL");
    let credential = Credential::long_term(user, realm, pass);

    let mut client = TurnClient::connect(uri, credential).expect("connect");
    let alloc = client
        .allocate(&AllocateOptions::default())
        .expect("allocate");
    println!("relayed address: {}", alloc.relayed_address());
    if let Some(mapped) = alloc.mapped_address() {
        println!("mapped address:  {mapped}");
    }
    println!("lifetime:        {:?}", alloc.lifetime());

    client.refresh(Duration::from_secs(600)).expect("refresh");
    println!("refreshed allocation; releasing on drop.");
}
