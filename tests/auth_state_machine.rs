//! Tests for the long-term authentication state machine: the `AuthState`
//! transitions and the full `401` challenge → re-send flow driven through a
//! mock in-memory transport.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};

use stun::{Attribute as StunAttribute, Class, ErrorCode, Message};
use turn::attribute::xor_key;
use turn::auth::AuthState;
use turn::{AllocateOptions, Attribute, Credential, Method, Transport};

#[test]
fn auth_state_starts_empty() {
    let state = AuthState::new();
    assert!(!state.is_ready());
    assert_eq!(state.realm(), None);
    assert_eq!(state.nonce(), None);
    assert_eq!(state.key(), None);
}

#[test]
fn challenge_makes_state_ready() {
    let mut state = AuthState::new();
    let cred = Credential::long_term("alice", "", "password");
    state.challenge(&cred, "example.org", "nonce-1");
    assert!(state.is_ready());
    assert_eq!(state.realm(), Some("example.org"));
    assert_eq!(state.nonce(), Some("nonce-1"));
    // Key is MD5(username:realm:password) per RFC 5389 §15.4.
    let expected = stun::auth::long_term_key("alice", "example.org", "password");
    assert_eq!(state.key(), Some(&expected));
}

#[test]
fn refresh_nonce_updates_only_nonce() {
    let mut state = AuthState::new();
    let cred = Credential::long_term("alice", "", "password");
    state.challenge(&cred, "example.org", "nonce-1");
    let key_before = *state.key().unwrap();
    state.refresh_nonce("nonce-2");
    assert_eq!(state.nonce(), Some("nonce-2"));
    assert_eq!(state.realm(), Some("example.org"));
    assert_eq!(state.key(), Some(&key_before));
}

/// A scripted in-memory TURN server. It answers an unauthenticated `Allocate`
/// with a `401` challenge (carrying `REALM`/`NONCE`), an authenticated
/// `Allocate` with a success response carrying the relayed address, and any
/// other authenticated request with a bare success response.
struct MockServer {
    state: Mutex<MockState>,
    signal: Condvar,
}

struct MockState {
    outbound: VecDeque<Vec<u8>>,
    challenges: usize,
    authed_allocates: usize,
}

const REALM: &str = "relay.example.org";
const NONCE: &str = "abc123nonce";

impl MockServer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(MockState {
                outbound: VecDeque::new(),
                challenges: 0,
                authed_allocates: 0,
            }),
            signal: Condvar::new(),
        })
    }

    fn respond(&self, request: &[u8]) {
        let message = Message::decode(request).expect("server decodes request");
        let tid = *message.transaction_id();
        let key = xor_key(tid.as_bytes());
        let authed = message.get(stun::attribute::types::NONCE).is_some();
        let method = message.method();

        let response = if method == Method::Allocate.to_stun() && !authed {
            // Unauthenticated request -> 401 challenge.
            self.state.lock().unwrap().challenges += 1;
            Message::builder(Method::Allocate.to_stun(), Class::ErrorResponse)
                .transaction_id(tid)
                .attribute(StunAttribute::ErrorCode(ErrorCode::new(
                    401,
                    "Unauthorized",
                )))
                .attribute(StunAttribute::Realm(REALM.to_owned()))
                .attribute(StunAttribute::Nonce(NONCE.to_owned()))
                .build_and_encode()
        } else if method == Method::Allocate.to_stun() {
            self.state.lock().unwrap().authed_allocates += 1;
            let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)), 51000);
            let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 40000);
            Message::builder(Method::Allocate.to_stun(), Class::SuccessResponse)
                .transaction_id(tid)
                .attribute(Attribute::XorRelayedAddress(relayed).to_stun(&key))
                .attribute(StunAttribute::XorMappedAddress(mapped))
                .attribute(Attribute::Lifetime(600).to_stun(&key))
                .build_and_encode()
        } else {
            // e.g. the zero-lifetime Refresh sent on drop.
            Message::builder(method, Class::SuccessResponse)
                .transaction_id(tid)
                .attribute(Attribute::Lifetime(0).to_stun(&key))
                .build_and_encode()
        };

        let mut guard = self.state.lock().unwrap();
        guard.outbound.push_back(response);
        self.signal.notify_all();
    }
}

impl Transport for MockServer {
    fn send(&self, data: &[u8]) -> turn::Result<()> {
        self.respond(data);
        Ok(())
    }

    fn receive(&self) -> turn::Result<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        loop {
            if let Some(datagram) = guard.outbound.pop_front() {
                return Ok(datagram);
            }
            guard = self.signal.wait(guard).unwrap();
        }
    }

    fn is_stream(&self) -> bool {
        false
    }
}

#[test]
fn allocate_performs_challenge_then_resend() {
    let server = MockServer::new();
    let transport: Arc<dyn Transport> = server.clone();
    let credential = Credential::long_term("alice", "", "password");

    let mut client = turn::TurnClient::with_transport(transport, credential);
    let allocation = client
        .allocate(&AllocateOptions::default())
        .expect("allocate succeeds after challenge");

    assert_eq!(
        allocation.relayed_address(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)), 51000)
    );
    assert_eq!(
        allocation.mapped_address(),
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            40000
        ))
    );

    let state = server.state.lock().unwrap();
    assert_eq!(state.challenges, 1, "exactly one 401 challenge");
    assert_eq!(state.authed_allocates, 1, "exactly one authenticated retry");
}
