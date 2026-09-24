use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use stun::{Attribute as StunAttribute, Class, ErrorCode, Message, TransactionId};
use turn::attribute::xor_key;
use turn::auth::{AuthState, Integrity, PasswordAlgorithm, PASSWORD_ALGORITHMS};
use turn::{AllocateOptions, Attribute, Credential, Error, Method, Transport, TurnClient};

fn error_response(
    code: u16,
    realm: Option<&str>,
    nonce: &str,
    algorithms: Option<&[u8]>,
) -> Message {
    let mut builder = Message::builder(Method::Allocate.to_stun(), Class::ErrorResponse)
        .transaction_id(TransactionId::try_random().unwrap())
        .attribute(StunAttribute::ErrorCode(ErrorCode::new(code, "challenge")));
    if let Some(realm) = realm {
        builder = builder.attribute(StunAttribute::Realm(realm.to_owned()));
    }
    builder = builder.attribute(StunAttribute::Nonce(nonce.to_owned()));
    if let Some(value) = algorithms {
        builder = builder.attribute(StunAttribute::Unknown {
            attribute_type: PASSWORD_ALGORITHMS,
            value: value.to_vec(),
        });
    }
    Message::decode(&builder.build_and_encode().unwrap()).unwrap()
}

fn sha256(input: &str) -> Vec<u8> {
    cryptokit::hashing::sha256(input.as_bytes()).unwrap()
}

const SHA256_ONLY: [u8; 4] = [0x00, 0x02, 0x00, 0x00];

#[test]
fn auth_state_starts_empty() {
    let state = AuthState::new();
    assert!(!state.is_ready());
    assert_eq!(state.realm(), None);
    assert_eq!(state.nonce(), None);
    assert_eq!(state.key(), None);
    assert_eq!(state.password_algorithm(), None);
}

#[test]
fn challenge_makes_state_ready() {
    let cred = Credential::long_term("alice", "", "password");
    let state = AuthState::from_challenge(
        &cred,
        &error_response(401, Some("example.org"), "nonce-1", None),
    )
    .unwrap();
    assert!(state.is_ready());
    assert_eq!(state.realm(), Some("example.org"));
    assert_eq!(state.nonce(), Some("nonce-1"));
    let expected = stun::auth::long_term_key("alice", "example.org", "password");
    assert_eq!(state.key(), Some(expected.as_slice()));
    assert_eq!(state.integrity(), Integrity::Sha1);
    assert_eq!(state.password_algorithm(), None);
}

#[test]
fn challenge_without_realm_or_nonce_is_refused() {
    let cred = Credential::long_term("alice", "", "password");
    let no_realm = error_response(401, None, "nonce-1", None);
    assert!(matches!(
        AuthState::from_challenge(&cred, &no_realm),
        Err(Error::MissingChallenge)
    ));
}

#[test]
fn pinned_realm_refuses_a_different_challenge_realm() {
    let cred = Credential::long_term("alice", "pinned.example", "password");
    let challenge = error_response(401, Some("example.org"), "nonce-1", None);
    assert!(matches!(
        AuthState::from_challenge(&cred, &challenge),
        Err(Error::AuthFailed)
    ));
    let matching = error_response(401, Some("pinned.example"), "nonce-1", None);
    assert_eq!(
        AuthState::from_challenge(&cred, &matching).unwrap().realm(),
        Some("pinned.example")
    );
}

#[test]
fn stale_nonce_updates_only_the_nonce() {
    let cred = Credential::long_term("alice", "", "password");
    let state = AuthState::from_challenge(
        &cred,
        &error_response(401, Some("example.org"), "nonce-1", None),
    )
    .unwrap();
    let next = state
        .with_stale_nonce(&error_response(438, Some("example.org"), "nonce-2", None))
        .unwrap();
    assert_eq!(next.nonce(), Some("nonce-2"));
    assert_eq!(next.realm(), Some("example.org"));
    assert_eq!(next.key(), state.key());
    assert_eq!(state.nonce(), Some("nonce-1"));
}

#[test]
fn stale_nonce_cannot_change_the_realm() {
    let cred = Credential::long_term("alice", "", "password");
    let state = AuthState::from_challenge(
        &cred,
        &error_response(401, Some("example.org"), "nonce-1", None),
    )
    .unwrap();
    let forged = error_response(438, Some("evil.example"), "nonce-2", None);
    assert!(matches!(
        state.with_stale_nonce(&forged),
        Err(Error::AuthFailed)
    ));
}

#[test]
fn stale_nonce_before_any_challenge_is_refused() {
    let stale = error_response(438, Some("example.org"), "nonce-2", None);
    assert!(matches!(
        AuthState::new().with_stale_nonce(&stale),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn sha256_key_follows_rfc_8489() {
    let cred = Credential::long_term("alice", "", "password");
    let challenge = error_response(
        401,
        Some("example.org"),
        "obMatJos2gAAAxyz",
        Some(&SHA256_ONLY),
    );
    let state = AuthState::from_challenge(&cred, &challenge).unwrap();
    assert_eq!(state.password_algorithm(), Some(PasswordAlgorithm::Sha256));
    assert_eq!(state.integrity(), Integrity::Sha256);
    assert_eq!(
        state.key(),
        Some(sha256("alice:example.org:password").as_slice())
    );
    assert_eq!(
        cred.long_term_key(PasswordAlgorithm::Sha256, "example.org")
            .unwrap()
            .as_slice(),
        sha256("alice:example.org:password").as_slice()
    );
}

#[test]
fn stale_nonce_must_repeat_the_password_algorithms() {
    let cred = Credential::long_term("alice", "", "password");
    let challenge = error_response(
        401,
        Some("example.org"),
        "obMatJos2gAAAxyz",
        Some(&SHA256_ONLY),
    );
    let state = AuthState::from_challenge(&cred, &challenge).unwrap();
    let stripped = error_response(438, Some("example.org"), "obMatJos2gAAAnew", None);
    assert!(matches!(
        state.with_stale_nonce(&stripped),
        Err(Error::PasswordAlgorithms(_))
    ));
    let changed = error_response(
        438,
        Some("example.org"),
        "obMatJos2gAAAnew",
        Some(&[0x00, 0x01, 0x00, 0x00]),
    );
    assert!(matches!(
        state.with_stale_nonce(&changed),
        Err(Error::PasswordAlgorithms(_))
    ));
    let repeated = error_response(
        438,
        Some("example.org"),
        "obMatJos2gAAAnew",
        Some(&SHA256_ONLY),
    );
    assert_eq!(
        state.with_stale_nonce(&repeated).unwrap().nonce(),
        Some("obMatJos2gAAAnew")
    );
}

#[test]
fn password_algorithms_parameters_are_skipped_with_padding() {
    let cred = Credential::long_term("alice", "", "password");
    let value = [
        0x00, 0x09, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    let challenge = error_response(401, Some("example.org"), "obMatJos2gAAAxyz", Some(&value));
    let state = AuthState::from_challenge(&cred, &challenge).unwrap();
    assert_eq!(state.password_algorithm(), Some(PasswordAlgorithm::Md5));
    let truncated = error_response(
        401,
        Some("example.org"),
        "obMatJos2gAAAxyz",
        Some(&[0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]),
    );
    assert!(matches!(
        AuthState::from_challenge(&cred, &truncated),
        Err(Error::PasswordAlgorithms(_))
    ));
}

#[test]
fn debug_output_never_contains_secrets() {
    let cred = Credential::long_term("alice", "example.org", "hunter2-secret");
    let printed = format!("{cred:?}");
    assert!(!printed.contains("hunter2-secret"), "{printed}");
    assert!(printed.contains("<redacted>"));
    assert!(printed.contains("alice"));

    let state = AuthState::from_challenge(
        &cred,
        &error_response(401, Some("example.org"), "nonce-1", None),
    )
    .unwrap();
    let key_hex: String = state
        .key()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key_bytes = format!("{:?}", state.key().unwrap());
    let printed = format!("{state:?}");
    assert!(!printed.contains(&key_hex), "{printed}");
    assert!(!printed.contains(&key_bytes), "{printed}");
    assert!(printed.contains("nonce-1"));
}

struct MemoryServer {
    state: Mutex<MemoryState>,
    signal: Condvar,
}

struct MemoryState {
    outbound: VecDeque<Vec<u8>>,
    closed: bool,
    challenges: usize,
    authed_allocates: usize,
}

const REALM: &str = "relay.example.org";
const NONCE: &str = "abc123nonce";

impl MemoryServer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(MemoryState {
                outbound: VecDeque::new(),
                closed: false,
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
        let long_term = stun::auth::long_term_key("alice", REALM, "password");
        let authed = message.verify_message_integrity(&long_term).is_ok();
        let method = message.method();

        let response = if !authed {
            self.state.lock().unwrap().challenges += 1;
            Message::builder(method, Class::ErrorResponse)
                .transaction_id(tid)
                .attribute(StunAttribute::ErrorCode(ErrorCode::new(
                    401,
                    "Unauthorized",
                )))
                .attribute(StunAttribute::Realm(REALM.to_owned()))
                .attribute(StunAttribute::Nonce(NONCE.to_owned()))
                .build_and_encode()
                .unwrap()
        } else if method == Method::Allocate.to_stun() {
            self.state.lock().unwrap().authed_allocates += 1;
            let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)), 51000);
            let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 40000);
            Message::builder(method, Class::SuccessResponse)
                .transaction_id(tid)
                .attribute(Attribute::XorRelayedAddress(relayed).to_stun(&key))
                .attribute(StunAttribute::XorMappedAddress(mapped))
                .attribute(Attribute::Lifetime(600).to_stun(&key))
                .with_message_integrity_sha1(&long_term)
                .build_and_encode()
                .unwrap()
        } else {
            Message::builder(method, Class::SuccessResponse)
                .transaction_id(tid)
                .attribute(Attribute::Lifetime(0).to_stun(&key))
                .with_message_integrity_sha1(&long_term)
                .build_and_encode()
                .unwrap()
        };

        let mut guard = self.state.lock().unwrap();
        guard.outbound.push_back(response);
        self.signal.notify_all();
    }
}

impl Transport for MemoryServer {
    fn send(&self, data: &[u8]) -> turn::Result<()> {
        self.respond(data);
        Ok(())
    }

    fn receive(&self) -> turn::Result<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        loop {
            if guard.closed {
                return Err(Error::Network("closed".into()));
            }
            if let Some(datagram) = guard.outbound.pop_front() {
                return Ok(datagram);
            }
            guard = self.signal.wait(guard).unwrap();
        }
    }

    fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.signal.notify_all();
    }

    fn is_stream(&self) -> bool {
        false
    }
}

#[test]
fn allocate_performs_challenge_then_resend() {
    let server = MemoryServer::new();
    let transport: Arc<dyn Transport> = server.clone();
    let credential = Credential::long_term("alice", "", "password");

    let mut client = TurnClient::with_transport(transport, credential).unwrap();
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

#[test]
fn close_stops_the_receiver_thread() {
    let server = MemoryServer::new();
    let transport: Arc<dyn Transport> = server.clone();
    let mut client =
        TurnClient::with_transport(transport, Credential::long_term("alice", "", "password"))
            .unwrap();
    client.allocate(&AllocateOptions::default()).unwrap();
    assert_eq!(Arc::strong_count(&server), 3);

    client.close(Duration::from_secs(1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while Arc::strong_count(&server) > 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(Arc::strong_count(&server), 2);
    assert!(server.state.lock().unwrap().closed);
    drop(client);
    assert_eq!(Arc::strong_count(&server), 1);
}

#[test]
fn dropping_the_client_releases_the_transport() {
    let server = MemoryServer::new();
    let transport: Arc<dyn Transport> = server.clone();
    let client =
        TurnClient::with_transport(transport, Credential::long_term("alice", "", "password"))
            .unwrap();
    drop(client);
    assert_eq!(Arc::strong_count(&server), 1);
}

struct ForgingStream {
    state: Mutex<(VecDeque<Vec<u8>>, bool, usize)>,
    signal: Condvar,
}

impl Transport for ForgingStream {
    fn send(&self, data: &[u8]) -> turn::Result<()> {
        let request = Message::decode(data).unwrap();
        let tid = *request.transaction_id();
        let authenticated = request
            .get(stun::attribute::types::MESSAGE_INTEGRITY)
            .is_some();
        let response = if authenticated {
            let key = xor_key(tid.as_bytes());
            let forged: SocketAddr = "198.51.100.66:9999".parse().unwrap();
            Message::builder(request.method(), Class::SuccessResponse)
                .transaction_id(tid)
                .attribute(Attribute::XorRelayedAddress(forged).to_stun(&key))
                .build_and_encode()
                .unwrap()
        } else {
            Message::builder(request.method(), Class::ErrorResponse)
                .transaction_id(tid)
                .attribute(StunAttribute::ErrorCode(ErrorCode::new(
                    401,
                    "Unauthorized",
                )))
                .attribute(StunAttribute::Realm(REALM.to_owned()))
                .attribute(StunAttribute::Nonce(NONCE.to_owned()))
                .build_and_encode()
                .unwrap()
        };
        let mut state = self.state.lock().unwrap();
        state.2 += usize::from(authenticated);
        state.0.push_back(response);
        self.signal.notify_all();
        Ok(())
    }

    fn receive(&self) -> turn::Result<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.1 {
                return Err(Error::Network("closed".into()));
            }
            if let Some(frame) = state.0.pop_front() {
                return Ok(frame);
            }
            state = self.signal.wait(state).unwrap();
        }
    }

    fn close(&self) {
        self.state.lock().unwrap().1 = true;
        self.signal.notify_all();
    }

    fn is_stream(&self) -> bool {
        true
    }
}

#[test]
fn stream_transport_ends_on_the_first_unauthenticated_response() {
    let transport = Arc::new(ForgingStream {
        state: Mutex::new((VecDeque::new(), false, 0)),
        signal: Condvar::new(),
    });
    let mut client = TurnClient::with_transport(
        transport.clone(),
        Credential::long_term("alice", "", "password"),
    )
    .unwrap();
    let started = Instant::now();
    let error = client.allocate(&AllocateOptions::default()).unwrap_err();
    assert!(matches!(error, Error::IntegrityViolation), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(transport.state.lock().unwrap().2, 1);
}
