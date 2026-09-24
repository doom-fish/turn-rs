#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use stun::attribute::types;
use stun::{Attribute as StunAttribute, Class, ErrorCode, Message, TransactionId};
use turn::attribute::xor_key;
use turn::auth::{PASSWORD_ALGORITHMS, USERHASH};
use turn::{Attribute, Credential, Method, TurnClient, TurnUri};

pub const USER: &str = "alice";
pub const PASSWORD: &str = "correct horse battery staple";
pub const REALM: &str = "relay.test";
pub const NONCE: &str = "nonce-one";

pub fn relayed_address() -> SocketAddr {
    "192.0.2.33:51000".parse().unwrap()
}

pub fn peer_address() -> SocketAddr {
    "203.0.113.7:4000".parse().unwrap()
}

pub fn sha256(input: &[u8]) -> Vec<u8> {
    cryptokit::hashing::sha256(input).unwrap()
}

pub struct Session {
    socket: UdpSocket,
    pub client: Option<SocketAddr>,
    pub realm: String,
    pub nonce: String,
    pub password: String,
    pub algorithms: Option<Vec<u8>>,
    pub requests: Vec<Message>,
}

impl Session {
    pub fn md5_key(&self) -> Vec<u8> {
        stun::auth::long_term_key(USER, &self.realm, &self.password).to_vec()
    }

    pub fn sha256_key(&self) -> Vec<u8> {
        sha256(format!("{USER}:{}:{}", self.realm, self.password).as_bytes())
    }

    fn uses_sha256(request: &Message) -> bool {
        request.get(types::MESSAGE_INTEGRITY_SHA256).is_some()
    }

    fn key_for(&self, request: &Message) -> Vec<u8> {
        match request.get(types::PASSWORD_ALGORITHM) {
            Some(StunAttribute::PasswordAlgorithm(algorithm)) if algorithm.algorithm == 0x0002 => {
                self.sha256_key()
            }
            _ => self.md5_key(),
        }
    }

    pub fn authenticated(&self, request: &Message) -> bool {
        let nonce_ok =
            matches!(request.get(types::NONCE), Some(StunAttribute::Nonce(n)) if *n == self.nonce);
        let key = self.key_for(request);
        let mac_ok = if Self::uses_sha256(request) {
            request.verify_message_integrity_sha256(&key).is_ok()
        } else {
            request.verify_message_integrity(&key).is_ok()
        };
        nonce_ok && mac_ok
    }

    pub fn send(&self, bytes: &[u8]) {
        if let Some(client) = self.client {
            self.socket.send_to(bytes, client).unwrap();
        }
    }

    pub fn build(
        &self,
        request: &Message,
        class: Class,
        attributes: Vec<StunAttribute>,
        integrity: bool,
    ) -> Vec<u8> {
        let mut builder =
            Message::builder(request.method(), class).transaction_id(*request.transaction_id());
        for attribute in attributes {
            builder = builder.attribute(attribute);
        }
        if integrity {
            let key = self.key_for(request);
            builder = if Self::uses_sha256(request) {
                builder.with_message_integrity_sha256(&key)
            } else {
                builder.with_message_integrity_sha1(&key)
            };
        }
        builder.with_fingerprint().build_and_encode().unwrap()
    }

    pub fn challenge(&self, request: &Message) {
        let mut attributes = vec![
            StunAttribute::ErrorCode(ErrorCode::new(401, "Unauthorized")),
            StunAttribute::Realm(self.realm.clone()),
            StunAttribute::Nonce(self.nonce.clone()),
        ];
        if let Some(value) = &self.algorithms {
            attributes.push(StunAttribute::Unknown {
                attribute_type: PASSWORD_ALGORITHMS,
                value: value.clone(),
            });
        }
        self.send(&self.build(request, Class::ErrorResponse, attributes, false));
    }

    pub fn error(&self, request: &Message, code: u16, extra: Vec<StunAttribute>, integrity: bool) {
        let mut attributes = vec![StunAttribute::ErrorCode(ErrorCode::new(code, "Error"))];
        attributes.extend(extra);
        self.send(&self.build(request, Class::ErrorResponse, attributes, integrity));
    }

    pub fn success(&self, request: &Message) {
        let key = xor_key(request.transaction_id().as_bytes());
        let method = request.method();
        let mut attributes = Vec::new();
        if method == Method::Allocate.to_stun() {
            attributes.push(Attribute::XorRelayedAddress(relayed_address()).to_stun(&key));
            attributes.push(StunAttribute::XorMappedAddress(self.client.unwrap()));
            attributes.push(Attribute::Lifetime(600).to_stun(&key));
        } else if method == Method::Refresh.to_stun() {
            let lifetime = lifetime_of(request).unwrap_or(600);
            attributes.push(Attribute::Lifetime(lifetime).to_stun(&key));
        }
        self.send(&self.build(request, Class::SuccessResponse, attributes, true));
    }

    pub fn forged_success(&self, request: &Message, relayed: SocketAddr, wrong_key: bool) {
        let key = xor_key(request.transaction_id().as_bytes());
        let mut builder = Message::builder(request.method(), Class::SuccessResponse)
            .transaction_id(*request.transaction_id())
            .attribute(Attribute::XorRelayedAddress(relayed).to_stun(&key))
            .attribute(Attribute::Lifetime(3600).to_stun(&key));
        if wrong_key {
            builder = builder.with_message_integrity_sha1(b"not the long-term key");
        }
        self.send(&builder.with_fingerprint().build_and_encode().unwrap());
    }

    pub fn data_indication(&self, peer: SocketAddr, payload: &[u8]) {
        self.send(&data_indication(peer, payload));
    }

    pub fn standard(&mut self, request: &Message) {
        if request.class() != Class::Request {
            return;
        }
        if self.authenticated(request) {
            self.success(request);
        } else {
            self.challenge(request);
        }
    }
}

pub fn data_indication(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let tid = TransactionId::try_random().unwrap();
    let key = xor_key(tid.as_bytes());
    Message::builder(Method::Data.to_stun(), Class::Indication)
        .transaction_id(tid)
        .attribute(Attribute::XorPeerAddress(peer).to_stun(&key))
        .attribute(Attribute::Data(payload.to_vec()).to_stun(&key))
        .build_and_encode()
        .unwrap()
}

pub fn lifetime_of(request: &Message) -> Option<u32> {
    let key = xor_key(request.transaction_id().as_bytes());
    request
        .attributes()
        .iter()
        .find_map(|attr| match Attribute::from_stun(attr, &key) {
            Ok(Some(Attribute::Lifetime(secs))) => Some(secs),
            _ => None,
        })
}

pub fn userhash_of(request: &Message) -> Option<Vec<u8>> {
    match request.get(USERHASH) {
        Some(StunAttribute::Unknown { value, .. }) => Some(value.clone()),
        _ => None,
    }
}

type Handler = Box<dyn FnMut(&mut Session, &Message) + Send>;

pub struct Server {
    pub addr: SocketAddr,
    session: Arc<Mutex<Session>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(handler: impl FnMut(&mut Session, &Message) + Send + 'static) -> Self {
        Self::start_with(PASSWORD, None, NONCE, Box::new(handler))
    }

    pub fn start_with(
        password: &str,
        algorithms: Option<Vec<u8>>,
        nonce: &str,
        mut handler: Handler,
    ) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let session = Arc::new(Mutex::new(Session {
            socket: socket.try_clone().unwrap(),
            client: None,
            realm: REALM.to_owned(),
            nonce: nonce.to_owned(),
            password: password.to_owned(),
            algorithms,
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let session = Arc::clone(&session);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::SeqCst) {
                    let (n, from) = match socket.recv_from(&mut buf) {
                        Ok(received) => received,
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                        {
                            continue
                        }
                        Err(e) => panic!("fake TURN server receive failed: {e}"),
                    };
                    let Ok(message) = Message::decode(&buf[..n]) else {
                        continue;
                    };
                    let mut session = session.lock().unwrap();
                    session.client = Some(from);
                    session.requests.push(message.clone());
                    handler(&mut session, &message);
                }
            })
        };
        Self {
            addr,
            session,
            stop,
            handle: Some(handle),
        }
    }

    pub fn uri(&self) -> TurnUri {
        format!("turn:127.0.0.1:{}", self.addr.port())
            .parse()
            .unwrap()
    }

    pub fn client(&self, password: &str) -> TurnClient {
        TurnClient::connect(self.uri(), Credential::long_term(USER, "", password)).unwrap()
    }

    pub fn requests(&self) -> Vec<Message> {
        self.session.lock().unwrap().requests.clone()
    }

    pub fn with_session<R>(&self, f: impl FnOnce(&mut Session) -> R) -> R {
        f(&mut self.session.lock().unwrap())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn requests_of(requests: &[Message], method: Method) -> Vec<Message> {
    requests
        .iter()
        .filter(|m| m.method() == method.to_stun() && m.class() == Class::Request)
        .cloned()
        .collect()
}

pub fn is_authenticated_request(message: &Message) -> bool {
    message.get(types::MESSAGE_INTEGRITY).is_some()
        || message.get(types::MESSAGE_INTEGRITY_SHA256).is_some()
}
