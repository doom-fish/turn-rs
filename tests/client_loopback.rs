mod common;

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use common::{
    data_indication, is_authenticated_request, lifetime_of, peer_address, relayed_address,
    requests_of, userhash_of, Server, Session, NONCE, PASSWORD, REALM, USER,
};
use stun::attribute::types;
use stun::{Attribute as StunAttribute, Class, Message};
use turn::auth::{Integrity, PasswordAlgorithm, PASSWORD_ALGORITHMS};
use turn::{AllocateOptions, ChannelData, Error, Method};

const FAST_RTO: Duration = Duration::from_millis(15);

fn allocated(server: &Server) -> turn::TurnClient {
    let mut client = server.client(PASSWORD);
    client.allocate(&AllocateOptions::default()).unwrap();
    client
}

fn is_request(request: &Message, method: Method) -> bool {
    request.class() == Class::Request && request.method() == method.to_stun()
}

fn nonce_of(request: &Message) -> Option<String> {
    match request.get(types::NONCE) {
        Some(StunAttribute::Nonce(nonce)) => Some(nonce.clone()),
        _ => None,
    }
}

#[test]
fn allocate_authenticates_every_step() {
    let server = Server::start(Session::standard);
    let mut client = server.client(PASSWORD);
    let allocation = client.allocate(&AllocateOptions::default()).unwrap();

    assert_eq!(allocation.relayed_address(), relayed_address());
    let requests = requests_of(&server.requests(), Method::Allocate);
    assert_eq!(requests.len(), 2);
    assert!(!is_authenticated_request(&requests[0]));
    assert!(requests[1].get(types::MESSAGE_INTEGRITY).is_some());
    assert!(requests[1].get(types::MESSAGE_INTEGRITY_SHA256).is_none());
    assert!(requests[1].verify_fingerprint().is_ok());
    assert!(server.with_session(|session| session.authenticated(&requests[1])));
    assert_eq!(client.auth_state().realm(), Some(REALM));
    assert_eq!(client.auth_state().nonce(), Some(NONCE));
    assert_eq!(client.auth_state().integrity(), Integrity::Sha1);
    assert_eq!(
        allocation.mapped_address().map(|a| a.ip()),
        Some([127, 0, 0, 1].into())
    );
}

#[test]
fn forged_allocate_success_is_ignored() {
    let attacker: SocketAddr = "198.51.100.66:9999".parse().unwrap();
    let server = Server::start(move |session, request| {
        if is_request(request, Method::Allocate) && session.authenticated(request) {
            session.forged_success(request, attacker, false);
            session.forged_success(request, attacker, true);
            thread::sleep(Duration::from_millis(30));
        }
        session.standard(request);
    });
    let mut client = server.client(PASSWORD);
    let allocation = client.allocate(&AllocateOptions::default()).unwrap();
    assert_eq!(allocation.relayed_address(), relayed_address());
    assert_eq!(
        client.allocation().unwrap().relayed_address(),
        relayed_address()
    );
}

#[test]
fn only_forged_successes_end_in_an_integrity_violation() {
    let attacker: SocketAddr = "198.51.100.66:9999".parse().unwrap();
    let server = Server::start(move |session, request| {
        if is_request(request, Method::Allocate) && is_authenticated_request(request) {
            session.forged_success(request, attacker, true);
        } else {
            session.standard(request);
        }
    });
    let mut client = server.client(PASSWORD);
    client.set_rto(FAST_RTO);
    let error = client.allocate(&AllocateOptions::default()).unwrap_err();
    assert!(matches!(error, Error::IntegrityViolation), "{error:?}");
    assert!(client.allocation().is_none());
}

#[test]
fn unauthenticated_success_to_the_first_request_is_ignored() {
    let attacker: SocketAddr = "198.51.100.66:9999".parse().unwrap();
    let server = Server::start(move |session, request| {
        if is_request(request, Method::Allocate) && !is_authenticated_request(request) {
            session.forged_success(request, attacker, false);
        }
        session.standard(request);
    });
    let mut client = server.client(PASSWORD);
    let allocation = client.allocate(&AllocateOptions::default()).unwrap();
    assert_eq!(allocation.relayed_address(), relayed_address());
}

#[test]
fn forged_stale_nonce_with_foreign_realm_is_ignored() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            session.error(
                request,
                438,
                vec![
                    StunAttribute::Realm("evil.test".to_owned()),
                    StunAttribute::Nonce("evil-nonce".to_owned()),
                ],
                false,
            );
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.refresh(Duration::from_secs(300)).unwrap();

    assert_eq!(client.auth_state().realm(), Some(REALM));
    assert_eq!(client.auth_state().nonce(), Some(NONCE));
    let refreshes = requests_of(&server.requests(), Method::Refresh);
    assert!(refreshes
        .iter()
        .all(|r| nonce_of(r).as_deref() == Some(NONCE)));
}

#[test]
fn forged_stale_nonce_does_not_replace_the_nonce() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            session.error(
                request,
                438,
                vec![
                    StunAttribute::Realm(REALM.to_owned()),
                    StunAttribute::Nonce("evil-nonce".to_owned()),
                ],
                false,
            );
            thread::sleep(Duration::from_millis(20));
            session.success(request);
            return;
        }
        if is_request(request, Method::Refresh) {
            return;
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.refresh(Duration::from_secs(300)).unwrap();
    assert_eq!(client.auth_state().realm(), Some(REALM));
    assert_eq!(client.auth_state().nonce(), Some(NONCE));
    let saw_forged_nonce = || {
        requests_of(&server.requests(), Method::Refresh)
            .iter()
            .any(|r| nonce_of(r).as_deref() == Some("evil-nonce"))
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while !saw_forged_nonce() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(saw_forged_nonce());

    let before = requests_of(&server.requests(), Method::Refresh).len();
    client.refresh(Duration::from_secs(300)).unwrap();
    let after = requests_of(&server.requests(), Method::Refresh);
    assert_eq!(nonce_of(&after[before]).as_deref(), Some(NONCE));
}

#[test]
fn genuine_stale_nonce_is_adopted_after_an_authenticated_retry() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.nonce == NONCE {
            session.nonce = "nonce-two".to_owned();
            session.error(
                request,
                438,
                vec![
                    StunAttribute::Realm(REALM.to_owned()),
                    StunAttribute::Nonce("nonce-two".to_owned()),
                ],
                false,
            );
            return;
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.refresh(Duration::from_secs(300)).unwrap();
    assert_eq!(client.auth_state().nonce(), Some("nonce-two"));
    assert_eq!(client.auth_state().realm(), Some(REALM));
}

#[test]
fn forged_unauthorized_after_allocation_is_ignored() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            session.error(
                request,
                401,
                vec![
                    StunAttribute::Realm("evil.test".to_owned()),
                    StunAttribute::Nonce("evil-nonce".to_owned()),
                ],
                false,
            );
            thread::sleep(Duration::from_millis(20));
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.refresh(Duration::from_secs(300)).unwrap();
    assert_eq!(client.auth_state().realm(), Some(REALM));
    assert_eq!(client.auth_state().nonce(), Some(NONCE));
}

#[test]
fn wrong_password_fails_without_waiting_for_the_timeout() {
    let server = Server::start(Session::standard);
    let mut client = server.client("wrong password");
    let started = Instant::now();
    let error = client.allocate(&AllocateOptions::default()).unwrap_err();
    assert!(matches!(error, Error::AuthFailed), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(client.auth_state().nonce().is_none());
}

#[test]
fn relayed_data_during_a_request_does_not_use_up_retransmissions() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            if session
                .requests
                .iter()
                .filter(|r| is_request(r, Method::Refresh))
                .count()
                == 1
            {
                for i in 0..40u8 {
                    session.data_indication(peer_address(), &[i]);
                }
                thread::sleep(Duration::from_millis(150));
                for i in 40..60u8 {
                    session.data_indication(peer_address(), &[i]);
                }
            }
            session.success(request);
            return;
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.create_permission(&[peer_address()]).unwrap();
    client.set_rto(Duration::from_millis(40));
    client.refresh(Duration::from_secs(300)).unwrap();

    for expected in 0..60u8 {
        let (from, payload) = client.recv(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(from, peer_address());
        assert_eq!(payload, vec![expected]);
    }
    assert_eq!(client.dropped_frames(), 0);
}

#[test]
fn pending_queue_is_bounded_and_counts_drops() {
    let server = Server::start(|session, request| {
        session.standard(request);
        if is_request(request, Method::CreatePermission) && session.authenticated(request) {
            for i in 0..10u8 {
                session.data_indication(peer_address(), &[i]);
            }
        }
    });
    let mut client = allocated(&server);
    client.set_pending_capacity(4);
    client.create_permission(&[peer_address()]).unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    while client.dropped_frames() < 6 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.dropped_frames(), 6);
    for expected in 6..10u8 {
        let (_, payload) = client.recv(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(payload, vec![expected]);
    }
    assert!(matches!(
        client.recv(Some(Duration::from_millis(50))),
        Err(Error::Timeout)
    ));
}

#[test]
fn malformed_frames_do_not_abort_a_request() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            session.send(b"\x00");
            session.send(b"not a TURN frame at all");
            session.send(&[0x40, 0x00, 0x00, 0x20, 1, 2, 3]);
            session.send(&[0x00, 0x01, 0x00, 0x04, 0x21, 0x12, 0xA4, 0x42]);
            let mut truncated = data_indication(peer_address(), b"payload");
            truncated.truncate(truncated.len() - 3);
            session.send(&truncated);
            session.send(&[0xFF; 32]);
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.refresh(Duration::from_secs(300)).unwrap();
    assert!(client.allocation().is_some());
}

#[test]
fn data_without_permission_or_binding_is_skipped() {
    let stranger: SocketAddr = "198.51.100.99:5000".parse().unwrap();
    let server = Server::start(move |session, request| {
        session.standard(request);
        if is_request(request, Method::CreatePermission) && session.authenticated(request) {
            session.data_indication(stranger, b"from a stranger");
            session.send(&ChannelData::encode(0x4abc, b"unbound channel").unwrap());
            session.data_indication(peer_address(), b"from the peer");
        }
    });
    let mut client = allocated(&server);
    client.create_permission(&[peer_address()]).unwrap();
    let (from, payload) = client.recv(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(from, peer_address());
    assert_eq!(payload, b"from the peer");
    assert!(matches!(
        client.recv(Some(Duration::from_millis(50))),
        Err(Error::Timeout)
    ));
}

#[test]
fn channel_data_on_a_bound_channel_is_delivered() {
    let server = Server::start(|session, request| {
        session.standard(request);
        if is_request(request, Method::ChannelBind) && session.authenticated(request) {
            session.send(&ChannelData::encode(0x4000, b"channel payload").unwrap());
        }
    });
    let mut client = allocated(&server);
    let channel = client.channel_bind(peer_address()).unwrap();
    assert_eq!(channel, 0x4000);
    let (from, payload) = client.recv(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(from, peer_address());
    assert_eq!(payload, b"channel payload");
}

#[test]
fn close_releases_the_allocation() {
    let server = Server::start(Session::standard);
    let mut client = allocated(&server);
    client.close(Duration::from_secs(2)).unwrap();

    let refreshes = requests_of(&server.requests(), Method::Refresh);
    assert_eq!(refreshes.len(), 1);
    assert_eq!(lifetime_of(&refreshes[0]), Some(0));
    assert!(server.with_session(|session| session.authenticated(&refreshes[0])));
    assert!(client.allocation().is_none());
    assert!(matches!(
        client.allocate(&AllocateOptions::default()),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn close_is_bounded_when_the_server_is_silent() {
    let server = Server::start(|session, request| {
        if !is_request(request, Method::Refresh) {
            session.standard(request);
        }
    });
    let mut client = allocated(&server);
    let started = Instant::now();
    let outcome = client.close(Duration::from_millis(300));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(matches!(outcome, Err(Error::Timeout)), "{outcome:?}");
    let refreshes = requests_of(&server.requests(), Method::Refresh);
    assert!(!refreshes.is_empty());
    assert!(refreshes.iter().all(|r| lifetime_of(r) == Some(0)));
}

#[test]
fn drop_is_bounded_when_the_server_is_silent() {
    let server = Server::start(|session, request| {
        if !is_request(request, Method::Refresh) {
            session.standard(request);
        }
    });
    let client = allocated(&server);
    let started = Instant::now();
    drop(client);
    assert!(
        started.elapsed() < turn::client::DROP_CLOSE_TIMEOUT + Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    assert!(!requests_of(&server.requests(), Method::Refresh).is_empty());
}

fn password_algorithms(entries: &[u16]) -> Vec<u8> {
    let mut value = Vec::new();
    for code in entries {
        value.extend_from_slice(&code.to_be_bytes());
        value.extend_from_slice(&[0, 0]);
    }
    value
}

#[test]
fn password_algorithms_negotiate_sha256() {
    let algorithms = password_algorithms(&[0x0002, 0x0001]);
    let server = Server::start_with(
        PASSWORD,
        Some(algorithms.clone()),
        "obMatJos2gAAAnonce",
        Box::new(Session::standard),
    );
    let mut client = server.client(PASSWORD);
    let allocation = client.allocate(&AllocateOptions::default()).unwrap();
    assert_eq!(allocation.relayed_address(), relayed_address());
    assert_eq!(
        client.auth_state().password_algorithm(),
        Some(PasswordAlgorithm::Sha256)
    );
    assert_eq!(client.auth_state().integrity(), Integrity::Sha256);

    let authenticated: Vec<Message> = requests_of(&server.requests(), Method::Allocate)
        .into_iter()
        .filter(is_authenticated_request)
        .collect();
    assert_eq!(authenticated.len(), 1);
    let request = &authenticated[0];
    assert!(request.get(types::MESSAGE_INTEGRITY).is_none());
    assert!(request.get(types::MESSAGE_INTEGRITY_SHA256).is_some());
    assert_eq!(
        request.get(PASSWORD_ALGORITHMS),
        Some(&StunAttribute::Unknown {
            attribute_type: PASSWORD_ALGORITHMS,
            value: algorithms,
        })
    );
    assert!(matches!(
        request.get(types::PASSWORD_ALGORITHM),
        Some(StunAttribute::PasswordAlgorithm(chosen)) if chosen.algorithm == 0x0002
    ));

    client.refresh(Duration::from_secs(300)).unwrap();
    let refresh = requests_of(&server.requests(), Method::Refresh).remove(0);
    assert!(refresh.get(types::MESSAGE_INTEGRITY_SHA256).is_some());
    assert!(refresh.get(types::MESSAGE_INTEGRITY).is_none());
}

#[test]
fn password_algorithms_prefers_the_servers_first_supported_entry() {
    let algorithms = password_algorithms(&[0x0077, 0x0001, 0x0002]);
    let server = Server::start_with(
        PASSWORD,
        Some(algorithms),
        "obMatJos2gAAAnonce",
        Box::new(Session::standard),
    );
    let mut client = server.client(PASSWORD);
    client.allocate(&AllocateOptions::default()).unwrap();
    assert_eq!(
        client.auth_state().password_algorithm(),
        Some(PasswordAlgorithm::Md5)
    );
    assert_eq!(client.auth_state().integrity(), Integrity::Sha256);
}

#[test]
fn stripped_password_algorithms_are_detected() {
    let server = Server::start_with(
        PASSWORD,
        None,
        "obMatJos2gAAAnonce",
        Box::new(Session::standard),
    );
    let mut client = server.client(PASSWORD);
    client.set_rto(FAST_RTO);
    let error = client.allocate(&AllocateOptions::default()).unwrap_err();
    assert!(matches!(error, Error::AuthFailed), "{error:?}");
    assert!(requests_of(&server.requests(), Method::Allocate)
        .iter()
        .all(|r| !is_authenticated_request(r)));
}

#[test]
fn unsupported_password_algorithms_are_refused() {
    let server = Server::start_with(
        PASSWORD,
        Some(password_algorithms(&[0x0003])),
        "obMatJos2gAAAnonce",
        Box::new(Session::standard),
    );
    let mut client = server.client(PASSWORD);
    client.set_rto(FAST_RTO);
    let error = client.allocate(&AllocateOptions::default()).unwrap_err();
    assert!(matches!(error, Error::AuthFailed), "{error:?}");
    assert!(requests_of(&server.requests(), Method::Allocate)
        .iter()
        .all(|r| !is_authenticated_request(r)));
}

#[test]
fn username_anonymity_sends_userhash() {
    let server = Server::start_with(
        PASSWORD,
        Some(password_algorithms(&[0x0002])),
        "obMatJos2wAAAnonce",
        Box::new(Session::standard),
    );
    let mut client = server.client(PASSWORD);
    client.allocate(&AllocateOptions::default()).unwrap();
    let request = requests_of(&server.requests(), Method::Allocate)
        .into_iter()
        .find(is_authenticated_request)
        .unwrap();
    assert!(request.get(types::USERNAME).is_none());
    assert_eq!(
        userhash_of(&request),
        Some(common::sha256(format!("{USER}:{REALM}").as_bytes()))
    );
}

#[test]
fn unbounded_timeouts_do_not_overflow() {
    let server = Server::start(|session, request| {
        session.standard(request);
        if is_request(request, Method::CreatePermission) && session.authenticated(request) {
            session.data_indication(peer_address(), b"late");
        }
    });
    let mut client = allocated(&server);
    client.create_permission(&[peer_address()]).unwrap();
    let (_, payload) = client.recv(Some(Duration::MAX)).unwrap();
    assert_eq!(payload, b"late");
    client.close(Duration::MAX).unwrap();
    assert!(requests_of(&server.requests(), Method::Refresh)
        .iter()
        .any(|r| lifetime_of(r) == Some(0)));
}

#[test]
fn allocation_mismatch_on_refresh_drops_the_allocation() {
    let server = Server::start(|session, request| {
        if is_request(request, Method::Refresh) && session.authenticated(request) {
            session.error(request, 437, Vec::new(), true);
            return;
        }
        session.standard(request);
    });
    let mut client = allocated(&server);
    client.create_permission(&[peer_address()]).unwrap();
    let error = client.refresh(Duration::from_secs(300)).unwrap_err();
    assert!(
        matches!(error, Error::Server { code: 437, .. }),
        "{error:?}"
    );
    assert!(client.allocation().is_none());
    assert!(client.permissions().is_empty());
    assert_eq!(client.next_maintenance(), None);
}
