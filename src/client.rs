//! Synchronous TURN client (`TurnClient`) over a pluggable transport.
//!
//! [`TurnClient`] drives the full client side of RFC 5766 / RFC 8656:
//! `Allocate`, `Refresh`, `CreatePermission`, `ChannelBind`, `Send`/`Data`
//! indications, and ChannelData framing. It is fully synchronous — no async
//! runtime is pulled in. A background receiver thread sorts inbound packets so
//! the caller can drive RFC 5389 retransmission timers (reused from `stun-rs`)
//! without blocking forever on the callback-based Network.framework receive
//! primitive.
//!
//! Control responses go to the transaction waiting for them, matched by
//! transaction ID and accepted only once `MESSAGE-INTEGRITY` (or
//! `MESSAGE-INTEGRITY-SHA256`) verifies with the long-term key. `Data`
//! indications and ChannelData frames, told apart by the leading-bytes rule of
//! [`crate::channel::classify`], go to a bounded pending queue that
//! [`TurnClient::recv`] drains; when it is full the oldest frame is dropped and
//! counted.

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stun::attribute::types as stun_types;
use stun::transaction::{RetransmitSchedule, DEFAULT_RTO};
use stun::{Attribute as StunAttribute, Class, Message, TransactionId};

use crate::allocation::{Allocation, DEFAULT_LIFETIME};
use crate::attribute::{self, AddressFamily, Attribute, EvenPort, PROTOCOL_UDP};
use crate::auth::{self, AuthState, Credential};
use crate::channel::{self, ChannelData, PacketKind, MAX_CHANNEL, MIN_CHANNEL};
use crate::channel_binding::ChannelBinding;
use crate::error::{Error, Result};
use crate::indication;
use crate::method::Method;
use crate::permission::Permission;
use crate::transport::{tcp::TcpTransport, tls::TlsTransport, udp::UdpTransport, Transport};

/// Default TURN port for `turn:` over UDP/TCP (RFC 5766 §6).
pub const DEFAULT_TURN_PORT: u16 = 3478;
/// Default TURN port for `turns:` over TLS (RFC 5766 §6).
pub const DEFAULT_TURNS_PORT: u16 = 5349;

/// The maximum number of authentication retries for a single transaction
/// (initial unauthenticated attempt, then `401` and `438` re-sends).
const MAX_AUTH_ATTEMPTS: usize = 5;

#[allow(missing_docs)]
pub const DEFAULT_PENDING_CAPACITY: usize = 256;

#[allow(missing_docs)]
pub const DROP_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

const RESPONSE_CAPACITY: usize = 32;
const RECEIVER_GRACE: Duration = Duration::from_millis(100);
const RESERVED_ATTRIBUTES: [u16; 7] = [0x0000, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x000B];

/// The transport scheme selected by a TURN URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `turn:` over UDP (the default).
    Udp,
    /// `turn:` over TCP (`?transport=tcp`).
    Tcp,
    /// `turns:` over TLS.
    Tls,
}

/// A parsed TURN URI (RFC 7065): `turn:host:port` or `turns:host:port`, with an
/// optional `?transport=udp|tcp` query selecting the transport for `turn:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnUri {
    /// The server host (DNS name or IP literal).
    pub host: String,
    /// The server port.
    pub port: u16,
    /// The selected transport scheme.
    pub scheme: Scheme,
}

impl FromStr for TurnUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (secure, rest) = if let Some(rest) = s.strip_prefix("turns:") {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix("turn:") {
            (false, rest)
        } else {
            return Err(Error::InvalidUri(s.to_owned()));
        };

        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };

        let want_tcp = query
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("transport=")))
            .map(|t| t.eq_ignore_ascii_case("tcp"))
            .unwrap_or(false);

        let default_port = if secure {
            DEFAULT_TURNS_PORT
        } else {
            DEFAULT_TURN_PORT
        };
        let (host, port) = split_host_port(authority, default_port)?;

        let scheme = if secure {
            Scheme::Tls
        } else if want_tcp {
            Scheme::Tcp
        } else {
            Scheme::Udp
        };

        Ok(Self { host, port, scheme })
    }
}

/// Split a `host:port` (or bare `host`) authority. Bracketed IPv6 literals
/// (`[::1]:3478`) are supported.
fn split_host_port(input: &str, default_port: u16) -> Result<(String, u16)> {
    if input.is_empty() {
        return Err(Error::InvalidUri(input.to_owned()));
    }
    if let Some(after_bracket) = input.strip_prefix('[') {
        let (host, tail) = after_bracket
            .split_once(']')
            .ok_or_else(|| Error::InvalidUri(input.to_owned()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| Error::InvalidUri(input.to_owned()))?,
            None => default_port,
        };
        return Ok((host.to_owned(), port));
    }
    match input.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| Error::InvalidUri(input.to_owned()))?;
            Ok((host.to_owned(), port))
        }
        None => Ok((input.to_owned(), default_port)),
    }
}

/// Options controlling an `Allocate` request (RFC 5766 §6, RFC 8656).
#[derive(Debug, Clone)]
pub struct AllocateOptions {
    /// The desired allocation lifetime.
    pub lifetime: Duration,
    /// The `REQUESTED-TRANSPORT` protocol number (UDP = 17, the default).
    pub requested_transport: u8,
    /// An optional `REQUESTED-ADDRESS-FAMILY` (RFC 6156).
    pub address_family: Option<AddressFamily>,
    /// An optional `ADDITIONAL-ADDRESS-FAMILY` for a dual-stack allocation
    /// (RFC 8656).
    pub additional_address_family: Option<AddressFamily>,
    /// An optional `EVEN-PORT` request.
    pub even_port: Option<EvenPort>,
    /// Set the `DONT-FRAGMENT` attribute.
    pub dont_fragment: bool,
    /// An optional `RESERVATION-TOKEN` from a prior `EVEN-PORT` reservation.
    pub reservation_token: Option<[u8; 8]>,
}

impl Default for AllocateOptions {
    fn default() -> Self {
        Self {
            lifetime: DEFAULT_LIFETIME,
            requested_transport: PROTOCOL_UDP,
            address_family: None,
            additional_address_family: None,
            even_port: None,
            dont_fragment: false,
            reservation_token: None,
        }
    }
}

enum Relayed {
    Data(SocketAddr, Vec<u8>),
    Channel(Vec<u8>),
}

struct InboxState {
    responses: VecDeque<Message>,
    pending: VecDeque<Relayed>,
    capacity: usize,
    dropped: u64,
    closed: Option<String>,
}

impl InboxState {
    fn stash(&mut self, relayed: Relayed) {
        if self.capacity == 0 {
            self.dropped += 1;
            return;
        }
        while self.pending.len() >= self.capacity {
            self.pending.pop_front();
            self.dropped += 1;
        }
        self.pending.push_back(relayed);
    }
}

struct Inbox {
    state: Mutex<InboxState>,
    ready: Condvar,
}

impl Inbox {
    fn new() -> Self {
        Self {
            state: Mutex::new(InboxState {
                responses: VecDeque::new(),
                pending: VecDeque::new(),
                capacity: DEFAULT_PENDING_CAPACITY,
                dropped: 0,
                closed: None,
            }),
            ready: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, InboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn deliver(&self, datagram: &[u8]) {
        let mut state = self.lock();
        match channel::classify(datagram) {
            PacketKind::ChannelData => state.stash(Relayed::Channel(datagram.to_vec())),
            PacketKind::Stun => match Message::decode(datagram) {
                Ok(message)
                    if matches!(
                        message.class(),
                        Class::SuccessResponse | Class::ErrorResponse
                    ) =>
                {
                    if state.responses.len() >= RESPONSE_CAPACITY {
                        state.responses.pop_front();
                    }
                    state.responses.push_back(message);
                }
                Ok(message) => match indication::decode_data(&message) {
                    Ok(Some((peer, data))) => state.stash(Relayed::Data(peer, data)),
                    _ => return,
                },
                Err(_) => return,
            },
            PacketKind::Unknown => return,
        }
        drop(state);
        self.ready.notify_all();
    }

    fn close(&self, reason: String) {
        self.lock().closed.get_or_insert(reason);
        self.ready.notify_all();
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, InboxState>,
        deadline: Option<Instant>,
    ) -> Option<MutexGuard<'a, InboxState>> {
        match deadline {
            None => Some(
                self.ready
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner),
            ),
            Some(deadline) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())?;
                Some(
                    self.ready
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0,
                )
            }
        }
    }
}

struct Attempt {
    transaction_id: TransactionId,
    auth: AuthState,
}

enum Reply {
    Accepted { attempt: usize, message: Message },
    Retry(AuthState),
}

enum Judgement {
    Accept,
    Retry(AuthState),
    Reject,
    Discard { rejection: bool },
    Fail(Error),
}

/// A synchronous TURN client bound to a single server connection.
pub struct TurnClient {
    transport: Arc<dyn Transport>,
    inbox: Arc<Inbox>,
    receiver: Option<JoinHandle<()>>,
    credential: Credential,
    auth: AuthState,
    allocation: Option<Allocation>,
    permissions: Vec<Permission>,
    bindings: Vec<ChannelBinding>,
    next_channel: u16,
    rto: Duration,
    closed: bool,
}

impl fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnClient")
            .field("allocation", &self.allocation)
            .field("permissions", &self.permissions.len())
            .field("bindings", &self.bindings.len())
            .field("auth", &self.auth)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl TurnClient {
    /// Connect to a TURN server identified by `uri`, using `credential` for the
    /// mandatory long-term authentication. The transport (UDP, TCP, or TLS) is
    /// selected by the URI scheme.
    ///
    /// This opens the connection and starts the receiver thread but does not
    /// yet allocate; call [`TurnClient::allocate`] next.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the connection cannot be established.
    pub fn connect(uri: TurnUri, credential: Credential) -> Result<Self> {
        let transport: Arc<dyn Transport> = match uri.scheme {
            Scheme::Udp => Arc::new(UdpTransport::connect(&uri.host, uri.port)?),
            Scheme::Tcp => Arc::new(TcpTransport::connect(&uri.host, uri.port)?),
            Scheme::Tls => Arc::new(TlsTransport::connect(&uri.host, uri.port)?),
        };
        Self::with_transport(transport, credential)
    }

    /// Construct a client over an already-established [`Transport`]. Useful for
    /// testing with an in-memory transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the receiver thread cannot be started.
    pub fn with_transport(transport: Arc<dyn Transport>, credential: Credential) -> Result<Self> {
        let inbox = Arc::new(Inbox::new());
        let receiver = spawn_receiver(Arc::clone(&transport), Arc::clone(&inbox))?;
        Ok(Self {
            transport,
            inbox,
            receiver: Some(receiver),
            credential,
            auth: AuthState::new(),
            allocation: None,
            permissions: Vec::new(),
            bindings: Vec::new(),
            next_channel: MIN_CHANNEL,
            rto: DEFAULT_RTO,
            closed: false,
        })
    }

    #[allow(missing_docs)]
    pub fn set_rto(&mut self, rto: Duration) {
        self.rto = rto;
    }

    #[allow(missing_docs)]
    pub fn set_pending_capacity(&mut self, capacity: usize) {
        let mut state = self.inbox.lock();
        state.capacity = capacity;
        while state.pending.len() > capacity {
            state.pending.pop_front();
            state.dropped += 1;
        }
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn dropped_frames(&self) -> u64 {
        self.inbox.lock().dropped
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn auth_state(&self) -> &AuthState {
        &self.auth
    }

    /// The current allocation, if one has been obtained.
    #[must_use]
    pub const fn allocation(&self) -> Option<&Allocation> {
        self.allocation.as_ref()
    }

    /// Request a relayed transport address from the server.
    ///
    /// Performs the full long-term-auth handshake: the first request is
    /// unauthenticated, the `401` challenge supplies `REALM`/`NONCE`, and the
    /// request is retried with `MESSAGE-INTEGRITY`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Server`] if the server rejects the allocation,
    /// [`Error::Timeout`] on no response, or a decode error on a malformed
    /// success response.
    pub fn allocate(&mut self, options: &AllocateOptions) -> Result<Allocation> {
        if self.allocation.is_some() {
            return Err(Error::InvalidState("an allocation already exists"));
        }
        let mut attrs = vec![
            Attribute::RequestedTransport(options.requested_transport),
            Attribute::Lifetime(u32::try_from(options.lifetime.as_secs()).unwrap_or(u32::MAX)),
        ];
        if let Some(family) = options.address_family {
            attrs.push(Attribute::RequestedAddressFamily(family));
        }
        if let Some(family) = options.additional_address_family {
            attrs.push(Attribute::AdditionalAddressFamily(family));
        }
        if let Some(even) = options.even_port {
            attrs.push(Attribute::EvenPort(even));
        }
        if options.dont_fragment {
            attrs.push(Attribute::DontFragment);
        }
        if let Some(token) = options.reservation_token {
            attrs.push(Attribute::ReservationToken(token));
        }

        let response = self.authed_request(Method::Allocate, &attrs, None)?;

        let mut relayed = None;
        let mut secondary = None;
        let mut mapped = None;
        let mut lifetime = options.lifetime;
        let key = response_key(&response);
        for attr in response.attributes() {
            match attr {
                StunAttribute::XorMappedAddress(addr) => mapped = Some(*addr),
                StunAttribute::Unknown { .. } => {
                    if let Some(turn) = Attribute::from_stun(attr, &key)? {
                        match turn {
                            Attribute::XorRelayedAddress(addr) => {
                                if relayed.is_none() {
                                    relayed = Some(addr);
                                } else {
                                    secondary = Some(addr);
                                }
                            }
                            Attribute::Lifetime(secs) => {
                                lifetime = Duration::from_secs(u64::from(secs));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        let relayed = relayed.ok_or(Error::MissingAttribute("XOR-RELAYED-ADDRESS"))?;
        let mut allocation = Allocation::new(relayed, mapped, lifetime);
        if let Some(addr) = secondary {
            allocation.set_secondary_relayed(addr);
        }
        self.allocation = Some(allocation.clone());
        Ok(allocation)
    }

    /// Refresh the current allocation with a new lifetime. A `lifetime` of zero
    /// releases the allocation (RFC 5766 §7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidState`] if there is no allocation, or a server /
    /// transport error.
    pub fn refresh(&mut self, lifetime: Duration) -> Result<()> {
        if self.allocation.is_none() {
            return Err(Error::InvalidState("no allocation to refresh"));
        }
        let secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
        let response =
            match self.authed_request(Method::Refresh, &[Attribute::Lifetime(secs)], None) {
                Err(Error::Server { code: 437, reason }) => {
                    self.allocation = None;
                    self.permissions.clear();
                    self.bindings.clear();
                    return Err(Error::Server { code: 437, reason });
                }
                outcome => outcome?,
            };

        if secs == 0 {
            self.allocation = None;
            self.permissions.clear();
            self.bindings.clear();
            return Ok(());
        }

        let granted = granted_lifetime(&response).unwrap_or(lifetime);
        if let Some(alloc) = self.allocation.as_mut() {
            alloc.renew(granted);
        }
        Ok(())
    }

    /// Install permissions for the given peer IP addresses (RFC 5766 §9). The
    /// port of each address is ignored; permissions are keyed by IP.
    ///
    /// # Errors
    ///
    /// Returns a server / transport error, or [`Error::InvalidState`] if no
    /// allocation exists.
    pub fn create_permission(&mut self, peers: &[SocketAddr]) -> Result<()> {
        if self.allocation.is_none() {
            return Err(Error::InvalidState("no allocation for permission"));
        }
        if peers.is_empty() {
            return Ok(());
        }
        let attrs: Vec<Attribute> = peers
            .iter()
            .map(|p| Attribute::XorPeerAddress(*p))
            .collect();
        self.authed_request(Method::CreatePermission, &attrs, None)?;
        for peer in peers {
            self.upsert_permission(peer.ip());
        }
        Ok(())
    }

    /// Send `payload` to `peer` via a `Send` indication (RFC 5766 §10).
    ///
    /// Indications are not authenticated and expect no response. A permission
    /// for the peer's IP must already exist or the server will silently drop
    /// the data.
    ///
    /// # Errors
    ///
    /// Returns a transport error if the send fails.
    pub fn send_to(&self, peer: SocketAddr, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        self.transport
            .send(&indication::encode_send(peer, payload)?)
    }

    /// Bind a channel to `peer` for compact ChannelData framing (RFC 5766 §11),
    /// returning the channel number. If `peer` already has a binding, the
    /// existing channel is refreshed and returned.
    ///
    /// # Errors
    ///
    /// Returns a server / transport error, or [`Error::InvalidState`] if no
    /// allocation exists.
    pub fn channel_bind(&mut self, peer: SocketAddr) -> Result<u16> {
        if self.allocation.is_none() {
            return Err(Error::InvalidState("no allocation for channel bind"));
        }
        let channel = match self.bindings.iter().find(|b| b.peer() == peer) {
            Some(existing) => existing.channel(),
            None => self.next_channel_number()?,
        };
        self.authed_request(
            Method::ChannelBind,
            &[
                Attribute::ChannelNumber(channel),
                Attribute::XorPeerAddress(peer),
            ],
            None,
        )?;
        self.upsert_binding(channel, peer);
        // A channel bind also refreshes the peer's permission (RFC 5766 §11.2).
        self.upsert_permission(peer.ip());
        Ok(channel)
    }

    /// Send `payload` over a previously bound `channel` as a ChannelData frame
    /// (RFC 5766 §11.4). The frame is always padded to a 4-byte boundary,
    /// which is REQUIRED over stream transports and permitted over UDP
    /// (RFC 5766 §11.5, RFC 8656 §12.4).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChannelNumber`] for an out-of-range channel, or
    /// a transport error.
    pub fn send_channel(&self, channel: u16, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        let frame = ChannelData::encode(channel, payload)?;
        self.transport.send(&frame)
    }

    /// Wait for relayed data, returning the peer address and the payload.
    /// Accepts both `Data` indications and ChannelData frames; a `timeout` of
    /// `None` waits indefinitely. `Data` indications from peers without a
    /// permission, ChannelData on unbound channels, and malformed frames are
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if `timeout` elapses first, or
    /// [`Error::Network`] if the transport closes.
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<(SocketAddr, Vec<u8>)> {
        self.ensure_open()?;
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        loop {
            let relayed = {
                let mut state = self.inbox.lock();
                loop {
                    if let Some(relayed) = state.pending.pop_front() {
                        break relayed;
                    }
                    if let Some(reason) = &state.closed {
                        return Err(Error::Network(format!("TURN transport closed: {reason}")));
                    }
                    state = self.inbox.wait(state, deadline).ok_or(Error::Timeout)?;
                }
            };
            if let Some(item) = self.accept_relayed(relayed) {
                return Ok(item);
            }
        }
    }

    /// Perform any due lifetime maintenance: refresh the allocation, any
    /// half-expired permissions, and any half-expired channel bindings. Call
    /// this periodically from the owning thread (see the README for the
    /// cooperative auto-refresh model).
    ///
    /// # Errors
    ///
    /// Returns the first server / transport error encountered.
    pub fn maintain(&mut self) -> Result<()> {
        let refresh_alloc = self
            .allocation
            .as_ref()
            .is_some_and(Allocation::refresh_due);
        if refresh_alloc {
            let lifetime = self
                .allocation
                .as_ref()
                .map_or(DEFAULT_LIFETIME, Allocation::lifetime);
            self.refresh(lifetime)?;
        }

        let stale_perms: Vec<SocketAddr> = self
            .permissions
            .iter()
            .filter(|p| p.refresh_due())
            .map(|p| SocketAddr::new(p.ip(), 0))
            .collect();
        let mut outcome = self.create_permission(&stale_perms);

        let stale_bindings: Vec<SocketAddr> = self
            .bindings
            .iter()
            .filter(|b| b.refresh_due())
            .map(ChannelBinding::peer)
            .collect();
        for peer in stale_bindings {
            if let Err(error) = self.channel_bind(peer) {
                if outcome.is_ok() {
                    outcome = Err(error);
                }
            }
        }
        self.permissions.retain(|p| !p.is_expired());
        self.bindings.retain(|b| !b.is_expired());
        outcome
    }

    /// The soonest [`Duration`] until any tracked object next needs a refresh,
    /// or `None` if nothing is allocated. Useful for sizing a maintenance
    /// sleep.
    #[must_use]
    pub fn next_maintenance(&self) -> Option<Duration> {
        let mut soonest: Option<Duration> = None;
        let mut consider = |d: Duration| {
            soonest = Some(soonest.map_or(d, |s| s.min(d)));
        };
        if let Some(alloc) = &self.allocation {
            consider(alloc.until_refresh());
        }
        for perm in &self.permissions {
            consider((crate::permission::PERMISSION_LIFETIME / 2).saturating_sub(perm.age()));
        }
        for binding in &self.bindings {
            consider((crate::channel_binding::CHANNEL_LIFETIME / 2).saturating_sub(binding.age()));
        }
        soonest
    }

    /// The active permissions.
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// The active channel bindings.
    #[must_use]
    pub fn bindings(&self) -> &[ChannelBinding] {
        &self.bindings
    }

    #[allow(missing_docs)]
    pub fn close(&mut self, timeout: Duration) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let deadline = Instant::now().checked_add(timeout);
        let released = if self.allocation.is_some() {
            self.authed_request(Method::Refresh, &[Attribute::Lifetime(0)], deadline)
                .map(drop)
        } else {
            Ok(())
        };
        self.closed = true;
        self.allocation = None;
        self.permissions.clear();
        self.bindings.clear();
        self.transport.close();
        let joined = self
            .join_receiver(deadline.map(|deadline| deadline.max(Instant::now() + RECEIVER_GRACE)));
        released.and(joined)
    }

    fn join_receiver(&mut self, deadline: Option<Instant>) -> Result<()> {
        let Some(receiver) = self.receiver.take() else {
            return Ok(());
        };
        while !receiver.is_finished() {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(Error::Network(
                    "TURN receiver thread did not stop before the deadline".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
        receiver
            .join()
            .map_err(|_| Error::Network("TURN receiver thread panicked".to_owned()))
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            Err(Error::InvalidState("client closed"))
        } else {
            Ok(())
        }
    }

    /// Run a request transaction with the long-term-auth retry loop, returning
    /// the decoded success response.
    fn authed_request(
        &mut self,
        method: Method,
        attrs: &[Attribute],
        deadline: Option<Instant>,
    ) -> Result<Message> {
        self.ensure_open()?;
        let mut attempts: Vec<Attempt> = Vec::with_capacity(MAX_AUTH_ATTEMPTS);
        let mut auth = self.auth.clone();
        while attempts.len() < MAX_AUTH_ATTEMPTS {
            let transaction_id = TransactionId::try_random()?;
            let request = self.build_request(transaction_id, method, attrs, &auth)?;
            attempts.push(Attempt {
                transaction_id,
                auth,
            });
            match self.transact(method, &request, &attempts, deadline)? {
                Reply::Accepted { attempt, message } => {
                    self.auth = attempts.swap_remove(attempt).auth;
                    return match message.class() {
                        Class::SuccessResponse => Ok(message),
                        _ => Err(server_error(&message)),
                    };
                }
                Reply::Retry(next) => auth = next,
            }
        }
        Err(Error::AuthFailed)
    }

    /// Build a request's wire bytes, attaching credentials and message
    /// integrity once the auth state is ready.
    fn build_request(
        &self,
        transaction_id: TransactionId,
        method: Method,
        attrs: &[Attribute],
        auth: &AuthState,
    ) -> Result<Vec<u8>> {
        let key = attribute::xor_key(transaction_id.as_bytes());
        let mut builder =
            Message::builder(method.to_stun(), Class::Request).transaction_id(transaction_id);
        for attr in attrs {
            builder = builder.attribute(attr.to_stun(&key));
        }
        Ok(auth
            .sign(builder, self.credential.username())
            .with_fingerprint()
            .build_and_encode()?)
    }

    /// Send a request and wait for the matching response, driving RFC 5389
    /// retransmission. Relayed data seen while waiting stays in the pending
    /// queue for [`TurnClient::recv`].
    fn transact(
        &self,
        method: Method,
        request: &[u8],
        attempts: &[Attempt],
        deadline: Option<Instant>,
    ) -> Result<Reply> {
        let current = attempts.len() - 1;
        let stream = self.transport.is_stream();
        let mut discarded = false;
        let mut rejected = false;
        let waits: Vec<Duration> = if stream {
            vec![RetransmitSchedule::with_rto(self.rto).sum()]
        } else {
            RetransmitSchedule::with_rto(self.rto).collect()
        };
        self.transport.send(request)?;
        for (sent, wait) in waits.iter().enumerate() {
            let until = match (Instant::now().checked_add(*wait), deadline) {
                (Some(until), Some(deadline)) => Some(until.min(deadline)),
                (until, None) => until,
                (None, deadline) => deadline,
            };
            while let Some(message) = self.next_response(until)? {
                let Some(index) = attempts
                    .iter()
                    .position(|attempt| &attempt.transaction_id == message.transaction_id())
                else {
                    continue;
                };
                if message.method() != method.to_stun() {
                    continue;
                }
                match self.judge(&message, &attempts[index].auth, index == current) {
                    Judgement::Accept => {
                        return Ok(Reply::Accepted {
                            attempt: index,
                            message,
                        })
                    }
                    Judgement::Retry(next) => return Ok(Reply::Retry(next)),
                    Judgement::Reject => return Err(Error::AuthFailed),
                    Judgement::Fail(error) => return Err(error),
                    Judgement::Discard { rejection } => {
                        discarded = true;
                        rejected |= rejection;
                        if stream {
                            break;
                        }
                    }
                }
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) || (stream && discarded)
            {
                break;
            }
            if sent + 1 < waits.len() {
                self.transport.send(request)?;
            }
        }
        Err(if rejected {
            Error::AuthFailed
        } else if discarded {
            Error::IntegrityViolation
        } else {
            Error::Timeout
        })
    }

    fn next_response(&self, until: Option<Instant>) -> Result<Option<Message>> {
        let mut state = self.inbox.lock();
        loop {
            if let Some(message) = state.responses.pop_front() {
                return Ok(Some(message));
            }
            if let Some(reason) = &state.closed {
                return Err(Error::Network(format!("TURN transport closed: {reason}")));
            }
            match self.inbox.wait(state, until) {
                Some(next) => state = next,
                None => return Ok(None),
            }
        }
    }

    fn judge(&self, message: &Message, auth: &AuthState, current: bool) -> Judgement {
        if message.get(stun_types::FINGERPRINT).is_some() && message.verify_fingerprint().is_err() {
            return Judgement::Discard { rejection: false };
        }
        let code = if message.class() == Class::ErrorResponse {
            error_code(message).map(|(code, _)| code)
        } else {
            None
        };
        if auth.verify(message) {
            let unknown = unknown_attributes(message);
            if !unknown.is_empty() {
                return Judgement::Fail(Error::Stun(stun::Error::UnknownAttributes(unknown)));
            }
            return match code {
                Some(438) if current => auth
                    .with_stale_nonce(message)
                    .map_or(Judgement::Discard { rejection: false }, Judgement::Retry),
                Some(438) => Judgement::Discard { rejection: false },
                Some(401) => Judgement::Reject,
                _ => Judgement::Accept,
            };
        }
        if !current {
            return Judgement::Discard { rejection: false };
        }
        match code {
            Some(401) if !self.auth.is_ready() => {
                match AuthState::from_challenge(&self.credential, message) {
                    Ok(next) if auth.is_ready() && next.realm() == auth.realm() => {
                        Judgement::Reject
                    }
                    Ok(next) => Judgement::Retry(next),
                    Err(_) => Judgement::Discard { rejection: true },
                }
            }
            Some(401) => Judgement::Discard { rejection: true },
            Some(438) if auth.is_ready() => auth
                .with_stale_nonce(message)
                .map_or(Judgement::Discard { rejection: false }, Judgement::Retry),
            _ => Judgement::Discard { rejection: false },
        }
    }

    fn accept_relayed(&self, relayed: Relayed) -> Option<(SocketAddr, Vec<u8>)> {
        match relayed {
            Relayed::Data(peer, data) => self
                .permissions
                .iter()
                .any(|p| p.ip() == peer.ip() && !p.is_expired())
                .then_some((peer, data)),
            Relayed::Channel(frame) => {
                let (number, payload) = ChannelData::decode(&frame).ok()?;
                let peer = self.bindings.iter().find(|b| b.channel() == number)?.peer();
                Some((peer, payload.to_vec()))
            }
        }
    }

    /// Allocate the next free channel number, wrapping within the valid range.
    fn next_channel_number(&mut self) -> Result<u16> {
        for _ in 0..=(MAX_CHANNEL - MIN_CHANNEL) {
            let candidate = self.next_channel;
            self.next_channel = if self.next_channel >= MAX_CHANNEL {
                MIN_CHANNEL
            } else {
                self.next_channel + 1
            };
            if !self.bindings.iter().any(|b| b.channel() == candidate) {
                return Ok(candidate);
            }
        }
        Err(Error::InvalidState("channel number space exhausted"))
    }

    /// Insert or refresh a permission for `ip`.
    fn upsert_permission(&mut self, ip: IpAddr) {
        if let Some(perm) = self.permissions.iter_mut().find(|p| p.ip() == ip) {
            perm.renew();
        } else {
            self.permissions.push(Permission::new(ip));
        }
    }

    /// Insert or refresh a channel binding.
    fn upsert_binding(&mut self, channel: u16, peer: SocketAddr) {
        if let Some(binding) = self.bindings.iter_mut().find(|b| b.channel() == channel) {
            binding.renew();
        } else {
            self.bindings.push(ChannelBinding::new(channel, peer));
        }
    }
}

impl Drop for TurnClient {
    fn drop(&mut self) {
        // Gracefully release the allocation with a zero-lifetime Refresh
        // (RFC 5766 §7). Best-effort: ignore any error during teardown.
        let _ = self.close(DROP_CLOSE_TIMEOUT);
    }
}

/// Reconstruct the XOR key from a decoded message's transaction ID.
fn response_key(message: &Message) -> attribute::XorKey {
    attribute::xor_key(message.transaction_id().as_bytes())
}

/// Extract a `(code, reason)` pair from an `ERROR-CODE` attribute.
fn error_code(message: &Message) -> Option<(u16, String)> {
    match message.get(stun::attribute::types::ERROR_CODE) {
        Some(StunAttribute::ErrorCode(err)) => Some((err.code(), err.reason.clone())),
        _ => None,
    }
}

fn server_error(message: &Message) -> Error {
    match error_code(message) {
        Some((401, _)) => Error::AuthFailed,
        Some((code, reason)) => Error::Server { code, reason },
        None => Error::Server {
            code: 0,
            reason: "no ERROR-CODE".into(),
        },
    }
}

fn unknown_attributes(message: &Message) -> Vec<u16> {
    message
        .unknown_comprehension_required()
        .into_iter()
        .filter(|attribute_type| {
            !attribute::is_turn_attribute(*attribute_type)
                && !RESERVED_ATTRIBUTES.contains(attribute_type)
                && *attribute_type != auth::USERHASH
        })
        .collect()
}

/// Extract the granted `LIFETIME` from a response, if present.
fn granted_lifetime(message: &Message) -> Option<Duration> {
    let key = response_key(message);
    for attr in message.attributes() {
        if let Ok(Some(Attribute::Lifetime(secs))) = Attribute::from_stun(attr, &key) {
            return Some(Duration::from_secs(u64::from(secs)));
        }
    }
    None
}

fn spawn_receiver(transport: Arc<dyn Transport>, inbox: Arc<Inbox>) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("turn-receiver".to_owned())
        .spawn(move || {
            let reason = loop {
                match transport.receive() {
                    Ok(datagram) if datagram.is_empty() => {}
                    Ok(datagram) => inbox.deliver(&datagram),
                    Err(error) => break error.to_string(),
                }
            };
            inbox.close(reason);
        })
        .map_err(|e| Error::Network(e.to_string()))
}
