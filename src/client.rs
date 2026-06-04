//! Synchronous TURN client (`TurnClient`) over a pluggable transport.
//!
//! [`TurnClient`] drives the full client side of RFC 5766 / RFC 8656:
//! `Allocate`, `Refresh`, `CreatePermission`, `ChannelBind`, `Send`/`Data`
//! indications, and ChannelData framing. It is fully synchronous — no async
//! runtime is pulled in. A background receiver thread feeds inbound packets to
//! an [`std::sync::mpsc`] channel so the caller can drive RFC 5389
//! retransmission timers (reused from `stun-rs`) without blocking forever on
//! the callback-based Network.framework receive primitive.
//!
//! Control responses, `Data` indications, and ChannelData frames all arrive on
//! the same channel; the client demultiplexes them by transaction ID and by
//! the leading-bytes rule of [`crate::channel::classify`], stashing relayed
//! data for [`TurnClient::recv`] while it waits for a matching response.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use stun::transaction::RetransmitSchedule;
use stun::{Attribute as StunAttribute, Class, Message, TransactionId};

use crate::allocation::{Allocation, DEFAULT_LIFETIME};
use crate::attribute::{self, AddressFamily, Attribute, EvenPort, PROTOCOL_UDP};
use crate::auth::{AuthState, Credential};
use crate::channel::{self, ChannelData, PacketKind, MAX_CHANNEL, MIN_CHANNEL};
use crate::channel_binding::ChannelBinding;
use crate::error::{Error, Result};
use crate::method::Method;
use crate::permission::Permission;
use crate::transport::{tcp::TcpTransport, tls::TlsTransport, udp::UdpTransport, Transport};

/// Default TURN port for `turn:` over UDP/TCP (RFC 5766 §6).
pub const DEFAULT_TURN_PORT: u16 = 3478;
/// Default TURN port for `turns:` over TLS (RFC 5766 §6).
pub const DEFAULT_TURNS_PORT: u16 = 5349;

/// The maximum number of authentication retries for a single transaction
/// (initial unauthenticated attempt, then `401` and `438` re-sends).
const MAX_AUTH_ATTEMPTS: usize = 4;

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

/// A synchronous TURN client bound to a single server connection.
pub struct TurnClient {
    transport: Arc<dyn Transport>,
    rx: mpsc::Receiver<Vec<u8>>,
    credential: Credential,
    auth: AuthState,
    allocation: Option<Allocation>,
    permissions: Vec<Permission>,
    bindings: Vec<ChannelBinding>,
    pending: VecDeque<(SocketAddr, Vec<u8>)>,
    next_channel: u16,
}

impl std::fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnClient")
            .field("allocation", &self.allocation)
            .field("permissions", &self.permissions.len())
            .field("bindings", &self.bindings.len())
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
        Ok(Self::with_transport(transport, credential))
    }

    /// Construct a client over an already-established [`Transport`]. Useful for
    /// testing with an in-memory transport.
    #[must_use]
    pub fn with_transport(transport: Arc<dyn Transport>, credential: Credential) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        spawn_receiver(Arc::clone(&transport), tx);
        Self {
            transport,
            rx,
            credential,
            auth: AuthState::new(),
            allocation: None,
            permissions: Vec::new(),
            bindings: Vec::new(),
            pending: VecDeque::new(),
            next_channel: MIN_CHANNEL,
        }
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

        let response = self.authed_request(Method::Allocate, &attrs)?;

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
        let response = self.authed_request(Method::Refresh, &[Attribute::Lifetime(secs)])?;

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
        self.authed_request(Method::CreatePermission, &attrs)?;
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
    pub fn send_to(&mut self, peer: SocketAddr, payload: &[u8]) -> Result<()> {
        let tid = TransactionId::random();
        let key = attribute::xor_key(tid.as_bytes());
        let bytes = Message::builder(Method::Send.to_stun(), Class::Indication)
            .transaction_id(tid)
            .attribute(Attribute::XorPeerAddress(peer).to_stun(&key))
            .attribute(Attribute::Data(payload.to_vec()).to_stun(&key))
            .build_and_encode();
        self.transport.send(&bytes)
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
        )?;
        self.upsert_binding(channel, peer);
        // A channel bind also refreshes the peer's permission (RFC 5766 §11.2).
        self.upsert_permission(peer.ip());
        Ok(channel)
    }

    /// Send `payload` over a previously bound `channel` as a ChannelData frame
    /// (RFC 5766 §11.4). Padding follows the transport: padded over UDP,
    /// unpadded over a stream transport (§11.5).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChannelNumber`] for an out-of-range channel, or
    /// a transport error.
    pub fn send_channel(&self, channel: u16, payload: &[u8]) -> Result<()> {
        let frame = if self.transport.is_stream() {
            ChannelData::encode_stream(channel, payload)?
        } else {
            ChannelData::encode(channel, payload)?
        };
        self.transport.send(&frame)
    }

    /// Block until relayed data arrives, returning the peer address and the
    /// payload. Accepts both `Data` indications and ChannelData frames.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Network`] if the transport closes, or a decode error on
    /// a malformed inbound message.
    pub fn recv(&mut self) -> Result<(SocketAddr, Vec<u8>)> {
        if let Some(item) = self.pending.pop_front() {
            return Ok(item);
        }
        loop {
            let datagram = self
                .rx
                .recv()
                .map_err(|_| Error::Network("transport receiver closed".into()))?;
            if let Some(item) = self.process_inbound(&datagram)? {
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

        let stale_perms: Vec<IpAddr> = self
            .permissions
            .iter()
            .filter(|p| p.refresh_due())
            .map(Permission::ip)
            .collect();
        for ip in stale_perms {
            self.create_permission(&[SocketAddr::new(ip, 0)])?;
        }

        let stale_bindings: Vec<SocketAddr> = self
            .bindings
            .iter()
            .filter(|b| b.refresh_due())
            .map(ChannelBinding::peer)
            .collect();
        for peer in stale_bindings {
            self.channel_bind(peer)?;
        }
        Ok(())
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

    /// Run a request transaction with the long-term-auth retry loop, returning
    /// the decoded success response.
    fn authed_request(&mut self, method: Method, attrs: &[Attribute]) -> Result<Message> {
        for _ in 0..MAX_AUTH_ATTEMPTS {
            let tid = TransactionId::random();
            let bytes = self.build_request(tid, method, attrs);
            let response = self.transact(tid, &bytes)?;

            match response.class() {
                Class::SuccessResponse => return Ok(response),
                Class::ErrorResponse => {
                    let (code, reason) = error_code(&response).ok_or(Error::Server {
                        code: 0,
                        reason: "no ERROR-CODE".into(),
                    })?;
                    match code {
                        401 => self.handle_challenge(&response, false)?,
                        438 => self.handle_challenge(&response, true)?,
                        _ => return Err(Error::Server { code, reason }),
                    }
                }
                _ => return Err(Error::Stun(stun::Error::BadMessageType)),
            }
        }
        Err(Error::AuthFailed)
    }

    /// Capture `REALM`/`NONCE` (or just the fresh `NONCE` for a stale-nonce
    /// retry) from a challenge response and update the auth state.
    fn handle_challenge(&mut self, response: &Message, stale_only: bool) -> Result<()> {
        let nonce = match response.get(stun::attribute::types::NONCE) {
            Some(StunAttribute::Nonce(n)) => n.clone(),
            _ => return Err(Error::MissingChallenge),
        };
        if stale_only && self.auth.is_ready() {
            self.auth.refresh_nonce(&nonce);
            return Ok(());
        }
        let realm = match response.get(stun::attribute::types::REALM) {
            Some(StunAttribute::Realm(r)) => r.clone(),
            _ => return Err(Error::MissingChallenge),
        };
        self.auth.challenge(&self.credential, &realm, &nonce);
        Ok(())
    }

    /// Build a request's wire bytes, attaching credentials + `MESSAGE-INTEGRITY`
    /// once the auth state is ready.
    fn build_request(&self, tid: TransactionId, method: Method, attrs: &[Attribute]) -> Vec<u8> {
        let key = attribute::xor_key(tid.as_bytes());
        let mut builder = Message::builder(method.to_stun(), Class::Request).transaction_id(tid);
        for attr in attrs {
            builder = builder.attribute(attr.to_stun(&key));
        }
        if let (Some(realm), Some(nonce), Some(long_key)) =
            (self.auth.realm(), self.auth.nonce(), self.auth.key())
        {
            builder = builder
                .attribute(StunAttribute::Username(
                    self.credential.username().to_owned(),
                ))
                .attribute(StunAttribute::Realm(realm.to_owned()))
                .attribute(StunAttribute::Nonce(nonce.to_owned()))
                .with_message_integrity_sha1(long_key);
        }
        builder.build_and_encode()
    }

    /// Send a request and wait for the matching response, driving RFC 5389
    /// retransmission. Inbound relayed data seen while waiting is stashed for
    /// [`TurnClient::recv`].
    fn transact(&mut self, tid: TransactionId, request: &[u8]) -> Result<Message> {
        self.transport.send(request)?;
        for wait in RetransmitSchedule::new() {
            match self.rx.recv_timeout(wait) {
                Ok(datagram) => {
                    if channel::classify(&datagram) == PacketKind::Stun {
                        if let Ok(message) = Message::decode(&datagram) {
                            if message.transaction_id() == &tid
                                && matches!(
                                    message.class(),
                                    Class::SuccessResponse | Class::ErrorResponse
                                )
                            {
                                return Ok(message);
                            }
                        }
                    }
                    // Not our response: it may be relayed data — stash it.
                    let _ = self.process_inbound(&datagram)?;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.transport.send(request)?;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::Network("transport receiver closed".into()))
                }
            }
        }
        Err(Error::Timeout)
    }

    /// Classify and decode an inbound packet. Returns `Some((peer, data))` for
    /// relayed data (a `Data` indication or ChannelData frame), or `None` for
    /// anything else (which is either consumed or ignored).
    fn process_inbound(&mut self, datagram: &[u8]) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        match channel::classify(datagram) {
            PacketKind::ChannelData => {
                let (channel, payload) = ChannelData::decode(datagram)?;
                if let Some(peer) = self
                    .bindings
                    .iter()
                    .find(|b| b.channel() == channel)
                    .map(ChannelBinding::peer)
                {
                    return Ok(Some((peer, payload.to_vec())));
                }
                Ok(None)
            }
            PacketKind::Stun => {
                let message = match Message::decode(datagram) {
                    Ok(m) => m,
                    Err(_) => return Ok(None),
                };
                if message.method() != Method::Data.to_stun()
                    || message.class() != Class::Indication
                {
                    return Ok(None);
                }
                let key = response_key(&message);
                let mut peer = None;
                let mut data = None;
                for attr in message.attributes() {
                    if let Some(turn) = Attribute::from_stun(attr, &key)? {
                        match turn {
                            Attribute::XorPeerAddress(addr) => peer = Some(addr),
                            Attribute::Data(bytes) => data = Some(bytes),
                            _ => {}
                        }
                    }
                }
                match (peer, data) {
                    (Some(peer), Some(data)) => Ok(Some((peer, data))),
                    _ => Ok(None),
                }
            }
            PacketKind::Unknown => Ok(None),
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
        if self.allocation.is_some() {
            let _ = self.refresh(Duration::from_secs(0));
        }
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

/// Spawn a detached receiver thread forwarding inbound packets to `tx`.
fn spawn_receiver(transport: Arc<dyn Transport>, tx: mpsc::Sender<Vec<u8>>) {
    thread::spawn(move || {
        while let Ok(datagram) = transport.receive() {
            if datagram.is_empty() {
                continue;
            }
            if tx.send(datagram).is_err() {
                break;
            }
        }
    });
}
