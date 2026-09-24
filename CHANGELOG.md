# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Security

- Responses were matched by transaction ID only, so an on-path attacker could
  forge an `Allocate` success (any relayed address or lifetime), a
  `438 Stale Nonce`, or a rejection. Every response to an authenticated request
  must now carry the integrity attribute the request used, verified with the
  long-term key, and a valid `FINGERPRINT` when one is present. Unauthenticated
  responses are discarded, with the initial `401` challenge as the only
  exception, and a request that only saw such responses fails with
  `Error::IntegrityViolation`.
- The realm, nonce, and key are stored only after an authenticated response,
  so an unauthenticated `401` or `438` can no longer change them. A `438` can
  still trigger a retry, but its nonce is kept only if the retry is answered
  with an authenticated response, and it never changes the realm. Responses to
  earlier attempts of the same request stay acceptable, so a forged `438` that
  races the real answer does not delay it.
- `Credential` and `AuthState` derived `Debug`, which printed the password and
  the long-term key. Both are redacted now, and the password and key are
  zeroized on drop. `Credential` no longer derives `PartialEq`/`Eq`.
- `Data` indications from peers without a permission are ignored
  (RFC 5766 §10.4).

### Fixed

- Every relayed datagram received while a request was waiting used up one of
  its retransmission slots, so `Refresh`, `CreatePermission`, and `ChannelBind`
  timed out while media flowed and the allocation could expire mid-call. Waits
  now run against a deadline and relayed data goes to the pending queue.
- Relayed data that arrived during a request was thrown away, although the docs
  said it was stashed, and a malformed frame aborted the request. It now waits
  in a bounded pending queue (the oldest frame is dropped when full and counted
  by `dropped_frames`), and malformed frames are skipped.
- `Drop` sent a blocking `Refresh` with `LIFETIME=0` that could take about
  20 s, and the receiver thread leaked with its socket until another datagram
  arrived. `close(timeout)`, and `Drop` with a 1 s bound, now limit the wait,
  cancel the transport, and join the thread.
- RFC 8656 `PASSWORD-ALGORITHMS` was claimed but not implemented. It is
  implemented now (see Added).
- The client retransmitted over TCP and TLS. It now waits once for the whole
  transaction timeout there and ends the request at the first response that
  fails the checks (RFC 5389 §7.2.2, RFC 8489 §9.2.5).
- A non-empty credential realm replaced the server's realm in `REALM`, which no
  server accepts. A challenge for a different realm is now refused.
- The UDP receive limit was 1500 bytes, so a `Data` indication carrying a
  full-size datagram was dropped. It is 4096 bytes now, and an oversized
  datagram is skipped instead of ending the receiver.
- ChannelData frames are always padded to a 4-byte boundary (RFC 5766 §11.5,
  RFC 8656 §12.4). 0.1.0 padded datagram frames only and sent TCP/TLS frames
  unpadded.
- `maintain` stopped at the first failure. It now renews all due permissions in
  one `CreatePermission`, tries every due channel binding, returns the first
  error, and forgets expired permissions and bindings.
- `allocate` with an allocation already in place is refused locally
  (`InvalidState`) instead of sending a request the server rejects with `437`.
- A `Refresh` answered with `437 Allocation Mismatch` left the lost allocation
  in place, so `next_maintenance` kept reporting it as due. The allocation, its
  permissions, and its channel bindings are now dropped (RFC 5766 §7).

### Changed

- **Breaking:** `Credential` is a struct with private fields, built with
  `Credential::long_term`; the `Credential::LongTerm { .. }` variant is gone. A
  non-empty realm must equal the realm of the server's challenge.
- **Breaking:** `Credential::long_term_key(realm)` is
  `long_term_key(algorithm, realm) -> Result<Zeroizing<Vec<u8>>>`.
- **Breaking:** `AuthState::challenge` and `AuthState::refresh_nonce` are
  replaced by `AuthState::from_challenge(&Credential, &Message)` and
  `AuthState::with_stale_nonce(&Message)`, which return a new state.
  `AuthState::key` returns `Option<&[u8]>`.
- **Breaking:** `TurnClient::with_transport` returns `Result<Self>`.
- **Breaking:** `TurnClient::recv(timeout: Option<Duration>)` replaces
  `recv()`. It returns `Error::Timeout` when the timeout elapses and skips
  malformed frames instead of failing.
- **Breaking:** `TurnClient::send_to` takes `&self`.
- **Breaking:** the `Transport` trait has a required `close(&self)`, which must
  make a blocked `receive` return an error.
- **Breaking:** `Error` gains `IntegrityViolation`, `PasswordAlgorithms`, and
  `Crypto`; `AuthFailed` also covers rejected credentials and realm mismatches.
- **Breaking:** `ChannelData::encode_stream` is removed; `encode` always pads.
- **Breaking:** requires stun-rs 0.2 (`>=0.2, <0.3`) and networkframework 0.14
  (`>=0.14, <0.15`), and adds cryptokit-rs 0.3 (`>=0.3, <0.4`) and `zeroize`
  (`>=1.6, <1.9`). The unused `libc` dependency is removed.
- Requests carry `FINGERPRINT`.
- `rust-version` is 1.82.

### Added

- `PASSWORD-ALGORITHMS` negotiation (RFC 8489 §9.2): nonce-cookie parsing,
  bid-down detection, MD5 and SHA-256 keys, the `PASSWORD-ALGORITHM` echo,
  `MESSAGE-INTEGRITY-SHA256` on every later request, and `USERHASH` when the
  server asks for username anonymity. New items: `auth::PasswordAlgorithm`,
  `auth::Integrity`, `auth::PASSWORD_ALGORITHMS`, `auth::USERHASH`,
  `AuthState::password_algorithm`, and `AuthState::integrity`.
- `TurnClient::close`, `set_rto`, `set_pending_capacity`, `dropped_frames`, and
  `auth_state`; `client::DEFAULT_PENDING_CAPACITY` and
  `client::DROP_CLOSE_TIMEOUT`.
- `indication::encode_send` and `indication::decode_data` for `Send` and
  `Data` indications.
- The offline `03_loopback_allocate` example, and tests against a scripted TURN
  server on `127.0.0.1`.

### Removed

- The `03_live_allocate` example, which needed an external TURN server.

## [0.1.0] - 2026-06-04

Initial release.

### Added

- TURN client ([RFC 5766] / [RFC 8656]) layered on the sibling `stun-rs` crate
  for message framing, integrity, and long-term key derivation.
- Methods: `Allocate`, `Refresh`, `Send`/`Data` indications, `CreatePermission`,
  and `ChannelBind`, encoded as STUN methods `0x0003`–`0x0009`.
- TURN attribute codec with a dedicated XOR-address implementation for
  `XOR-PEER-ADDRESS` and `XOR-RELAYED-ADDRESS`, layered on the pass-through
  `stun::Attribute::Unknown` variant. Also `CHANNEL-NUMBER`, `LIFETIME`,
  `DATA`, `REQUESTED-ADDRESS-FAMILY`, `EVEN-PORT`, `REQUESTED-TRANSPORT`,
  `DONT-FRAGMENT`, `RESERVATION-TOKEN`, and `ADDITIONAL-ADDRESS-FAMILY`.
- ChannelData framing with first-byte STUN/ChannelData demultiplexing
  (`classify`) and transport-aware padding: datagram frames are padded to a
  4-byte boundary, stream frames are not (RFC 5766 §11.5).
- Long-term authentication state machine: unauthenticated request → `401`
  challenge (capturing `REALM`/`NONCE`) → re-send with `MESSAGE-INTEGRITY`, with
  `438` stale-nonce refresh.
- Allocation, permission, and channel-binding lifetime accounting with a
  cooperative `maintain` / `next_maintenance` auto-refresh helper.
- Synchronous `TurnClient` with a background receiver thread and transaction
  demultiplexing, over UDP (default), TCP, and TLS.
- `TurnUri` parser for `turn:` / `turns:` URIs, including `?transport=tcp`.
- Offline examples (`01_allocate`, `02_channel_data`) and an env-gated live
  example (`03_live_allocate`).

[RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
[RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
