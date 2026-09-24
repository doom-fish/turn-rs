# Coverage

This document tracks which parts of the TURN specifications this crate
implements, and what is intentionally deferred.

## Specifications

| Spec | Title | Status |
| ---- | ----- | ------ |
| [RFC 5766] | Traversal Using Relays around NAT (TURN) | Client implemented |
| [RFC 8656] | TURN (bis) | Dual-stack attributes implemented; happy-eyeballs deferred |
| [RFC 8489] §9.2 | Long-term credential mechanism | Implemented, including `PASSWORD-ALGORITHMS`, `USERHASH`, and response authentication |
| [RFC 6156] | TURN Extension for IPv6 | `REQUESTED-ADDRESS-FAMILY` implemented |

## Methods

| Method | Value | Request | Indication | Notes |
| ------ | ----- | ------- | ---------- | ----- |
| `Allocate` | `0x0003` | ✅ | — | full long-term-auth handshake |
| `Refresh` | `0x0004` | ✅ | — | including zero-lifetime release |
| `Send` | `0x0006` | — | ✅ | unauthenticated, per RFC 5766 §10 |
| `Data` | `0x0007` | — | ✅ | inbound, demultiplexed into `recv` |
| `CreatePermission` | `0x0008` | ✅ | — | one or more `XOR-PEER-ADDRESS` |
| `ChannelBind` | `0x0009` | ✅ | — | auto-assigns channel `0x4000`+ |

## Attributes

| Attribute | Type | Encode | Decode | Notes |
| --------- | ---- | ------ | ------ | ----- |
| `CHANNEL-NUMBER` | `0x000C` | ✅ | ✅ | 16-bit + 2 reserved bytes |
| `LIFETIME` | `0x000D` | ✅ | ✅ | seconds |
| `XOR-PEER-ADDRESS` | `0x0012` | ✅ | ✅ | IPv4 + IPv6, own XOR codec |
| `DATA` | `0x0013` | ✅ | ✅ | relayed payload |
| `XOR-RELAYED-ADDRESS` | `0x0016` | ✅ | ✅ | IPv4 + IPv6, own XOR codec |
| `REQUESTED-ADDRESS-FAMILY` | `0x0017` | ✅ | ✅ | IPv4 / IPv6 (RFC 6156 / 8656) |
| `EVEN-PORT` | `0x0018` | ✅ | ✅ | with reserve (`R`) bit |
| `REQUESTED-TRANSPORT` | `0x0019` | ✅ | ✅ | UDP (`17`) |
| `DONT-FRAGMENT` | `0x001A` | ✅ | ✅ | zero-length flag |
| `RESERVATION-TOKEN` | `0x0022` | ✅ | ✅ | 8-byte token |
| `ADDITIONAL-ADDRESS-FAMILY` | `0x8000` | ✅ | ✅ | dual-stack (RFC 8656 §14.9) |

Integrity, fingerprint, `USERNAME`, `REALM`, `NONCE`, `PASSWORD-ALGORITHM`, and
`ERROR-CODE` are handled by the sibling `stun-rs` crate. `PASSWORD-ALGORITHMS`
(`0x8002`) and `USERHASH` (`0x001E`) are built and parsed in this crate's `auth`
module.

✅ implemented · ⚠️ partial / passthrough

## Layering on `stun-rs`

`stun::Attribute` is `#[non_exhaustive]`, so TURN attributes cannot be added to
that enum from this crate. Instead, each TURN attribute encodes to a
`stun::Attribute::Unknown { attribute_type, value }` with a pre-encoded value,
and decodes from any `Unknown` whose type is in the TURN registry. The
XOR-obfuscated address attributes (`XOR-PEER-ADDRESS`, `XOR-RELAYED-ADDRESS`)
use the same `magic-cookie || transaction-id` XOR key as STUN; because that
codec is private to `stun-rs`, an identical implementation lives in this crate's
`attribute` module. The transaction ID is set explicitly on each request so the
key can be precomputed.

## ChannelData padding (RFC 5766 §11.5, RFC 8656 §12.4)

ChannelData frames carry a 4-byte header (channel number + length) followed by
the payload. This crate **always pads** frames to a 4-byte boundary because
padding is REQUIRED over stream transports (TCP / TLS-over-TCP) and is
permitted (RECOMMENDED) over UDP. The `Length` field records the unpadded
payload length, so the decoder always returns exactly `Length` payload bytes
and discards trailing padding regardless of transport. This is enforced by the
`padding_rules` test suite.

## Authentication

Long-term authentication is mandatory for TURN. Requests
(`Allocate`/`Refresh`/`CreatePermission`/`ChannelBind`) run an auth retry loop
(RFC 8489 §9.2): the first attempt is unauthenticated; a `401` supplies
`REALM`/`NONCE`; the request is retried with `USERNAME`/`REALM`/`NONCE` and
`MESSAGE-INTEGRITY`; a `438` (stale nonce) captures a fresh `NONCE` and retries.
Each attempt uses a new transaction ID. `Send`/`Data` indications are not
authenticated, per RFC 5766 §10.

- **Response authentication.** Every response to an authenticated request must
  carry the integrity attribute the request used, verified with the long-term
  key, and a valid `FINGERPRINT` when one is present. Other responses are
  discarded and retransmission continues; if nothing authenticated arrives the
  request fails with `Error::IntegrityViolation`. Over TCP/TLS there is no
  retransmission, and the first discarded response ends the request.
- **State changes.** The realm, nonce, and key are stored only after an
  authenticated response. The initial `401` is accepted unauthenticated (it
  cannot be anything else); a pinned credential realm must match it. Later
  unauthenticated `401`s are ignored, and an unauthenticated `438` can trigger a
  retry with its nonce but does not replace the stored nonce unless the retry is
  answered with an authenticated response. A `438` never changes the realm.
  Responses to earlier attempts of the same request remain acceptable.
- **Credential rejection.** A second `401` for the same realm during the
  initial exchange means the password is wrong; the client does not retry and
  returns `Error::AuthFailed` at once.
- **`PASSWORD-ALGORITHMS`.** The nonce cookie (`obMatJos2` plus the security
  feature bits) is parsed. If it announces password algorithms but the
  attribute is missing, or the list has neither MD5 nor SHA-256, the client does
  not retry. Otherwise it picks the first supported entry, derives the key
  (`SHA-256(username:realm:password)` or the MD5 form), echoes the list with
  `PASSWORD-ALGORITHM`, and authenticates every later request with
  `MESSAGE-INTEGRITY-SHA256` only. A `438` must repeat the same list.
- **`USERHASH`.** When the nonce cookie sets the username-anonymity bit, the
  client sends `USERHASH = SHA-256(username:realm)` instead of `USERNAME`.
- **Secrets.** `Credential` keeps the password and `AuthState` the key in
  zeroizing buffers; neither prints them in `Debug`.
- **OpaqueString.** Realm and password are used as UTF-8 bytes; the RFC 8265
  OpaqueString profile is not applied, which only matters for non-ASCII values.

## Receive path

A background thread reads the transport and sorts what arrives. STUN responses
go to the waiting request; `Data` indications and ChannelData frames go to a
bounded pending queue (`DEFAULT_PENDING_CAPACITY` = 256 frames, adjustable with
`set_pending_capacity`) that drops its oldest frame when full and counts drops
(`dropped_frames`). Waiting for a response runs against a deadline, so relayed
media never consumes retransmissions. `recv` skips malformed frames, `Data`
indications from peers without a permission, and ChannelData on unbound
channels. `close(timeout)` releases the allocation with a bounded wait, cancels
the transport, and joins the receiver thread; `Drop` does the same with a 1 s
bound.

## Transports

| Transport | URI | Status |
| --------- | --- | ------ |
| UDP | `turn:` | ✅ implemented, default; tested against an in-process loopback server |
| TCP | `turn:?transport=tcp` | ✅ implemented, length-prefixed reassembly; no end-to-end test |
| TLS | `turns:` | ✅ compiles and frames as TCP; no end-to-end test |

## Deferred

- TURN-TCP connection management (`Connect` / `ConnectionBind` /
  `ConnectionAttempt`, RFC 6062) — only UDP relays are negotiated.
- ICMP `Data` indication relaying (RFC 8656 §11.5 ICMP attribute).
- RFC 8656 happy-eyeballs ordering between dual-stack relayed candidates.
- A background auto-refresh worker thread; refresh is cooperative
  (`maintain` / `next_maintenance`) by design.
- `ALTERNATE-SERVER` redirects (`300 Try Alternate`): an authenticated `300`
  is reported as `Error::Server`, an unauthenticated one is discarded.
- `MESSAGE-INTEGRITY-SHA256` truncation: responses must carry the full 32-byte
  value.

[RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
[RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489
[RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
