# Coverage

This document tracks which parts of the TURN specifications this crate
implements, and what is intentionally deferred.

## Specifications

| Spec | Title | Status |
| ---- | ----- | ------ |
| [RFC 5766] | Traversal Using Relays around NAT (TURN) | Client implemented |
| [RFC 8656] | TURN (bis) | Dual-stack attributes implemented; happy-eyeballs deferred |
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

Integrity, fingerprint, `USERNAME`, `REALM`, `NONCE`, and `ERROR-CODE` are
handled by the sibling `stun-rs` crate.

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
(`Allocate`/`Refresh`/`CreatePermission`/`ChannelBind`) run an auth retry loop:
the first attempt is unauthenticated; a `401` supplies `REALM`/`NONCE`; the
request is retried with `USERNAME`/`REALM`/`NONCE` and `MESSAGE-INTEGRITY`; a
`438` (stale nonce) captures a fresh `NONCE` and retries. Each attempt uses a
new transaction ID. `Send`/`Data` indications are not authenticated, per
RFC 5766 §10.

## Transports

| Transport | URI | Status |
| --------- | --- | ------ |
| UDP | `turn:` | ✅ implemented, default, live-tested path |
| TCP | `turn:?transport=tcp` | ✅ implemented, length-prefixed reassembly |
| TLS | `turns:` | ✅ compiles and frames as TCP; not live-tested |

## Deferred

- TURN-TCP connection management (`Connect` / `ConnectionBind` /
  `ConnectionAttempt`, RFC 6062) — only UDP relays are negotiated.
- ICMP `Data` indication relaying (RFC 8656 §11.5 ICMP attribute).
- RFC 8656 happy-eyeballs ordering between dual-stack relayed candidates.
- A background auto-refresh worker thread; refresh is cooperative
  (`maintain` / `next_maintenance`) by design.

[RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
[RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
[RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
