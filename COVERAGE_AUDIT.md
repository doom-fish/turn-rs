# Coverage Audit

`turn` is a protocol implementation, not a 1:1 binding of an Apple framework,
so this audit is an honest accounting of (a) the system symbols it relies on
(all indirectly) and (b) the TURN protocol surface it covers versus the
relevant RFCs.

## System symbols bound directly

**None.** This crate binds no Apple system symbols of its own. Everything below
the TURN layer is delegated to siblings:

| Capability | Provided by | Notes |
| ---------- | ----------- | ----- |
| Message framing, integrity, fingerprint | `stun-rs` | `MESSAGE-INTEGRITY` (HMAC-SHA1), `FINGERPRINT` (CRC-32) |
| Long-term key `MD5(user:realm:pass)` | `stun-rs` (`auth::long_term_key`) | CommonCrypto `CC_MD5` |
| Transaction-ID CSPRNG | `stun-rs` (`TransactionId::random`) | `SecRandomCopyBytes` |
| UDP / TCP / TLS transport | `networkframework-rs` | Network.framework |

`build.rs` links `Security.framework` only to mirror the sibling crates' link
flags; this crate calls into it transitively, not directly.

## Protocol surface vs. RFCs

| Area | RFC | Covered | Gaps |
| ---- | --- | ------- | ---- |
| `Allocate` + relayed address | 5766 §6 | ✅ | UDP relays only |
| Long-term auth challenge loop | 5766 §4 | ✅ `401`→resend, `438`→resend | — |
| `Refresh` + lifetime release | 5766 §7 | ✅ incl. `LIFETIME=0` | — |
| `CreatePermission` | 5766 §9 | ✅ | — |
| `Send` / `Data` indications | 5766 §10 | ✅ unauthenticated | — |
| `ChannelBind` + ChannelData | 5766 §11 | ✅ | — |
| ChannelData padding | 5766 §11.5 / 8656 §12.4 | ✅ always padded | REQUIRED on TCP/TLS, permitted on UDP |
| XOR address codec | 5766 §14.3/§14.5 | ✅ IPv4 + IPv6 | re-implemented (stun codec is private) |
| `EVEN-PORT` / `RESERVATION-TOKEN` | 5766 §14.6/§14.9 | ✅ encode/decode | server-side reservation not exercised |
| Dual-stack relays | 8656 §14.7/§14.9 | ⚠️ attributes only | no happy-eyeballs ordering |
| IPv6 relays | 6156 | ✅ `REQUESTED-ADDRESS-FAMILY` | — |
| TURN over TCP relays | 6062 | ❌ | `Connect`/`ConnectionBind` out of scope |
| ICMP relaying | 8656 §11.5 | ❌ | not decoded |

✅ complete · ⚠️ partial · ❌ not implemented

## Honest notes

- **TLS is framed identically to TCP and is not live-tested.** `turns:` selects
  a TLS transport that reuses the TCP length-prefixed reassembler; it compiles
  and is exercised by unit tests through the shared framing code, but there is
  no end-to-end test against a TLS relay.
- **Auto-refresh is cooperative, not threaded.** Allocation, permission, and
  channel-binding lifetimes are tracked, but renewal happens only when the
  caller invokes `maintain`; `next_maintenance` reports the soonest due
  interval. This keeps the single background receiver thread free of mutating
  contention.
- **The XOR-address codec is duplicated from `stun-rs`.** `stun`'s
  `encode_xor` / `decode_xor` are `pub(crate)`, so an identical implementation
  lives here. Both derive the key as `magic-cookie || transaction-id`; the
  request transaction ID is set explicitly so the key is known before encoding.

[RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
[RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
[RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
[RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062
