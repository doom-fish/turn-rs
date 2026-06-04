# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024

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
  (`classify`) and RFC-compliant 4-byte padding on every frame (RFC 5766
  §11.5, RFC 8656 §12.4: padding REQUIRED on TCP / TLS-over-TCP and
  permitted on UDP).
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
