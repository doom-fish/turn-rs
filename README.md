# turn

[![crates.io](https://img.shields.io/badge/crates.io-unpublished-lightgrey.svg)](https://github.com/doom-fish/turn-rs)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A pure-Rust **TURN** (Traversal Using Relays around NAT) client, implementing
[RFC 5766] (updated by [RFC 8656]) on top of the sibling `stun-rs` crate.

TURN is built directly on STUN, so this crate delegates all message framing,
`MESSAGE-INTEGRITY`, `FINGERPRINT`, and long-term-credential key derivation to
`stun-rs`, and adds the TURN methods, the TURN attribute registry, ChannelData
framing, the long-term authentication state machine, and a synchronous
[`TurnClient`].

It is built for WebRTC peers and other ICE-compliant endpoints that need a
relayed transport address when both direct and server-reflexive paths through a
NAT fail.

## Features

- **Methods** — `Allocate`, `Refresh`, `Send`/`Data` indications,
  `CreatePermission`, and `ChannelBind` (RFC 5766 §5–§11).
- **Attributes** — `CHANNEL-NUMBER`, `LIFETIME`, `XOR-PEER-ADDRESS`, `DATA`,
  `XOR-RELAYED-ADDRESS`, `REQUESTED-ADDRESS-FAMILY`, `EVEN-PORT`,
  `REQUESTED-TRANSPORT`, `DONT-FRAGMENT`, `RESERVATION-TOKEN`, and
  `ADDITIONAL-ADDRESS-FAMILY`, with their own XOR-address codec layered on
  `stun::Attribute::Unknown`.
- **ChannelData** — 4-byte framing with first-byte STUN/ChannelData
  demultiplexing and RFC-compliant 4-byte padding (RFC 5766 §11.5,
  RFC 8656 §12.4).
- **Long-term auth** — the mandatory `MESSAGE-INTEGRITY` mechanism with the full
  `401` challenge → re-send and `438` stale-nonce → re-send state machine, keyed
  on `MD5(username:realm:password)` from `stun-rs`.
- **Lifetime accounting** — allocation, permission, and channel-binding
  expiry tracking with a cooperative auto-refresh helper.
- **Transports** — a synchronous client over UDP (default), TCP, and TLS,
  selected by the `turn:` / `turns:` URI scheme.

There are **no third-party runtime dependencies**: only `libc` and the sibling
`stun-rs` / `networkframework` crates. Cryptography and the transport come from
Apple system libraries by way of those crates.

## Quick start

Allocate a relay, install a permission, relay some data, then bind a channel:

```rust,no_run
use std::time::Duration;
use turn::{AllocateOptions, Credential, TurnClient, TurnUri};

# fn main() -> Result<(), turn::Error> {
let uri: TurnUri = "turn:turn.example.org:3478".parse()?;
let mut client = TurnClient::connect(uri, Credential::long_term("user", "", "pass"))?;

let alloc = client.allocate(&AllocateOptions::default())?;
println!("relayed address: {}", alloc.relayed_address());

let peer = "203.0.113.5:50000".parse().unwrap();
client.create_permission(&[peer])?;
client.send_to(peer, b"hello")?;

let channel = client.channel_bind(peer)?;
client.send_channel(channel, b"hello again")?;

// Receive relayed data (Data indications or ChannelData frames):
let (from, data) = client.recv()?;
println!("{} bytes from {from}", data.len());

client.refresh(Duration::from_secs(600))?;
drop(client); // releases the allocation with a zero-lifetime Refresh
# Ok(())
# }
```

### Keeping an allocation alive

This client does **not** spawn a background worker to renew state; refresh is
cooperative so the single-receiver design stays lock-free. Drive it from your
own loop:

```rust,no_run
# use std::time::Duration;
# fn run(client: &mut turn::TurnClient) -> Result<(), turn::Error> {
loop {
    // Refresh any allocation, permission, or channel binding that is due.
    client.maintain()?;

    // Sleep until the next item needs attention (or do other work).
    if let Some(wait) = client.next_maintenance() {
        std::thread::sleep(wait.min(Duration::from_secs(5)));
    }
}
# }
```

## Examples

```sh
# Build an authenticated Allocate request and hex-dump it (offline):
cargo run --example 01_allocate

# Encode/decode ChannelData and demonstrate STUN/ChannelData demux (offline):
cargo run --example 02_channel_data

# Live allocation against a real TURN server (network + credentials):
TURN_LIVE_TESTS=1 \
TURN_URL=turn:turn.example.org:3478 \
TURN_USER=alice TURN_REALM=example.org TURN_PASS=s3cr3t \
cargo run --example 03_live_allocate
```

## Platform

This crate targets **macOS** (and other Apple platforms): transport is provided
by Network.framework via the sibling `networkframework` crate, and all
cryptography comes from Apple system libraries via `stun-rs`.

## Minimum Supported Rust Version

Rust **1.76**.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
[RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
[`TurnClient`]: https://docs.rs/turn
