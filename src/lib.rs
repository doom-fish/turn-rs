//! `turn` — a pure-Rust TURN (Traversal Using Relays around NAT) client,
//! layered on [`stun`].
//!
//! This crate implements the client side of [RFC 5766] (updated by
//! [RFC 8656]). TURN is built directly on STUN, so all message framing,
//! integrity, fingerprinting, and long-term-credential key derivation are
//! delegated to the sibling `stun-rs` crate; this crate adds the TURN methods,
//! the TURN attribute registry, ChannelData framing, the long-term
//! authentication state machine, and a synchronous [`TurnClient`].
//!
//! TURN gives WebRTC peers and other ICE-compliant endpoints a relayed
//! transport address when direct and server-reflexive paths through a NAT both
//! fail.
//!
//! # Highlights
//!
//! * TURN [methods][method]: `Allocate`, `Refresh`, `Send`/`Data` indications,
//!   `CreatePermission`, and `ChannelBind`.
//! * The TURN [attribute] registry, including the XOR-obfuscated
//!   `XOR-PEER-ADDRESS` / `XOR-RELAYED-ADDRESS`, layered on
//!   [`stun::Attribute::Unknown`].
//! * [ChannelData][channel] framing with first-byte STUN/ChannelData
//!   demultiplexing and transport-aware padding (RFC 5766 §11.5).
//! * The mandatory long-term [auth] mechanism with a `REALM`/`NONCE`
//!   refresh state machine (`401` → re-send, `438` → re-send).
//! * [Allocation][allocation], [permission], and
//!   [channel binding][channel_binding] lifetime accounting with cooperative
//!   auto-refresh.
//! * A synchronous [`TurnClient`] over [UDP][transport::udp],
//!   [TCP][transport::tcp], and [TLS][transport::tls].
//!
//! There are no third-party runtime dependencies: only `libc` and the sibling
//! `stun-rs` / `networkframework` crates.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use turn::{AllocateOptions, Credential, TurnClient, TurnUri};
//!
//! # fn main() -> Result<(), turn::Error> {
//! let uri: TurnUri = "turn:turn.example.org:3478".parse()?;
//! let mut client = TurnClient::connect(uri, Credential::long_term("user", "", "pass"))?;
//!
//! let alloc = client.allocate(&AllocateOptions::default())?;
//! let _relayed = alloc.relayed_address();
//!
//! let peer = "203.0.113.5:50000".parse().unwrap();
//! client.create_permission(&[peer])?;
//! client.send_to(peer, b"hello")?;
//!
//! let channel = client.channel_bind(peer)?;
//! client.send_channel(channel, b"hello again")?;
//!
//! client.refresh(Duration::from_secs(600))?;
//! drop(client); // sends Refresh with LIFETIME=0
//! # Ok(())
//! # }
//! ```
//!
//! [RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
//! [RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod allocation;
pub mod attribute;
pub mod auth;
pub mod channel;
pub mod channel_binding;
pub mod client;
pub mod error;
pub mod method;
pub mod permission;
pub mod transport;

pub use allocation::Allocation;
pub use attribute::{AddressFamily, Attribute, EvenPort};
pub use auth::{AuthState, Credential};
pub use channel::{ChannelData, PacketKind};
pub use channel_binding::ChannelBinding;
pub use client::{AllocateOptions, Scheme, TurnClient, TurnUri};
pub use error::{Error, Result};
pub use method::Method;
pub use permission::Permission;
pub use transport::Transport;
