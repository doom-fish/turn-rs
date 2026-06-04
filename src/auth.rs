//! Long-term credentials and the realm/nonce authentication state for TURN.
//!
//! TURN servers always require the long-term credential mechanism (RFC 5766
//! §4): the first `Allocate` is answered with `401 Unauthorized` carrying a
//! `REALM` and a `NONCE`, and the client retries with `USERNAME`, `REALM`,
//! `NONCE`, and a `MESSAGE-INTEGRITY` computed over the long-term key
//! `MD5(username ":" realm ":" password)` (delegated to
//! [`stun::auth::long_term_key`]). When the server later rejects a request with
//! `438 Stale Nonce`, the client captures the fresh `NONCE` and retries.

use stun::auth::long_term_key;

/// A TURN credential.
///
/// TURN mandates the long-term mechanism, so this is currently a single
/// variant; the enum leaves room for future credential types without breaking
/// the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credential {
    /// Long-term credentials: a username, realm, and password.
    LongTerm {
        /// The authentication username (UTF-8).
        username: String,
        /// The authentication realm (UTF-8). May be empty, in which case the
        /// realm advertised by the server in its `401` challenge is used.
        realm: String,
        /// The shared password.
        password: String,
    },
}

impl Credential {
    /// Construct a long-term credential.
    #[must_use]
    pub fn long_term(
        username: impl Into<String>,
        realm: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::LongTerm {
            username: username.into(),
            realm: realm.into(),
            password: password.into(),
        }
    }

    /// The credential username.
    #[must_use]
    pub fn username(&self) -> &str {
        match self {
            Self::LongTerm { username, .. } => username,
        }
    }

    /// The configured realm (possibly empty if it is to be learned from the
    /// server's challenge).
    #[must_use]
    pub fn realm(&self) -> &str {
        match self {
            Self::LongTerm { realm, .. } => realm,
        }
    }

    /// The credential password.
    #[must_use]
    pub fn password(&self) -> &str {
        match self {
            Self::LongTerm { password, .. } => password,
        }
    }

    /// Derive the long-term HMAC key for a given effective realm.
    ///
    /// `MD5(username ":" realm ":" password)` per RFC 5766 §4 / RFC 5389 §15.4.
    #[must_use]
    pub fn long_term_key(&self, realm: &str) -> [u8; 16] {
        long_term_key(self.username(), realm, self.password())
    }
}

/// The mutable authentication state carried across a TURN session: the realm
/// and nonce learned from the server, plus the cached long-term key.
///
/// This is the data structure the realm/nonce refresh loop mutates as it walks
/// the `401` → re-send → `438` → re-send states.
#[derive(Debug, Clone, Default)]
pub struct AuthState {
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<[u8; 16]>,
}

impl AuthState {
    /// Create an empty authentication state (before the first challenge).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the `REALM` / `NONCE` from a server challenge and (re)derive the
    /// long-term key for that realm against `credential`.
    ///
    /// If the credential carries a non-empty realm it takes precedence over the
    /// server-advertised one (some deployments pin the realm); otherwise the
    /// server's realm is adopted.
    pub fn challenge(&mut self, credential: &Credential, realm: &str, nonce: &str) {
        let effective_realm = if credential.realm().is_empty() {
            realm.to_owned()
        } else {
            credential.realm().to_owned()
        };
        self.key = Some(credential.long_term_key(&effective_realm));
        self.realm = Some(effective_realm);
        self.nonce = Some(nonce.to_owned());
    }

    /// Update only the nonce, e.g. after a `438 Stale Nonce` response, keeping
    /// the realm and derived key.
    pub fn refresh_nonce(&mut self, nonce: &str) {
        self.nonce = Some(nonce.to_owned());
    }

    /// The effective realm, once a challenge has been processed.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    /// The current nonce, once a challenge has been processed.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// The cached long-term HMAC key, once a challenge has been processed.
    #[must_use]
    pub fn key(&self) -> Option<&[u8; 16]> {
        self.key.as_ref()
    }

    /// Whether the state is ready to authenticate a request (a challenge has
    /// been processed and the key is derived).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.key.is_some() && self.realm.is_some() && self.nonce.is_some()
    }
}
