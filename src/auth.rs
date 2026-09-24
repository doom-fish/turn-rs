//! Long-term credentials and the realm/nonce authentication state for TURN.
//!
//! TURN servers always require the long-term credential mechanism (RFC 5766
//! §4, RFC 8489 §9.2): the first `Allocate` is answered with `401 Unauthorized`
//! carrying a `REALM` and a `NONCE`, and the client retries with `USERNAME`,
//! `REALM`, `NONCE`, and a message-integrity attribute computed over the
//! long-term key. Without `PASSWORD-ALGORITHMS` the key is
//! `MD5(username ":" realm ":" password)` (delegated to
//! [`stun::auth::long_term_key`]) and the attribute is `MESSAGE-INTEGRITY`.
//! When the challenge carries `PASSWORD-ALGORITHMS`, the first supported
//! algorithm (SHA-256 or MD5) derives the key and every request uses
//! `MESSAGE-INTEGRITY-SHA256`. When the server later rejects a request with
//! `438 Stale Nonce`, the client captures the fresh `NONCE` and retries.

use std::fmt;

use stun::attribute::types as stun_types;
use stun::auth::long_term_key;
use stun::{Attribute as StunAttribute, Message, MessageBuilder};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[allow(missing_docs)]
pub const PASSWORD_ALGORITHMS: u16 = 0x8002;

#[allow(missing_docs)]
pub const USERHASH: u16 = 0x001E;

const NONCE_COOKIE: &str = "obMatJos2";
const PASSWORD_ALGORITHMS_BIT: u32 = 1 << 23;
const USERNAME_ANONYMITY_BIT: u32 = 1 << 22;
const SHA256_LEN: usize = 32;

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordAlgorithm {
    Md5,
    Sha256,
}

impl PasswordAlgorithm {
    #[allow(missing_docs)]
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Md5 => 0x0001,
            Self::Sha256 => 0x0002,
        }
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(Self::Md5),
            0x0002 => Some(Self::Sha256),
            _ => None,
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Integrity {
    Sha1,
    Sha256,
}

/// A long-term TURN credential (RFC 5766 §4): a username, an optional realm,
/// and a password.
#[derive(Clone)]
pub struct Credential {
    username: String,
    realm: String,
    password: Zeroizing<String>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("username", &self.username)
            .field("realm", &self.realm)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credential {
    /// Construct a long-term credential.
    ///
    /// An empty `realm` accepts the realm the server advertises in its `401`
    /// challenge; a non-empty one must equal it, or the challenge is refused.
    #[must_use]
    pub fn long_term(
        username: impl Into<String>,
        realm: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            realm: realm.into(),
            password: Zeroizing::new(password.into()),
        }
    }

    /// The credential username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The configured realm (possibly empty if it is to be learned from the
    /// server's challenge).
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The credential password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Derive the long-term HMAC key for a given effective realm.
    ///
    /// `MD5(username ":" realm ":" password)` or
    /// `SHA-256(username ":" realm ":" password)` per RFC 8489 §18.5.1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the SHA-256 digest cannot be computed.
    pub fn long_term_key(
        &self,
        algorithm: PasswordAlgorithm,
        realm: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match algorithm {
            PasswordAlgorithm::Md5 => Ok(long_term_key(&self.username, realm, &self.password)),
            PasswordAlgorithm::Sha256 => sha256_joined(&[
                self.username.as_bytes(),
                realm.as_bytes(),
                self.password.as_bytes(),
            ]),
        }
    }

    fn userhash(&self, realm: &str) -> Result<Vec<u8>> {
        Ok(sha256_joined(&[self.username.as_bytes(), realm.as_bytes()])?.to_vec())
    }
}

fn sha256_joined(parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Zeroizing::new(Vec::new());
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            input.push(b':');
        }
        input.extend_from_slice(part);
    }
    let digest = Zeroizing::new(
        cryptokit::hashing::sha256(&input).map_err(|_| Error::Crypto("SHA-256 failed"))?,
    );
    if digest.len() != SHA256_LEN {
        return Err(Error::Crypto("SHA-256 returned an unexpected length"));
    }
    Ok(digest)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SecurityFeatures {
    password_algorithms: bool,
    username_anonymity: bool,
}

fn security_features(nonce: &str) -> SecurityFeatures {
    let Some(encoded) = nonce
        .strip_prefix(NONCE_COOKIE)
        .and_then(|rest| rest.get(..4))
    else {
        return SecurityFeatures::default();
    };
    let mut bits = 0u32;
    for byte in encoded.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return SecurityFeatures::default(),
        };
        bits = (bits << 6) | u32::from(digit);
    }
    SecurityFeatures {
        password_algorithms: bits & PASSWORD_ALGORITHMS_BIT != 0,
        username_anonymity: bits & USERNAME_ANONYMITY_BIT != 0,
    }
}

fn nonce_of(response: &Message) -> Result<String> {
    match response.get(stun_types::NONCE) {
        Some(StunAttribute::Nonce(nonce)) => Ok(nonce.clone()),
        _ => Err(Error::MissingChallenge),
    }
}

fn password_algorithms_of(response: &Message) -> Option<Vec<u8>> {
    match response.get(PASSWORD_ALGORITHMS) {
        Some(StunAttribute::Unknown { value, .. }) => Some(value.clone()),
        _ => None,
    }
}

fn first_supported(algorithms: &[u8]) -> Result<PasswordAlgorithm> {
    let mut offset = 0usize;
    while offset < algorithms.len() {
        let header = algorithms
            .get(offset..offset + 4)
            .ok_or(Error::PasswordAlgorithms(
                "PASSWORD-ALGORITHMS is truncated",
            ))?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if offset + 4 + length > algorithms.len() {
            return Err(Error::PasswordAlgorithms(
                "PASSWORD-ALGORITHMS is truncated",
            ));
        }
        if length == 0 {
            if let Some(algorithm) = PasswordAlgorithm::from_code(code) {
                return Ok(algorithm);
            }
        }
        offset += 4 + length.next_multiple_of(4);
    }
    Err(Error::PasswordAlgorithms(
        "PASSWORD-ALGORITHMS lists no supported algorithm",
    ))
}

/// The authentication state carried across a TURN session: the realm and
/// nonce learned from the server, the negotiated password algorithm, and the
/// cached long-term key.
///
/// The client replaces its state only after a response authenticated with the
/// key shows the server accepted it.
#[derive(Clone, Default)]
pub struct AuthState {
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<Zeroizing<Vec<u8>>>,
    algorithm: Option<PasswordAlgorithm>,
    algorithms: Option<Vec<u8>>,
    userhash: Option<Vec<u8>>,
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthState")
            .field("realm", &self.realm)
            .field("nonce", &self.nonce)
            .field("password_algorithm", &self.algorithm)
            .field("userhash", &self.userhash.is_some())
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl AuthState {
    /// Create an empty authentication state (before the first challenge).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(missing_docs)]
    pub fn from_challenge(credential: &Credential, response: &Message) -> Result<Self> {
        let realm = match response.get(stun_types::REALM) {
            Some(StunAttribute::Realm(realm)) => realm.clone(),
            _ => return Err(Error::MissingChallenge),
        };
        let nonce = nonce_of(response)?;
        if !credential.realm().is_empty() && credential.realm() != realm {
            return Err(Error::AuthFailed);
        }
        let features = security_features(&nonce);
        let algorithms = password_algorithms_of(response);
        if features.password_algorithms && algorithms.is_none() {
            return Err(Error::PasswordAlgorithms(
                "nonce cookie announces PASSWORD-ALGORITHMS but the attribute is missing",
            ));
        }
        let algorithm = algorithms.as_deref().map(first_supported).transpose()?;
        let key = credential.long_term_key(algorithm.unwrap_or(PasswordAlgorithm::Md5), &realm)?;
        let userhash = if features.username_anonymity {
            Some(credential.userhash(&realm)?)
        } else {
            None
        };
        Ok(Self {
            realm: Some(realm),
            nonce: Some(nonce),
            key: Some(key),
            algorithm,
            algorithms,
            userhash,
        })
    }

    #[allow(missing_docs)]
    pub fn with_stale_nonce(&self, response: &Message) -> Result<Self> {
        if !self.is_ready() {
            return Err(Error::InvalidState("stale nonce before any challenge"));
        }
        let nonce = nonce_of(response)?;
        if let Some(StunAttribute::Realm(realm)) = response.get(stun_types::REALM) {
            if self.realm.as_deref() != Some(realm.as_str()) {
                return Err(Error::AuthFailed);
            }
        }
        let features = security_features(&nonce);
        let algorithms = password_algorithms_of(response);
        if features.password_algorithms && algorithms.is_none() {
            return Err(Error::PasswordAlgorithms(
                "nonce cookie announces PASSWORD-ALGORITHMS but the attribute is missing",
            ));
        }
        if algorithms != self.algorithms {
            return Err(Error::PasswordAlgorithms(
                "PASSWORD-ALGORITHMS changed within a session",
            ));
        }
        if features.username_anonymity != self.userhash.is_some() {
            return Err(Error::AuthFailed);
        }
        let mut next = self.clone();
        next.nonce = Some(nonce);
        Ok(next)
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
    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref().map(Vec::as_slice)
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn password_algorithm(&self) -> Option<PasswordAlgorithm> {
        self.algorithm
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn integrity(&self) -> Integrity {
        if self.algorithms.is_some() {
            Integrity::Sha256
        } else {
            Integrity::Sha1
        }
    }

    /// Whether the state is ready to authenticate a request (a challenge has
    /// been processed and the key is derived).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.key.is_some() && self.realm.is_some() && self.nonce.is_some()
    }

    pub(crate) fn sign(&self, builder: MessageBuilder, username: &str) -> MessageBuilder {
        let (Some(realm), Some(nonce), Some(key)) = (&self.realm, &self.nonce, &self.key) else {
            return builder;
        };
        let mut builder = match &self.userhash {
            Some(hash) => builder.attribute(StunAttribute::Unknown {
                attribute_type: USERHASH,
                value: hash.clone(),
            }),
            None => builder.attribute(StunAttribute::Username(username.to_owned())),
        };
        builder = builder
            .attribute(StunAttribute::Realm(realm.clone()))
            .attribute(StunAttribute::Nonce(nonce.clone()));
        if let (Some(value), Some(algorithm)) = (&self.algorithms, self.algorithm) {
            builder = builder
                .attribute(StunAttribute::Unknown {
                    attribute_type: PASSWORD_ALGORITHMS,
                    value: value.clone(),
                })
                .attribute(StunAttribute::PasswordAlgorithm(stun::PasswordAlgorithm {
                    algorithm: algorithm.code(),
                    parameters: Vec::new(),
                }));
        }
        match self.integrity() {
            Integrity::Sha1 => builder.with_message_integrity_sha1(key),
            Integrity::Sha256 => builder.with_message_integrity_sha256(key),
        }
    }

    pub(crate) fn verify(&self, message: &Message) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        match self.integrity() {
            Integrity::Sha1 => message.verify_message_integrity(key).is_ok(),
            Integrity::Sha256 => message.verify_message_integrity_sha256(key).is_ok(),
        }
    }
}
