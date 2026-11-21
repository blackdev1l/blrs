use serde::{Deserialize, Serialize};

use crate::error::AuthError;
use crate::sha256::Sha256;

/// The action an authorization token authorizes (BUD-11 `t` tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Get,
    Upload,
    List,
    Delete,
    Media,
}

impl Action {
    /// The `t` tag verb for this action.
    pub fn verb(self) -> &'static str {
        match self {
            Action::Get => "get",
            Action::Upload => "upload",
            Action::List => "list",
            Action::Delete => "delete",
            Action::Media => "media",
        }
    }

    /// Parses a `t` tag verb.
    pub fn from_verb(verb: &str) -> Option<Self> {
        match verb {
            "get" => Some(Action::Get),
            "upload" => Some(Action::Upload),
            "list" => Some(Action::List),
            "delete" => Some(Action::Delete),
            "media" => Some(Action::Media),
            _ => None,
        }
    }
}

/// A NIP-01 nostr event, as carried inside an authorization token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    #[serde(default)]
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    /// All values for the first tag named `name`, in order.
    pub fn tag_values(&self, name: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|k| k == name))
            .filter_map(|tag| tag.get(1).map(String::as_str))
            .collect()
    }
}

/// A parsed BUD-11 authorization token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthToken {
    pub event: NostrEvent,
}

/// Everything the server must supply to validate a token.
#[derive(Clone, Copy, Debug)]
pub struct VerifyContext<'a> {
    /// The action the target endpoint performs.
    pub action: Action,
    /// This server's domain name, matched against `server` tags (e.g. `cdn.example.com`).
    pub host: &'a str,
    /// The blob hash implied by the endpoint, when it has one.
    pub blob: Option<&'a Sha256>,
    /// Whether at least one matching `x` tag is required (BUD-11 table).
    pub require_x: bool,
    /// Current unix time, injected so expiry is testable.
    pub now: i64,
}

/// The verified identity behind a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedUser {
    pub pubkey: String,
}

impl AuthToken {
    /// Decodes an `Authorization: Nostr <base64url-no-pad json>` header value.
    pub fn from_authorization_header(value: &str) -> Result<Self, AuthError> {
        todo!("lane A: scheme check + base64url decode + serde_json parse")
    }

    /// Runs the BUD-11 validation checklist in order.
    ///
    /// 1. kind is 24242
    /// 2. `created_at` is in the past
    /// 3. `expiration` tag is present and in the future
    /// 4. a `t` tag matches the endpoint's action
    /// 5. if any `server` tag is present, this host is among them
    /// 6. if the endpoint requires it, an `x` tag matches the blob hash
    pub fn verify(&self, ctx: VerifyContext<'_>) -> Result<AuthorizedUser, AuthError> {
        todo!("lane A: BUD-11 checklist")
    }
}

/// Computes the NIP-01 canonical event id.
///
/// This is `sha256` of the compact JSON array
/// `[0, pubkey, created_at, kind, tags, content]`.
pub fn event_id(event: &NostrEvent) -> Result<String, AuthError> {
    todo!("lane A: NIP-01 canonical serialization + sha256")
}

/// Verifies the event's BIP-340 schnorr signature against its `pubkey`.
pub fn verify_signature(event: &NostrEvent) -> Result<(), AuthError> {
    todo!("lane A: secp256k1 schnorr verify")
}
