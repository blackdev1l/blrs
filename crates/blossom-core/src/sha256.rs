use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

/// A SHA-256 digest.
///
/// Blossom addresses blobs by the sha256 of their exact bytes, so this type is
/// the primary key of the whole server. It only ever holds 32 bytes and is
/// `Copy`; the textual form is validated on the way in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    /// Length of the lowercase hex form.
    pub const HEX_LEN: usize = 64;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The lowercase hex encoding.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses exactly 64 lowercase hex characters.
    ///
    /// Uppercase, a short/long string, or any non-hex byte is rejected: the
    /// BUDs are explicit that pubkeys and hashes are lowercase hex.
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        if s.len() != Self::HEX_LEN {
            return Err(CoreError::InvalidHash);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CoreError::InvalidHash);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| CoreError::InvalidHash)?;
        Ok(Self(out))
    }
}

impl FromStr for Sha256 {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({})", self.to_hex())
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
