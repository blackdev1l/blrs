use crate::error::CoreError;
use crate::sha256::Sha256;

/// Splits a `/<sha256>[.ext]` path segment into its hash and optional extension.
///
/// BUD-01 requires `GET /<sha256>` and `HEAD /<sha256>` to accept an optional
/// file extension, and requires the response MIME type to come from the blob
/// rather than the extension. The extension is therefore advisory only.
///
/// Returns [`CoreError::InvalidHash`] when the leading component is not exactly
/// 64 lowercase hex characters.
pub fn parse_blob_path(segment: &str) -> Result<(Sha256, Option<&str>), CoreError> {
    todo!("lane A: split at the first '.', validate the hash, keep the extension verbatim")
}
