use serde::{Deserialize, Serialize};

use crate::mime::MimeType;
use crate::sha256::Sha256;

/// A BUD-02 blob descriptor.
///
/// Returned by `PUT /upload` and `PUT /mirror`. The `url` field is required to
/// carry a file extension so the value can be embedded in social posts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub mime: String,
    pub uploaded: i64,
    /// BUD-08 NIP-94 metadata tags, when the server chooses to return them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip94: Option<Vec<Vec<String>>>,
}

impl BlobDescriptor {
    /// Builds a descriptor whose `url` is `{base_url}/{sha256}{ext}`.
    ///
    /// `base_url` has any trailing slash trimmed; the extension comes from the
    /// MIME type so the URL is always embeddable (BUD-02).
    pub fn new(base_url: &str, hash: &Sha256, size: u64, mime: &MimeType, uploaded: i64) -> Self {
        todo!("lane A: build url with canonical extension")
    }

    /// Adds the BUD-08 `nip94` tag array.
    pub fn with_nip94(mut self) -> Self {
        todo!("lane A: emit nip94 tags")
    }
}
