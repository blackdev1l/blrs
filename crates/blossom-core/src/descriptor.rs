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
        let sha256 = hash.to_hex();
        let url = format!(
            "{}/{}{}",
            base_url.trim_end_matches('/'),
            sha256,
            mime.extension()
        );
        Self {
            url,
            sha256,
            size,
            mime: mime.as_str().to_string(),
            uploaded,
            nip94: None,
        }
    }

    /// Adds the BUD-08 `nip94` tag array.
    pub fn with_nip94(mut self) -> Self {
        self.nip94 = Some(vec![
            vec!["url".to_string(), self.url.clone()],
            vec!["m".to_string(), self.mime.clone()],
            vec!["x".to_string(), self.sha256.clone()],
            vec!["size".to_string(), self.size.to_string()],
        ]);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::BlobDescriptor;
    use crate::mime::MimeType;
    use crate::sha256::Sha256;

    // The worked example from BUD-02.
    const HASH_HEX: &str = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    fn hash() -> Sha256 {
        Sha256::parse(HASH_HEX).unwrap()
    }

    #[test]
    fn new_builds_url_with_canonical_extension() {
        let descriptor = BlobDescriptor::new(
            "https://cdn.example.com",
            &hash(),
            184292,
            &MimeType::parse("application/pdf"),
            1725105921,
        );

        assert_eq!(
            descriptor.url,
            format!("https://cdn.example.com/{HASH_HEX}.pdf")
        );
        assert_eq!(descriptor.sha256, HASH_HEX);
        assert_eq!(descriptor.size, 184292);
        assert_eq!(descriptor.mime, "application/pdf");
        assert_eq!(descriptor.uploaded, 1725105921);
        assert_eq!(descriptor.nip94, None);
    }

    #[test]
    fn new_trims_trailing_slash_from_base_url() {
        let descriptor = BlobDescriptor::new(
            "https://cdn.example.com/",
            &hash(),
            1,
            &MimeType::parse("image/png"),
            0,
        );

        assert_eq!(
            descriptor.url,
            format!("https://cdn.example.com/{HASH_HEX}.png")
        );
    }

    #[test]
    fn new_uses_bin_extension_for_unknown_type() {
        let descriptor = BlobDescriptor::new(
            "https://cdn.example.com",
            &hash(),
            1,
            &MimeType::parse("application/x-made-up"),
            0,
        );

        assert!(
            descriptor.url.ends_with(".bin"),
            "url was {}",
            descriptor.url
        );
    }

    #[test]
    fn with_nip94_emits_bud08_tags() {
        let descriptor = BlobDescriptor::new(
            "https://cdn.example.com",
            &hash(),
            184292,
            &MimeType::parse("application/pdf"),
            1725105921,
        )
        .with_nip94();

        let tags = descriptor.nip94.expect("nip94 tags");
        let url = format!("https://cdn.example.com/{HASH_HEX}.pdf");
        assert!(tags.contains(&vec!["url".to_string(), url]));
        assert!(tags.contains(&vec!["m".to_string(), "application/pdf".to_string()]));
        assert!(tags.contains(&vec!["x".to_string(), HASH_HEX.to_string()]));
        assert!(tags.contains(&vec!["size".to_string(), "184292".to_string()]));
    }

    #[test]
    fn serde_uses_type_key_and_omits_absent_nip94() {
        let descriptor = BlobDescriptor::new(
            "https://cdn.example.com",
            &hash(),
            184292,
            &MimeType::parse("application/pdf"),
            1725105921,
        );

        let json = serde_json::to_value(&descriptor).unwrap();
        assert!(json.get("type").is_some(), "json was {json}");
        assert!(json.get("mime").is_none(), "json was {json}");
        assert!(json.get("nip94").is_none(), "json was {json}");

        let json = serde_json::to_value(descriptor.with_nip94()).unwrap();
        assert!(json.get("nip94").is_some(), "json was {json}");
    }
}
