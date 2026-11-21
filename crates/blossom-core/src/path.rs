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
    let (hash_part, ext) = match segment.split_once('.') {
        None => (segment, None),
        Some((hash_part, "")) => (hash_part, None),
        Some((hash_part, ext)) => (hash_part, Some(ext)),
    };
    let hash = Sha256::parse(hash_part)?;
    Ok((hash, ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the empty string, a published vector.
    const HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn bare_hash_has_no_extension() {
        let (hash, ext) = parse_blob_path(HASH).expect("valid hash");
        assert_eq!(hash.to_hex(), HASH);
        assert_eq!(ext, None);
    }

    #[test]
    fn simple_extension_is_preserved_verbatim() {
        let path = format!("{HASH}.pdf");
        let (hash, ext) = parse_blob_path(&path).expect("valid path");
        assert_eq!(hash.to_hex(), HASH);
        assert_eq!(ext, Some("pdf"));
    }

    #[test]
    fn extension_case_is_preserved() {
        let path = format!("{HASH}.PDF");
        let (_, ext) = parse_blob_path(&path).expect("valid path");
        assert_eq!(ext, Some("PDF"));
    }

    #[test]
    fn extension_splits_at_first_dot() {
        let path = format!("{HASH}.tar.gz");
        let (_, ext) = parse_blob_path(&path).expect("valid path");
        assert_eq!(ext, Some("tar.gz"));
    }

    #[test]
    fn empty_extension_is_none() {
        let path = format!("{HASH}.");
        let (_, ext) = parse_blob_path(&path).expect("valid path");
        assert_eq!(ext, None);
    }

    #[test]
    fn uppercase_hash_is_rejected() {
        let upper = HASH.to_uppercase();
        assert_eq!(parse_blob_path(&upper), Err(CoreError::InvalidHash));
    }

    #[test]
    fn wrong_length_hash_is_rejected() {
        assert_eq!(parse_blob_path(&HASH[..63]), Err(CoreError::InvalidHash));
        let longer = format!("{HASH}0");
        assert_eq!(parse_blob_path(&longer), Err(CoreError::InvalidHash));
    }

    #[test]
    fn non_hex_character_is_rejected() {
        // 64 characters, but 'z' is not a hex digit.
        let bad = format!("{}z", &HASH[..63]);
        assert_eq!(parse_blob_path(&bad), Err(CoreError::InvalidHash));
    }

    #[test]
    fn empty_segment_is_rejected() {
        assert_eq!(parse_blob_path(""), Err(CoreError::InvalidHash));
    }
}
