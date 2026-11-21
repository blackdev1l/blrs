/// A normalized MIME type: lowercase `type/subtype`, with no parameters.
///
/// Blossom requires a `Content-Type` on every blob response and falls back to
/// `application/octet-stream` when the type is unknown (BUD-01). The canonical
/// file extension is derived from this value for descriptor URLs (BUD-02).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MimeType(String);

impl MimeType {
    /// The BUD-01 fallback for unknown types.
    pub const OCTET_STREAM: &'static str = "application/octet-stream";

    /// The BUD-10 fallback file extension.
    pub const DEFAULT_EXTENSION: &'static str = ".bin";

    /// Builds the `application/octet-stream` fallback.
    pub fn octet_stream() -> Self {
        Self(Self::OCTET_STREAM.to_string())
    }

    /// Normalizes a `Content-Type` header value.
    ///
    /// Drops any `;charset=...` parameters and lowercases the result. Values
    /// that are not `type/subtype` shape collapse to `application/octet-stream`.
    pub fn parse(value: &str) -> Self {
        todo!("lane A: normalize Content-Type, strip parameters, fallback to octet-stream")
    }

    /// Detects the MIME type from the leading bytes of a blob.
    ///
    /// Only the first few hundred bytes are needed; returns `None` when no
    /// signature matches so the caller can fall back to the extension.
    pub fn sniff(head: &[u8]) -> Option<Self> {
        todo!("lane A: magic-byte detection")
    }

    /// Guesses the MIME type from a filename or a bare extension.
    ///
    /// Accepts `.pdf`, `pdf`, or `photo.png`.
    pub fn from_extension(ext: &str) -> Option<Self> {
        todo!("lane A: extension lookup")
    }

    /// The canonical file extension for this type, including the leading dot.
    ///
    /// Falls back to `.bin` for unknown types (BUD-10).
    pub fn extension(&self) -> &'static str {
        todo!("lane A: mime -> canonical extension")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
