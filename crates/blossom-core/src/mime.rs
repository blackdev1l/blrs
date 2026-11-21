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
        let essence = value.split(';').next().unwrap_or("").trim();
        let mut parts = essence.split('/');
        let (Some(ty), Some(sub), None) = (parts.next(), parts.next(), parts.next()) else {
            return Self::octet_stream();
        };
        if !is_token(ty) || !is_token(sub) {
            return Self::octet_stream();
        }
        Self(format!(
            "{}/{}",
            ty.to_ascii_lowercase(),
            sub.to_ascii_lowercase()
        ))
    }

    /// Detects the MIME type from the leading bytes of a blob.
    ///
    /// Only the first few hundred bytes are needed; returns `None` when no
    /// signature matches so the caller can fall back to the extension.
    pub fn sniff(head: &[u8]) -> Option<Self> {
        infer::get(head).map(|kind| Self::parse(kind.mime_type()))
    }

    /// Guesses the MIME type from a filename or a bare extension.
    ///
    /// Accepts `.pdf`, `pdf`, or `photo.png`.
    pub fn from_extension(ext: &str) -> Option<Self> {
        let bare = ext
            .rsplit('.')
            .next()
            .unwrap_or(ext)
            .trim()
            .to_ascii_lowercase();
        if bare.is_empty() {
            return None;
        }
        mime_guess::from_ext(&bare)
            .first()
            .map(|mime| Self::parse(mime.essence_str()))
    }

    /// The canonical file extension for this type, including the leading dot.
    ///
    /// Falls back to `.bin` for unknown types (BUD-10).
    pub fn extension(&self) -> &'static str {
        match self.0.as_str() {
            "application/pdf" => ".pdf",
            "application/json" => ".json",
            "application/zip" => ".zip",
            "application/gzip" => ".gz",
            "application/wasm" => ".wasm",
            "application/javascript" => ".js",
            "image/png" => ".png",
            "image/jpeg" => ".jpg",
            "image/gif" => ".gif",
            "image/webp" => ".webp",
            "image/svg+xml" => ".svg",
            "image/bmp" => ".bmp",
            "image/tiff" => ".tiff",
            "image/avif" => ".avif",
            "image/x-icon" | "image/vnd.microsoft.icon" => ".ico",
            "audio/mpeg" => ".mp3",
            "audio/ogg" => ".ogg",
            "audio/wav" | "audio/x-wav" => ".wav",
            "audio/flac" => ".flac",
            "audio/aac" => ".aac",
            "audio/webm" => ".weba",
            "video/mp4" => ".mp4",
            "video/webm" => ".webm",
            "video/mpeg" => ".mpeg",
            "video/quicktime" => ".mov",
            "video/x-matroska" => ".mkv",
            "text/plain" => ".txt",
            "text/html" => ".html",
            "text/css" => ".css",
            "text/csv" => ".csv",
            "text/markdown" => ".md",
            "text/xml" | "application/xml" => ".xml",
            "font/woff" => ".woff",
            "font/woff2" => ".woff2",
            "font/ttf" => ".ttf",
            "font/otf" => ".otf",
            _ => Self::DEFAULT_EXTENSION,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// True when `s` is a non-empty RFC 7230 token (the shape of `type`/`subtype`).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::MimeType;

    #[test]
    fn parse_normalizes_content_type() {
        assert_eq!(
            MimeType::parse("application/pdf").as_str(),
            "application/pdf"
        );
        assert_eq!(
            MimeType::parse("APPLICATION/PDF").as_str(),
            "application/pdf"
        );
        assert_eq!(
            MimeType::parse("text/plain; charset=utf-8").as_str(),
            "text/plain"
        );
        assert_eq!(MimeType::parse("  image/png  ").as_str(), "image/png");
    }

    #[test]
    fn parse_falls_back_to_octet_stream() {
        assert_eq!(MimeType::parse("").as_str(), MimeType::OCTET_STREAM);
        assert_eq!(MimeType::parse("garbage").as_str(), MimeType::OCTET_STREAM);
    }

    #[test]
    fn sniff_detects_known_magic_bytes() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(MimeType::sniff(&png).unwrap().as_str(), "image/png");

        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(MimeType::sniff(&jpeg).unwrap().as_str(), "image/jpeg");

        assert_eq!(MimeType::sniff(b"GIF87a").unwrap().as_str(), "image/gif");
        assert_eq!(
            MimeType::sniff(b"%PDF-1.7").unwrap().as_str(),
            "application/pdf"
        );

        let webp = [b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'];
        assert_eq!(MimeType::sniff(&webp).unwrap().as_str(), "image/webp");
    }

    #[test]
    fn sniff_returns_none_for_unknown_or_empty() {
        assert_eq!(MimeType::sniff(&[]), None);
        assert_eq!(MimeType::sniff(b"this is not a known file signature"), None);
    }

    #[test]
    fn from_extension_resolves_known_extensions() {
        assert_eq!(
            MimeType::from_extension("pdf").unwrap().as_str(),
            "application/pdf"
        );
        assert_eq!(
            MimeType::from_extension(".pdf").unwrap().as_str(),
            "application/pdf"
        );
        assert_eq!(
            MimeType::from_extension("photo.png").unwrap().as_str(),
            "image/png"
        );
        assert_eq!(
            MimeType::from_extension("PNG").unwrap().as_str(),
            "image/png"
        );
    }

    #[test]
    fn from_extension_returns_none_for_unknown() {
        assert_eq!(MimeType::from_extension("definitelynotarealext"), None);
    }

    #[test]
    fn extension_maps_types_to_canonical_suffixes() {
        assert_eq!(MimeType::parse("application/pdf").extension(), ".pdf");
        assert_eq!(MimeType::parse("image/png").extension(), ".png");
        assert_eq!(MimeType::parse("image/jpeg").extension(), ".jpg");
        assert_eq!(MimeType::parse("video/mp4").extension(), ".mp4");
        assert_eq!(MimeType::parse("text/plain").extension(), ".txt");
        assert_eq!(MimeType::octet_stream().extension(), ".bin");
        assert_eq!(MimeType::parse("application/x-made-up").extension(), ".bin");
    }
}
