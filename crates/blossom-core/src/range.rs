/// An inclusive byte range, as defined by RFC 7233.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    /// Inclusive, unlike the `Content-Range` header's exclusive end.
    pub end: u64,
}

impl ByteRange {
    /// Number of bytes covered, which is the `Content-Length` of a 206.
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Always false: a constructed range covers at least one byte.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The `Content-Range` header value for this range.
    pub fn content_range(&self, total_len: u64) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, total_len)
    }
}

/// The outcome of evaluating a `Range` header against a known blob length.
///
/// BUD-01 makes range support a SHOULD and assigns distinct status codes, so
/// the parse result is kept distinct from the HTTP mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No usable `Range` header: serve the whole blob with `200 OK`.
    Full,
    /// One satisfiable range: serve `206 Partial Content`.
    Partial(ByteRange),
    /// Well-formed but outside the blob: `416 Range Not Satisfiable`.
    Unsatisfiable,
    /// Syntactically invalid: `400 Bad Request`.
    Malformed,
}

/// Parses a `Range` header value (RFC 7233 section 3) against `total_len`.
///
/// Handles `bytes=start-end`, `bytes=start-`, and the suffix form `bytes=-N`.
/// Multiple ranges are not supported by this server and are reported as
/// `Malformed` rather than silently truncated.
pub fn parse_range(header: Option<&str>, total_len: u64) -> RangeOutcome {
    todo!("lane A: RFC 7233 single-range parsing")
}
