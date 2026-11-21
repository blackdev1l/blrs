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
    let Some(value) = header else {
        return RangeOutcome::Full;
    };
    let value = value.trim();
    if value.is_empty() {
        return RangeOutcome::Full;
    }
    let Some(spec) = value.strip_prefix("bytes=") else {
        return RangeOutcome::Malformed;
    };
    // This server answers a single range only; a list is not silently truncated.
    if spec.contains(',') {
        return RangeOutcome::Malformed;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Malformed;
    };
    if start_s.is_empty() {
        let Ok(suffix) = end_s.parse::<u64>() else {
            return RangeOutcome::Malformed;
        };
        if suffix == 0 || total_len == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        return RangeOutcome::Partial(ByteRange {
            start: total_len.saturating_sub(suffix),
            end: total_len - 1,
        });
    }
    let Ok(start) = start_s.parse::<u64>() else {
        return RangeOutcome::Malformed;
    };
    if total_len == 0 || start >= total_len {
        return RangeOutcome::Unsatisfiable;
    }
    if end_s.is_empty() {
        return RangeOutcome::Partial(ByteRange {
            start,
            end: total_len - 1,
        });
    }
    let Ok(end) = end_s.parse::<u64>() else {
        return RangeOutcome::Malformed;
    };
    if end < start {
        return RangeOutcome::Malformed;
    }
    let end = end.min(total_len - 1);
    RangeOutcome::Partial(ByteRange { start, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_blank_header_is_full() {
        assert_eq!(parse_range(None, 1000), RangeOutcome::Full);
        assert_eq!(parse_range(Some(""), 1000), RangeOutcome::Full);
        assert_eq!(parse_range(Some("   "), 1000), RangeOutcome::Full);
    }

    #[test]
    fn closed_range_is_partial() {
        assert_eq!(
            parse_range(Some("bytes=0-99"), 1000),
            RangeOutcome::Partial(ByteRange { start: 0, end: 99 })
        );
    }

    #[test]
    fn end_offset_past_blob_is_clamped() {
        assert_eq!(
            parse_range(Some("bytes=900-2000"), 1000),
            RangeOutcome::Partial(ByteRange {
                start: 900,
                end: 999
            })
        );
    }

    #[test]
    fn start_at_or_past_end_is_unsatisfiable() {
        assert_eq!(
            parse_range(Some("bytes=1000-"), 1000),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            parse_range(Some("bytes=1000-1000"), 1000),
            RangeOutcome::Unsatisfiable
        );
    }

    #[test]
    fn zero_length_suffix_is_unsatisfiable() {
        assert_eq!(
            parse_range(Some("bytes=-0"), 1000),
            RangeOutcome::Unsatisfiable
        );
    }

    #[test]
    fn any_range_on_empty_blob_is_unsatisfiable() {
        assert_eq!(
            parse_range(Some("bytes=0-"), 0),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            parse_range(Some("bytes=-500"), 0),
            RangeOutcome::Unsatisfiable
        );
    }

    #[test]
    fn reversed_bounds_are_malformed() {
        assert_eq!(
            parse_range(Some("bytes=500-100"), 1000),
            RangeOutcome::Malformed
        );
    }

    #[test]
    fn multiple_ranges_are_malformed() {
        assert_eq!(
            parse_range(Some("bytes=0-99,200-299"), 1000),
            RangeOutcome::Malformed
        );
    }

    #[test]
    fn unknown_unit_is_malformed() {
        assert_eq!(
            parse_range(Some("items=0-99"), 1000),
            RangeOutcome::Malformed
        );
    }

    #[test]
    fn non_numeric_or_empty_spec_is_malformed() {
        assert_eq!(
            parse_range(Some("bytes=abc"), 1000),
            RangeOutcome::Malformed
        );
        assert_eq!(parse_range(Some("bytes="), 1000), RangeOutcome::Malformed);
    }

    #[test]
    fn suffix_range_is_last_n_bytes() {
        assert_eq!(
            parse_range(Some("bytes=-500"), 1000),
            RangeOutcome::Partial(ByteRange {
                start: 500,
                end: 999
            })
        );
        assert_eq!(
            parse_range(Some("bytes=-5000"), 1000),
            RangeOutcome::Partial(ByteRange { start: 0, end: 999 })
        );
    }

    #[test]
    fn open_ended_range_runs_to_blob_end() {
        assert_eq!(
            parse_range(Some("bytes=100-"), 1000),
            RangeOutcome::Partial(ByteRange {
                start: 100,
                end: 999
            })
        );
        assert_eq!(
            parse_range(Some("bytes=0-"), 1000),
            RangeOutcome::Partial(ByteRange { start: 0, end: 999 })
        );
    }

    #[test]
    fn single_byte_range_has_len_one() {
        let outcome = parse_range(Some("bytes=0-0"), 1000);
        let RangeOutcome::Partial(range) = outcome else {
            panic!("expected Partial, got {outcome:?}");
        };
        assert_eq!(range, ByteRange { start: 0, end: 0 });
        assert_eq!(range.len(), 1);
    }

    #[test]
    fn content_range_uses_inclusive_bounds_over_total() {
        let r = ByteRange { start: 0, end: 99 };
        assert_eq!(r.content_range(1000), "bytes 0-99/1000");
    }
}
