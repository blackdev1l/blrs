# 01 — Implement the total disk quota

Status: ready-for-agent
Type: task

Implements the spec in `../spec.md`.

## Scope

- `blossom-store`: a `max_total_bytes` field on `StoreConfig`; committed and
  in-flight byte accounting; `StoreError::QuotaExceeded`; the three enforcement
  points; release the reservation on every exit path; recompute the committed
  total in `open()`.
- `blossom-http`: the `--max-total-size` / `BLOSSOM_MAX_TOTAL_SIZE` flag with
  the suffix parser, wire it into `StoreConfig`, and map `QuotaExceeded` to
  `429` with an `X-Reason` that names the quota. `HEAD /upload` must refuse too.

## Notes

- Do not regress the existing per-blob `max_blob_size` check (413); they are
  independent limits and both apply.
- The in-flight reservation must be released by the same guard that removes the
  temp file, so a client abort cannot leak budget.
- Depends on the HTTP crate existing, so it lands after the HTTP lane.
