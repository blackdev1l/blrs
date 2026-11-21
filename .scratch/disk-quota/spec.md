# Spec: total disk quota

**Status:** ready-for-agent
**Requested by:** operator, 2025-11-22

## Requirement

The server must accept a flag setting the total disk budget it may use for
stored blobs — for example `4G` means 4G is available. Once stored blobs reach
that budget, the server refuses to receive more files.

## Decisions

**Flag.** `--max-total-size` / `BLOSSOM_MAX_TOTAL_SIZE`. Absent or `0` means no
limit, preserving today's behaviour.

**Suffixes.** `k`, `m`, `g`, `t`, optionally followed by `b`, or `ib`
(`kib`, `mib`, ...), all case-insensitive. Every suffix is **binary**
(1024-based), because the value is compared against real card capacity:
`4G` = `4GiB` = 4294967296 bytes. A bare number is bytes, so an exact value is
always expressible without suffix ambiguity.

**Scope.** Total stored blob bytes across all users, not per-user. In-flight
upload bytes are counted against the same budget, so concurrent uploads cannot
overshoot it even transiently.

**Behaviour on exhaustion.** Refuse with `429 Too Many Requests`. BUD-02's
status table lists 429 for "a rate limit or quota"; the BUDs do not mention 507.
The `X-Reason` must say the quota is exhausted so an operator can tell a full
disk from a rate limit.

**Deduplication is free.** Re-uploading a blob that already exists consumes no
new space and must never be refused, even at 100% of budget.

**Deletion frees space immediately.**

**Self-healing.** The committed total is recomputed from the index when the
store opens, so the counter cannot drift across crashes.

## Enforcement points

A quota that is only checked at insert time is not a disk-space guarantee: two
concurrent 400 MB uploads against 500 MB free would both stream to `tmp/`
before either is refused. So the check runs at three points:

1. **Before reading the body**, using the client's `Content-Length`. Cheapest
   refusal, saves the bandwidth entirely.
2. **While streaming**, so a client that lies about its size (or sends no
   `Content-Length`) cannot blow past the budget, and so `tmp/` usage is bounded
   by the same number.
3. **At insert**, closing the race between concurrent uploads by accounting for
   in-flight reservations atomically with the row insert.

`HEAD /upload` must reflect the same refusal, since BUD-06 exists precisely so
clients can be told before uploading.

The in-flight reservation must be released on *every* exit path, including a
client abort mid-upload — the same guard that removes the temp file owns it.

## Status codes

| Situation | Code | BUD |
| --- | --- | --- |
| New blob would exceed the budget | `429` | BUD-02 quota row |
| Blob already exists, budget exhausted | `200` / `201` as normal | BUD-02 dedupe |

## Out of scope

- Per-user quotas. BUD-02's 429 row also covers those, but nothing here requires
  them.
- A `Retry-After` header: retrying does not help until space is freed, so
  advertising a retry delay would be misleading.
- Advertising remaining space on `GET /`. Worth doing later; not requested.

## Verification

- Unit: the size parser (`4G`, `4g`, `4gb`, `4GiB`, `500M`, `1024`, `0`,
  absent, and rejects `4X` / `-1` / `4GG`).
- Store: a put that fits succeeds; one that would exceed the budget is refused;
  dedupe at 100% still succeeds; a delete frees budget for a subsequent put;
  concurrent puts cannot between them exceed the budget; a client that lies in
  `Content-Length` is still stopped mid-stream; the reservation is released
  after a failed or aborted upload, so budget is not leaked.
- HTTP: `PUT /upload` and `HEAD /upload` both return 429 with `X-Reason` when
  the budget is exhausted.
