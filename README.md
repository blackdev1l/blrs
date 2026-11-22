# blrs — a Blossom server in Rust

A [Blossom](https://github.com/hzrd149/blossom) blob server, written in Rust and
sized to run on a Raspberry Pi.

Blossom is a set of HTTP endpoints for storing and retrieving blobs of binary
data, addressed by the sha256 of their contents, with [nostr](https://github.com/nostr-protocol/nostr)
keys as identities. The protocol is defined by the **BUDs** (Blossom Upgrade
Documents); this README cites them per feature.

## Spec coverage

| Endpoint | BUD | Status |
| --- | --- | --- |
| `GET /<sha256>[.ext]` (+ `Range`) | [01](https://github.com/hzrd149/blossom/blob/master/buds/01.md) | planned |
| `HEAD /<sha256>[.ext]` | [01](https://github.com/hzrd149/blossom/blob/master/buds/01.md) | planned |
| `PUT /upload` | [02](https://github.com/hzrd149/blossom/blob/master/buds/02.md) | planned |
| `HEAD /upload` | [06](https://github.com/hzrd149/blossom/blob/master/buds/06.md) | planned |
| `PUT /mirror` | [04](https://github.com/hzrd149/blossom/blob/master/buds/04.md) | planned |
| `PUT /media`, `HEAD /media` | [05](https://github.com/hzrd149/blossom/blob/master/buds/05.md) | planned |
| `PUT /report` | [09](https://github.com/hzrd149/blossom/blob/master/buds/09.md) | planned |
| `GET /list/<pubkey>` | [12](https://github.com/hzrd149/blossom/blob/master/buds/12.md) | planned |
| `DELETE /<sha256>` | [12](https://github.com/hzrd149/blossom/blob/master/buds/12.md) | planned |
| Nostr auth tokens (kind `24242`) | [11](https://github.com/hzrd149/blossom/blob/master/buds/11.md) | planned |
| NIP-94 tags in descriptor | [08](https://github.com/hzrd149/blossom/blob/master/buds/08.md) | planned |
| `402` payment headers | [07](https://github.com/hzrd149/blossom/blob/master/buds/07.md) | not implemented (optional) |

BUD-03 (user server list) and BUD-10 (`blossom:` URIs) are client-side
conventions; a server does not implement them.

## Architecture

```
crates/
  blossom-core    pure domain logic, no I/O: hashes, MIME types, descriptors,
                  byte ranges, BUD-11 token validation
  blossom-store   content-addressed storage + SQLite metadata index
  blossom-http    axum router, handlers, CORS, error mapping, SSRF policy
```

The dependency direction is one way — `http → store → core` — and `blossom-core`
is I/O-free, so the fiddly parts (NIP-01 event ids, RFC 7233 ranges, MIME
sniffing) are tested as plain functions.

## Design decisions

**Streaming, never buffering.** An upload is hashed as it is written to a
temporary file, then renamed into place. A blob is never held in memory, which
is what keeps the process inside a Pi's RAM regardless of file size.

**Verified before visible.** The temporary file is only renamed to its final
`blobs/<aa>/<sha256>` path after the hash matches. A failed or truncated upload
can never be observed under its final name.

**Crash-aware, bounded writes.** The temporary file is removed by a guard on
any failed or cancelled upload, and `open` sweeps leftover `tmp/*.part` files.
After the rename, the shard directory is `fsync`ed before the index row is
inserted, and `open` re-indexes any orphan blob file (the filename is the hash,
so the bytes are already valid). A re-upload of identical bytes is answered from
the index without rewriting the SD card. Durability across a power cut is
best-effort: a blob written but not yet indexed is recovered on the next start,
but the most recent write can still be lost. A `DELETE` removes the file, then
the row, and records the hash on the blocklist in the same transaction, so a
removed blob cannot be re-uploaded (BUD-09).

**Metadata is separate from bodies.** Size, MIME type, owner, and upload time
live in SQLite, so `/list`, quota checks, and ownership checks are index lookups
rather than directory walks.

**Static routes win over the blob route.** `/upload`, `/mirror`, `/media`,
`/report`, and `/list/...` are registered as literal segments, so they can never
be shadowed by `/<sha256>`.

**No OpenSSL.** `reqwest` is built with `rustls`, which keeps the dependency
tree pure Rust and cross-compilation to the Pi simple.

## Building and testing

The host has no Rust toolchain; the deployment target is Linux/aarch64. Every
build and test runs in a container via `./dcargo.sh`:

```sh
./dcargo.sh check --workspace --all-targets
./dcargo.sh test --workspace
./dcargo.sh clippy --workspace --all-targets -- -D warnings
./dcargo.sh build --release
```

The release profile is tuned for the Pi: thin LTO, one codegen unit,
`panic = "abort"`, and stripped symbols.

### Building the Raspberry Pi binaries

```sh
./scripts/build-pi.sh
```

Produces two artifacts, because a 32-bit userland cannot run a 64-bit binary and
DietPi is installed as either:

| Artifact | Target | Runs on |
| --- | --- | --- |
| `dist/blrs-aarch64` | `aarch64-unknown-linux-gnu` | Pi 3/4/5, 64-bit OS (`arm64`) |
| `dist/blrs-armv7` | `armv7-unknown-linux-gnueabihf` | Pi 2/3/4/5, 32-bit OS (`armv7l`) |

Both need **glibc >= 2.31**, so they run on bullseye and bookworm. They are built
from a bullseye base **deliberately** — the binary links against the build
image's glibc, so building on a newer base would raise the floor and silently
produce artifacts that fail to start on older hosts. ARMv6 (Pi 1 / Zero) is not
covered.

### Deploying to the Pi

```sh
./scripts/deploy-pi.sh              # uses the `pi` ssh alias
./scripts/deploy-pi.sh dietpi@host:8822
```

It asks the remote host for `uname -m`, picks the matching artifact, installs it
to `/opt/blrs` via a temp name plus `mv` so a dropped connection
cannot leave a half-written binary in place, and then runs `--version` on the
host to confirm the artifact actually executes.

It deliberately does **not** use `scp`. OpenSSH 9.0+ implements `scp` on top of
SFTP, so `scp` fails outright against a server with no SFTP subsystem even
though `ssh` works. Piping over `ssh` needs only an ssh client at each end. If
you want `scp` itself, `scp -O` forces the legacy protocol.

### Releases

`.github/workflows/release.yml` publishes a release on every push to `main`,
tagged `v<version>-main.<run_number>` so each build is addressable and a re-run
lands on the same tag. It ships three Linux tarballs
(`blrs-<version>-<target>.tar.gz` for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, and `armv7-unknown-linux-gnueabihf`), a Windows zip
(`blrs-<version>-x86_64-pc-windows-msvc.zip`, with `blrs.exe` at its root), and a
`SHA256SUMS` file covering all of them. The Linux binaries are cross-built in a
bullseye container; the Windows binary is built natively with MSVC on
`windows-latest` and smoke-run before packaging.

## Running

```sh
./blrs --data-dir /var/lib/blrs --public-url https://cdn.example.com
```

Configuration is available as CLI flags or `BLOSSOM_*` environment variables:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--bind` | `BLOSSOM_BIND` | `0.0.0.0:3000` | Listen address |
| `--data-dir` | `BLOSSOM_DATA_DIR` | `./data` | Blob and index storage |
| `--public-url` | `BLOSSOM_PUBLIC_URL` | `http://localhost:3000` | Base URL for descriptor `url` fields |
| `--max-blob-size` | `BLOSSOM_MAX_BLOB_SIZE` | `104857600` | Largest accepted blob, in bytes |
| `--auth` | `BLOSSOM_AUTH` | `writes` | `none`, `writes`, or `all` |
| `--enable-list` | `BLOSSOM_ENABLE_LIST` | `true` | Expose `GET /list/<pubkey>` |
| `--enable-mirror` | `BLOSSOM_ENABLE_MIRROR` | `true` | Expose `PUT /mirror` |
| `--enable-media` | `BLOSSOM_ENABLE_MEDIA` | `true` | Expose `PUT /media` |
| `--mirror-allow-private` | `BLOSSOM_MIRROR_ALLOW_PRIVATE` | `false` | Allow mirroring from private addresses |
| `--blocked-mime` | `BLOSSOM_BLOCKED_MIME` | _(empty)_ | Comma-separated MIME types to refuse |
| `--max-total-size` | `BLOSSOM_MAX_TOTAL_SIZE` | `0` (unlimited) | Total budget for stored blobs |

`--max-total-size` accepts `k`/`m`/`g`/`t`, optionally followed by `b` or `ib`,
case-insensitively. **Every suffix is binary**, because the value is compared
against real card capacity: `4G` = `4GiB` = 4294967296 bytes. A bare number is
bytes, so an exact value is never ambiguous. `0` or absent means unlimited.

It is a whole-server budget, enforced at three points: before reading a body
(from the declared `Content-Length`), while streaming — so a client that lies
about its length is still stopped — and authoritatively inside the insert
transaction, so concurrent uploads cannot between them exceed it. Exhaustion is
`429` with an `X-Reason`. Re-uploading a blob that already exists consumes no new
space and is never refused, even at 100%.

`--max-blob-size` and `--max-total-size` are independent; both apply.

## Logging

`RUST_LOG` controls the verbosity filter; without it the server defaults to
`info`. At that level the log carries a startup line with the bound address, one
request line per HTTP request — method, path, and the response status, including
CORS preflights and unmatched routes — and a structured line for every
successful write (`PUT /upload`, `PUT /media`, `PUT /mirror`, and
`DELETE /<sha256>`) with the blob `sha256`, its byte `size`, the `owner` pubkey,
and the `outcome` (`created`/`existed`/`deleted`), so an upload can be grepped by
hash. Authorization failures log at `warn`, and storage errors at `warn` or
`error`. A request to a disabled endpoint (`/media`, `/mirror`, `/list`) logs a
`warn` naming the flag that turns it on, so a 404 is never bare. The
`Authorization` header and token contents are never logged.

```sh
RUST_LOG=blossom_http=debug ./blrs --data-dir ./data
```

## Security notes

`PUT /mirror` fetches a user-supplied URL, which is a server-side request
forgery vector. BUD-04 requires restricting origins to HTTP/HTTPS and refusing
loopback, private, and link-local destinations — for both IPv4 and IPv6, and on
every redirect. `--mirror-allow-private` exists for local testing and should
stay off in production.

An authorization token with no `server` tag is valid on any server that accepts
it (BUD-11). This is a real risk for `delete` tokens specifically, since an
intercepted token can be replayed against any server holding the same blob.
Deployments that require authorization for deletes should expect clients to
scope their tokens.

## License

MIT.
