#!/usr/bin/env bash
# Build a release binary for Raspberry Pi (aarch64 Linux) and copy it to dist/.
#
# The host has no Rust toolchain, so everything runs in Docker. The result is
# dist/blossom-aarch64 — a dynamically linked aarch64 binary that needs glibc
# >= 2.31, i.e. Raspberry Pi OS bullseye or bookworm.
#
# Usage:  ./scripts/build-pi.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W)"
IMAGE="${BLOSSOM_PI_IMAGE:-blrs-pi:1}"
TARGET="aarch64-unknown-linux-gnu"

export MSYS_NO_PATHCONV=1

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "build-pi: building $IMAGE (one time)" >&2
  docker build -t "$IMAGE" -f "$ROOT/docker/Dockerfile.pi" "$ROOT/docker" >&2
fi

KEY="$(printf '%s' "$ROOT" | md5sum | cut -c1-12)"
VOLUME="blossom-target-$KEY"

echo "build-pi: compiling for $TARGET" >&2
docker run --rm \
  -v "$ROOT":/work -w /work \
  -v blossom-cargo-registry:/usr/local/cargo/registry \
  -v blossom-cargo-git:/usr/local/cargo/git \
  -v "$VOLUME":/work/target \
  -e CARGO_TERM_COLOR=always \
  "$IMAGE" \
  cargo build --release --target "$TARGET" -p blossom-http

echo "build-pi: extracting artifact" >&2
mkdir -p "$ROOT/dist"
docker run --rm \
  -v "$ROOT":/work \
  -v "$VOLUME":/work/target \
  "$IMAGE" \
  bash -c "cp /work/target/$TARGET/release/blossom /work/dist/blossom-aarch64 && chmod +x /work/dist/blossom-aarch64"

echo "build-pi: dist/blossom-aarch64" >&2
file "$ROOT/dist/blossom-aarch64" 2>/dev/null || ls -la "$ROOT/dist"
