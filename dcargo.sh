#!/usr/bin/env bash
# Run cargo inside the Linux toolchain container.
#
# The host has no Rust toolchain, and the deployment target is a Raspberry Pi
# (Linux/aarch64), so every build and test runs in `rust:1-bookworm`.
#
# Usage:
#   ./dcargo.sh test
#   ./dcargo.sh test -p blossom-store
#   ./dcargo.sh clippy --all-targets -- -D warnings
#   ./dcargo.sh build --release
set -euo pipefail

# `pwd -W` is an MSYS/Git-Bash extension that yields a Windows path for the
# Docker volume mount below; GNU `pwd` rejects the option, so fall back to the
# physical path on a real Linux host.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && { pwd -W 2>/dev/null || pwd -P; })"
IMAGE="${BLOSSOM_RUST_IMAGE:-blrs-rust:1}"

# The upstream `rust` image ships without clippy, which this project gates on,
# and without the aarch64 cross toolchain. `docker/Dockerfile` adds both.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if [ "$IMAGE" = "blrs-rust:1" ]; then
    echo "dcargo: building $IMAGE (one time)" >&2
    docker build -t "$IMAGE" "$ROOT/docker" >&2
  else
    echo "dcargo: image $IMAGE not found" >&2
    exit 1
  fi
fi

# A shared registry volume avoids re-downloading crates on every invocation.
# The target volume is keyed to this checkout so worktrees do not collide.
KEY="$(printf '%s' "$ROOT" | md5sum | cut -c1-12)"

# Git-Bash rewrites `/work` into a Windows path before Docker sees it.
export MSYS_NO_PATHCONV=1

exec docker run --rm \
  -v "$ROOT":/work \
  -w /work \
  -v blossom-cargo-registry:/usr/local/cargo/registry \
  -v blossom-cargo-git:/usr/local/cargo/git \
  -v "blossom-target-$KEY":/work/target \
  -e CARGO_TERM_COLOR=always \
  "$IMAGE" \
  cargo "$@"
