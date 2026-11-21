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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -W)"
IMAGE="${BLOSSOM_RUST_IMAGE:-rust:1-bookworm}"

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
