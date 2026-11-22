#!/usr/bin/env bash
# Build release binaries for Raspberry Pi and copy them to dist/.
#
# Two artifacts, because we cannot assume a 32-bit or a 64-bit userland:
#   dist/blrs-aarch64      arm64 / aarch64  (Pi 3/4/5 on a 64-bit OS)
#   dist/blrs-armv7        armv7l           (Pi 2/3/4/5 on a 32-bit OS)
#
# Both need glibc >= 2.31, so they run on Raspberry Pi OS / DietPi bullseye and
# bookworm. ARMv6 (Pi 1 / Zero) is not covered.
#
# Usage:  ./scripts/build-pi.sh
set -euo pipefail

# `pwd -W` is an MSYS/Git-Bash extension that yields a Windows path for the
# Docker volume mount; GNU `pwd` rejects the option, so fall back to the
# physical path on a real Linux host.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd -P; })"
IMAGE="${BLOSSOM_PI_IMAGE:-blrs-pi:1}"

export MSYS_NO_PATHCONV=1

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "build-pi: building $IMAGE (one time, a few minutes)" >&2
  docker build -t "$IMAGE" -f "$ROOT/docker/Dockerfile.pi" "$ROOT/docker" >&2
fi

KEY="$(printf '%s' "$ROOT" | md5sum | cut -c1-12)"
VOLUME="blossom-target-$KEY"

run_in_image() {
  docker run --rm \
    -v "$ROOT":/work -w /work \
    -v blossom-cargo-registry:/usr/local/cargo/registry \
    -v blossom-cargo-git:/usr/local/cargo/git \
    -v "$VOLUME":/work/target \
    -e CARGO_TERM_COLOR=always \
    "$IMAGE" "$@"
}

build_one() {
  local target="$1" artifact="$2"
  echo "build-pi: compiling $target" >&2
  run_in_image cargo build --release --target "$target" -p blossom-http
  mkdir -p "$ROOT/dist"
  run_in_image bash -c \
    "cp /work/target/$target/release/blrs /work/dist/$artifact && chmod +x /work/dist/$artifact"
  echo "build-pi: dist/$artifact" >&2
}

build_one aarch64-unknown-linux-gnu     blrs-aarch64
build_one armv7-unknown-linux-gnueabihf blrs-armv7

echo >&2
for f in blrs-aarch64 blrs-armv7; do
  printf '%-20s %s\n' "$f" "$(file -b "$ROOT/dist/$f" | cut -c1-72)" >&2
done
