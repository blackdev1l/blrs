# Extends the official Rust image with what this project needs but the upstream
# image omits: clippy (a required gate), rustfmt, and the aarch64 cross
# toolchain used to produce Raspberry Pi binaries.
#
# Build:  docker build -t blrs-rust:1 docker/
# (dcargo.sh builds it automatically if it is missing.)
FROM rust:1-bookworm

RUN rustup component add clippy rustfmt \
 && rustup target add aarch64-unknown-linux-gnu \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

# Cargo config for the Pi target. `rust:1-bookworm` already sets CC_* for the
# host; these point the linker at the cross toolchain instead.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
