#!/usr/bin/env bash
# Copy the correct Pi binary to a host and install it.
#
# Deliberately does NOT use scp. OpenSSH 9.0+ implements scp on top of SFTP, so
# scp fails outright against a server with no SFTP subsystem even though ssh
# works fine. Piping over ssh needs only an ssh client at each end.
#
# Usage:
#   ./scripts/deploy-pi.sh                 # uses the `pi` ssh alias
#   ./scripts/deploy-pi.sh dietpi@host:8822
#   ./scripts/deploy-pi.sh pi /opt/blrs
set -euo pipefail

TARGET="${1:-pi}"
DEST="${2:-/opt/blrs}"
# `pwd -W` is an MSYS/Git-Bash extension that yields a Windows path; GNU `pwd`
# rejects the option, so fall back to the physical path on a real Linux host.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd -P; })"

echo "deploy: asking $TARGET for its architecture" >&2
if ! MACHINE="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" 'uname -m')"; then
  cat >&2 <<EOF
deploy: cannot reach '$TARGET'.

Check, in order:
  1. the host is powered on and reachable   ping / nc -vz <host> <port>
  2. the alias carries the right user+port  ssh -G $TARGET | grep -E '^(hostname|user|port)'
  3. your key is accepted                   ssh -v $TARGET

Note: OpenSSH 9+ scp uses SFTP. If scp alone fails but ssh works, add -O or use
this script instead.
EOF
  exit 1
fi
echo "deploy: remote is $MACHINE" >&2

case "$MACHINE" in
  aarch64|arm64) ARTIFACT=blrs-aarch64 ;;
  armv7l|armv7)  ARTIFACT=blrs-armv7 ;;
  armv6l|armv6)
    echo "deploy: $MACHINE is ARMv6 (Pi 1 / Zero); no artifact is built for it." >&2
    echo "deploy: it would need arm-unknown-linux-gnueabihf plus a v6 cross gcc." >&2
    exit 1 ;;
  *) echo "deploy: unsupported architecture '$MACHINE'" >&2; exit 1 ;;
esac

BIN="$ROOT/dist/$ARTIFACT"
if [ ! -f "$BIN" ]; then
  echo "deploy: $BIN is missing. Run scripts/build-pi.sh first." >&2
  exit 1
fi

echo "deploy: sending $ARTIFACT ($(wc -c <"$BIN" | tr -d ' ') bytes)" >&2
# Write to a temp name and mv into place, so a dropped connection cannot leave a
# half-written binary where the service expects a working one.
ssh -o BatchMode=yes "$TARGET" \
  "cat > '$DEST.new' && chmod +x '$DEST.new' && mv -f '$DEST.new' '$DEST'" < "$BIN"

echo "deploy: installed $DEST" >&2
ssh -o BatchMode=yes "$TARGET" "'$DEST' --version"
