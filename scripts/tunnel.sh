#!/usr/bin/env bash
# Reverse SSH tunnel: the server's port 18090 -> this machine's 127.0.0.1:8090 (beta.sh).
# (8090 is taken on the theorycorner server. Its sshd has GatewayPorts=yes, so the port binds
# on all interfaces; ufw's default-deny keeps it unreachable from outside, and nginx proxies.)
#   scripts/tunnel.sh user@your-server
# Reconnects if the connection drops. Binds to the server's loopback only; nginx proxies to it.
set -euo pipefail
TARGET=${1:?usage: scripts/tunnel.sh user@host}
PORT=${BETA_PORT:-8090}
REMOTE_PORT=${BETA_REMOTE_PORT:-18090}
while true; do
  ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -R "127.0.0.1:$REMOTE_PORT:127.0.0.1:$PORT" "$TARGET" || true
  echo "tunnel dropped; reconnecting in 5s" >&2
  sleep 5
done
