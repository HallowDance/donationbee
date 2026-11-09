#!/usr/bin/env bash
# Local dev Postgres in ./.pgdata (no system service, unix socket only).
#   scripts/devdb.sh start|stop|url
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="$PWD/.pgdata/data"
SOCK="$PWD/.pgdata/sock"

case "${1:-start}" in
  start)
    if [ ! -d "$DATA" ]; then
      mkdir -p "$SOCK"
      initdb -D "$DATA" -U postgres --auth=trust >/dev/null
    fi
    pg_ctl -D "$DATA" -o "-k $SOCK -c listen_addresses=''" -l "$PWD/.pgdata/log" -w start >/dev/null
    psql -h "$SOCK" -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='vpp'" | grep -q 1 \
      || psql -h "$SOCK" -U postgres -qc "CREATE DATABASE vpp"
    echo "export VPP_DATABASE_URL='postgresql+psycopg://postgres@/vpp?host=$SOCK'"
    ;;
  stop) pg_ctl -D "$DATA" -m fast stop ;;
  url) echo "postgresql+psycopg://postgres@/vpp?host=$SOCK" ;;
  *) echo "usage: $0 start|stop|url" >&2; exit 2 ;;
esac
