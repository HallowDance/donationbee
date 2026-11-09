#!/usr/bin/env bash
# Public beta (demo data, Stripe test mode) served on 127.0.0.1:8090 for a tunnel to expose.
#   scripts/beta.sh            start everything (Ctrl-C stops it)
# State lives in ./.beta (gitignored): online key, session secret, witness key and state.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST=${BETA_HOST:-bee.theorycorner.com}
PORT=${BETA_PORT:-8090}
WPORT=${BETA_WITNESS_PORT:-8091}
B=$PWD/.beta
mkdir -p "$B" && chmod 700 "$B"

eval "$(scripts/devdb.sh start)"
SOCK=$PWD/.pgdata/sock
psql -h "$SOCK" -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='vpp_beta'" | grep -q 1 \
  || psql -h "$SOCK" -U postgres -qc "CREATE DATABASE vpp_beta"

export VPP_DATABASE_URL="postgresql+psycopg://postgres@/vpp_beta?host=$SOCK"
export VPP_ORIGIN="$HOST/log"
export VPP_PUBLIC_BASE_URL="https://$HOST"
export VPP_RP_ID="$HOST"
export VPP_SIGNING_KEY_PATH="$B/online.key"
export VPP_OTS_ENABLED=false
export VPP_BANNER="Beta: demo hives with example data. Payments are off for now, and the demo witness is run by us."
[ -f "$B/secret" ] || (umask 077; python3 -c "import secrets; print(secrets.token_hex(32))" > "$B/secret")
export VPP_SECRET_KEY="$(cat "$B/secret")"

(cd server && uv run alembic upgrade head 2>/dev/null)
[ -f "$VPP_SIGNING_KEY_PATH" ] || uv run vpp keygen >/dev/null
if [ "$(psql -h "$SOCK" -U postgres -d vpp_beta -tAc 'SELECT count(*) FROM ledger_entries')" = "0" ]; then
  uv run vpp demo-seed
fi

# Demo witness (clearly labelled in the banner; real ones must be run by other people).
ONLINE=$(uv run python -c "import pathlib; from vpp.ledger import LedgerKey; print(LedgerKey.load(pathlib.Path('$VPP_SIGNING_KEY_PATH')).public_key.hex())")
LOGVKEY=$(uv run python -c "from vpp.ledger.note import vkey; print(vkey('$VPP_ORIGIN', bytes.fromhex('$ONLINE')))")
[ -f "$B/witness.key" ] || uv run vpp-witness keygen --name "$HOST/demo-witness" --out "$B/witness.key" > "$B/witness.vkey"
cat > "$B/witness.json" <<J
{"name": "$HOST/demo-witness", "key_file": "witness.key", "state_dir": "witness-state",
 "logs": [{"origin": "$VPP_ORIGIN", "vkeys": ["$LOGVKEY"]}]}
J
export VPP_WITNESSES="[{\"vkey\": \"$(cat "$B/witness.vkey")\", \"url\": \"http://127.0.0.1:$WPORT\"}]"

uv run vpp-witness serve --config "$B/witness.json" --port "$WPORT" 2>>"$B/witness.log" &
PIDS=$!
trap 'kill $PIDS 2>/dev/null || true' EXIT
sleep 1 && uv run vpp witness-push

echo "Serving https://$HOST via 127.0.0.1:$PORT (point the tunnel there). Ctrl-C to stop."
uv run uvicorn vpp.app:app --host 127.0.0.1 --port "$PORT" --proxy-headers --forwarded-allow-ips 127.0.0.1
