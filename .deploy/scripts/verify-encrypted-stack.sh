#!/bin/bash
# Verification of the encrypted open5gs-compose deployment (run on the Docker host).
# Suitable for any deployment (test stand or production); deployment-specific
# values are overridable via environment variables:
#   IMSI_PATTERN - regex scanned for plaintext IMSIs in /data/db
#                  (default: test IMSI range 99999XXXXXXXXXX)
#   BAO_ADDR     - host:port of the OpenBao TLS listener (default: localhost:8200)
#   WEBUI_URL    - webui URL for the HTTP check (default: http://localhost:9999/)
set -u
cd "$(dirname "$0")/../.."
# Compose file chain: base + local overrides + encrypted PSMDB overlay
# (+ MongoDB TLS overlay when its CA exists - auto-detected).
IMSI_PATTERN="${IMSI_PATTERN:-99999[0-9]{10}}"
BAO_ADDR="${BAO_ADDR:-localhost:8200}"
WEBUI_URL="${WEBUI_URL:-http://localhost:9999/}"
# Compose chain: follow the deployment's COMPOSE_FILE (.env) - it is the
# switch for the TLS overlay; fall back to the base encrypted chain.
CF="${COMPOSE_FILE:-}"
if [ -z "$CF" ] && [ -f .env ]; then
  CF=$(grep -E '^COMPOSE_FILE=' .env | head -1 | cut -d= -f2-)
fi
if [ -n "$CF" ]; then
  IFS=':;' read -r -a _CF_LIST <<<"$CF"
else
  _CF_LIST=(docker-compose.yaml docker-compose.override.yaml docker-compose.encryption.yaml)
fi
COMPOSE_FILES=()
for _f in "${_CF_LIST[@]}"; do COMPOSE_FILES+=(-f "$_f"); done
dc() { docker compose "${COMPOSE_FILES[@]}" "$@"; }
# TLS mode: read from the running mongod config (single source of truth)
DBTLS=false
if dc exec -T mongodb grep -q 'requireTLS' /etc/mongod.conf 2>/dev/null; then
  DBTLS=true
fi
MONGO_TLS_FLAGS=""
if [ "$DBTLS" = true ]; then
  MONGO_TLS_FLAGS="--tls --tlsCAFile /etc/mongodb-tls-ca/ca.crt"
fi

echo "=== 0. MongoDB TLS overlay: $DBTLS ==="

echo "=== 1. Container status ==="
dc ps --format '{{.Name}}\t{{.Status}}' | sort

echo
echo "=== 2. MongoDB: databases ==="
dc exec -T mongodb mongo $MONGO_TLS_FLAGS --quiet --eval 'db.adminCommand({listDatabases:1}).databases.forEach(function(d){print("  - "+d.name)})'

echo
echo "=== 3. MongoDB: open5gs collections ==="
dc exec -T mongodb mongo $MONGO_TLS_FLAGS --quiet open5gs --eval 'print("  subscribers: "+db.subscribers.countDocuments({})); print("  accounts: "+db.accounts.countDocuments({}))'

echo
echo "=== 4. mongod encryption status (from log) ==="
dc logs mongodb 2>&1 | grep -iE 'master encryption key|Encryption keys DB|vault' | tail -5

echo
echo "=== 5. TLS connection to OpenBao ($BAO_ADDR) ==="
TLS_OUT=$(echo | openssl s_client -connect "$BAO_ADDR" -CAfile .deploy/docker/openbao/tls/ca.crt 2>/dev/null | grep -E "Verify return code|subject=" | head -3)
if [ -n "$TLS_OUT" ]; then
  echo "$TLS_OUT"
else
  echo "  WARNING: no TLS response from $BAO_ADDR (is the OpenBao port published on this host?)"
fi

echo
echo "=== 6. KV v2 master key secret ==="
dc exec -T openbao sh -c 'export BAO_TOKEN=$(cat /openbao/secrets/root-token); V=$(bao kv get -field=value secret/psmdb-encryption 2>/dev/null); if [ -n "$V" ] && [ ${#V} -ge 32 ]; then echo "  OK: master key readable (len=${#V}; value is never printed)"; else echo "  FAIL: master key missing or too short"; fi'

echo
echo "=== 7. Plaintext check: IMSI patterns in data files (pattern: $IMSI_PATTERN) ==="
dc exec -T mongodb sh -c "HITS=\$(grep -rlE \"$IMSI_PATTERN\" /data/db 2>/dev/null | head -5); if [ -n \"\$HITS\" ]; then echo '  WARNING: plaintext IMSI found in:'; echo \"\$HITS\"; else echo '  OK: no plaintext IMSI found in /data/db'; fi"

echo
echo "=== 8. webui (idempotent admin bootstrap + HTTP check) ==="
dc exec -T mongodb mongo $MONGO_TLS_FLAGS --quiet /opt/init/init.js && echo "  init.js OK"
curl -s -o /dev/null -w "  webui $WEBUI_URL -> HTTP %{http_code}\n" "$WEBUI_URL" || true

echo
echo "=== 9. EKI-TK: transport keys in OpenBao (metadata only) ==="
for eki in 1 2 3 4 5; do
  if META=$(dc exec -T openbao sh -c "export BAO_ADDR=http://127.0.0.1:8201; export BAO_TOKEN=\$(cat /openbao/secrets/root-token); bao kv metadata get -mount=secret transport-keys/eki-$eki" 2>/dev/null | grep -E 'current_version' | head -1); then
    echo "  EKI $eki: $META"
  fi
done
if dc exec -T openbao sh -c 'export BAO_ADDR=http://127.0.0.1:8201; export BAO_TOKEN=$(cat /openbao/secrets/root-token); bao kv get -field=value -mount=secret network/milenage-op >/dev/null' 2>/dev/null; then
  echo "  network/milenage-op: present"
else
  echo "  network/milenage-op: ABSENT (import-profiles.sh will fail-closed)"
fi

echo
echo "=== 10. EKI-TK: profile load files ==="
if ls .deploy/profiles/*.csv >/dev/null 2>&1; then
  for f in .deploy/profiles/*.csv; do
    ROWS=$(grep -vc '^#\|^$' "$f")
    echo "  $f: $ROWS profile row(s)"
  done
else
  echo "  (no profile files in .deploy/profiles/)"
fi

echo
echo "=== Verification done ==="
