#!/bin/bash
# Import UICC profiles from a load file into the open5gs AUC (MongoDB).
# Columns: IMSI,EKI,E_KI,E_OPC,AMF[,HMAC]  (new layout; E_OPC is optional)
# Legacy files IMSI,EKI,E_KI,AMF[,HMAC] are still accepted (auto-detect: the
# 4th column is E_OPC when it is 32 hex, AMF when it is 1-4 hex).
#
# Per row: TK fetched from the KMS by EKI -> (HMAC verified when the last column is
# present, or IMPORT_REQUIRE_HMAC=1) -> eKi decrypted to Ki ->
# OPc taken from the file (E_OPC, decrypted with the same TK) or, when the
# column is absent, derived in the network as AES128(network OP, Ki)
# (3GPP TS 35.208 Annex C) with a per-row warning -> subscriber
# created/updated in the 'subscribers' collection.
#
# Fail-closed: ANY error (unknown/revoked EKI, KMS down, HMAC mismatch when checked, malformed
# eKi, bad DB write) aborts the import - no partial, silently-wrong state.
# Replay-safe: re-importing the same file only updates existing records (idempotent).
#
# Usage: import-profiles.sh <profiles-file.csv>
# Env (optional):
#   IMPORT_DB_URI  - DB URI for the one-shot dbctl container
#                    (default: taken from the running 'hss' container env, i.e. the
#                     single source of truth for the stack; mongodb://mongodb/open5gs
#                     if hss is not running)
#   BAO_ADDR / BAO_CA_FILE / BAO_TOKEN_FILE - see lib-bao.sh
#
# Auto-detects the MongoDB TLS overlay (docker-compose.dbtls.yaml +
# .deploy/docker/mongodb-tls/ca.crt): adds --tls to in-container mongo shell and
# the CA mount to the one-shot dbctl container.
#
# NOTE (prototype): for NEW subscribers the plaintext Ki is passed as CLI args to
# gradiant/open5gs-dbctl (the known-good document creator); it is visible in the
# host process list only for the duration of the write. Residual documented in
# EKI-TK-ENCRYPTION.md (fully closed only by the core-fork roadmap item).
set -uo pipefail
cd "$(dirname "$0")/../.."
source .deploy/scripts/lib-bao.sh

FILE="${1:-}"
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "Usage: $0 <profiles-file.csv>" >&2; exit 2
fi

# Compose chain: base + override + encryption (+ dbtls when active)
# Compose chain: follow the deployment's COMPOSE_FILE (.env) - it is the
# switch for the TLS overlay; fall back to the base encrypted chain.
DCFILES=()
CF="${COMPOSE_FILE:-}"
if [ -z "$CF" ] && [ -f .env ]; then
  CF=$(grep -E '^COMPOSE_FILE=' .env | head -1 | cut -d= -f2-)
fi
if [ -n "$CF" ]; then
  IFS=':;' read -r -a DCFILES <<<"$CF"
else
  DCFILES=(docker-compose.yaml docker-compose.override.yaml docker-compose.encryption.yaml)
fi
dc() { local _a=(); local _f; for _f in "${DCFILES[@]}"; do _a+=(-f "$_f"); done; docker compose "${_a[@]}" "$@"; }

MONGO_CID=$(dc ps -q mongodb 2>/dev/null | head -1)
[ -n "$MONGO_CID" ] || { echo "ERROR: mongodb container not found - is the stack up?" >&2; exit 1; }
NET_ID=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}{{end}}' "$MONGO_CID" 2>/dev/null | head -1)
[ -n "$NET_ID" ] || { echo "ERROR: cannot resolve core network of the mongodb container" >&2; exit 1; }

# TLS mode: read from the running mongod config (single source of truth -
# the overlay may or may not be active in the current deployment)
MTLS=""
DBCTL_CA_MOUNT=()
if dc exec -T mongodb grep -q 'requireTLS' /etc/mongod.conf 2>/dev/null; then
  MTLS="--tls --tlsCAFile /etc/mongodb-tls-ca/ca.crt"
  DBCTL_CA_MOUNT=(-v "$PWD/.deploy/docker/mongodb-tls/ca.crt:/etc/mongodb-tls-ca/ca.crt:ro")
fi

# DB URI: prefer the running stack's value (single source of truth)
if [ -z "${IMPORT_DB_URI:-}" ]; then
  HSS_CID=$(dc ps -q hss 2>/dev/null | head -1)
  if [ -n "$HSS_CID" ]; then
    DB_URI=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$HSS_CID" 2>/dev/null | grep '^DB_URI=' | head -1 | cut -d= -f2-)
  fi
  [ -n "$DB_URI" ] || DB_URI="mongodb://mongodb/open5gs"
else
  DB_URI="$IMPORT_DB_URI"
fi
echo "import: DB_URI from stack: $(printf '%s' "$DB_URI" | sed 's/:[^:@/]*@/:***@/g')"

mongo_eval_stdin() { # $1 = JS; runs in the mongodb container, JS via stdin (not process args)
  dc exec -T mongodb mongo $MTLS 127.0.0.1:27017/open5gs --quiet 2>&1 <<<"$1"
}

row=0; created=0; updated=0; nochange=0
abort() { echo "[row $row] FAIL: $1 - import ABORTED (fail-closed)" >&2; exit 1; }

while IFS= read -r line; do
  case "$line" in ''|\#*) continue;; esac
  row=$((row+1))
  IFS=',' read -r -a F <<<"$line"
  NF=${#F[@]}
  IMSI="${F[0]:-}"; EKI="${F[1]:-}"; E_KI="${F[2]:-}"
  E_OPC=""; AMF=""; HMAC=""
  # Column layout (disambiguated by count + length of column 4):
  #   new:  IMSI,EKI,E_KI,E_OPC,AMF[,HMAC]        (E_OPC: 32 hex)
  #   legacy: IMSI,EKI,E_KI,AMF[,HMAC]            (AMF: 1-4 hex)
  case $NF in
    3) : ;;
    4) AMF="${F[3]}" ;;
    5)
      if echo "${F[3]}" | grep -Eq '^[0-9a-fA-F]{32}$'; then
        E_OPC="${F[3]}"; AMF="${F[4]:-8000}"
      elif [ -z "${F[3]}" ] || echo "${F[3]}" | grep -Eq '^[0-9a-fA-F]{1,4}$'; then
        AMF="${F[3]}"; HMAC="${F[4]:-}"
      else
        abort "column 4 is neither E_OPC (32 hex) nor AMF (1-4 hex): '${F[3]}'"
      fi ;;
    6)
      E_OPC="${F[3]}"; AMF="${F[4]:-}"; HMAC="${F[5]:-}" ;;
    *) abort "unexpected column count $NF (expected 3-6)" ;;
  esac
  if [ -n "$E_OPC" ] && ! echo "$E_OPC" | grep -Eq '^[0-9a-fA-F]{32}$'; then
    abort "E_OPC is not 32 hex"
  fi

  echo "$IMSI" | grep -Eq '^[0-9]{14,15}$' || abort "bad IMSI '$IMSI'"
  _bao_check_eki "$EKI" || abort "bad EKI '$EKI'"
  echo "$E_KI" | grep -Eq '^[0-9a-fA-F]{32}$' || abort "E_KI is not 32 hex"
  [ -n "$AMF" ] || AMF="8000"

  # 1. TK by EKI (fail-closed on unknown/revoked EKI or KMS down)
  TK=$(_bao_get "$EKI") || abort "TK for EKI=$EKI not available (unknown/revoked EKI or KMS down)"

  # 2. Integrity (optional - under review): a row MAY carry HMAC as the last
  #    column; if present it is verified over the columns actually in the row.
  #    IMPORT_REQUIRE_HMAC=1 makes the column mandatory.
  if [ -n "$HMAC" ]; then
    HK=$(printf '%s' "${TK}pLTE-inBOX-EKI-MAC" | openssl dgst -sha256 -hex | awk '{print $NF}')
    if [ -n "$E_OPC" ]; then COVER="${IMSI}|${EKI}|${E_KI}|${E_OPC}|${AMF}"
    else COVER="${IMSI}|${EKI}|${E_KI}|${AMF}"; fi
    EXPECT=$(printf '%s' "$COVER" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$HK" | awk '{print $NF}')
    [ "${HMAC,,}" = "${EXPECT,,}" ] || abort "HMAC mismatch (file corrupted, tampered, or wrong EKI/TK)"
  elif [ "${IMPORT_REQUIRE_HMAC:-0}" = "1" ]; then
    abort "HMAC missing (IMPORT_REQUIRE_HMAC=1)"
  fi

  # 3. eKi -> Ki (AES-128-ECB decrypt with the same TK)
  KI=$(printf '%s' "$E_KI" \
    | python3 -c 'import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' \
    | openssl enc -d -nopad -aes-128-ecb -K "$TK" 2>/dev/null \
    | python3 -c 'import sys,binascii; print(binascii.hexlify(sys.stdin.buffer.read()).decode().strip())')
  echo "$KI" | grep -Eq '^[0-9a-fA-F]{32}$' || abort "decrypted Ki is invalid (wrong EKI/TK?)"

  # 4. OPc: preferred - from the file (E_OPC, provided by the KPXD, decrypted
  #    with the same TK as Ki); fallback - derive in the network from the
  #    network OP: OPc = AES128(OP, Ki) (MILENAGE, TS 35.208 Annex C).
  if [ -n "$E_OPC" ]; then
    OPC=$(printf '%s' "$E_OPC" \
      | python3 -c 'import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' \
      | openssl enc -d -nopad -aes-128-ecb -K "$TK" 2>/dev/null \
      | python3 -c 'import sys,binascii; print(binascii.hexlify(sys.stdin.buffer.read()).decode().strip())')
    echo "$OPC" | grep -Eq '^[0-9a-fA-F]{32}$' || abort "decrypted OPc is invalid (bad E_OPC or wrong EKI/TK?)"
  else
    echo "warning [row $row]: E_OPC absent - OPc derived by the network (AES128(OP_net, Ki)); prefer the KPXD-provided E_OPC column" >&2
    NETOP=$(_bao_netop) || abort "no E_OPC in the file and network OP not available in KMS (secret network/milenage-op)"
    OPC=$(printf '%s' "$KI" \
      | python3 -c 'import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' \
      | openssl enc -nopad -aes-128-ecb -K "$NETOP" \
      | python3 -c 'import sys,binascii; print(binascii.hexlify(sys.stdin.buffer.read()).decode().strip())')
    echo "$OPC" | grep -Eq '^[0-9a-fA-F]{32}$' || abort "OPc derivation failed"
  fi

  # 5. Write to the AUC
  EXISTS=$(mongo_eval_stdin 'print(db.subscribers.findOne({imsi:"'$IMSI'"},{imsi:1}) ? "Y" : "N")')
  case "$EXISTS" in
    Y)
      R=$(mongo_eval_stdin 'var r=db.subscribers.updateOne({imsi:"'$IMSI'"},{$set:{"security.k":"'$KI'","security.opc":"'$OPC'","security.amf":"'$AMF'"}}); print(r.modifiedCount>0 ? "updated" : "nochange")')
      [ "$R" = "updated" ] || [ "$R" = "nochange" ] || abort "mongo updateOne: $R"
      if [ "$R" = "updated" ]; then updated=$((updated+1)); else nochange=$((nochange+1)); fi
      echo "[row $row] imsi=$IMSI eki=$EKI: security keys $R"
      ;;
    N)
      # NOTE: --entrypoint "" is REQUIRED - the image entrypoint is ["bin/bash","-c"],
      # which would swallow the dbctl command (same trick as the 'populate' service).
      R=$(docker run --rm --entrypoint "" --network "$NET_ID" ${DBCTL_CA_MOUNT[@]+"${DBCTL_CA_MOUNT[@]}"} \
        -e DB_URI="$DB_URI" \
        gradiant/open5gs-dbctl:0.10.3 open5gs-dbctl add_ue_with_slice "$IMSI" "$KI" "$OPC" internet 1 ffffff 2>&1)
      RC=$?
      if [ $RC -ne 0 ]; then
        abort "dbctl add_ue_with_slice rc=$RC: $(printf '%s' "$R" | tail -1)"
      fi
      if [ "$IMSI" != "$(mongo_eval_stdin 'print((db.subscribers.findOne({imsi:"'$IMSI'"},{imsi:1})||{}).imsi||"")')" ]; then
        abort "subscriber not found in DB after dbctl add"
      fi
      # dbctl default amf is "8000"; apply the file value if different
      if [ "$AMF" != "8000" ]; then
        mongo_eval_stdin 'db.subscribers.updateOne({imsi:"'$IMSI'"},{$set:{"security.amf":"'$AMF'"}}); print("ok")' >/dev/null \
          || abort "security.amf update"
      fi
      created=$((created+1)); echo "[row $row] imsi=$IMSI eki=$EKI: subscriber created"
      ;;
    *)
      abort "subscriber existence check returned: $EXISTS"
      ;;
  esac
done < "$FILE"

echo "Import complete: file=$FILE rows=$row created=$created updated=$updated unchanged=$nochange"
