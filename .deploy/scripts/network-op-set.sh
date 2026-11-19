#!/bin/bash
# Store the network MILENAGE OP in OpenBao (KV v2, secret/data/network/milenage-op).
#
# What the network OP is for (see EKI-TK-ENCRYPTION.md, "Сетевой OP: импорт"):
#   - Fallback only: import-profiles.sh derives per-UE OPc = AES128(OP, Ki)
#     (3GPP TS 35.208 Annex C) when the load file has NO E_OPC column.
#   - When the supplier (KPXD) provides E_OPC, the network OP is not needed
#     at import time (it may stay absent from the KMS).
#   - Optional cross-check vector: if the KPXD uses the same network OP,
#     a derived OPc must equal the KPXD-provided one.
#
# Usage:
#   network-op-set.sh <key-file>   # preferred: file with the OP (32 hex characters)
#   network-op-set.sh <32-hex OP>  # backward compatible; the value is visible in the
#                                  # process list for the duration of the call
#
# Re-running creates a new KV version. OPc values already stored in the AUC
# remain valid (they were derived under the old OP); only future derivations
# (imports without E_OPC) use the new OP.
set -uo pipefail
cd "$(dirname "$0")/../.."
source .deploy/scripts/lib-bao.sh

ARG="${1:-}"
OP=""
if [ -z "$ARG" ]; then
  echo "Usage: $0 <key-file-with-32hex-OP> | <32-hex OP>" >&2
  exit 2
fi
if echo "$ARG" | grep -Eq '^[0-9a-fA-F]{32}$'; then
  OP="$ARG"
  echo "warning: OP passed on the command line - it is visible in the process list; prefer a key file" >&2
elif [ -f "$ARG" ]; then
  OP=$(tr -d '[:space:]' < "$ARG" | head -c 64)
else
  echo "ERROR: $ARG is neither 32 hex characters nor an existing file" >&2
  exit 2
fi

echo "$OP" | grep -Eq '^[0-9a-fA-F]{32}$' || { echo "ERROR: OP must be exactly 32 hex characters (16 bytes)" >&2; exit 2; }

if _bao_put "network/milenage-op" value "$OP"; then
  echo "network OP stored at secret/data/network/milenage-op (value never printed)."
  echo "Verify with: bao kv metadata get secret/network/milenage-op"
  if [ -f "$ARG" ] && [ "$ARG" != "$(echo "$ARG" | grep -E '^[0-9a-fA-F]{32}$')" ]; then
    echo "Then securely delete the OP file: shred -u $ARG"
  fi
else
  echo "ERROR: failed to store network OP in the KMS" >&2
  exit 1
fi
