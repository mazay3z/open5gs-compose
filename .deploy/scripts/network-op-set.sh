#!/bin/bash
# Store the network MILENAGE OP in OpenBao (KV v2, secret/data/network/milenage-op).
# import-profiles.sh uses it to derive per-UE OPc = AES128(OP, Ki) (3GPP TS 35.208 Annex C).
#
# Usage: network-op-set.sh <32-hex OP>
# Re-running creates a new KV version (old OPc values in the AUC remain valid until
# the affected subscribers are re-imported; see EKI-TK-ENCRYPTION.md, "Rotation").
set -uo pipefail
cd "$(dirname "$0")/../.."
source .deploy/scripts/lib-bao.sh

OP="${1:-}"
echo "$OP" | grep -Eq '^[0-9a-fA-F]{32}$' || { echo "Usage: $0 <32-hex OP>" >&2; exit 2; }

if _bao_put "network/milenage-op" value "$OP"; then
  echo "network OP stored at secret/data/network/milenage-op (value never printed)."
else
  echo "ERROR: failed to store network OP in the KMS" >&2
  exit 1
fi
