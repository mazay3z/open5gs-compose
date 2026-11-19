#!/bin/bash
# Transport key (TK) lifecycle for EKI-based profile import (EKI-TK-ENCRYPTION.md).
# TK is stored in OpenBao (KV v2) at secret/transport-keys/eki-<EKI>.
#
# Usage:
#   tk-mgmt.sh create <EKI>   # generate a new TK (AES-128, 32 hex) and store it in the KMS
#   tk-mgmt.sh meta   <EKI>   # print KV metadata (versions only; never the key)
#   tk-mgmt.sh revoke <EKI>   # back up the TK (gitignored dir) and delete it from the KMS
#   tk-mgmt.sh import <EKI> <file-with-32hex>  # store an externally provided TK
#                                              # (value never printed; existing EKI is not overwritten)
#
# create is idempotent: an existing EKI is NEVER regenerated (old profile files
# would stop decrypting). The TK value is never printed.
set -uo pipefail
cd "$(dirname "$0")/../.."
source .deploy/scripts/lib-bao.sh

cmd="${1:-}"; eki="${2:-}"
case "$cmd" in
  create|meta|revoke|import) : ;;
  *) echo "Usage: $0 {create|import|meta|revoke} <EKI> [key-file]" >&2; exit 2 ;;
esac
_bao_check_eki "$eki" || exit 2
_bao_precheck || exit 2

case "$cmd" in
create)
  if _bao_exists "$eki"; then
    echo "EKI $eki: TK already exists in the KMS - keeping it (not regenerating)."
    exit 0
  fi
  TK=$(openssl rand -hex 16)
  if _bao_put "transport-keys/eki-$eki" key "$TK"; then
    echo "EKI $eki: TK created and stored at secret/transport-keys/eki-$eki (value never printed)."
  else
    echo "ERROR: failed to store TK for EKI $eki in the KMS" >&2
    exit 1
  fi
  ;;
meta)
  if ! META=$(_bao_meta "$eki"); then
    echo "EKI $eki: not present in the KMS (unknown or revoked)."
    exit 1
  fi
  printf '%s' "$META" | python3 -c 'import sys,json; d=json.load(sys.stdin); d=d.get("data",d); print("EKI:", sys.argv[1]); print("current_version:", d.get("current_version")); print("created_time:", d.get("created_time"))' "$eki"
  ;;
import)
  # Import an externally provided TK (e.g. delivered by the profile supplier / KPXD).
  # The key is read from a file (never typed on the command line, never printed).
  KEYFILE="${3:-}"
  if [ -z "$KEYFILE" ] || [ ! -f "$KEYFILE" ]; then
    echo "Usage: $0 import <EKI> <key-file>  (key-file: exactly 32 hex characters)" >&2
    exit 2
  fi
  if _bao_exists "$eki"; then
    echo "EKI $eki: TK already exists in the KMS - refusing to overwrite."
    echo "If the key was really re-issued, revoke the old one first: $0 revoke $eki"
    exit 1
  fi
  TK=$(tr -d '[:space:]' < "$KEYFILE" | head -c 64)
  echo "$TK" | grep -Eq '^[0-9a-fA-F]{32}$' || {
    echo "ERROR: key file must contain exactly 32 hex characters (16 bytes = AES-128 TK)" >&2
    exit 2
  }
  if _bao_put "transport-keys/eki-$eki" key "$TK"; then
    echo "EKI $eki: externally provided TK imported into OpenBao (value never printed)."
    echo "Verify with: $0 meta $eki"
    echo "Then securely delete the key file: shred -u $KEYFILE"
  else
    echo "ERROR: failed to import TK for EKI $eki into the KMS" >&2
    exit 1
  fi
  ;;
revoke)
  if ! TK=$(_bao_get "$eki"); then
    echo "EKI $eki: not present in the KMS - nothing to revoke."
    exit 0
  fi
  REV_DIR=".deploy/secrets/revoked"
  mkdir -p "$REV_DIR" && chmod 700 "$REV_DIR"
  STAMP=$(date +%Y%m%d-%H%M%S)
  printf '%s' "$TK" > "$REV_DIR/eki-$eki-$STAMP.hex"
  chmod 600 "$REV_DIR/eki-$eki-$STAMP.hex"
  echo "EKI $eki: last-resort TK backup written to $REV_DIR/eki-$eki-$STAMP.hex (gitignored)."
  if _bao_delete "transport-keys/eki-$eki"; then
    echo "EKI $eki: REVOKED. Profile files with EKI=$eki can no longer be imported."
  else
    echo "ERROR: failed to delete EKI $eki from the KMS (backup kept)" >&2
    exit 1
  fi
  ;;
esac
