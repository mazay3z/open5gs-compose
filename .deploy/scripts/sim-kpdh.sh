#!/bin/bash
# "KPXD" (SIM key personalization center) simulator for the pLTE-in-BOX prototype.
# Generates/extends a UICC profile load file in which the subscriber key is
# ENCRYPTED with the transport key (TK, AES-128-ECB) bound to an EKI.
#
# The plaintext Ki never appears in the file, in git, or in the logs.
#
# File format (see .deploy/profiles/README.md):
#   # comments / header
#   IMSI,EKI,E_KI,AMF[,HMAC]             (HMAC is optional - under review)
#   E_KI = AES-128-ECB(TK_EKI, Ki)            [32 hex; Ki is exactly 16 bytes, no padding]
#   HMAC = HMAC-SHA256(HK, "IMSI|EKI|E_KI|AMF") [64 hex, only with --hmac]
#   HK   = SHA256(TK_EKI || "pLTE-inBOX-EKI-MAC")
#
# OPc is NOT part of the file: the network derives OPc = AES128(OP, Ki) from its
# own network OP (3GPP TS 35.208 Annex C) at import time.
#
# Usage:
#   sim-kpdh.sh --gen   <EKI> <IMSI> [--amf <AMF>] [--out <file>] [--hmac]
#   sim-kpdh.sh --rekey <EKI> <IMSI> --ki <32hex> [--amf <AMF>] [--out <file>] [--hmac]
#   --gen  : Ki generated from /dev/urandom - emulates KPXD personalization
#   --rekey: re-encrypt known keys (e.g. migration of a plaintext ue.list row)
#   --hmac : add the optional 5th HMAC column (default: 4-column file)
#
# Fail-closed: if the KMS is unavailable or the EKI is unknown, the file is NOT written.
set -uo pipefail
cd "$(dirname "$0")/../.."
source .deploy/scripts/lib-bao.sh

MODE="${1:-}"; EKI="${2:-}"; IMSI="${3:-}"
shift 3 2>/dev/null || true
AMF="8000"; OUT=""; KI=""; WITH_HMAC=0
while [ $# -gt 0 ]; do
  case "$1" in
    --amf) AMF="${2:-}"; shift 2;;
    --ki)  KI="${2:-}"; shift 2;;
    --out) OUT="${2:-}"; shift 2;;
    --hmac) WITH_HMAC=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

case "$MODE" in
  --gen)   [ -z "$KI" ] || { echo "--gen does not accept --ki (Ki must be generated here)" >&2; exit 2; }
           KI=$(openssl rand -hex 16)
           ;;
  --rekey) [ -n "$KI" ] || { echo "--rekey requires --ki <32hex>" >&2; exit 2; }
           ;;
  *) echo "Usage: $0 --gen <EKI> <IMSI> [--amf A] [--out F]
       | $0 --rekey <EKI> <IMSI> --ki H32 [--amf A] [--out F]" >&2; exit 2;;
esac

_bao_check_eki "$EKI" || exit 2
echo "$IMSI" | grep -Eq '^[0-9]{14,15}$' || { echo "ERROR: IMSI '$IMSI' is not 14-15 digits" >&2; exit 2; }
echo "$KI"   | grep -Eq '^[0-9a-fA-F]{32}$' || { echo "ERROR: Ki must be 32 hex chars" >&2; exit 2; }
[ -n "$AMF" ] || AMF="8000"
[ -n "$OUT" ] || OUT=".deploy/profiles/profiles-eki-$EKI.csv"

# Fail-closed: no TK -> no file.
TK=$(_bao_get "$EKI") || exit 1

# eKi = AES-128-ECB(TK, Ki); hex<->bin via python3 (no xxd dependency).
E_KI=$(printf '%s' "$KI" \
  | python3 -c 'import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' \
  | openssl enc -nopad -aes-128-ecb -K "$TK" \
  | python3 -c 'import sys,binascii; print(binascii.hexlify(sys.stdin.buffer.read()).decode().strip())')
[ ${#E_KI} -eq 32 ] || { echo "ERROR: internal - E_KI length ${#E_KI} != 32" >&2; exit 1; }

ROW="$IMSI,$EKI,$E_KI,$AMF"
HDR='# pLTE-in-BOX UICC profile load file (TK per KPXD practice, GSMA FS.28 "Acceptable").
# Columns: IMSI,EKI,E_KI,AMF[,HMAC]  (HMAC is optional - under review; pass --hmac to add it)
# E_KI = AES-128-ECB(TK_EKI, Ki), 32 hex. OPc is derived by the network at import.
# See .deploy/profiles/README.md.'
if [ "$WITH_HMAC" = "1" ]; then
  HK=$(printf '%s' "${TK}pLTE-inBOX-EKI-MAC" | openssl dgst -sha256 -hex | awk '{print $NF}')
  HMAC=$(printf '%s' "$IMSI|$EKI|$E_KI|$AMF" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$HK" | awk '{print $NF}')
  ROW="$ROW,$HMAC"
  HDR="$HDR
# This file uses HMAC: HMAC-SHA256(HK, IMSI|EKI|E_KI|AMF), HK = SHA256(TK_EKI + pLTE-inBOX-EKI-MAC)."
fi
mkdir -p "$(dirname "$OUT")"
if [ ! -f "$OUT" ]; then
  printf '%s\n' "$HDR" > "$OUT"
fi
echo "$ROW" >> "$OUT"
echo "profile appended to $OUT (imsi=$IMSI eki=$EKI$([ "$WITH_HMAC" = 1 ] && echo ', with HMAC')); plaintext Ki not stored in the file."
