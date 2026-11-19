#!/bin/bash
# Generate a TEST transport key (TK) file for `tk-mgmt.sh import`.
# Emulates the "key file from the profile supplier (KPXD)" of the field flow.
#
# Usage: gen-tk-file.sh <output-file> [--show]
#   e.g.: bash .deploy/scripts/gen-tk-file.sh /tmp/test-eki-9.key
#         bash .deploy/scripts/tk-mgmt.sh import 9 /tmp/test-eki-9.key
#
# The key is 16 random bytes (AES-128, 32 hex characters), written with
# mode 600. The value is NEVER printed by default (tk-mgmt convention);
# --show prints it - only for checking the test setup.
set -euo pipefail
cd "$(dirname "$0")/../.."

SHOW=0
OUT=""
for a in "$@"; do
  case "$a" in
    --show) SHOW=1;;
    *) OUT="$a";;
  esac
done
if [ -z "$OUT" ]; then
  echo "Usage: $0 <output-file> [--show]" >&2
  exit 2
fi
if [ -e "$OUT" ]; then
  echo "refusing to overwrite existing file: $OUT" >&2
  exit 1
fi

TK=$(openssl rand -hex 16)
umask 077
printf '%s\n' "$TK" > "$OUT"
chmod 600 "$OUT"

echo "test TK file written: $OUT (32 hex chars, mode 600)"
if [ "$SHOW" = 1 ]; then
  echo "value (--show): $TK"
fi
echo "next: bash .deploy/scripts/tk-mgmt.sh import <EKI> $OUT"
echo "after import: shred -u $OUT"
