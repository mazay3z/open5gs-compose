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

SHOW=0
OUT=""
for a in "$@"; do
  case "$a" in
    -h|--help)
      cat <<'USAGE'
Usage: gen-tk-file.sh <output-file> [--show]

Generate a TEST transport key (TK) file for `tk-mgmt.sh import`
(16 random bytes, 32 hex characters, mode 600).

Options:
  --show   print the generated key value (default: never printed)
  -h, --help  this help

Example:
  gen-tk-file.sh /tmp/test-eki-9.key
  tk-mgmt.sh import 9 /tmp/test-eki-9.key
USAGE
      exit 0;;
    --show) SHOW=1;;
    -*) echo "unknown option: $a (try: $0 --help)" >&2; exit 2;;
    *)
      if [ -n "$OUT" ]; then
        echo "unexpected extra argument: $a" >&2; exit 2
      fi
      OUT="$a";;
  esac
done
if [ -z "$OUT" ]; then
  echo "Usage: $0 <output-file> [--show]" >&2
  exit 2
fi
case "$OUT" in
  -*) echo "output file must not start with '-': $OUT" >&2; exit 2;;
esac
if [ -e "$OUT" ]; then
  echo "refusing to overwrite existing file: $OUT" >&2
  exit 1
fi

TK=$(openssl rand -hex 16)
umask 077
printf '%s\n' "$TK" > "$OUT"
chmod 600 -- "$OUT"

echo "test TK file written: $OUT (32 hex chars, mode 600)"
if [ "$SHOW" = 1 ]; then
  echo "value (--show): $TK"
fi
echo "next: bash .deploy/scripts/tk-mgmt.sh import <EKI> $OUT"
echo "after import: shred -u $OUT"
