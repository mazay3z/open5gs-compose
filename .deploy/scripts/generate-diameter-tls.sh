#!/bin/bash
# Regenerate Diameter TLS material (CA + per-node leaf certs) for
# hss/mme/pcrf/smf. The previously committed private keys were removed
# from the repository working tree (secret cleanup, PLTEBOX-137 Q5); this
# script recreates them locally (keys are gitignored). The .conf files
# reference TLS_Cred at parse time, so these files MUST exist for
# hss/mme/pcrf/smf to start.
#
# NOTE: Diameter TLS is NOT enabled in the .conf files (peers use No_TLS);
# the leaf certs are parsed by freeDiameter but the connections stay plain.
# Enabling S6a/S6b TLS is a P2 follow-up - see EKI-TK-ENCRYPTION.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

BASE=".deploy/docker/diameter"
CA_DIR="$BASE/ca"
NODES="hss mme pcrf smf"

mkdir -p "$CA_DIR"
if [ ! -s "$CA_DIR/ca.key" ]; then
  echo "Generating Diameter CA..."
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" \
    -subj "/CN=diameter-ca/O=pLTE-in-Box" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  chmod 600 "$CA_DIR/ca.key"
  # TLS_CA in each node .conf points to <node>/ca.crt - keep it in sync
  for n in $NODES; do cp "$CA_DIR/ca.crt" "$BASE/$n/ca.crt"; done
fi

for n in $NODES; do
  d="$BASE/$n"
  if [ -s "$d/$n.key" ]; then
    echo "$n: key already present, skipping"
    continue
  fi
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$d/$n.key" -out "$d/$n.csr" \
    -subj "/CN=$n.localdomain/O=pLTE-in-Box"
  EXT=$(mktemp)
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=clientAuth,serverAuth"
    echo "subjectAltName=DNS:$n.localdomain,DNS:$n"
  } > "$EXT"
  openssl x509 -req -in "$d/$n.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial -out "$d/$n.crt" -days 825 -sha256 -extfile "$EXT"
  rm -f "$EXT" "$d/$n.csr" "$CA_DIR/ca.srl"
  chmod 644 "$d/$n.key"  # freeDiameter in the container runs non-root; must read the key (original repo files were 644)
  echo "$n: leaf cert generated"
done
echo "Diameter TLS material ready under $BASE (keys gitignored)."
