#!/bin/bash
# Generate TLS certificates for MongoDB (mongod requireTLS) used by the
# docker-compose.dbtls.yaml overlay. Run ON THE SERVER from anywhere.
# Certificates are placed in .deploy/docker/mongodb-tls/:
#   - ca.crt          (public; mounted into every DB consumer and the mongo shell)
#   - server.crt/key  (private; key is gitignored)
#   - server.pem      (cert+key concatenated; mounted into mongod)
set -euo pipefail
cd "$(dirname "$0")/../.."

TLS_DIR=".deploy/docker/mongodb-tls"
mkdir -p "$TLS_DIR"
cd "$TLS_DIR"

if [ -s server.pem ] && [ -s ca.crt ]; then
  echo "MongoDB TLS material already exists in $TLS_DIR, skipping generation."
  exit 0
fi

echo "Generating CA (10 years)..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=mongodb-ca/O=pLTE-in-Box" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "Generating server certificate (mongodb, localhost, 127.0.0.1)..."
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=mongodb/O=pLTE-in-Box"

cat > server-ext.cnf <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:mongodb,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server-ext.cnf

rm -f server.csr server-ext.cnf ca.srl
cat server.crt server.key > server.pem

chmod 600 ca.key server.key server.pem
chmod 644 ca.crt server.crt

echo "Verifying certificate..."
openssl verify -CAfile ca.crt server.crt
echo "MongoDB TLS generated in $TLS_DIR:"
ls -l ca.crt server.crt server.pem
