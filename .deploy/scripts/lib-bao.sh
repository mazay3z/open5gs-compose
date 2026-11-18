#!/bin/bash
# Shared helpers for the EKI-TK scripts (EKI-TK-ENCRYPTION.md).
# Values (TK, network OP) are printed to stdout only; never logged.
# Fail-closed: unknown/revoked EKI, missing secret, or KMS down -> nonzero exit.
#
# Variables (overridable):
#   BAO_ADDR       - KMS TLS endpoint (default https://127.0.0.1:8200)
#   BAO_CA_FILE    - CA certificate (default .deploy/docker/openbao/tls/ca.crt)
#   BAO_TOKEN_FILE - root token. Default: .deploy/secrets/bao-root-token if readable,
#                    otherwise .deploy/docker/local-data/openbao/secrets/root-token.
#                    (The local-data copy is root-owned on the stand; copy it once:
#                     sudo cp .deploy/docker/local-data/openbao/secrets/root-token \
#                         .deploy/secrets/bao-root-token && chmod 600 ...)

_BAO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BAO_ADDR="${BAO_ADDR:-https://127.0.0.1:8200}"
BAO_CA_FILE="${BAO_CA_FILE:-$_BAO_ROOT/.deploy/docker/openbao/tls/ca.crt}"
if [ -z "${BAO_TOKEN_FILE:-}" ]; then
  if [ -r "$_BAO_ROOT/.deploy/secrets/bao-root-token" ]; then
    BAO_TOKEN_FILE="$_BAO_ROOT/.deploy/secrets/bao-root-token"
  else
    BAO_TOKEN_FILE="$_BAO_ROOT/.deploy/docker/local-data/openbao/secrets/root-token"
  fi
fi

_bao_check_eki() {
  # $1 = eki
  case "$1" in
    ''|*[!0-9]*) echo "lib-bao: invalid EKI '$1' (expected positive integer)" >&2; return 2 ;;
  esac
  [ "$1" -ge 1 ] || { echo "lib-bao: invalid EKI '$1' (expected >= 1)" >&2; return 2; }
}

_bao_precheck() {
  command -v curl >/dev/null 2>&1 || { echo "lib-bao: curl not found" >&2; return 2; }
  [ -r "$BAO_TOKEN_FILE" ] || {
    echo "lib-bao: token file not readable: $BAO_TOKEN_FILE" >&2
    echo "lib-bao: fix: sudo cp .deploy/docker/local-data/openbao/secrets/root-token .deploy/secrets/bao-root-token && chmod 600 .deploy/secrets/bao-root-token" >&2
    return 2
  }
  [ -r "$BAO_CA_FILE" ] || { echo "lib-bao: CA file not readable: $BAO_CA_FILE" >&2; return 2; }
}

# _bao_hdr -> path to a temp file (mode 600) containing the X-Vault-Token header.
_bao_hdr() {
  local h
  h=$(mktemp) || return 1
  chmod 600 "$h"
  printf 'X-Vault-Token: %s\n' "$(cat "$BAO_TOKEN_FILE")" > "$h"
  printf '%s' "$h"
}

# _bao_kv_get_field <secret-path> <field>
#   secret-path is relative to the KV v2 mount 'secret', e.g. 'transport-keys/eki-1'
#   prints the value of data.<field> (empty line if absent); rc=1 if the secret/KMS is unavailable
_bao_kv_get_field() {
  local path="$1" field="$2" hdr resp
  _bao_precheck || return 2
  hdr=$(_bao_hdr) || return 2
  if ! resp=$(curl -fsS --cacert "$BAO_CA_FILE" -H "@$hdr" \
      "${BAO_ADDR}/v1/secret/data/${path}" 2>/dev/null); then
    rm -f "$hdr"
    return 1
  fi
  rm -f "$hdr"
  printf '%s' "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['data'].get('$field',''))" \
    || { echo "lib-bao: malformed KMS response for $path" >&2; return 1; }
}

# _bao_get <EKI> -> prints TK hex (32 chars) for transport-keys/eki-<EKI>
_bao_get() {
  _bao_check_eki "$1" || return 2
  local tk
  tk=$(_bao_kv_get_field "transport-keys/eki-$1" key) || {
    echo "lib-bao: EKI $1: TK not available (unknown/revoked EKI or KMS down) - fail-closed" >&2
    return 1
  }
  [ -n "$tk" ] || { echo "lib-bao: EKI $1: empty TK in KMS" >&2; return 1; }
  printf '%s' "$tk"
}

# _bao_netop -> prints the network MILENAGE OP (32 hex) from network/milenage-op
_bao_netop() {
  local op
  op=$(_bao_kv_get_field "network/milenage-op" value) || {
    echo "lib-bao: network OP not available (secret network/milenage-op missing or KMS down) - fail-closed" >&2
    return 1
  }
  [ -n "$op" ] || { echo "lib-bao: network OP empty in KMS" >&2; return 1; }
  printf '%s' "$op"
}

# _bao_exists <EKI> -> 0 if TK present in KMS, 1 otherwise
_bao_exists() {
  _bao_check_eki "$1" || return 2
  _bao_precheck || return 2
  local hdr rc
  hdr=$(_bao_hdr) || return 2
  curl -fsS --cacert "$BAO_CA_FILE" -H "@$hdr" -o /dev/null \
    "${BAO_ADDR}/v1/secret/data/transport-keys/eki-$1" 2>/dev/null
  rc=$?
  rm -f "$hdr"
  return $rc
}

# _bao_meta <EKI> -> prints KV metadata JSON (versions only, no key value)
_bao_meta() {
  _bao_check_eki "$1" || return 2
  _bao_precheck || return 2
  local hdr rc
  hdr=$(_bao_hdr) || return 2
  curl -fsS --cacert "$BAO_CA_FILE" -H "@$hdr" \
    "${BAO_ADDR}/v1/secret/metadata/transport-keys/eki-$1"
  rc=$?
  rm -f "$hdr"
  return $rc
}

# _bao_put <secret-path> <field> <value> -> write (KV v2: creates a new version)
_bao_put() {
  local path="$1" field="$2" value="$3" hdr rc
  _bao_precheck || return 2
  hdr=$(_bao_hdr) || return 2
  curl -fsS --cacert "$BAO_CA_FILE" -H "@$hdr" -X POST \
    -d "{\"data\":{\"$field\":\"$value\"}}" \
    "${BAO_ADDR}/v1/secret/data/${path}" >/dev/null
  rc=$?
  rm -f "$hdr"
  return $rc
}

# _bao_delete <secret-path> -> delete the secret (KV v2 metadata delete)
_bao_delete() {
  local path="$1" hdr rc
  _bao_precheck || return 2
  hdr=$(_bao_hdr) || return 2
  curl -fsS --cacert "$BAO_CA_FILE" -H "@$hdr" -X DELETE \
    "${BAO_ADDR}/v1/secret/metadata/${path}" >/dev/null
  rc=$?
  rm -f "$hdr"
  return $rc
}
