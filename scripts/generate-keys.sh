#!/usr/bin/env bash
#
# Generates an RSA key pair suitable for JWT signing and verification.
#
# The private key is sensitive signing material and must be protected
# according to the security requirements of the environment in which it
# is used. The authenticator server requires only the public key.
#
# Existing keys are never overwritten unless explicitly requested.
# Private key contents are never printed.
#
# Usage:
#   scripts/generate-keys.sh
#   scripts/generate-keys.sh --force
#   scripts/generate-keys.sh --dir /path/to/keys
#   scripts/generate-keys.sh --bits 3072
#
# Defaults:
#   output directory: secrets
#   RSA key size:     3072 bits
#
# Output:
#   <dir>/jwt-private.pem
#   <dir>/jwt-public.pem

set -euo pipefail

readonly DEFAULT_OUT_DIR="secrets"
readonly DEFAULT_KEY_BITS=3072
readonly MIN_KEY_BITS=2048

FORCE=0
OUT_DIR="${DEFAULT_OUT_DIR}"
KEY_BITS="${DEFAULT_KEY_BITS}"

usage() {
  cat <<'EOF'
Usage:
  scripts/generate-keys.sh [options]

Options:
  --dir <path>   Output directory. Default: secrets
  --bits <bits>  RSA key size. Default: 3072
  --force        Overwrite an existing key pair
  -h, --help     Show this help

Output:
  <dir>/jwt-private.pem
  <dir>/jwt-public.pem
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      ;;
    --dir)
      [[ $# -ge 2 ]] || die "--dir requires a value"
      OUT_DIR="$2"
      shift
      ;;
    --bits)
      [[ $# -ge 2 ]] || die "--bits requires a value"
      KEY_BITS="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac

  shift
done

command -v openssl >/dev/null 2>&1 \
  || die "openssl is required but was not found"

[[ -n "${OUT_DIR}" ]] \
  || die "output directory must not be empty"

[[ "${KEY_BITS}" =~ ^[0-9]+$ ]] \
  || die "--bits must be a positive integer"

(( KEY_BITS >= MIN_KEY_BITS )) \
  || die "RSA key size must be at least ${MIN_KEY_BITS} bits"

PRIVATE_KEY="${OUT_DIR}/jwt-private.pem"
PUBLIC_KEY="${OUT_DIR}/jwt-public.pem"

mkdir -p "${OUT_DIR}"

if [[ "${FORCE}" -eq 0 ]]; then
  for file in "${PRIVATE_KEY}" "${PUBLIC_KEY}"; do
    if [[ -e "${file}" ]]; then
      echo "error: refusing to overwrite existing file: ${file}" >&2
      echo "re-run with --force to overwrite the key pair" >&2
      exit 1
    fi
  done
fi

# Restrict permissions for every file created by this script. The public key
# is explicitly relaxed to 0644 after successful generation.
umask 077

PRIVATE_TMP="$(mktemp "${OUT_DIR}/.jwt-private.pem.XXXXXX")"
PUBLIC_TMP="$(mktemp "${OUT_DIR}/.jwt-public.pem.XXXXXX")"

cleanup() {
  rm -f "${PRIVATE_TMP}" "${PUBLIC_TMP}"
}

trap cleanup EXIT INT TERM

echo "generating RSA key pair (${KEY_BITS} bits)..."

openssl genpkey \
  -algorithm RSA \
  -pkeyopt "rsa_keygen_bits:${KEY_BITS}" \
  -out "${PRIVATE_TMP}"

openssl pkey \
  -in "${PRIVATE_TMP}" \
  -pubout \
  -out "${PUBLIC_TMP}"

chmod 600 "${PRIVATE_TMP}"
chmod 644 "${PUBLIC_TMP}"

# Move the complete pair into its final location only after both keys have
# been generated successfully.
mv -f "${PRIVATE_TMP}" "${PRIVATE_KEY}"
mv -f "${PUBLIC_TMP}" "${PUBLIC_KEY}"

trap - EXIT INT TERM

echo "wrote private key: ${PRIVATE_KEY}"
echo "wrote public key:  ${PUBLIC_KEY}"
echo
echo "keep the private key secret and restrict access to trusted signing environments"
echo "the authenticator server requires only the public key"
