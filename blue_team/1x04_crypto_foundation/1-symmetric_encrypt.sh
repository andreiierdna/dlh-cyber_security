#!/bin/bash

set -euo pipefail

readonly SCRIPT_NAME="1-symmetric_encrypt.sh"
readonly ITERATIONS=100000
readonly KEY_LENGTH=32

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <input_file> <output_file> <mode>

Arguments:
    input_file    Path to the file to encrypt
    output_file   Path for the encrypted output
    mode          Encryption mode: cbc or gcm

Examples:
    ${SCRIPT_NAME} patient_record.txt patient_record.enc cbc
    ${SCRIPT_NAME} backup.sql backup.enc gcm

The script prompts for a password and derives the AES-256 key
automatically using PBKDF2.
EOF
}

log() {
    local level="$1"
    shift
    echo "[${level}] $*" >&2
}

die() {
    local exit_code="$1"
    shift
    log "ERROR" "$*"
    exit "${exit_code}"
}

# ---------------------------------------------------------------------------
# Validate arguments
# ---------------------------------------------------------------------------

if [[ $# -ne 3 ]]; then
    usage
    die 1 "Exactly 3 arguments required."
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
MODE=$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')

if [[ ! -f "$INPUT_FILE" ]]; then
    die 2 "Input file not found: $INPUT_FILE"
fi

if [[ ! -r "$INPUT_FILE" ]]; then
    die 2 "Input file is not readable: $INPUT_FILE"
fi

case "$MODE" in
    cbc)
        CIPHER="aes-256-cbc"
        ;;
    gcm)
        CIPHER="aes-256-gcm"
        ;;
    *)
        die 3 "Unsupported mode '$3'. Use 'cbc' or 'gcm'."
        ;;
esac

# ---------------------------------------------------------------------------
# Check OpenSSL
# ---------------------------------------------------------------------------

if ! command -v openssl >/dev/null 2>&1; then
    die 4 "OpenSSL is not installed or not available in PATH."
fi

if ! openssl kdf -help >/dev/null 2>&1; then
    die 4 "This script requires OpenSSL 3.0 or newer."
fi

log "INFO" "Using $(openssl version)"

# ---------------------------------------------------------------------------
# Read password
# ---------------------------------------------------------------------------

read -r -s -p "Enter encryption password: " PASSWORD
echo >&2

read -r -s -p "Confirm encryption password: " PASSWORD_CONFIRM
echo >&2

if [[ -z "$PASSWORD" ]]; then
    die 1 "Password cannot be empty."
fi

if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    die 1 "Passwords do not match."
fi

# ---------------------------------------------------------------------------
# Generate salt automatically
# ---------------------------------------------------------------------------

SALT_HEX=$(openssl rand -hex 16)

# Convert password to hexadecimal so PBKDF2 can safely receive it.
PASSWORD_HEX=$(printf '%s' "$PASSWORD" | od -An -tx1 | tr -d ' \n')

# ---------------------------------------------------------------------------
# Derive 256-bit AES key using PBKDF2-SHA256
# ---------------------------------------------------------------------------

AES_KEY=$(
    openssl kdf \
        -keylen "$KEY_LENGTH" \
        -kdfopt digest:SHA256 \
        -kdfopt "hexpass:${PASSWORD_HEX}" \
        -kdfopt "hexsalt:${SALT_HEX}" \
        -kdfopt "iter:${ITERATIONS}" \
        PBKDF2 |
    tr -d ':\r\n '
)

# Remove password variables as soon as they are no longer needed.
unset PASSWORD
unset PASSWORD_CONFIRM
unset PASSWORD_HEX

if [[ ${#AES_KEY} -ne 64 ]]; then
    die 4 "Failed to derive a valid AES-256 key."
fi

# ---------------------------------------------------------------------------
# Display encryption parameters
# ---------------------------------------------------------------------------

log "INFO" "Encryption Parameters:"
log "INFO" "  Input:       $INPUT_FILE"
log "INFO" "  Output:      $OUTPUT_FILE"
log "INFO" "  Cipher:      $CIPHER"
log "INFO" "  KDF:         PBKDF2-SHA256"
log "INFO" "  Iterations:  $ITERATIONS"

# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

log "INFO" "Starting encryption..."

START_TIME=$(date +%s%N)

if openssl cms \
    -encrypt \
    "-${CIPHER}" \
    -secretkey "$AES_KEY" \
    -secretkeyid "$SALT_HEX" \
    -binary \
    -in "$INPUT_FILE" \
    -out "$OUTPUT_FILE" \
    -outform DER; then

    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

    chmod 600 "$OUTPUT_FILE"

    log "INFO" "Encryption completed successfully."
    log "INFO" "  Mode:         $MODE"
    log "INFO" "  Elapsed time: ${ELAPSED_MS} ms"
    log "INFO" "  Output file:  $OUTPUT_FILE"
else
    rm -f "$OUTPUT_FILE"
    die 4 "Encryption failed."
fi

unset AES_KEY

exit 0
