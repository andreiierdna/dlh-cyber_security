#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file> <expected_sha256_hash>"
    exit 1
fi

FILE="$1"
EXPECTED_HASH="$2"

if [[ ! -f "$FILE" ]]; then
    echo "Error: File not found: $FILE"
    exit 1
fi

# Normalize the expected hash to lowercase.
EXPECTED_HASH=$(printf '%s' "$EXPECTED_HASH" | tr '[:upper:]' '[:lower:]')

# Validate SHA-256 format: exactly 64 hexadecimal characters.
if [[ ! "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: Expected hash must be a 64-character SHA-256 hexadecimal value."
    exit 1
fi

ACTUAL_HASH=$(sha256sum -- "$FILE" | awk '{print $1}')

if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
    exit 1
fi
