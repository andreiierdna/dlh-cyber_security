#!/bin/bash

set -u

usage() {
    echo "Usage:"
    echo "  $0 sign <file> <private_key>"
    echo "  $0 verify <file> <signature_file> <public_key>"
    exit 1
}

# At least one argument is required for the mode.
if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"

case "$MODE" in

    sign)
        if [[ $# -ne 3 ]]; then
            usage
        fi

        FILE="$2"
        PRIVATE_KEY="$3"
        SIGNATURE="${FILE}.sig"

        if [[ ! -f "$FILE" ]]; then
            echo "ERROR: File not found: $FILE"
            exit 1
        fi

        if [[ ! -f "$PRIVATE_KEY" ]]; then
            echo "ERROR: Private key not found: $PRIVATE_KEY"
            exit 1
        fi

        if openssl dgst -sha256 \
            -sign "$PRIVATE_KEY" \
            -out "$SIGNATURE" \
            "$FILE"; then

            echo "SIGNATURE CREATED: $SIGNATURE"
            exit 0
        else
            echo "ERROR: Signing failed"
            exit 1
        fi
        ;;

    verify)
        if [[ $# -ne 4 ]]; then
            usage
        fi

        FILE="$2"
        SIGNATURE="$3"
        PUBLIC_KEY="$4"

        if [[ ! -f "$FILE" ]]; then
            echo "ERROR: File not found: $FILE"
            exit 1
        fi

        if [[ ! -f "$SIGNATURE" ]]; then
            echo "ERROR: Signature file not found: $SIGNATURE"
            exit 1
        fi

        if [[ ! -f "$PUBLIC_KEY" ]]; then
            echo "ERROR: Public key not found: $PUBLIC_KEY"
            exit 1
        fi

        if openssl dgst -sha256 \
            -verify "$PUBLIC_KEY" \
            -signature "$SIGNATURE" \
            "$FILE"; then

            echo "SIGNATURE VALID"
            exit 0
        else
            echo "SIGNATURE INVALID"
            exit 1
        fi
        ;;

    *)
        echo "ERROR: Mode must be 'sign' or 'verify'"
        usage
        ;;
esac
