#!/bin/bash
# Decode a WebSphere XOR obfuscated string given as the first argument.
#
# WebSphere obfuscates values by prefixing them with "{xor}" and then
# base64 encoding the result of XOR-ing each byte with the key 0x5F (95).
# This script reverses that process to recover the original plain text.

hash="$1"

# Strip the leading "{xor}" tag from the input, if present.
encoded="${hash#\{xor\}}"

# Base64 decode the remaining string and dump the raw byte values.
bytes=$(echo -n "$encoded" | base64 -d | od -An -tu1)

result=""

for byte in $bytes
do
	xor=$((byte ^ 95))
	octal=$(printf '%03o' "$xor")
	result="$result$(printf "\\$octal")"
done

printf '%s\n' "$result"
