#!/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 "$1"; john --show --format=raw-md5 "$1" | head -n -2 | cut -d: -f2 > 4-password.txt
