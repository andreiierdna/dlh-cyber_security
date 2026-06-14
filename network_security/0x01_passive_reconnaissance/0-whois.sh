#!/bin/bash
whois "$1" | awk -F': ' '/^(Registrant|Admin|Tech)/ {f=$1; v=$2; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); if (f ~ /Street$/) v=v " "; if (f ~ /Phone Ext$|Fax Ext$/) f=f ":"; printf "%s%s,%s", (NR==1?"":"\n"), f, v} END {printf ""}' > "$1.csv"
