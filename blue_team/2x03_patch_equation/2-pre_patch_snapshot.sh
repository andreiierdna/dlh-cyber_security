#!/bin/bash
# =============================================================================
# Name:    2-pre_patch_snapshot.sh
# Purpose: Capture pre_patch_state.json - the exact before-state every later
#          validation and rollback step compares against.
# Author:  Andrei
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 2
# An apt command that exits 0 proves nothing. Proof requires an exact baseline:
# package versions, service states, listening sockets, conffile hashes and the
# kernel, captured before the first package is touched.
#
# Schema (stable - tasks 3/4/5/9 read it):
#   timestamp, hostname, kernel, packages (count), services (count),
#   package_versions {pkg: version}, services_detail [...], listening [...],
#   conffile_hashes {path: sha256}, reboot_required
#
# Idempotent: read-only.
# =============================================================================

set -o pipefail
export LC_ALL=C

OUT=${1:-pre_patch_state.json}

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# 1. Packages -------------------------------------------------------------------
dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' 2>/dev/null \
	| awk -F'\t' '$3 ~ /install ok installed/ { print $1"\t"$2 }' > "$TMP/packages.tsv"
PKG_N=$(grep -c . "$TMP/packages.tsv" || true)
jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}' \
	"$TMP/packages.tsv" > "$TMP/package_versions.json"

# 2. Services -------------------------------------------------------------------
# ActiveState/SubState/MainPID for every active service unit
systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
	| awk '{print $1}' > "$TMP/units.txt"
: > "$TMP/services.jsonl"
while read -r unit; do
	[ -z "$unit" ] && continue
	# systemctl show prints one property per line
	state=$(systemctl show -p ActiveState --value "$unit" 2>/dev/null)
	sub=$(systemctl show -p SubState --value "$unit" 2>/dev/null)
	pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
	jq -n --arg s "$unit" --arg a "$state" --arg sub "$sub" --argjson pid "${pid:-0}" \
		'{service: $s, active_state: $a, sub_state: $sub, main_pid: $pid}' >> "$TMP/services.jsonl"
done < "$TMP/units.txt"
# jq -n pretty-prints over several lines, so count values (not lines) and give
# --slurpfile a real path instead of inline JSON
jq -s . "$TMP/services.jsonl" > "$TMP/services.json"
SVC_N=$(jq 'length' "$TMP/services.json")

# 3. Listening sockets ------------------------------------------------------------
ss -tulnpH 2>/dev/null | awk '{
	proto = $1; local = $5; proc = ""
	if ($0 ~ /users:\(\(/) {
		proc = $0; sub(/.*users:\(\(/, "", proc); sub(/\).*/, "", proc); gsub(/"/, "", proc)
	}
	ip = local; sub(/:[0-9]+$/, "", ip); port = local; sub(/.*:/, "", port)
	print proto"\t"ip"\t"port"\t"proc
}' > "$TMP/sockets.tsv"
jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
	| {proto: .[0], local_address: .[1], port: (.[2] | tonumber), process: .[3]})' \
	"$TMP/sockets.tsv" > "$TMP/listening.json"

# 4. Conffile hashes ---------------------------------------------------------------
# dpkg records md5 sums of conffiles; we hash the live files with SHA-256 so
# drift is detectable with one algorithm. Missing files are recorded as null.
dpkg-query -W -f='${Conffiles}\n' 2>/dev/null \
	| awk 'NF >= 2 && $1 ~ /^\// { print $1 }' | sort -u > "$TMP/conffiles.txt"
: > "$TMP/hashes.tsv"
while read -r f; do
	[ -z "$f" ] && continue
	if [ -f "$f" ]; then
		printf '%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" >> "$TMP/hashes.tsv"
	else
		printf '%s\t%s\n' "$f" "MISSING" >> "$TMP/hashes.tsv"
	fi
done < "$TMP/conffiles.txt"
CONF_N=$(grep -c . "$TMP/hashes.tsv" || true)
jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}' \
	"$TMP/hashes.tsv" > "$TMP/hashes.json"

# 5. Kernel and reboot indicator ---------------------------------------------------
KERNEL=$(uname -r)
REBOOT=false
[ -f /var/run/reboot-required ] && REBOOT=true

jq -n --arg ts "$(date -Iseconds)" --arg host "$(hostname)" --arg kernel "$KERNEL" \
	--argjson pkgn "$PKG_N" --argjson svcn "$SVC_N" --argjson confn "$CONF_N" \
	--argjson reboot "$REBOOT" \
	--slurpfile pv "$TMP/package_versions.json" \
	--slurpfile svc "$TMP/services.json" \
	--slurpfile listen "$TMP/listening.json" \
	--slurpfile conf "$TMP/hashes.json" '
	{timestamp: $ts, hostname: $host, kernel: $kernel,
	 packages: $pkgn, services: $svcn,
	 package_versions: $pv[0],
	 services_detail: ($svc[0] | sort_by(.service)),
	 listening: $listen[0],
	 conffile_hashes: $conf[0],
	 conffile_count: $confn,
	 reboot_required: $reboot}' > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

SIZE=$(du -h "$OUT" | cut -f1)
echo "Snapshot: $OUT"
echo "Size: $SIZE"
echo "Kernel: $KERNEL"
echo "Reboot required: $REBOOT"
echo "Packages: $PKG_N | Services: $SVC_N | Sockets: $(jq 'length' "$TMP/listening.json") | Conffiles hashed: $CONF_N"
