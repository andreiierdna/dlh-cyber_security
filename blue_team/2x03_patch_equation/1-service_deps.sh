#!/bin/bash
# =============================================================================
# Name:    1-service_deps.sh
# Purpose: Build service_dependency_map.json - which package owns each active
#          service's executable, which library packages it links, how critical it
#          is, and whether a patch forces a restart.
# Author:  Andrei
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 1
# A libssl3 update does not touch libssl3 in isolation: it touches every process
# that has the library mapped. This map is what turns "patch libssl3" into
# "restart apache2, ssh and mysql afterwards".
#
# Input:  service_criticality.json  (optional; unlisted services default to low)
# Output: service_dependency_map.json
#
# Method per active service:
#   ExecStart path from systemctl show, else readlink /proc/<MainPID>/exe
#     (apache2 runs /usr/sbin/apachectl, a shell script - its real binary is the
#      MainPID exe, so both sources are needed)
#   package of the executable: dpkg -S
#   shared libraries: ldd (skipped for scripts / statically linked binaries)
#   package of each library: dpkg -S on the resolved path
#   restart_required_on_patch: true when the service links at least one library
#     package, because upgrading it replaces the mapped file
#
# Idempotent: read-only.
# =============================================================================

set -o pipefail
export LC_ALL=C

CRIT_FILE=${1:-service_criticality.json}
OUT=${2:-service_dependency_map.json}

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo '{"services":{}}' > "$TMP/crit.json"
if [ -r "$CRIT_FILE" ]; then
	jq -s '.[0] * .[1]' "$TMP/crit.json" "$CRIT_FILE" > "$TMP/crit2.json" 2>/dev/null \
		&& mv "$TMP/crit2.json" "$TMP/crit.json" \
		|| echo "[!] $CRIT_FILE is not valid JSON - all services default to low" >&2
else
	echo "[!] $CRIT_FILE not found - all services default to low" >&2
fi

# package_of <path>: owning package ("-" when unowned)
package_of() {
	local pkg
	pkg=$(dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1)
	[ -z "$pkg" ] && pkg="-"
	echo "$pkg"
}

# exec_of <unit>: executable path
exec_of() {
	local unit="$1" path pid
	path=$(systemctl show -p ExecStart --value "$unit" 2>/dev/null \
		| sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -1)
	# Scripts (apachectl) and wrapper shells: prefer the live process image
	pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
	if [ -n "$pid" ] && [ "$pid" != 0 ] && [ -e "/proc/$pid/exe" ]; then
		local live
		live=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
		if [ -z "$path" ] || { [ -n "$live" ] && ! file -b "$path" 2>/dev/null | grep -q ELF; }; then
			[ -n "$live" ] && path="$live"
		fi
	fi
	echo "$path"
}

: > "$TMP/rows.jsonl"
COUNT=0
while read -r unit; do
	[ -z "$unit" ] && continue
	exec_path=$(exec_of "$unit")
	[ -z "$exec_path" ] && continue

	owning=$(package_of "$exec_path")
	linked=""
	# Shared libraries (skip ldd noise: vdso, ld.so, missing entries)
	while read -r lib; do
		[ -z "$lib" ] && continue
		pkg=$(package_of "$lib")
		[ "$pkg" = "-" ] || linked="$linked $pkg"
	done < <(ldd "$exec_path" 2>/dev/null | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' | sort -u)

	linked=$(printf '%s\n' $linked | sort -u | paste -sd ' ' -)
	all=$(printf '%s\n' "$owning" $linked | tr ' ' '\n' | grep -v '^-$' | grep -v '^$' | sort -u)
	all_json=$(printf '%s\n' "$all" | jq -R . | jq -s .)
	n_linked=$(grep -c . <<< "$all" || true)
	restart=false
	[ "$n_linked" -gt 1 ] && restart=true
	crit=$(jq -r --arg u "$unit" '.services[$u] // "low"' "$TMP/crit.json")

	jq -n --arg service "$unit" --arg exec "$exec_path" --arg owning "$owning" \
		--argjson linked "$all_json" --arg crit "$crit" --argjson restart "$restart" \
		'{service: $service, exec_path: $exec, owning_package: $owning,
		  linked_packages: $linked, criticality: $crit,
		  restart_required_on_patch: $restart}' >> "$TMP/rows.jsonl"
	COUNT=$((COUNT + 1))
done < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" --argjson n "$COUNT" '
	{generated_at: $ts, hostname: $host,
	 summary: {active_services: $n,
	           critical: (map(select(.criticality == "critical")) | length),
	           high: (map(select(.criticality == "high")) | length),
	           restart_pressure: (map(select(.restart_required_on_patch)) | length)},
	 services: (sort_by(.criticality, .service))}' "$TMP/rows.jsonl" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Active services mapped: $COUNT"
jq -r '.summary | "Critical: \(.critical) | High: \(.high) | Restart-on-patch: \(.restart_pressure)"' "$OUT"
jq -r '.services[] | select(.criticality == "critical") | "  \(.service) -> \(.linked_packages | join(", "))"' "$OUT"
echo "Report saved to: $OUT"
