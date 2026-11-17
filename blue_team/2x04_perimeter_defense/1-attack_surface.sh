#!/bin/bash
# =============================================================================
# Name:    1-attack_surface.sh
# Purpose: Classify every listening socket in network_baseline.json: owning
#          package, systemd unit, function, criticality and exposure flags.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 1
# The baseline says which ports are open. This says which ones should not be.
# Inputs : network_baseline.json, MedDefense_Lab/capstone/service_catalog.json,
#          MedDefense_Lab/capstone/service_criticality.json
# Output : attack_surface.json
# Idempotent: read-only.
# =============================================================================
set -o pipefail
export LC_ALL=C

LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
BASE=${1:-network_baseline.json}
CATALOG=${2:-$LAB/capstone/service_catalog.json}
CRIT=${3:-$LAB/capstone/service_criticality.json}
OUT=${4:-attack_surface.json}

[ -r "$BASE" ] || { echo "Error: $BASE not found - run 0-network_baseline.sh first" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }
[ "$EUID" -eq 0 ] || echo "[!] not root: dpkg -S and systemd mapping may be incomplete" >&2

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# pid -> systemd unit map (one systemctl call, not one per socket)
systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
	| awk '{print $1}' | while read -r u; do
		pid=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
		[ -n "$pid" ] && [ "$pid" != 0 ] && printf '%s\t%s\n' "$pid" "$u"
	done > "$TMP/pid_unit.tsv"

# Catalog lookups are done with awk on TSV: a single jq "or" expression over
# three optional keys silently mis-binds and returns booleans.
jq -r '.[] | [(.service // ""), (.process // ""), (.package // ""), (.function // "")] | @tsv' \
	"$CATALOG" > "$TMP/catalog.tsv" 2>/dev/null || : > "$TMP/catalog.tsv"
jq -r '.[] | [(.service // ""), (.process // ""), (.criticality // "")] | @tsv' \
	"$CRIT" > "$TMP/crit.tsv" 2>/dev/null || : > "$TMP/crit.tsv"

# lookup <file> <service> <process> <package> <column> -> first non-empty match
lookup() {
	awk -F'\t' -v s="$2" -v p="$3" -v k="$4" -v col="$5" '
		(s != "" && $1 == s) { print $col; found = 1; exit }
		(p != "" && $2 == p) { print $col; found = 1; exit }
		(k != "" && $3 == k) { print $col; found = 1; exit }
	' "$1"
}

jq -c '.listening_sockets[]' "$BASE" > "$TMP/socks.jsonl"
: > "$TMP/rows.jsonl"

while IFS= read -r sock; do
	proto=$(jq -r '.proto' <<< "$sock")
	addr=$(jq -r '.bind_addr' <<< "$sock")
	port=$(jq -r '.port' <<< "$sock")
	proc=$(jq -r '.process // ""' <<< "$sock")
	pid=$(jq -r '.pid // 0' <<< "$sock")

	# owning package and executable from the live process
	pkg=""; exe=""
	if [ "$pid" -gt 0 ] && [ -e "/proc/$pid/exe" ]; then
		exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
		pkg=$(dpkg -S "$exe" 2>/dev/null | head -1 | cut -d: -f1)
	fi
	[ -z "$exe" ] && [ -n "$proc" ] && exe=$(command -v "$proc" 2>/dev/null)
	[ -z "$pkg" ] && [ -n "$exe" ] && pkg=$(dpkg -S "$exe" 2>/dev/null | head -1 | cut -d: -f1)
	[ -z "$pkg" ] && pkg="unknown"

	unit=$(awk -F'\t' -v p="$pid" '$1 == p {print $2; exit}' "$TMP/pid_unit.tsv")
	[ -z "$unit" ] && [ -n "$proc" ] && unit=$(awk -F'\t' -v p="$proc" '$2 != "" {n=split($2,a,"."); if (a[1]==p) {print $2; exit}}' "$TMP/pid_unit.tsv")

	# function from the catalog: unit, then process, then package
	function=$(lookup "$TMP/catalog.tsv" "$unit" "$proc" "$pkg" 4)
	[ -z "$function" ] && function="unknown"

	crit=$(lookup "$TMP/crit.tsv" "$unit" "$proc" "" 3)
	[ -z "$crit" ] && crit="low"

	# exposure rules
	flags="[]"
	add_flag() { flags=$(jq -c --arg f "$1" '. + [$f] | unique' <<< "$flags"); }
	case "$addr" in 0.0.0.0|::|"*") wildcard=yes ;; *) wildcard=no ;; esac
	case "$function" in
		telnet|ftp|rlogin|"nfs v2/v3") add_flag "insecure_protocol_${function// /_}" ;;
		snmp|snmpv1|snmpv2c) add_flag "insecure_protocol_snmpv2c" ;;
	esac
	if [ "$wildcard" = yes ]; then
		add_flag "bound_0.0.0.0"
		case "$function" in
			database) add_flag "database_exposed" ;;
			rpc) add_flag "rpc_exposed" ;;
		esac
	fi

	jq -n --arg proto "$proto" --arg addr "$addr" --argjson port "$port" \
		--arg proc "$proc" --argjson pid "$pid" --arg exe "$exe" --arg pkg "$pkg" \
		--arg unit "$unit" --arg fn "$function" --arg crit "$crit" --argjson flags "$flags" \
		'{proto: $proto, port: $port, bind_addr: $addr, process: $proc, pid: $pid,
		  exec_path: (if $exe == "" then null else $exe end),
		  package: $pkg, service: (if $unit == "" then null else $unit end),
		  function: $fn, criticality: $crit, exposure_flags: $flags}' >> "$TMP/rows.jsonl"
done < "$TMP/socks.jsonl"

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" '
	{generated_at: $ts, hostname: $host,
	 sockets: (sort_by(.port)),
	 summary: {total_sockets: length,
	   flagged: ([ .[] | select((.exposure_flags | length) > 0) ] | length),
	   by_function: (group_by(.function) | map({key: .[0].function, value: length}) | from_entries),
	   unknown_function: ([ .[] | select(.function == "unknown") ] | length),
	   by_severity: (group_by(.criticality) | map({key: .[0].criticality, value: length}) | from_entries),
	   by_flag: ([ .[].exposure_flags[] ] | group_by(.) | map({key: .[0], value: length}) | from_entries)}}' \
	"$TMP/rows.jsonl" > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

TOTAL=$(jq '.summary.total_sockets' "$OUT")
echo "Listening sockets: $TOTAL"
jq -r '.sockets[] | "  \(.proto)/\(.port) \(.bind_addr) \(.process // "-") [\(.function)/\(.criticality)] \(if (.exposure_flags|length)>0 then "FLAGS: \(.exposure_flags|join(","))" else "" end)"' "$OUT"
echo "Flagged: $(jq '.summary.flagged' "$OUT")   Unknown function: $(jq '.summary.unknown_function' "$OUT")"
echo "Report saved to: $OUT"
