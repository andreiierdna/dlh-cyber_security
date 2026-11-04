#!/bin/bash
# =============================================================================
# Name:    12-linux_detection_proof.sh
# Purpose: Correlate linux_attack_log.json (ground truth) with the telemetry
#          actually captured (auditd, auth.log, syslog) and produce the
#          detection matrix (linux_detection_matrix.json).
# Author:  MedDefense blue team (Holberton 2x02 - Task 12)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 12
# Ground truth says what the attacker did; this script proves what the sensors
# saw. Each action is searched in a +/-30s window around its recorded timestamp.
# Detail levels:
#   Full    - event captured with the fields needed to investigate it
#   Partial - event captured but a key field (path, command line) is missing
#   Missed  - no event in any source
#
# Usage: sudo ./12-linux_detection_proof.sh [linux_attack_log.json] [matrix.json]
# =============================================================================

set -o pipefail
export LC_ALL=C

GROUND=${1:-linux_attack_log.json}
OUT=${2:-linux_detection_matrix.json}
WINDOW=30          # seconds after the recorded timestamp
LOOKBACK=5         # seconds before it (clock/audit granulation)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0) - audit.log is root-only" >&2
	exit 1
fi
[ -r "$GROUND" ] || { echo "Error: $GROUND not found - run 11-linux_attack_sim.sh first" >&2; exit 1; }
for c in ausearch jq; do
	command -v "$c" >/dev/null 2>&1 || { echo "Error: $c not found" >&2; exit 1; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# line_epoch <log line>: epoch of a syslog/RFC3339 line (0 if unparsable)
line_epoch() {
	local line="$1" ts
	if [[ "$line" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+) ]]; then
		ts="${BASH_REMATCH[1]}"
		date -d "$ts" +%s 2>/dev/null || echo 0
	else
		ts=$(awk '{print $1" "$2" "$3}' <<< "$line")
		date -d "$ts $(date +%Y)" +%s 2>/dev/null || echo 0
	fi
}

# file_events <file> <extended regex> <start epoch> <end epoch>
# prints matching lines whose timestamp falls inside the window
file_events() {
	local file="$1" re="$2" s="$3" e="$4" line ep
	[ -r "$file" ] || return 0
	while IFS= read -r line; do
		ep=$(line_epoch "$line")
		[ "$ep" -ge "$s" ] && [ "$ep" -le "$e" ] && printf '%s\n' "$line"
	done < <(grep -Ei -- "$re" "$file" 2>/dev/null)
}

# Source definitions per action number
audit_key_for() {
	case "$1" in
		1) echo identity ;;
		2) echo sudoers ;;
		3) echo process_exec ;;
		4) echo network_connect ;;
		5) echo cron_persist ;;
		6) echo identity ;;
	esac
}
audit_filter_for() {
	case "$1" in
		1) echo 'name=/etc/(passwd|shadow|group)' ;;
		2) echo 'name=/etc/sudoers\.d' ;;
		3) echo 'suspicious_bin' ;;
		4) echo 'syscall=(socket|connect)' ;;
		5) echo 'name=/etc/(cron\.d|crontab)|/var/spool/cron' ;;
		6) echo 'name=/etc/shadow' ;;
	esac
}
auth_pattern_for() {
	case "$1" in
		1) echo 'useradd' ;;
		2) echo 'sudoers' ;;
		*) echo '' ;;
	esac
}
syslog_pattern_for() {
	case "$1" in
		1) echo 'useradd|new user' ;;
		5) echo 'cron' ;;
		*) echo '' ;;
	esac
}

ACTION_COUNT=$(jq '.actions | length' "$GROUND")
echo "[*] Loading ground truth ($ACTION_COUNT actions)..."
echo "[*] Searching telemetry..."

printf '%-33s %-14s %-16s %-9s %s\n' "Action" "Source" "Key" "Detail" "Status"
printf '%-33s %-14s %-16s %-9s %s\n' "------" "------" "---" "------" "------"

TMP_JSN="$TMP/TMP_JSN.jsonl"
: > "$TMP_JSN"
CAPTURED=0
MULTI=0

for i in $(seq 0 $((ACTION_COUNT - 1))); do
	num=$(jq -r ".actions[$i].action_number" "$GROUND")
	name=$(jq -r ".actions[$i].action" "$GROUND")
	ts=$(jq -r ".actions[$i].timestamp" "$GROUND")
	key=$(audit_key_for "$num")
	afilter=$(audit_filter_for "$num")
	apat=$(auth_pattern_for "$num")
	spat=$(syslog_pattern_for "$num")

	s_epoch=$(( $(date -d "$ts" +%s) - LOOKBACK ))
	e_epoch=$(( $(date -d "$ts" +%s) + WINDOW ))
	s_d=$(date -d "@$s_epoch" +%x); s_t=$(date -d "@$s_epoch" +%T)
	e_d=$(date -d "@$e_epoch" +%x); e_t=$(date -d "@$e_epoch" +%T)

	DETECTIONS="$TMP/dets.jsonl"
	: > "$DETECTIONS"
	ACT_CAPTURED=0
	ACT_SOURCES=0
	FIRST=1

	# --- auditd -----------------------------------------------------------------
	AUD=$(ausearch --input-logs -k "$key" -ts "$s_d" "$s_t" -te "$e_d" "$e_t" -i 2>/dev/null)
	COUNT=$(grep -c '^----' <<< "$AUD" || true)
	if [ "$COUNT" -gt 0 ]; then
		if grep -Eq -- "$afilter" <<< "$AUD"; then detail="Full"; else detail="Partial"; fi
		fields=$(grep -oE 'name=[^ ]+' <<< "$AUD" | head -1 | sed 's/^name=//')
		[ -z "$fields" ] && fields="key=$key"
		[ "$FIRST" -eq 1 ] && printf '%-33s %-14s %-16s %-9s %s\n' "$name" "auditd" "$key" "$detail" "[CAPTURED]" || \
			printf '%-33s %-14s %-16s %-9s %s\n' "" "auditd" "$key" "$detail" "[CAPTURED]"
		FIRST=0
		ACT_CAPTURED=1
		ACT_SOURCES=$((ACT_SOURCES + 1))
		jq -n --arg src auditd --arg key "$key" --arg detail "$detail" --argjson count "$COUNT" --arg fields "$fields" \
			'{source: $src, audit_key: $key, event_count: $count, detail: $detail, key_fields: $fields}' >> "$DETECTIONS"
	fi

	# --- auth.log ------------------------------------------------------------------
	if [ -n "$apat" ]; then
		AUTH=$(file_events /var/log/auth.log "$apat" "$s_epoch" "$e_epoch")
		if [ -n "$AUTH" ]; then
			detail="Full"
			grep -q 'name=' <<< "$AUTH" || detail="Partial"
			[ "$FIRST" -eq 1 ] && printf '%-33s %-14s %-16s %-9s %s\n' "$name" "auth.log" "-" "$detail" "[CAPTURED]" || \
				printf '%-33s %-14s %-16s %-9s %s\n' "" "auth.log" "-" "$detail" "[CAPTURED]"
			FIRST=0
			ACT_CAPTURED=1
			ACT_SOURCES=$((ACT_SOURCES + 1))
			jq -n --arg src auth.log --arg detail "$detail" --arg msg "$(head -1 <<< "$AUTH" | cut -c1-160)" \
				'{source: $src, audit_key: null, event_count: 1, detail: $detail, excerpt: $msg}' >> "$DETECTIONS"
		fi
	fi

	# --- syslog -----------------------------------------------------------------------
	if [ -n "$spat" ]; then
		SYS=$(file_events /var/log/syslog "$spat" "$s_epoch" "$e_epoch")
		if [ -n "$SYS" ]; then
			[ "$FIRST" -eq 1 ] && printf '%-33s %-14s %-16s %-9s %s\n' "$name" "syslog" "-" "Partial" "[CAPTURED]" || \
				printf '%-33s %-14s %-16s %-9s %s\n' "" "syslog" "-" "Partial" "[CAPTURED]"
			FIRST=0
			ACT_CAPTURED=1
			ACT_SOURCES=$((ACT_SOURCES + 1))
			jq -n --arg src syslog --arg detail "Partial" --arg msg "$(head -1 <<< "$SYS" | cut -c1-160)" \
				'{source: $src, audit_key: null, event_count: 1, detail: $detail, excerpt: $msg}' >> "$DETECTIONS"
		fi
	fi

	if [ "$ACT_CAPTURED" -eq 0 ]; then
		printf '%-33s %-14s %-16s %-9s %s\n' "$name" "-" "-" "-" "[MISSED]"
		jq -n '{source: null, audit_key: null, event_count: 0, detail: "Missed", key_fields: null}' >> "$DETECTIONS"
		ACT_CAPTURED=1   # counted below as missed, not captured
		MISSED_FLAG=1
	else
		CAPTURED=$((CAPTURED + 1))
		MISSED_FLAG=0
		[ "$ACT_SOURCES" -gt 1 ] && MULTI=$((MULTI + 1))
	fi

	jq -n --argjson n "$num" --arg name "$name" --arg ts "$ts" --arg key "$key" \
		--argjson dets "$(jq -s . "$DETECTIONS")" --argjson sources "$ACT_SOURCES" --argjson missed "$MISSED_FLAG" \
		'{action_number: $n, action: $name, timestamp: $ts, expected_audit_key: $key,
		  sources_captured: $sources, status: (if $missed == 1 then "MISSED" else "CAPTURED" end),
		  detections: $dets}' >> "$TMP_JSN"
done

MISSED=$((ACTION_COUNT - CAPTURED))
PCT=0
[ "$ACTION_COUNT" -gt 0 ] && PCT=$((CAPTURED * 100 / ACTION_COUNT))

jq -s --arg host "$(hostname)" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--argjson total "$ACTION_COUNT" --argjson captured "$CAPTURED" --argjson missed "$MISSED" \
	--argjson multi "$MULTI" --argjson pct "$PCT" --argjson window "$WINDOW" '
	{platform: "linux", host: $host, generated_at: $ts,
	 window_seconds: $window,
	 source_coverage: (["auditd", "auth.log", "syslog"]),
	 actions: .,
	 summary: {total_actions: $total, captured: $captured, missed: $missed,
	           coverage_percent: $pct, multi_source: $multi}}' "$TMP_JSN" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Actions: $ACTION_COUNT | Captured: $CAPTURED/$ACTION_COUNT ($PCT%) | Multi-source: $MULTI"
echo "Report saved to: $OUT"
[ "$MISSED" -eq 0 ]
