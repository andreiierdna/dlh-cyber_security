#!/bin/bash
# =============================================================================
# Name:    13-consolidated_export.sh
# Purpose: Merge the Windows and Linux telemetry exports with the attacker
#          ground truth into the SOC handoff package (telemetry_handoff/).
# Author:  MedDefense blue team (Holberton 2x02 - Task 13)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 13
# Module 3 starts with the SOC receiving this directory. Everything is JSON,
# timestamps are UTC ISO 8601 on both platforms, and every event carries the
# four common fields the analysts filter on: timestamp, hostname, source_type,
# event_category. The ground truth travels separately so the SOC can score
# their own detections against it.
#
# Inputs (current directory):
#   windows_events_export.json  (Task 3)   linux_events_export.json (Task 7)
#   windows_attack_log.json     (Task 9)   linux_attack_log.json    (Task 11)
# Output:
#   telemetry_handoff/windows_events.json
#   telemetry_handoff/linux_events.json
#   telemetry_handoff/attack_ground_truth.json
# =============================================================================

set -o pipefail
export LC_ALL=C

WIN_EVENTS=${1:-windows_events_export.json}
LIN_EVENTS=${2:-linux_events_export.json}
WIN_TRUTH=${3:-windows_attack_log.json}
LIN_TRUTH=${4:-linux_attack_log.json}
OUTDIR=${5:-telemetry_handoff}

command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

missing=0
for f in "$WIN_EVENTS" "$LIN_EVENTS" "$WIN_TRUTH" "$LIN_TRUTH"; do
	if [ ! -r "$f" ]; then
		echo "Error: missing $f" >&2
		missing=$((missing + 1))
	fi
done
if [ "$missing" -gt 0 ]; then
	echo "  $WIN_EVENTS <- Task 3 (Windows telemetry normalizer)" >&2
	echo "  $WIN_TRUTH  <- Task 9 (Windows attacker simulation)" >&2
	echo "  $LIN_EVENTS <- Task 7 (7-linux_export.sh)" >&2
	echo "  $LIN_TRUTH  <- Task 11 (11-linux_attack_sim.sh)" >&2
	echo "Error: cannot build the handoff package until all four exist" >&2
	exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Both exports may be a bare array or an object with an "events" array
jq 'if type == "array" then . elif has("events") then .events else error("unknown export shape") end' \
	"$WIN_EVENTS" > "$TMP/win.json" || exit 1
jq 'if type == "array" then . elif has("events") then .events else error("unknown export shape") end' \
	"$LIN_EVENTS" > "$TMP/lin.json" || exit 1

WIN_N=$(jq 'length' "$TMP/win.json")
LIN_N=$(jq 'length' "$TMP/lin.json")
echo "[*] Loading Windows events ($WIN_N)..."
echo "[*] Loading Linux events ($LIN_N)..."

# --- Normalize timestamps ------------------------------------------------------
# Windows exports use whatever the event log produced (local time, 7-digit
# fractions, or epoch). Convert every distinct value once with date(1); values
# already in UTC ISO 8601 are left untouched.
normalize_ts() {
	local ts="$1" frac
	case "$ts" in
		[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z)
			echo "$ts" ;;
		*)
			# trim over-long fractional seconds (Windows: 7 digits, date(1) takes 6)
			frac=$(sed -E 's/.*T[0-9]{2}:[0-9]{2}:[0-9]{2}\.([0-9]+).*/\1/' <<< "$ts")
			if [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] && [ "${#frac}" -gt 6 ]; then
				ts=$(sed -E "s/(\.[0-9]{6})[0-9]+/\1/" <<< "$ts")
			fi
			date -u -d "$ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$ts"
			;;
	esac
}

echo "[*] Normalizing timestamps to UTC..."
{
	jq -r '.[].timestamp // empty' "$TMP/win.json"
	jq -r '.[].timestamp // empty' "$TMP/lin.json"
} | sort -u > "$TMP/ts_list.txt"

: > "$TMP/ts_map.tsv"
while IFS= read -r ts; do
	[ -z "$ts" ] && continue
	printf '%s\t%s\n' "$ts" "$(normalize_ts "$ts")" >> "$TMP/ts_map.tsv"
done < "$TMP/ts_list.txt"

# map file -> JSON object {"old": "new"}
jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}' \
	"$TMP/ts_map.tsv" > "$TMP/ts_map.json"

# apply <file> <out>: replace timestamps and sort chronologically
apply_map() {
	jq --slurpfile m "$TMP/ts_map.json" '
		map(.timestamp = ($m[0][.timestamp] // .timestamp))
		| sort_by(.timestamp)' "$1" > "$2"
}
apply_map "$TMP/win.json" "$TMP/win_norm.json"
apply_map "$TMP/lin.json" "$TMP/lin_norm.json"

WIN_CHANGED=$(jq --slurpfile m "$TMP/ts_map.json" '[.[] | select(.timestamp != ($m[0][.timestamp] // .timestamp))] | length' "$TMP/win.json")
LIN_CHANGED=$(jq --slurpfile m "$TMP/ts_map.json" '[.[] | select(.timestamp != ($m[0][.timestamp] // .timestamp))] | length' "$TMP/lin.json")
if [ "$WIN_CHANGED" -eq 0 ] && [ "$LIN_CHANGED" -eq 0 ]; then
	echo "    Windows: $WIN_CHANGED events normalized, Linux: $LIN_CHANGED events normalized"
else
	echo "    Windows: $WIN_CHANGED events normalized"
	echo "    Linux: $LIN_CHANGED events normalized"
fi

# --- Field consistency -------------------------------------------------------------
REQUIRED='["timestamp","hostname","source_type","event_category"]'
echo "[*] Verifying field consistency..."
BAD=$(jq --argjson req "$REQUIRED" '
	[.[] | select(
		(. as $e | ([ $req[] | . as $k | (($e | has($k)) and ($e[$k] != null) and ($e[$k] != "")) ] | all)) | not)] | length' \
	"$TMP/win_norm.json")
BAD_L=$(jq --argjson req "$REQUIRED" '
	[.[] | select(
		(. as $e | ([ $req[] | . as $k | (($e | has($k)) and ($e[$k] != null) and ($e[$k] != "")) ] | all)) | not)] | length' \
	"$TMP/lin_norm.json")
if [ "$BAD" -eq 0 ] && [ "$BAD_L" -eq 0 ]; then
	printf '    Required fields present in all events    [OK]\n'
else
	printf '    %s event(s) missing a required field    [FAIL]\n' "$((BAD + BAD_L))" >&2
	jq -r --argjson req "$REQUIRED" '
		.[] | select((. as $e | ([ $req[] | . as $k | (($e | has($k)) and ($e[$k] != null) and ($e[$k] != "")) ] | all)) | not)
		| "    missing fields: \($req - (keys))"' "$TMP/win_norm.json" "$TMP/lin_norm.json" | head -5 >&2
	exit 1
fi

# --- Ground truth ---------------------------------------------------------------------
echo "[*] Combining ground truth..."
WIN_ACT=$(jq '.actions | length' "$WIN_TRUTH")
LIN_ACT=$(jq '.actions | length' "$LIN_TRUTH")
jq -n --slurpfile w "$WIN_TRUTH" --slurpfile l "$LIN_TRUTH" \
	--arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson nw "$WIN_ACT" --argjson nl "$LIN_ACT" '
	{
	  generated_at: $ts,
	  note: "Ground truth for scoring SOC detections. Timestamps are UTC ISO 8601.",
	  totals: {windows: $nw, linux: $nl, total: ($nw + $nl)},
	  actions: (
	    ([ $w[0].actions[] | . + {platform: "windows"} ]
	     + [ $l[0].actions[] | . + {platform: "linux"} ])
	    | sort_by(.platform, .action_number))
	}' > "$TMP/truth.json"

# --- Handoff directory ------------------------------------------------------------------
echo "[*] Building handoff directory..."
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
jq -c '.[]' "$TMP/win_norm.json" | jq -s '.' > "$OUTDIR/windows_events.json"
jq -c '.[]' "$TMP/lin_norm.json" | jq -s '.' > "$OUTDIR/linux_events.json"
cp "$TMP/truth.json" "$OUTDIR/attack_ground_truth.json"

size() { du -h "$1" | cut -f1; }
echo "$OUTDIR/"
printf '  %-26s (%s events, %s)\n' "windows_events.json" "$(jq length "$OUTDIR/windows_events.json")" "$(size "$OUTDIR/windows_events.json")"
printf '  %-26s (%s events, %s)\n' "linux_events.json" "$(jq length "$OUTDIR/linux_events.json")" "$(size "$OUTDIR/linux_events.json")"
printf '  %-26s (%s actions)\n' "attack_ground_truth.json" "$(jq '.actions | length' "$OUTDIR/attack_ground_truth.json")"
echo "Total: $((WIN_N + LIN_N)) events across 2 platforms"
