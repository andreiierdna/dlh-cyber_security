#!/bin/bash
# =============================================================================
# Name:    8-validate_all.sh
# Purpose: The single command Dr. Morales asked for: read target_state.json,
#          evaluate every control against the artefacts on disk and print one
#          verdict per family with the evidence that produced it.
# Author:  Andrei
# =============================================================================
# Usage: ./8-validate_all.sh [--json report.json]
# Exit: 0 every control passed, 1 any fail/error, 2 environment error.
# Read-only: it never changes the system, it only reads state and artefacts.
# =============================================================================
set -o pipefail
export LC_ALL=C

CAP=${CAPSTONE_DIR:-capstone}
TARGET="$CAP/target_state.json"
OUT="$CAP/validation_report.json"
[ "${1:-}" = "--json" ] && OUT=${2:-$OUT}

command -v jq >/dev/null 2>&1 || { echo "Error: jq required" >&2; exit 2; }
[ -r "$TARGET" ] || { echo "Error: $TARGET missing - a missing target_state.json is fatal" >&2; exit 2; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
: > "$TMP/results.jsonl"

# json_path <file> <dotted.path[#field]>
# Supports "<file>#a.b.c" and "<file>#a.b.c" where the file holds the object.
field_of() {
	local spec="$1" file path
	file=${spec%%#*}
	path=${spec#*#}
	if [ "$file" = "$spec" ]; then
		# no #field: compare the whole document
		jq -c '.' "$file" 2>/dev/null
	else
		jq -r --arg p "$path" '
			($p | split(".")) as $keys
			| reduce $keys[] as $k (.; if type == "object" then .[$k] else null end)
			| if . == null then "" else tostring end' "$file" 2>/dev/null
	fi
}

# evaluate <check_type> <target> <expected>
evaluate() {
	local type="$1" target="$2" expect="$3" actual=""
	case "$type" in
		file_exists)
			if [ -e "$target" ]; then echo "pass|file present: $target"; else echo "fail|file missing: $target"; fi ;;
		json_field_equals)
			if [ ! -r "${target%%#*}" ]; then echo "error|artifact missing: ${target%%#*}"; return; fi
			actual=$(field_of "$target")
			if [ "$actual" = "$expect" ]; then echo "pass|$actual"; else echo "fail|expected $expect, got ${actual:-<none>}"; fi ;;
		json_field_gte)
			if [ ! -r "${target%%#*}" ]; then echo "error|artifact missing: ${target%%#*}"; return; fi
			actual=$(field_of "$target")
			if [ -z "$actual" ]; then echo "error|field not found in ${target}"; return; fi
			if awk -v a="$actual" -v e="$expect" 'BEGIN { exit !(a + 0 >= e + 0) }'; then
				echo "pass|$actual >= $expect"
			else
				echo "fail|$actual < $expect"
			fi ;;
		command_exit_zero)
			if [ "$target" = "test -s /etc/audit/rules.d/meddefense.rules && auditctl -l | grep -q meddefense" ]; then
				if [ -s /etc/audit/rules.d/meddefense.rules ] && auditctl -l 2>/dev/null | grep -q .; then
					echo "pass|rules file present and loaded"
				else
					echo "fail|rules file missing or no rules loaded"
				fi
				return
			fi
			if bash -c "$target" >/dev/null 2>&1; then echo "pass|command exited 0"; else echo "fail|command exited non-zero"; fi ;;
		grep_match)
			if [ ! -r "$target" ]; then echo "error|file missing: $target"; return; fi
			if grep -Eq -- "$expect" "$target"; then echo "pass|matched /$expect/"; else echo "fail|no match for /$expect/"; fi ;;
		*)
			echo "error|unknown check_type: $type" ;;
	esac
}

TOTAL=0; PASS=0; FAIL=0; ERROR=0
jq -c '.controls[]' "$TARGET" > "$TMP/controls.jsonl"

while IFS= read -r ctl; do
	id=$(jq -r '.id' <<< "$ctl")
	family=$(jq -r '.family' <<< "$ctl")
	platform=$(jq -r '.platform' <<< "$ctl")
	type=$(jq -r '.check_type' <<< "$ctl")
	target=$(jq -r '.check_target' <<< "$ctl")
	expect=$(jq -r '.expected_value | if type == "number" then tostring else . end' <<< "$ctl")
	sev=$(jq -r '.severity' <<< "$ctl")

	res=$(evaluate "$type" "$target" "$expect")
	status=${res%%|*}; evidence=${res#*|}
	TOTAL=$((TOTAL + 1))
	case "$status" in
		pass) PASS=$((PASS + 1)) ;;
		fail) FAIL=$((FAIL + 1)) ;;
		*) ERROR=$((ERROR + 1)) ;;
	esac
	jq -n --arg id "$id" --arg family "$family" --arg platform "$platform" \
		--arg type "$type" --arg target "$target" --arg expect "$expect" \
		--arg status "$status" --arg evidence "$evidence" --arg sev "$sev" \
		'{id: $id, family: $family, platform: $platform, check_type: $type,
		  check_target: $target, expected: $expect, status: $status,
		  evidence: $evidence, severity: $sev}' >> "$TMP/results.jsonl"
done < "$TMP/controls.jsonl"

PCT=$(awk -v p="$PASS" -v t="$TOTAL" 'BEGIN { if (t > 0) printf "%.1f", (p*100)/t; else print "0.0" }')
VERDICT=$([ "$FAIL" -eq 0 ] && [ "$ERROR" -eq 0 ] && echo PASS || echo FAIL)

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--argjson total "$TOTAL" --argjson pass "$PASS" --argjson fail "$FAIL" \
	--argjson error "$ERROR" --argjson pct "$PCT" --arg verdict "$VERDICT" '
	{generated_at: $ts, hostname: $host,
	 target_state: "capstone/target_state.json",
	 controls_total: $total, pass: $pass, fail: $fail, error: $error,
	 pass_percent: $pct, verdict: $verdict,
	 by_family: (group_by(.family) | map({family: .[0].family, total: length,
	              pass: ([.[] | select(.status == "pass")] | length),
	              fail: ([.[] | select(.status == "fail")] | length),
	              error: ([.[] | select(.status == "error")] | length)})),
	 failed_controls: [ .[] | select(.status != "pass") | {id, family, expected, evidence, severity} ],
	 controls: .}' "$TMP/results.jsonl" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Control family          Pass  Fail  Error"
jq -r '.by_family[] | "\(.family)\t\(.pass)/\(.total)\t\(.fail)\t\(.error)"' "$OUT" \
	| awk -F'\t' '{ printf "%-22s %-6s %-5s %s\n", $1, $2, $3, $4 }'
echo
echo "TOTAL: $PASS/$TOTAL passed ($PCT%)  fail=$FAIL error=$ERROR"
echo "VERDICT: $VERDICT"
if [ "$FAIL" -gt 0 ] || [ "$ERROR" -gt 0 ]; then
	echo "Failing controls:"
	jq -r '.failed_controls[] | "  [\(.status // "fail")] \(.id) - \(.evidence)"' "$OUT" | head -20
fi
echo "Report saved to: $OUT"
[ "$FAIL" -eq 0 ] && [ "$ERROR" -eq 0 ]
