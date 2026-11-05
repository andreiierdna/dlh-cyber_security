#!/bin/bash
# =============================================================================
# Name:    5-post_patch_validate.sh
# Purpose: Prove the host is healthy after the patch run: services still active,
#          sockets still listening, critical services answering liveness probes.
# Author:  Andrei
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 5
# apt exiting 0 is not evidence. This script compares the live system against
# pre_patch_state.json and probes the critical services, then exits non-zero if
# anything regressed (so a CI/CD wrapper or cron job fails loudly).
#
# Checks:
#   service  - every service in the snapshot still active (not active = regression)
#   socket   - every socket in the snapshot still listening
#   probe    - every 'critical' service in service_dependency_map.json answers
#              the liveness command from service_probes.json
#
# Exit codes: 0 all passed, 1 at least one regression or failed probe.
# =============================================================================

set -o pipefail
export LC_ALL=C

PRE=${1:-pre_patch_state.json}
DEPS=${2:-service_dependency_map.json}
PROBES=${3:-service_probes.json}
OUT=${4:-post_patch_validation.json}
PROBE_TIMEOUT=15

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
for f in "$PRE" "$DEPS"; do
	[ -r "$f" ] || { echo "Error: $f not found - run tasks 1 and 2 first" >&2; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/details.jsonl"

# --- 1. Service state ---------------------------------------------------------
SVC_TOTAL=0
SVC_PASS=0
while read -r unit; do
	[ -z "$unit" ] && continue
	SVC_TOTAL=$((SVC_TOTAL + 1))
	now=$(systemctl show -p ActiveState --value "$unit" 2>/dev/null)
	sub=$(systemctl show -p SubState --value "$unit" 2>/dev/null)
	if [ "$now" = "active" ]; then
		status=pass
		SVC_PASS=$((SVC_PASS + 1))
	else
		status=regression
	fi
	jq -n --arg t service --arg target "$unit" --arg exp active \
		--arg act "${now:-unknown}" --arg sub "$sub" --arg st "$status" \
		'{type: $t, target: $target, expected: $exp, actual: $act, sub_state: $sub, status: $st}' \
		>> "$TMP/details.jsonl"
done < <(jq -r '.services_detail[].service' "$PRE")

# --- 2. Listening sockets ------------------------------------------------------
SOCK_TOTAL=0
SOCK_PASS=0
ss -tulnH 2>/dev/null | awk '{print $1"\t"$5}' > "$TMP/now.tsv"
while read -r proto ip port; do
	[ -z "$port" ] && continue
	SOCK_TOTAL=$((SOCK_TOTAL + 1))
	# Match on protocol and port; a rebind to another address is a change worth
	# flagging but does not drop service, so the address is compared too.
	if awk -v p="$proto" -v prt="$port" -v a="$ip" '
		{ n = $2; sub(/:[0-9]+$/, "", n); p2 = $2; sub(/.*:/, "", p2) }
		$1 == p && p2 == prt && n == a { found = 1 }
		END { exit(found ? 0 : 1) }' "$TMP/now.tsv"; then
		status=pass
		SOCK_PASS=$((SOCK_PASS + 1))
	else
		if awk -v p="$proto" -v prt="$port" '{ p2 = $2; sub(/.*:/, "", p2) } $1 == p && p2 == prt { found = 1 } END { exit(found ? 0 : 1) }' "$TMP/now.tsv"; then
			status=regression   # still listening, but on a different address
		else
			status=regression
		fi
	fi
	jq -n --arg t socket --arg target "$proto/$ip:$port" --arg exp listening \
		--arg act "$(awk -v p="$proto" -v prt="$port" '{ p2 = $2; sub(/.*:/, "", p2) } $1 == p && p2 == prt { print $2; exit }' "$TMP/now.tsv")" \
		--arg st "$status" \
		'{type: $t, target: $target, expected: $exp, actual: (if $act == "" then "not listening" else $act end), status: $st}' \
		>> "$TMP/details.jsonl"
done < <(jq -r '.listening[] | "\(.proto)\t\(.local_address)\t\(.port)"' "$PRE")

# --- 3. Critical liveness probes -------------------------------------------------
PROBE_TOTAL=0
PROBE_PASS=0
if [ -r "$PROBES" ]; then
	while read -r unit; do
		[ -z "$unit" ] && continue
		cmd=$(jq -r --arg u "$unit" '.probes[$u].command // empty' "$PROBES")
		[ -z "$cmd" ] && continue
		PROBE_TOTAL=$((PROBE_TOTAL + 1))
		if timeout "$PROBE_TIMEOUT" bash -c "$cmd" >/dev/null 2>&1; then
			status=pass
			PROBE_PASS=$((PROBE_PASS + 1))
		else
			status=probe_failed
		fi
		jq -n --arg t probe --arg target "$unit" --arg cmd "$cmd" --arg st "$status" \
			'{type: $t, target: $target, probe: $cmd, status: $st}' >> "$TMP/details.jsonl"
	done < <(jq -r '.services[] | select(.criticality == "critical") | .service' "$DEPS")
else
	echo "[!] $PROBES not found - skipping critical liveness probes" >&2
fi

# --- Report ------------------------------------------------------------------------
jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" '
	{generated_at: $ts, hostname: $host,
	 total_checks: length,
	 passed: ([ .[] | select(.status == "pass") ] | length),
	 failed: ([ .[] | select(.status != "pass") ] | length),
	 summary: {service_checks: ([ .[] | select(.type == "service") ] | length),
	           socket_checks: ([ .[] | select(.type == "socket") ] | length),
	           probe_checks: ([ .[] | select(.type == "probe") ] | length)},
	 verdict: (if ([ .[] | select(.status != "pass") ] | length) == 0 then "PASS" else "FAIL" end),
	 details: (sort_by(.type, .target))}' "$TMP/details.jsonl" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

PASSED=$(jq '.passed' "$OUT")
FAILED=$(jq '.failed' "$OUT")
printf 'Service state checks:     %d/%d   %s\n' "$SVC_PASS" "$SVC_TOTAL" "$([ "$SVC_PASS" -eq "$SVC_TOTAL" ] && echo PASS || echo FAIL)"
printf 'Listening socket checks:  %d/%d   %s\n' "$SOCK_PASS" "$SOCK_TOTAL" "$([ "$SOCK_PASS" -eq "$SOCK_TOTAL" ] && echo PASS || echo FAIL)"
printf 'Critical liveness probes: %d/%d   %s\n' "$PROBE_PASS" "$PROBE_TOTAL" "$([ "$PROBE_PASS" -eq "$PROBE_TOTAL" ] && echo PASS || echo FAIL)"
echo "VERDICT: $(jq -r '.verdict' "$OUT") ($PASSED/$((PASSED + FAILED)))"
jq -r '.details[] | select(.status != "pass") | "  \(.status): \(.target) (\(.actual // "-"))"' "$OUT"
echo "Report saved to: $OUT"
[ "$FAILED" -eq 0 ]
