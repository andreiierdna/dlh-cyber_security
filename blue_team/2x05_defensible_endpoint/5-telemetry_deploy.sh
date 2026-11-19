#!/bin/bash
# =============================================================================
# Name:    5-telemetry_deploy.sh
# Purpose: Deploy/verify auditd coverage on hawthorne-app-01, run an authorized
#          test sequence, prove each action left a trace and export 30 minutes of
#          Linux telemetry in the Module 3 schema.
# Author:  Andrei
# =============================================================================
# Output: capstone/telemetry/linux_events.json, linux_coverage.json
# Exit: 0 every test action captured, 1 a miss, 2 environment error.
# =============================================================================
set -o pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
PRIOR2X02=${PRIOR_2X02:-$LAB/capstone/prior/2x02}
CAP=${CAPSTONE_DIR:-$ROOT/capstone}
TEL="$CAP/telemetry"
RULES=/etc/audit/rules.d/meddefense.rules

[ "$EUID" -eq 0 ] || { echo "Error: run as root (sudo $0)" >&2; exit 2; }
command -v auditctl ausearch jq >/dev/null 2>&1 || { echo "Error: audit tools and jq required" >&2; exit 2; }
mkdir -p "$TEL"

# --- 1. auditd deployed and rules loaded ---------------------------------------
echo "[*] Verifying auditd..."
systemctl is-active --quiet auditd || systemctl start auditd
if [ ! -s "$RULES" ]; then
	echo "Error: $RULES missing - run 3-linux_harden.sh first" >&2
	exit 2
fi
LOADED=$(auditctl -l | grep -c .)
echo "    auditd active, $LOADED rules loaded"

# The 2x00 rule set covers identity/sudoers/sshd but not process execution or
# cron persistence. The 2x02 refinement adds those; without it two of the six
# authorized test actions would be invisible.
if ! auditctl -l | grep -q process_exec; then
	echo "[*] Applying 2x02 rule refinement (process_exec, cron_persist, network_connect)..."
	if [ -x "$PRIOR2X02/5-auditd_refine.sh" ]; then
		"$PRIOR2X02/5-auditd_refine.sh" >/dev/null 2>&1 || { echo "Error: refinement failed" >&2; exit 2; }
	else
		echo "Error: $PRIOR2X02/5-auditd_refine.sh missing" >&2; exit 2
	fi
	echo "    rules loaded: $(auditctl -l | grep -c .)"
fi

# --- 2. controlled test sequence ------------------------------------------------
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
: > "$TMP/actions.jsonl"
FAIL=0; TOTAL=0

# captured <key> <start time> <label-marker>: count matching SYSCALL records
captured() {
	local key="$1" t="$2" marker="$3" out n
	out=$(ausearch --input-logs -m SYSCALL -k "$key" -ts "$(date +%x)" "$t" -i 2>/dev/null)
	n=$(grep -c '^----' <<< "$out" || true)
	if [ "$n" -gt 0 ] && { [ -z "$marker" ] || grep -q -- "$marker" <<< "$out"; }; then echo "$n"; else echo 0; fi
}

test_action() {
	# test_action <name> <audit key> <marker> <command>
	local name="$1" key="$2" marker="$3" cmd="$4" t n status
	sleep 1
	t=$(date +%T)
	bash -c "$cmd" >/dev/null 2>&1
	sleep 2
	n=$(captured "$key" "$t" "$marker")
	TOTAL=$((TOTAL + 1))
	if [ "$n" -gt 0 ]; then status=pass; else status=fail; FAIL=$((FAIL + 1)); fi
	printf '  %-34s key=%-14s %-8s [%s]\n' "$name" "$key" "$status" "$n events"
	jq -n --arg action "$name" --arg key "$key" --arg status "$status" --argjson hits "$n" \
		--arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{action: $action, audit_key: $key, status: $status, events: $hits, timestamp: $ts}' >> "$TMP/actions.jsonl"
}

echo "[*] Running authorized test sequence..."
test_action "create user" identity "meddefense-telemetry" \
	"useradd -M -s /usr/sbin/nologin meddefense-telemetry"
test_action "remove user" identity "meddefense-telemetry" \
	"userdel meddefense-telemetry 2>/dev/null || true"
test_action "service management" process_exec "systemctl" \
	"systemctl restart cron"
test_action "cron job scheduled" cron_persist "telemetry-test" \
	"echo '# meddefense telemetry test' > /etc/cron.d/telemetry-test"
test_action "cron job removed" cron_persist "telemetry-test" \
	"rm -f /etc/cron.d/telemetry-test"
test_action "authorized find as root" process_exec "/usr/bin/find" \
	"find /etc -maxdepth 1 -name 'host*' >/dev/null"

# safety net: never leave test artefacts behind
userdel meddefense-telemetry 2>/dev/null || true
rm -f /etc/cron.d/telemetry-test

# --- 3. export 30 minutes of telemetry -------------------------------------------
echo "[*] Exporting last 30 minutes of Linux telemetry..."
if [ -x "$PRIOR2X02/7-linux_export.sh" ]; then
	( cd "$TEL" && "$PRIOR2X02/7-linux_export.sh" 1 linux_events_raw.json >/dev/null 2>&1 ) || true
fi
SINCE=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
if [ -s "$TEL/linux_events_raw.json" ]; then
	jq --arg since "$SINCE" '
		if type == "object" and has("events") then
			.events |= map(select(.timestamp >= $since))
			| .counts = {total: (.events | length),
			             by_source: (.events | group_by(.source_type) | map({key: .[0].source_type, value: length}) | from_entries),
			             by_category: (.events | group_by(.event_category) | map({key: .[0].event_category, value: length}) | from_entries)}
		else . end' "$TEL/linux_events_raw.json" > "$TEL/linux_events.json"
	rm -f "$TEL/linux_events_raw.json"
else
	jq -n --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{platform: "linux", host: "hawthorne-app-01",
		exported_at: $ts, counts: {total: 0}, events: []}' > "$TEL/linux_events.json"
fi

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--argjson total "$TOTAL" --argjson fail "$FAIL" \
	--arg events "$TEL/linux_events.json" '
	{generated_at: $ts, hostname: $host, platform: "linux",
	 source: "auditd + syslog",
	 tests_total: $total, tests_passed: ($total - $fail), tests_failed: $fail,
	 verdict: (if $fail == 0 then "PASS" else "FAIL" end),
	 export_path: $events, export_events: ($total * 0 + 0),
	 actions: .}' "$TMP/actions.jsonl" > "$TEL/linux_coverage.json"

EVENTS=$(jq '.counts.total // (.events | length)' "$TEL/linux_events.json" 2>/dev/null || echo 0)
jq --argjson e "$EVENTS" '.export_events = $e' "$TEL/linux_coverage.json" > "$TEL/linux_coverage.tmp" \
	&& mv "$TEL/linux_coverage.tmp" "$TEL/linux_coverage.json"

echo "Coverage: $((TOTAL - FAIL))/$TOTAL actions captured; exported events: $EVENTS"
echo "Artifacts: $TEL/linux_events.json, $TEL/linux_coverage.json"
[ "$FAIL" -eq 0 ]
