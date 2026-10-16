#!/bin/bash
#
# 11-audit_coverage_test.sh - Prove that the Task 10 audit rules capture the events MedDefense cares about.

export LC_ALL=C

OUT="${1:-audit_validation.json}"
TEST_WEB_FILE=/etc/apache2/.meddefense-audit-test.tmp
TEST_CRON_FILE=/etc/cron.d/meddefense-audit-test
ARTIFACTS=("$TEST_WEB_FILE" "$TEST_CRON_FILE")

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
for cmd in auditctl ausearch jq; do
	command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found (run 10-auditd_config.sh)" >&2; exit 1; }
done
if ! systemctl is-active --quiet auditd.service; then
	echo "Error: auditd is not running (run 10-auditd_config.sh)" >&2
	exit 1
fi

cleanup() {
	rm -f "${ARTIFACTS[@]}"
}
RESULTS=$(mktemp)
trap 'cleanup; rm -f "$RESULTS"' EXIT
trap 'exit 130' INT TERM

# run_test <n> <name> <audit key> <command>
TOTAL=6
CAPTURED=0
MISSED=0
run_test() {
	local n="$1" name="$2" key="$3" command="$4" start_d start_t ts events count excerpt status
	sleep 1   # one-second ausearch granularity: keep test windows separate
	start_d=$(date +%x)
	start_t=$(date +%T)
	ts=$(date -Iseconds)
	bash -c "$command" >/dev/null 2>&1
	sleep 2   # let auditd flush
	# --input-logs: read the log files even when stdin is not a terminal
	events=$(ausearch --input-logs -m SYSCALL -k "$key" -ts "$start_d" "$start_t" -i 2>/dev/null)
	count=$(grep -c '^----' <<< "$events")
	# Excerpt: the analyst-relevant fields of the first matching SYSCALL record
	excerpt=$(grep -m1 '^type=SYSCALL' <<< "$events" \
		| grep -oE '(msg=audit\([^)]*\)|syscall=[^ ]+|success=[^ ]+|exit=[^ ]+|auid=[^ ]+| uid=[^ ]+|comm=[^ ]+|exe=[^ ]+|key=[^ ]+)' \
		| sed 's/^ //' | paste -sd ' ')
	if [ "$count" -gt 0 ]; then
		status="CAPTURED"
		CAPTURED=$((CAPTURED + 1))
	else
		status="MISSED"
		MISSED=$((MISSED + 1))
	fi
	printf '[%d/%d] %-34s [%s]\n' "$n" "$TOTAL" "$name" "$status"
	jq -n --argjson id "$n" --arg name "$name" --arg key "$key" --arg cmd "$command" \
		--arg ts "$ts" --arg status "$status" --argjson count "$count" --arg excerpt "$excerpt" \
		'{id: $id, test_name: $name, expected_key: $key, command: $cmd, timestamp: $ts,
		  capture_status: $status, event_count: $count, excerpt: $excerpt}' >> "$RESULTS"
}

echo "[*] Running audit telemetry coverage tests..."
run_test 1 "sudo execution" priv_esc \
	"sudo -n true"
run_test 2 "shadow access" identity \
	"runuser -u nobody -- /bin/sh -c ': >> /etc/shadow'"
run_test 3 "suspicious download tool" suspicious_download \
	"curl --version"
run_test 4 "sshd config read" sshd_config \
	"cat /etc/ssh/sshd_config > /dev/null; chmod \$(stat -c %a /etc/ssh/sshd_config) /etc/ssh/sshd_config"
run_test 5 "monitored test file write" meddefense_web \
	"echo 'MedDefense audit coverage test - safe to delete' > $TEST_WEB_FILE; rm -f $TEST_WEB_FILE"
run_test 6 "cron configuration check" cron_config \
	"echo '# MedDefense audit coverage test - comment only, never runs' > $TEST_CRON_FILE; rm -f $TEST_CRON_FILE"

echo "[*] Cleaning test artifacts..."
cleanup
LEFT=()
for f in "${ARTIFACTS[@]}"; do
	[ -e "$f" ] && LEFT+=("$f")
done
CLEAN_STATUS="clean"
[ "${#LEFT[@]}" -eq 0 ] || CLEAN_STATUS="artifacts remaining"

jq -s \
	--arg host "$(hostname)" --arg ts "$(date -Iseconds)" \
	--argjson total "$TOTAL" --argjson captured "$CAPTURED" --argjson missed "$MISSED" \
	--arg clean "$CLEAN_STATUS" \
	--argjson artifacts "$(printf '%s\n' "${ARTIFACTS[@]}" | jq -R . | jq -s .)" \
	--argjson left "$(printf '%s\n' "${LEFT[@]}" | jq -R 'select(length > 0)' | jq -s .)" \
	--argjson rules "$(auditctl -l | jq -R . | jq -s .)" \
	'{
		host: $host,
		timestamp: $ts,
		summary: {tests_executed: $total, captured: $captured, missed: $missed},
		tests: .,
		cleanup: {status: $clean, artifacts: $artifacts, remaining: $left},
		active_rules: $rules
	}' "$RESULTS" > "$OUT"

echo "Tests executed: $TOTAL"
echo "Captured: $CAPTURED"
echo "Missed: $MISSED"
echo "Report saved to: $OUT"
[ "$MISSED" -eq 0 ] && [ "$CLEAN_STATUS" = "clean" ]
