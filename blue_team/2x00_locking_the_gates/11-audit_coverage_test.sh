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
on_exit() { cleanup; rm -f "$RESULTS"; }
on_signal() { exit 130; }
trap on_exit EXIT
trap on_signal INT TERM

# run_test <n> <name> <audit key> <command>
TOTAL=6
CAPTURED=0
MISSED=0
