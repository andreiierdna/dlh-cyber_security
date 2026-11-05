#!/bin/bash
# =============================================================================
# Name:    4-patch_execute.sh
# Purpose: Execute patch_plan.json safely: advisory lock, per-package pre/post
#          state, service restarts, full execution log, resumable output.
# Author:  Andrei
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 4
# This is the step the project exists to make safe. Rules enforced here:
#   - only one instance at a time (advisory lock; exit 2 if held)
#   - every package is upgraded explicitly (--only-upgrade) - never a blanket
#     apt upgrade -y
#   - pre and post state are captured around each package, service restarts are
#     recorded, and the log is rewritten after every entry so an interrupted run
#     is still consistent and auditable
#   - a dpkg lock held by another process is waited out with exponential backoff
#     (up to 120s) instead of failing immediately
#
# Exit codes: 0 all succeeded, 1 at least one failed, 2 lock not acquired.
# Usage: sudo ./4-patch_execute.sh [patch_plan.json] [patch_execution_log.json]
# =============================================================================

set -o pipefail
export LC_ALL=C

PLAN=${1:-patch_plan.json}
OUT=${2:-patch_execution_log.json}
LOCK_FILE=/var/lock/meddefense-patch.lock
APT_TIMEOUT=900
DPKG_WAIT_MAX=120

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
[ -r "$PLAN" ] || { echo "Error: $PLAN not found - run 3-patch_plan.sh first" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { echo "Error: flock is required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/entries.jsonl"

export DEBIAN_FRONTEND=noninteractive

# --- Advisory lock ----------------------------------------------------------------
echo "[*] Acquiring lock $LOCK_FILE... "
exec 9> "$LOCK_FILE"
if ! flock -n 9; then
	echo "Error: another patch run holds $LOCK_FILE - refusing to run concurrently" >&2
	exit 2
fi
echo "    OK"
# fd 9 is closed automatically when the script exits (also on error/signal),
# which releases the lock - no stale-lock risk.

# --- Helpers -----------------------------------------------------------------------
installed_version() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null || echo "not-installed"; }

service_state() {
	# {"service": "...", "active_state": "...", "sub_state": "..."}
	local u="$1"
	jq -n --arg s "$u" \
		--arg a "$(systemctl show -p ActiveState --value "$u" 2>/dev/null)" \
		--arg b "$(systemctl show -p SubState --value "$u" 2>/dev/null)" \
		'{service: $s, active_state: $a, sub_state: $b}'
}

services_block() {
	# services_block '<json array of unit names>' -> JSON array of states
	jq -r '.[]' <<< "$1" 2>/dev/null | while read -r u; do
		[ -n "$u" ] && service_state "$u"
	done | jq -s .
}

# Wait for a dpkg lock held by someone else (exponential backoff, max 120s)
wait_for_dpkg() {
	local waited=0 delay=2
	while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock \
		>/dev/null 2>&1; do
		if [ "$waited" -ge "$DPKG_WAIT_MAX" ]; then
			return 1
		fi
		sleep "$delay"
		waited=$((waited + delay))
		delay=$((delay * 2))
		[ "$delay" -gt 30 ] && delay=30
	done
	return 0
}

write_log() {
	# write_log <started_at> <finished_at> - always leaves valid JSON behind
	jq -s --arg started "$1" --arg finished "$2" --arg host "$(hostname)" \
		--arg hash "$PLAN_HASH" '
		{started_at: $started, finished_at: $finished, hostname: $host,
		 plan_source_hash: $hash,
		 entries: .}' "$TMP/entries.jsonl" > "$OUT"
}

PLAN_HASH=$(sha256sum "$PLAN" | cut -d' ' -f1)
ENTRIES=$(jq '.plan | length' "$PLAN")
echo "[*] Loading plan: $PLAN ($ENTRIES entries)"

STARTED=$(date -Iseconds)
FAILED=0
OK=0
i=0
while [ "$i" -lt "$ENTRIES" ]; do
	entry=$(jq -c ".plan[$i]" "$PLAN")
	pkg=$(jq -r '.package' <<< "$entry")
	bucket=$(jq -r '.bucket' <<< "$entry")
	requires_restart=$(jq -r '.requires_restart' <<< "$entry")
	requires_reboot=$(jq -r '.requires_reboot' <<< "$entry")
	svcs=$(jq -c '.affected_services' <<< "$entry")
	i=$((i + 1))

	pre_version=$(installed_version "$pkg")
	pre_services=$(services_block "$svcs")
	start_epoch=$(date +%s)
	status="success"
	reason=""
	stdout_log=""
	stderr_log=""
	exit_code=0

	if ! wait_for_dpkg; then
		status="failed"
		reason="dpkg lock still held after ${DPKG_WAIT_MAX}s"
		exit_code=1
	else
		timeout "$APT_TIMEOUT" apt-get install --only-upgrade -y "$pkg" \
			> "$TMP/out" 2> "$TMP/err"
		exit_code=$?
		stdout_log=$(tail -20 "$TMP/out")
		stderr_log=$(tail -20 "$TMP/err")
		if [ "$exit_code" -ne 0 ]; then
			status="failed"
			if grep -qi "could not get lock" "$TMP/err"; then
				reason="dpkg lock contention"
			elif [ "$exit_code" -eq 124 ]; then
				reason="apt timed out after ${APT_TIMEOUT}s"
			else
				reason="apt-get exited $exit_code"
			fi
		fi
	fi

	duration=$(( $(date +%s) - start_epoch ))
	post_version=$(installed_version "$pkg")
	post_services=$(services_block "$svcs")

	# Service restart (never during a pending reboot: the reboot does it)
	restart_json="[]"
	if [ "$status" = success ] && [ "$requires_restart" = true ] && [ "$requires_reboot" != true ]; then
		: > "$TMP/restarts.jsonl"
		while read -r u; do
			[ -z "$u" ] && continue
			if systemctl try-restart "$u" >/dev/null 2>&1; then
				r="ok"
			else
				r="failed"
			fi
			jq -n --arg s "$u" --arg r "$r" \
				--arg a "$(systemctl show -p ActiveState --value "$u" 2>/dev/null)" \
				'{service: $s, restart: $r, active_state: $a}' >> "$TMP/restarts.jsonl"
			printf '      try-restart %-26s %s\n' "$u" "$([ "$r" = ok ] && echo OK || echo FAILED)"
		done < <(jq -r '.[]' <<< "$svcs")
		restart_json=$(jq -s . "$TMP/restarts.jsonl")
	fi

	printf '[%d/%d] %-24s %-12s apt-get ... %s (%ss)\n' "$i" "$ENTRIES" "$pkg" "$bucket" \
		"$([ "$status" = success ] && echo OK || echo FAILED)" "$duration"

	jq -n --arg pkg "$pkg" --arg bucket "$bucket" --arg status "$status" --arg reason "$reason" \
		--argjson exit_code "$exit_code" --argjson duration "$duration" \
		--arg pre_v "$pre_version" --arg post_v "$post_version" \
		--argjson pre_svc "$pre_services" --argjson post_svc "$post_services" \
		--argjson restarts "$restart_json" \
		--arg out "$stdout_log" --arg err "$stderr_log" \
		--argjson restart_req "$requires_restart" --argjson reboot_req "$requires_reboot" \
		'{package: $pkg, bucket: $bucket, status: $status, reason: (if $reason == "" then null else $reason end),
		  apt_exit_code: $exit_code, duration_seconds: $duration,
		  requires_restart: $restart_req, requires_reboot: $reboot_req,
		  pre: {installed_version: $pre_v, services: $pre_svc},
		  post: {installed_version: $post_v, services: $post_svc},
		  restarts: $restarts,
		  stdout_tail: $out, stderr_tail: $err}' >> "$TMP/entries.jsonl"

	if [ "$status" = success ]; then
		OK=$((OK + 1))
	else
		FAILED=$((FAILED + 1))
		# Failure stops the rollout: a broken dependency must not poison later
		# packages. Finalization below still runs and the log stays valid.
		break
	fi

	write_log "$STARTED" "$(date -Iseconds)"
done

FINISHED=$(date -Iseconds)
write_log "$STARTED" "$FINISHED" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Succeeded: $OK  Failed: $FAILED"
echo "Log saved to: $OUT"
[ "$FAILED" -eq 0 ]
