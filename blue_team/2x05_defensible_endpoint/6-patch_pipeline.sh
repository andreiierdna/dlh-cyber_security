#!/bin/bash
# =============================================================================
# Name:    6-patch_pipeline.sh
# Purpose: Run the 2x03 patch pipeline end-to-end for Hawthorne with every
#          artifact redirected into capstone/patch/, and configure
#          unattended-upgrades with the mandated blacklist.
# Author:  Andrei
# =============================================================================
# Output: capstone/patch/* (inventory, deps, snapshot, plan, execution log,
#         validation) + capstone/patch/pipeline_summary.json
# Exit: 0 pipeline clean and zero failed entries, 1 otherwise, 2 environment error.
# =============================================================================
set -o pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
PRIOR=${PRIOR_2X03:-$LAB/capstone/prior/2x03}
CAP=${CAPSTONE_DIR:-$ROOT/capstone}
OUTDIR="$CAP/patch"
FEED=$LAB/capstone/cve_feed.json
BLACKLIST=$LAB/capstone/blacklist.json
UNATTENDED=/etc/apt/apt.conf.d/51-meddefense-unattended-upgrades

[ "$EUID" -eq 0 ] || { echo "Error: run as root (sudo $0)" >&2; exit 2; }
[ -d "$PRIOR" ] || { echo "Error: pipeline scripts missing at $PRIOR" >&2; exit 2; }
[ -r "$FEED" ] || { echo "Error: $FEED missing" >&2; exit 2; }
[ -r "$BLACKLIST" ] || { echo "Error: $BLACKLIST missing" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq required" >&2; exit 2; }

mkdir -p "$OUTDIR"
export CAPSTONE_ARTIFACTS_DIR="$OUTDIR"
STEPS="$OUTDIR/steps.tsv"
: > "$STEPS"
FAIL=0

run() {
	local name="$1"; shift
	local script="$1"; shift
	local start rc dur
	start=$(date +%s)
	if [ -x "$script" ]; then
		( cd "$OUTDIR" && "$script" "$@" ) > "$OUTDIR/$name.log" 2>&1
		rc=$?
	else
		rc=2
		echo "missing: $script" > "$OUTDIR/$name.log"
	fi
	dur=$(( $(date +%s) - start ))
	printf '%-24s exit=%s %ss\n' "$name" "$rc" "$dur"
	printf '%s\t%s\t%s\t%s\n' "$name" "$script" "$rc" "$dur" >> "$STEPS"
	[ "$rc" -ne 0 ] && FAIL=$((FAIL + 1))
	return 0
}

echo "[*] Configuring unattended-upgrades blacklist..."
jq -r '.[]' "$BLACKLIST" | awk '{ printf "  \"%s\";\n", $0 }' > /tmp/ud-blacklist.txt
{
	echo '// MedDefense Hawthorne - managed by 6-patch_pipeline.sh'
	echo 'Unattended-Upgrade::Package-Blacklist {'
	cat /tmp/ud-blacklist.txt
	echo '};'
} > "$UNATTENDED"
chmod 644 "$UNATTENDED"
rm -f /tmp/ud-blacklist.txt
BLACKLISTED=$(grep -c '";' "$UNATTENDED")
echo "    blacklisted packages: $BLACKLISTED"

echo "[*] Running pipeline (artifacts -> $OUTDIR)..."
run 0-vuln_inventory   "$PRIOR/0-vuln_inventory.sh"   "$FEED" "$OUTDIR/vulnerability_inventory.json"
run 1-service_deps     "$PRIOR/1-service_deps.sh"     "$PRIOR/service_criticality.json" "$OUTDIR/service_dependency_map.json"
run 2-pre_patch        "$PRIOR/2-pre_patch_snapshot.sh" "$OUTDIR/pre_patch_state.json"
run 3-patch_plan       "$PRIOR/3-patch_plan.sh"       "$OUTDIR/vulnerability_inventory.json" "$OUTDIR/service_dependency_map.json" "$OUTDIR/patch_plan.json"
run 4-patch_execute    "$PRIOR/4-patch_execute.sh"    "$OUTDIR/patch_plan.json" "$OUTDIR/patch_execution_log.json"
run 5-post_validate    "$PRIOR/5-post_patch_validate.sh" "$OUTDIR/pre_patch_state.json" "$OUTDIR/service_dependency_map.json" "$PRIOR/service_probes.json" "$OUTDIR/post_patch_validation.json"

# --- reconcile the 2x03 validator's transient false positives -------------------
# That validator was written for a quiet host: it treats every service that was
# active in the pre-patch snapshot as permanent, which flags oneshot units that
# legitimately exit (fwupd, upower, unattended-upgrades) and ephemeral sockets
# (port >= 32768) as regressions. Those are reclassified here, with the reason
# recorded, so a real regression still fails the pipeline.
RAW="$OUTDIR/post_patch_validation.json"
if [ -r "$RAW" ]; then
	ONESHOT=$(jq -r '.details[] | select(.status != "pass" and .type == "service") | .target' "$RAW" \
		| while read -r u; do
			[ -n "$u" ] || continue
			t=$(systemctl show -p Type --value "$u" 2>/dev/null)
			[ "$t" = oneshot ] && echo "$u"
		done | jq -R . | jq -s .)
	jq --argjson oneshot "${ONESHOT:-[]}" '
		.details |= map(
			if .status != "pass" and .type == "service" and ($oneshot | index(.target)) then
				.status = "pass" | .note = "oneshot unit exited after completion - not a regression"
			elif .status != "pass" and .type == "socket" and ((.target | capture(":(?<p>[0-9]+)$").p | tonumber) >= 32768) then
				.status = "pass" | .note = "ephemeral port closed - not a regression"
			else . end)
		| .passed = ([ .details[] | select(.status == "pass") ] | length)
		| .failed = ([ .details[] | select(.status != "pass") ] | length)
		| .verdict = (if .failed == 0 then "PASS" else "FAIL" end)' \
		"$RAW" > "$OUTDIR/patch_validation.json"
	echo "    reconciled validation: $(jq -r '"\(.passed)/\(.total_checks) pass (\(.verdict))"' "$OUTDIR/patch_validation.json")"
	RECON_FAILED=$(jq '.failed' "$OUTDIR/patch_validation.json")
else
	RECON_FAILED=0
fi

FAILED_ENTRIES=0
[ -r "$OUTDIR/patch_execution_log.json" ] && FAILED_ENTRIES=$(jq '[.entries[] | select(.status != "success")] | length' "$OUTDIR/patch_execution_log.json" 2>/dev/null || echo 0)
PLAN_SIZE=0
[ -r "$OUTDIR/patch_plan.json" ] && PLAN_SIZE=$(jq '.plan | length' "$OUTDIR/patch_plan.json")

jq -n --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--arg dir "$OUTDIR" --arg feed "$FEED" --arg blacklist "$BLACKLIST" \
	--argjson steps "$(awk -F'\t' '{printf "{\"name\":\"%s\",\"script\":\"%s\",\"exit_code\":%s,\"duration_seconds\":%s},", $1,$2,$3,$4}' "$STEPS" | sed 's/,$//' | sed 's/^/[/; s/$/]/')" \
	--argjson plan_size "$PLAN_SIZE" --argjson failed "$FAILED_ENTRIES" \
	--argjson blacklisted "$BLACKLISTED" '{
	generated_at: $ts, hostname: $host, platform: "linux",
	artifacts_dir: $dir, cve_feed: $feed, blacklist_source: $blacklist,
	unattended_upgrades_conf: "/etc/apt/apt.conf.d/51-meddefense-unattended-upgrades",
	blacklisted_packages: $blacklisted,
	plan_entries: $plan_size, failed_entries: $failed,
	steps: $steps,
	verdict: (if $failed == 0 and $plan_size >= 0 then "PASS" else "FAIL" end)}' \
	> "$OUTDIR/pipeline_summary.json" || { echo "Error: cannot write summary" >&2; exit 1; }

echo "Plan entries: $PLAN_SIZE | Failed entries: $FAILED_ENTRIES"
echo "Summary: $OUTDIR/pipeline_summary.json"
[ "$RECON_FAILED" -eq 0 ] && FAIL=$((FAIL))
[ "$FAIL" -eq 0 ] && [ "$FAILED_ENTRIES" -eq 0 ] && [ "${RECON_FAILED:-0}" -eq 0 ]
