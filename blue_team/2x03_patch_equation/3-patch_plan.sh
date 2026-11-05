#!/bin/bash
# =============================================================================
# Name:    3-patch_plan.sh
# Purpose: Join the vulnerability inventory with the service dependency map into
#          a deterministic, prioritized patch_plan.json.
# Author:  Andrei
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 3
# Inputs: vulnerability_inventory.json (what is exposed) and
#         service_dependency_map.json (what a patch disturbs).
# The output is the execution order for 4-patch_execute.sh.
#
# Scoring (constants below, deliberately explicit so the policy is reviewable):
#   score = cvss_weight   * max_cvss
#         + kev_weight    * in_cisa_kev
#         + criticality_weight * max(criticality of affected services)
#         + exposure_weight * exposure_rank
#
#   exposure_rank: security pocket = 3 (attacker-reachable fix), updates = 2,
#                  backports = 1, unknown = 0
#   criticality:   critical = 4, high = 3, medium = 2, low = 1
#
# Buckets: emergency >= 7, urgent 4..7, scheduled < 4.
# A kernel or systemd update always requires a reboot; any other patch that
# disturbs a service requires (try-)restart of that service only.
#
# Idempotent: read-only, deterministic - identical inputs give an identical plan.
# =============================================================================

set -o pipefail
export LC_ALL=C

INV=${1:-vulnerability_inventory.json}
DEPS=${2:-service_dependency_map.json}
OUT=${3:-patch_plan.json}

# --- Policy constants -----------------------------------------------------------
CVSS_WEIGHT=1.0
KEV_WEIGHT=2.0
CRITICALITY_WEIGHT=0.5
EXPOSURE_WEIGHT=0.3
EMERGENCY_THRESHOLD=7
URGENT_THRESHOLD=4

for f in "$INV" "$DEPS"; do
	[ -r "$f" ] || { echo "Error: $f not found - run the earlier tasks first" >&2; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

jq -n \
	--slurpfile inv "$INV" --slurpfile deps "$DEPS" \
	--arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--argjson cw "$CVSS_WEIGHT" --argjson kw "$KEV_WEIGHT" \
	--argjson crw "$CRITICALITY_WEIGHT" --argjson ew "$EXPOSURE_WEIGHT" \
	--argjson em "$EMERGENCY_THRESHOLD" --argjson ur "$URGENT_THRESHOLD" '
	def crit_rank: if . == "critical" then 4 elif . == "high" then 3
	               elif . == "medium" then 2 else 1 end;
	def exposure_rank: if . == "security" then 3 elif . == "updates" then 2
	                  elif . == "backports" then 1 else 0 end;
	def is_kernel: test("^linux-(image|generic|headers|modules)");
	def is_systemd: test("^systemd($|-)");

	($deps[0].services) as $services
	| [ $inv[0].packages[] as $p
	    | ([ $services[] | select((.linked_packages | index($p.package)) != null) | .service ]) as $affected
	    | ([ $services[] | select((.linked_packages | index($p.package)) != null) | .criticality ] | map(crit_rank) | max // 1) as $maxcrit
	    | (($p.max_cvss // 0) * $cw
	       + (if $p.in_cisa_kev then $kw else 0 end)
	       + ($maxcrit * $crw)
	       + (($p.source_pocket | exposure_rank) * $ew)) as $score
	    | {package: $p.package,
	       installed_version: $p.installed_version,
	       candidate_version: $p.candidate_version,
	       source_pocket: $p.source_pocket,
	       cves: $p.cves,
	       max_cvss: $p.max_cvss,
	       severity: $p.severity,
	       in_cisa_kev: $p.in_cisa_kev,
	       score: (((($score * 100) | round) / 100)),
	       bucket: (if $score >= $em then "emergency"
	                elif $score >= $ur then "urgent" else "scheduled" end),
	       affected_services: (if ($p.package | is_kernel) then ["(kernel-wide)"] else ($affected | unique) end),
	       requires_restart: (($affected | length) > 0),
	       requires_reboot: (($p.package | is_kernel) or ($p.package | is_systemd)),
	       rollback_target_version: $p.installed_version} ]
	| sort_by(-.score, .package)
	| to_entries
	| map(.value + {rank: (.key + 1)})
	| . as $plan
	| {generated_at: $ts, hostname: $host,
	   weights: {cvss: $cw, kev: $kw, criticality: $crw, exposure: $ew,
	             emergency_threshold: $em, urgent_threshold: $ur},
	   plan: $plan,
	   summary: {total: ($plan | length),
	             emergency: ([ $plan[] | select(.bucket == "emergency") ] | length),
	             urgent: ([ $plan[] | select(.bucket == "urgent") ] | length),
	             scheduled: ([ $plan[] | select(.bucket == "scheduled") ] | length),
	             reboot_required: ([ $plan[] | select(.requires_reboot) ] | length > 0),
	             kev_entries: ([ $plan[] | select(.in_cisa_kev) ] | length)}}
	' > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Emergency: $(jq '.summary.emergency' "$OUT")   Urgent: $(jq '.summary.urgent' "$OUT")   Scheduled: $(jq '.summary.scheduled' "$OUT")"
if [ "$(jq '.summary.reboot_required' "$OUT")" = true ]; then
	echo "Reboot required by plan: yes (kernel/systemd update present)"
else
	echo "Reboot required by plan: no"
fi
jq -r '.plan[] | "  #\(.rank) \(.package) \(.installed_version) -> \(.candidate_version)  score=\(.score) [\(.bucket)]" + (if (.affected_services | length) > 0 then "  services: \(.affected_services | join(","))" else "" end)' "$OUT"
echo "Report saved to: $OUT"
