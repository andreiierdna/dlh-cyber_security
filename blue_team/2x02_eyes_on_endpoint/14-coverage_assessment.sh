#!/bin/bash
# =============================================================================
# Name:    14-coverage_assessment.sh
# Purpose: Produce telemetry_coverage_assessment.json - the metadata file that
#          travels with the handoff package and tells the SOC what the dataset
#          can and cannot reveal.
# Author:  MedDefense blue team (Holberton 2x02 - Task 14)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 14
# Combines the handoff package, both detection matrices, the quality reports and
# the Sysmon coverage matrix into one assessment:
#   - what the SOC can detect   (covered ATT&CK techniques + responsible source)
#   - what is partially visible (captured without the fields needed to pivot)
#   - what is blind             (no telemetry at all) and how to close the gap
#
# Inputs (relative to the directory given, default "."):
#   telemetry_handoff/{windows_events,linux_events,attack_ground_truth}.json
#   windows_detection_matrix.json  linux_detection_matrix.json
#   windows_telemetry_quality.json linux_telemetry_quality.json   (optional*)
#   sysmon_coverage_matrix.json                                    (optional*)
# (*) Produced by the telemetry-quality tasks, which are not part of this lab
#     folder. When absent the assessment still runs: the score fields become
#     null, a warning is printed and confidence is derived from detection
#     coverage alone. The file is listed under known_gaps so the gap is visible.
#
# Usage: ./14-coverage_assessment.sh [dir]
# Output: telemetry_coverage_assessment.json
# =============================================================================

set -o pipefail
export LC_ALL=C

DIR=${1:-.}
HANDOFF="$DIR/telemetry_handoff"
OUT="$DIR/telemetry_coverage_assessment.json"

command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

REQUIRED=(
	"$HANDOFF/windows_events.json"
	"$HANDOFF/linux_events.json"
	"$HANDOFF/attack_ground_truth.json"
	"$DIR/windows_detection_matrix.json"
	"$DIR/linux_detection_matrix.json"
)
missing=0
for f in "${REQUIRED[@]}"; do
	[ -r "$f" ] || { echo "Error: missing $f" >&2; missing=$((missing + 1)); }
done
if [ "$missing" -gt 0 ]; then
	echo "Error: $missing required input(s) missing - run tasks 3, 7, 9, 10, 11, 12 and 13 first" >&2
	exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo '{}' > "$TMP/empty.json"

# optional_input <file> <name> -> echoes "path ok" (1 = file present)
optional_input() {
	if [ -r "$1" ]; then
		printf '%s 1\n' "$1"
	else
		echo "[!] $2 not found - quality fields will be null" >&2
		printf '%s 0\n' "$TMP/empty.json"
	fi
}
read -r WQ_F WQ_OK < <(optional_input "$DIR/windows_telemetry_quality.json" windows_telemetry_quality.json)
read -r LQ_F LQ_OK < <(optional_input "$DIR/linux_telemetry_quality.json" linux_telemetry_quality.json)
read -r SC_F SC_OK < <(optional_input "$DIR/sysmon_coverage_matrix.json" sysmon_coverage_matrix.json)

echo "[*] Loading telemetry handoff package..."
WIN_N=$(jq 'length' "$HANDOFF/windows_events.json")
LIN_N=$(jq 'length' "$HANDOFF/linux_events.json")
GT_N=$(jq '.actions | length' "$HANDOFF/attack_ground_truth.json")
echo "Windows events: $WIN_N"
echo "Linux events: $LIN_N"
echo "Ground truth actions: $GT_N"

# Recommendation per ATT&CK technique family, used to fill known_gaps
recommendation() {
	case "$1" in
		T1136*) echo "Enable identity-file auditing (auditd -w /etc/passwd,/etc/shadow; Windows 4720/4728) and retain it 90 days" ;;
		T1098*) echo "Audit group membership changes (Security 4728/4732) and correlate with the account-creation event" ;;
		T1548*) echo "Audit sudoers/sudoers.d writes and command execution (auditd -w /etc/sudoers.d; Sysmon EID 1 for sudo)" ;;
		T1059*) echo "Enable process-execution telemetry (auditd execve; Sysmon EID 1) and PowerShell script-block logging (4104)" ;;
		T1053*) echo "Watch cron and scheduled-task creation (auditd -w /etc/cron.d,/var/spool/cron; Security 4698)" ;;
		T1003*) echo "Audit reads of credential stores (auditd -F path=/etc/shadow -F perm=r; Sysmon 10 on lsass access)" ;;
		T1071*|T1105*) echo "Log socket/connect syscalls and proxy/DNS flows (auditd -k network_connect; Sysmon EID 3/22)" ;;
		T1547*) echo "Audit startup-folder file creation and Run-key writes (Sysmon EID 11 for the Startup path, EID 13 for Run keys)" ;;
		*) echo "Add a detection source for this technique and re-run the coverage test" ;;
	esac
}

echo "[*] Building assessment..."
jq -n \
	--slurpfile we "$HANDOFF/windows_events.json" \
	--slurpfile le "$HANDOFF/linux_events.json" \
	--slurpfile gt "$HANDOFF/attack_ground_truth.json" \
	--slurpfile wm "$DIR/windows_detection_matrix.json" \
	--slurpfile lm "$DIR/linux_detection_matrix.json" \
	--slurpfile wq "$WQ_F" --argjson wq_ok "$WQ_OK" \
	--slurpfile lq "$LQ_F" --argjson lq_ok "$LQ_OK" \
	--slurpfile sc "$SC_F" --argjson sc_ok "$SC_OK" '
	# ---- normalise both detection matrices into one row shape -----------------
	def win_rows:
		[ ($wm[0].rows // $wm[0].actions // $wm[0] // [])[]
		  | {platform: "windows",
		     action: (.Action // .action // .name // "unknown"),
		     detail: ((.Detail // .detail // .Status // .status // "Missed") | tostring
		              | if test("(?i)full") then "Full"
		                elif test("(?i)partial") then "Partial"
		                else "Missed" end),
		     sources: ([ (.Source // .source // "") | tostring ]
		               | map(select(length > 0 and . != "Missed")))} ];
	def lin_rows:
		[ ($lm[0].actions // $lm[0].rows // [])[]
		  | {platform: "linux",
		     action: (.action // .Action),
		     detail: (([.detections[]?.detail] | map(if . == "Full" then 3 elif . == "Partial" then 2 else 1 end) | max // 1)
		              | if . == 3 then "Full" elif . == 2 then "Partial" else "Missed" end),
		     sources: [ (.detections[]?.source // empty) ] | unique} ];
	def rows: (win_rows + lin_rows);

	def technique_of($a):
		(($gt[0].actions // [])[]
		 | select((.action // .description // .name) == $a.action)
		 | select((.platform // $a.platform) == $a.platform)
		 | (.mitre_technique // .technique // .attack_technique // "")) // "";
	# Both authoring styles: "T1059.004 - Unix Shell" and
	# "T1136.001 Create Account: Local Account"
	def tid:
		if test("T[0-9]{4}(\\.[0-9]{3})?")
		then capture("(?<t>T[0-9]{4}(\\.[0-9]{3})?)").t else "unknown" end;
	def tdesc: sub("^T[0-9]{4}(\\.[0-9]{3})?[ :-]*"; "");

	# A multi-source detection is several matrix rows for one action: merge them so
	# the action is counted once (total actions must equal the ground truth).
	(rows) as $r0
	| ([ $r0[] ] | group_by(.platform + "|" + .action)
	   | map({platform: .[0].platform, action: .[0].action,
	          detail: (map(.detail) | if any(. == "Full") then "Full"
	                  elif any(. == "Partial") then "Partial" else "Missed" end),
	          sources: ([ .[].sources[] ] | unique)})) as $r
	| [ $r[] | . + {technique: technique_of(.), tid: (technique_of(.) | tid)} ] as $rows_t
	| ([ $rows_t[] | select(.tid != "unknown") ] | group_by(.tid)
	   | map({
	       technique: .[0].tid,
	       description: (.[0].technique | tdesc),
	       best_detail: (map(.detail) | if any(. == "Full") then "Full"
	                     elif any(. == "Partial") then "Partial" else "Missed" end),
	       platforms: (map(.platform) | unique),
	       sources: ([ .[].sources[] ] | unique),
	       actions: ([ .[].action ] | unique)
	     })) as $tech
	| ([ $tech[] | select(.best_detail == "Full") ]) as $covered
	| ([ $tech[] | select(.best_detail == "Partial") ]) as $partial
	| ([ $tech[] | select(.best_detail == "Missed") ]) as $blind
	| ([ $we[0][] + {platform: "windows"} ] + [ $le[0][] + {platform: "linux"} ]) as $all
	| (if $wq_ok == 1 then ($wq[0].score // $wq[0].overall_score // $wq[0].quality_score // null) else null end) as $wscore
	| (if $lq_ok == 1 then ($lq[0].score // $lq[0].overall_score // $lq[0].quality_score // null) else null end) as $lscore
	| ($rows_t | length) as $total_actions
	| ([ $rows_t[] | select(.detail != "Missed") ] | length) as $captured
	| ($total_actions - $captured) as $missed_actions
	| ([ $rows_t[] | select((.sources | length) > 1) ] | length) as $multi
	| (($captured * 100) / ([$total_actions, 1] | max) | floor) as $pct
	| (if $missed_actions == 0 and $wq_ok == 1 and $lq_ok == 1 and ($wscore // 0) >= 90 and ($lscore // 0) >= 90 then "high"
	   elif $pct >= 90 and ($wq_ok == 0 or ($wscore // 0) >= 75) and ($lq_ok == 0 or ($lscore // 0) >= 75) then "acceptable"
	   else "low" end) as $confidence
	| ([ $tech[] | select(.best_detail != "Full")
	     | {description: (.description + " (" + (.actions | join(", ")) + ")"),
	        impacted_platform: (.platforms | join(", ")),
	        impacted_technique: .technique,
	        reason: (if .best_detail == "Missed" then "no telemetry source captured this action"
	                 else "captured without the fields needed to pivot (command line, path or user missing)" end),
	        recommended_instrumentation: "" } ]) as $tech_gaps
	| ([ $tech_gaps[]
	     | . + {impacted_platform: .impacted_platform} ]) as $gaps
	| {
	    generated_at: (now | todate),
	    platforms: ["windows", "linux"],
	    total_events: ($all | length),
	    events_by_platform: ($all | group_by(.platform) | map({key: .[0].platform, value: length}) | from_entries),
	    events_by_source_type: ($all | group_by(.source_type) | map({key: .[0].source_type, value: length}) | from_entries),
	    events_by_event_category: ($all | group_by(.event_category) | map({key: .[0].event_category, value: length}) | from_entries),
	    detection_summary: {
	      total_simulated_actions: $total_actions,
	      captured_actions: $captured,
	      missed_actions: $missed_actions,
	      multi_source_detections: $multi,
	      coverage_percent: $pct
	    },
	    attack_coverage: {
	      covered: ($covered | map({technique, description, platforms, sources})),
	      partially_covered: ($partial | map({technique, description, platforms, sources})),
	      blind: ($blind | map({technique, description, platforms})),
	      covered_technique_count: ($covered | length),
	      partial_technique_count: ($partial | length),
	      blind_technique_count: ($blind | length)
	    },
	    known_gaps: ($gaps + (if ($wq_ok == 0 or $lq_ok == 0 or $sc_ok == 0) then
	      [{description: "Telemetry quality inputs not provided",
	        impacted_platform: ((if $wq_ok == 0 then "windows" else "" end)
	                           + (if ($wq_ok == 0 and $lq_ok == 0) then ", " else "" end)
	                           + (if $lq_ok == 0 then "linux" else "" end)),
	        impacted_technique: "n/a",
	        reason: "windows_telemetry_quality.json / linux_telemetry_quality.json / sysmon_coverage_matrix.json are produced by the telemetry-quality tasks (not part of this lab folder)",
	        recommended_instrumentation: "Run the telemetry-quality tasks and re-run this assessment to obtain scored confidence"}]
	      else [] end)),
	    quality_summary: {
	      windows_score: $wscore,
	      linux_score: $lscore,
	      sysmon_coverage: (if $sc_ok == 1 then ($sc[0].coverage_percent // $sc[0].coverage // null) else null end),
	      final_handoff_confidence: $confidence
	    }
	  }
	' > "$TMP/assessment.json" || { echo "Error: cannot build assessment" >&2; exit 1; }

# Fill the recommendation table (kept in bash so the mapping stays readable)
jq --argjson map "$(jq -r '.known_gaps[].impacted_technique' "$TMP/assessment.json" | sort -u \
	| while IFS= read -r t; do printf '%s\t%s\n' "$t" "$(recommendation "$t")"; done \
	| jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}')" '
	.known_gaps |= map(.recommended_instrumentation = ($map[.impacted_technique] // "Add a detection source for this technique and re-run the coverage test"))' \
	"$TMP/assessment.json" > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Detection matrix: $(jq -r '.detection_summary.captured_actions' "$OUT")/$(jq -r '.detection_summary.total_simulated_actions' "$OUT") captured"
echo "ATT&CK covered: $(jq -r '.attack_coverage.covered_technique_count' "$OUT")"
echo "ATT&CK partial: $(jq -r '.attack_coverage.partial_technique_count' "$OUT")"
echo "ATT&CK blind: $(jq -r '.attack_coverage.blind_technique_count' "$OUT")"
echo "Windows quality: $(jq -r '.quality_summary.windows_score // "n/a"' "$OUT")"
echo "Linux quality: $(jq -r '.quality_summary.linux_score // "n/a"' "$OUT")"
echo "Confidence: $(jq -r '.quality_summary.final_handoff_confidence' "$OUT")"
echo "Report saved to: $OUT"
