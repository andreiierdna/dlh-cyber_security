#!/bin/bash
# =============================================================================
# Name:    10-rule_validation.sh
# Purpose: Prove each custom MedDefense rule fires against its labelled PCAP.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 10
# A rule that never fires is worse than no rule: it buys false confidence.
# Each rule is replayed against the capture built to exercise it with -S, so
# community rules cannot mask a broken custom rule.
# Exit: 0 all fired, 1 any missed.
# =============================================================================
set -o pipefail
export LC_ALL=C

LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
RULES=${1:-meddefense.rules}
YAML=${2:-suricata.yaml}
OUT=${3:-rule_validation.json}
LABELS=$LAB/PCAPs/labels

[ -r "$RULES" ] || { echo "Error: $RULES not found" >&2; exit 1; }
[ -r "$YAML" ] || { echo "Error: $YAML not found - run 8-suricata_setup.sh first" >&2; exit 1; }
command -v suricata jq >/dev/null || { echo "Error: suricata and jq are required" >&2; exit 1; }

RULES_ABS=$(readlink -f "$RULES")
RULE_COUNT=$(grep -cE '^(alert|drop|pass|reject)[[:space:]]' "$RULES_ABS")
echo "[*] Loading $(basename "$RULES")...          $RULE_COUNT rules"
echo "[*] Running validation against labeled PCAPs..."
echo

# sid|name|pcap
TESTS=(
	"9000001|MEDDEV to Internet|meddev_egress.pcap"
	"9000002|Guest to SMB|guest_smb.pcap"
	"9000003|Large Outbound From Server|large_outbound.pcap"
	"9000004|DNS Tunneling Long Label|dns_tunnel.pcap"
	"9000005|Clinical to Unauthorized DB|clinical_wrong_db.pcap"
	"9000006|Telnet to MEDDEV|telnet_meddev.pcap"
)

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
: > "$TMP/results.jsonl"
PASSED=0
FAILED=0

for t in "${TESTS[@]}"; do
	IFS='|' read -r sid name pcap <<< "$t"
	outdir=$TMP/run-$sid
	mkdir -p "$outdir"
	printf 'sid %s %s\n' "$sid" "$name"
	printf '  target: %s\n' "$pcap"
	if [ ! -r "$LABELS/$pcap" ]; then
		printf '  expected: fire\n  observed: capture missing       FAIL\n\n'
		FAILED=$((FAILED + 1))
		jq -n --arg sid "$sid" --arg name "$name" --arg pcap "$pcap" \
			'{sid: $sid, name: $name, pcap: $pcap, hits: 0, status: "FAIL", reason: "capture missing"}' >> "$TMP/results.jsonl"
		continue
	fi
	suricata -c "./$YAML" -S "$RULES_ABS" -r "$LABELS/$pcap" -l "$outdir" > "$TMP/run-$sid.log" 2>&1
	hits=0
	[ -f "$outdir/eve.json" ] && hits=$(jq -r --argjson sid "$sid" \
		'select(.event_type=="alert" and .alert.signature_id==$sid)' "$outdir/eve.json" 2>/dev/null | jq -s 'length')
	if [ "${hits:-0}" -gt 0 ]; then
		printf '  expected: fire\n  observed: fire (%s hits)                PASS\n\n' "$hits"
		PASSED=$((PASSED + 1))
		status=PASS
	else
		printf '  expected: fire\n  observed: no hits                FAIL\n\n'
		FAILED=$((FAILED + 1))
		status=FAIL
	fi
	jq -n --arg sid "$sid" --arg name "$name" --arg pcap "$pcap" --argjson hits "${hits:-0}" \
		--arg status "$status" '{sid: $sid, name: $name, pcap: $pcap, hits: $hits, status: $status}' \
		>> "$TMP/results.jsonl"
done

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--arg rules "$(basename "$RULES_ABS")" --argjson declared "$RULE_COUNT" \
	--argjson passed "$PASSED" --argjson failed "$FAILED" '
	{generated_at: $ts, hostname: $host, rules_file: $rules,
	 rules_declared: $declared,
	 summary: {rules: ($passed + $failed), passed: $passed, failed: $failed,
	           verdict: (if $failed == 0 then "PASS" else "FAIL" end)},
	 validations: .}' "$TMP/results.jsonl" > "$OUT" || exit 1

echo "Rules:  $RULE_COUNT"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Report saved to: $OUT"
[ "$FAILED" -eq 0 ]
