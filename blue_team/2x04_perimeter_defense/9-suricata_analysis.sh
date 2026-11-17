#!/bin/bash
# =============================================================================
# Name:    9-suricata_analysis.sh
# Purpose: Replay a PCAP through Suricata and classify every alert by signature,
#          source, destination, severity and MedDefense category.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 9
# The ruleset is authoritative; this script is a reader, not a detector.
# Usage: sudo ./9-suricata_analysis.sh [pcap] [output.json] [signature_categories.json]
# Idempotent: replays into a fresh temp directory every run.
# =============================================================================
set -o pipefail
export LC_ALL=C

LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
PCAP=${1:-$LAB/PCAPs/mixed_traffic.pcap}
OUT=${2:-suricata_alerts.json}
YAML=${YAML:-suricata.yaml}
CATEGORIES=${3:-$LAB/capstone/signature_categories.json}

[ -r "$PCAP" ] || { echo "Error: $PCAP not found" >&2; exit 1; }
[ -r "$YAML" ] || { echo "Error: $YAML not found - run 8-suricata_setup.sh first" >&2; exit 1; }
command -v suricata >/dev/null && command -v jq >/dev/null \
	|| { echo "Error: suricata and jq are required" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
STARTED=$(date -Iseconds)

echo "[*] Replaying $(basename "$PCAP")..."
suricata -c "./$YAML" -r "$PCAP" -l "$TMP" > "$TMP/suricata.log" 2>&1
SURICATA_EXIT=$?
EVE=$TMP/eve.json
[ -f "$EVE" ] || { echo "Error: no eve.json (suricata exit $SURICATA_EXIT)" >&2; tail -5 "$TMP/suricata.log" >&2; exit 1; }

# Classification: the shipped sid->category map first, then signature text.
# Keeping both means a new community rule that the map has not seen yet is still
# bucketed instead of landing in "other".
cat > "$TMP/classify.jq" <<'JQ'
def cat_of($sid; $sig):
  (($categories[0].signatures // {})[$sid|tostring]) //
  (if   ($sig|test("(?i)scan|nmap|probe|recon")) then "reconnaissance"
   elif ($sig|test("(?i)psexec|smb|netbios|lateral|admin share")) then "lateral_movement"
   elif ($sig|test("(?i)exfil|tunnel|dns|large transfer")) then "exfiltration"
   elif ($sig|test("(?i)cobalt|beacon|c2|trojan|backdoor|rat|miner")) then "malware_c2"
   elif ($sig|test("(?i)exploit|shellcode|overflow|rce|cve-")) then "exploit"
   elif ($sig|test("(?i)policy|cleartext|telnet|ftp|snmp|insecure")) then "policy_violation"
   else "other" end);
[ .[] | select(.event_type == "alert") ] as $alerts
| {pcap: $pcap, hostname: $host, started_at: $started, finished_at: $finished,
   suricata_exit: $exit,
   total_alerts: ($alerts | length),
   unique_signatures: ([ $alerts[].alert.signature ] | unique | length),
   severity_distribution: ($alerts | group_by(.alert.severity)
      | map({key: (.[0].alert.severity|tostring), value: length}) | from_entries),
   by_signature: ($alerts | group_by(.alert.signature)
      | map({key: .[0].alert.signature, value: length}) | from_entries),
   by_category: ([ $alerts[] | {cat: cat_of(.alert.signature_id; .alert.signature)} ]
      | group_by(.cat) | map({key: .[0].cat, value: length}) | from_entries),
   top_sources: ($alerts | group_by(.src_ip)
      | map({key: .[0].src_ip, value: length}) | sort_by(-.value) | .[0:10]),
   top_destinations: ($alerts | group_by(.dest_ip)
      | map({key: .[0].dest_ip, value: length}) | sort_by(-.value) | .[0:10]),
   alerts: [ $alerts[] | {
      timestamp: .timestamp, src_ip: .src_ip, src_port: .src_port,
      dst_ip: .dest_ip, dst_port: .dest_port, proto: .proto,
      signature: .alert.signature, signature_id: .alert.signature_id,
      category: .alert.category, severity: .alert.severity,
      meddefense_category: cat_of(.alert.signature_id; .alert.signature),
      action: .alert.action } ] }
JQ

jq -s -f "$TMP/classify.jq" \
	--arg pcap "$PCAP" --arg host "$(hostname)" --arg started "$STARTED" \
	--arg finished "$(date -Iseconds)" --argjson exit "$SURICATA_EXIT" \
	--slurpfile categories "$CATEGORIES" "$EVE" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "PCAP: $(basename "$PCAP")   suricata exit: $SURICATA_EXIT"
echo "Alerts: $(jq '.total_alerts' "$OUT")   unique signatures: $(jq '.unique_signatures' "$OUT")"
echo "By category:"
jq -r '.by_category | to_entries | sort_by(-.value) | .[] | "  \(.key): \(.value)"' "$OUT"
echo "Top sources:"
jq -r '.top_sources[] | "  \(.key): \(.value)"' "$OUT"
echo "Report saved to: $OUT"
[ "$(jq '.total_alerts' "$OUT")" -gt 0 ]
