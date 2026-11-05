#!/bin/bash
# =============================================================================
# Name:    0-vuln_inventory.sh
# Purpose: Build vulnerability_inventory.json - every installed package with a
#          pending security update, its CVEs, CVSS score, severity and CISA KEV
#          status. Measurement step for the whole patch pipeline.
# Author:  MedDefense blue team (Holberton 2x03 - Task 0)
# =============================================================================
# MedDefense 2x03 "The Patch Equation" - Task 0
# Answers Dr. Morales' first question: which of our systems are exposed.
#
# Methodology (native tooling only, no external aggregator):
#   dpkg-query -W          -> installed package set
#   apt list --upgradable  -> packages with an available update + source pocket
#   apt-cache policy       -> archive/pocket confirmation
#   apt-get changelog      -> CVE ids from the newest (candidate) changelog entry
#   /usr/share/ubuntu-advantage-tools usn data -> fallback when the changelog is
#                            unreachable
#   cve_feed.json          -> CVSS base score and CISA KEV flag per CVE
#
# "Vulnerable" = has a pending update from a security pocket, or the feed names a
# CVE for it. Updates/backports-only packages are counted in the summary but not
# reported as vulnerable on their own.
#
# Idempotent: read-only, no package state is touched.
# Usage: sudo ./0-vuln_inventory.sh [cve_feed.json] [output.json]
# =============================================================================

set -o pipefail
export LC_ALL=C

FEED=${1:-cve_feed.json}
OUT=${2:-vulnerability_inventory.json}

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0) - apt-get changelog and dpkg need root" >&2
	exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Feed is optional: a missing/partial feed degrades to "unrated", never fails
echo '{"cves":{},"packages":{}}' > "$TMP/feed.json"
if [ -r "$FEED" ]; then
	jq -s '.[0] * .[1]' "$TMP/feed.json" "$FEED" > "$TMP/feed2.json" 2>/dev/null \
		&& mv "$TMP/feed2.json" "$TMP/feed.json" \
		|| echo "[!] $FEED is not valid JSON - continuing without it" >&2
else
	echo "[!] $FEED not found - severity will be 'unrated' where the changelog gives no CVSS" >&2
fi

# 1. Installed packages ---------------------------------------------------------
INSTALLED=$(dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null \
	| awk '$3 == "install" && $4 == "ok" && $5 == "installed" { print $1"\t"$2 }')
INSTALLED_N=$(grep -c . <<< "$INSTALLED" || true)

# 2. Pending updates + source pocket --------------------------------------------
# apt list --upgradable: "pkg/jammy-updates,jammy-security 2.4.15 all [upgradable from: 2.4.14]"
apt list --upgradable 2>/dev/null | awk '
	/^Listing/ || !/\[upgradable from:/ { next }
	{
		split($1, a, "/")            # a[1]=package  a[2]=jammy-updates,jammy-security
		pkg = a[1]; pockets = a[2]
		cand = $2
		inst = $0; sub(/.*\[upgradable from: /, "", inst); sub(/\].*/, "", inst)
		pocket = "unknown"
		if (pockets ~ /-security/)      pocket = "security"
		else if (pockets ~ /-updates/)  pocket = "updates"
		else if (pockets ~ /-backports/) pocket = "backports"
		print pkg"\t"inst"\t"cand"\t"pocket
	}' > "$TMP/upgradable.tsv"
UPG_N=$(grep -c . "$TMP/upgradable.tsv" || true)

# 3. CVE extraction --------------------------------------------------------------
# changelog_cves <pkg>: CVEs named in the newest changelog entry only (older
# entries describe updates already installed and would pollute the inventory)
changelog_cves() {
	timeout 45 apt-get changelog "$1" 2>/dev/null \
		| awk '/^ -- / { exit } { print }' \
		| grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' | sort -u | paste -sd ' ' -
}
# usn_cves <pkg>: fallback from the locally cached Ubuntu Security Notice data
usn_cves() {
	local f
	f=$(grep -rl "^$1\b" /usr/share/ubuntu-advantage-tools/*.json 2>/dev/null | head -1)
	[ -n "$f" ] || return 0
	jq -r --arg p "$1" '
		.. | objects | select(.package? == $p) | (.cves // [])[]?' "$f" 2>/dev/null | sort -u | paste -sd ' ' -
}

# Rows are accumulated as JSON lines: the CVE list contains spaces, so a TSV
# round-trip would corrupt fields on packages with several CVEs.
: > "$TMP/rows.jsonl"
VULN=0
KEV=0
SEC_N=0
while IFS=$'\t' read -r pkg inst cand pocket; do
	[ -z "$pkg" ] && continue
	[ "$pocket" = security ] && SEC_N=$((SEC_N + 1))

	# CVEs: changelog first, USN fallback, feed merged on top
	cves=""
	if [ "$pocket" = security ]; then
		cves=$(changelog_cves "$pkg")
		[ -z "$cves" ] && cves=$(usn_cves "$pkg")
	fi
	feed_cves=$(jq -r --arg p "$pkg" '(.packages[$p] // []) | join(" ")' "$TMP/feed.json")
	cves=$(printf '%s %s\n' "$cves" "$feed_cves" | tr ' ' '\n' | grep -E '^CVE-' | sort -u | paste -sd ' ' -)

	# Vulnerable = CVE evidence, or a pending security update
	[ -z "$cves" ] && [ "$pocket" != security ] && continue
	VULN=$((VULN + 1))

	cve_json="[]"
	max_cvss="null"
	kev="false"
	if [ -n "$cves" ]; then
		cve_json=$(printf '%s\n' $cves | jq -R . | jq -cs .)
		feed_meta=$(jq -r --argjson cves "$cve_json" '
			[ $cves[] as $c | (.cves[$c] // empty) ] as $d
			| [ ($d | map(.cvss) | if length > 0 then max else null end),
			    ($d | any(.in_cisa_kev == true)) ] | @tsv' "$TMP/feed.json")
		max_cvss=$(cut -f1 <<< "$feed_meta")
		kev=$(cut -f2 <<< "$feed_meta")
		[ -z "$max_cvss" ] && max_cvss="null"
		[ -z "$kev" ] && kev="false"
	fi

	sev=$(awk -v s="$max_cvss" 'BEGIN {
		if (s == "null" || s == "") print "unrated";
		else if (s >= 9.0) print "critical";
		else if (s >= 7.0) print "high";
		else if (s >= 4.0) print "medium";
		else print "low" }')
	[ "$kev" = true ] && KEV=$((KEV + 1))

	jq -n --arg pkg "$pkg" --arg inst "$inst" --arg cand "$cand" --arg pocket "$pocket" \
		--argjson cves "$cve_json" --arg max "$max_cvss" --arg sev "$sev" --arg kev "$kev" \
		'{package: $pkg, installed_version: $inst, candidate_version: $cand,
		  source_pocket: $pocket, cves: $cves,
		  max_cvss: (if $max == "null" then null else ($max | tonumber) end),
		  severity: $sev, in_cisa_kev: ($kev == "true")}' >> "$TMP/rows.jsonl"
done < "$TMP/upgradable.tsv"

# 4. Emit JSON -------------------------------------------------------------------
jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--argjson installed "$INSTALLED_N" --argjson upgradable "$UPG_N" \
	--argjson security "$SEC_N" --argjson vulnerable "$VULN" --argjson kev "$KEV" '
	{generated_at: $ts, hostname: $host,
	 summary: {installed_packages: $installed, upgradable: $upgradable,
	           security_pocket_upgrades: $security, vulnerable: $vulnerable,
	           cisa_kev_hits: $kev},
	 packages: (sort_by(.package))}' "$TMP/rows.jsonl" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

# 5. Summary ---------------------------------------------------------------------
echo "Installed packages: $INSTALLED_N"
echo "Upgradable packages: $UPG_N (security pocket: $SEC_N)"
echo "Vulnerable packages: $VULN (CISA KEV: $KEV)"
jq -r '.packages[] | "  \(.package) \(.installed_version) -> \(.candidate_version) [\(.severity)] \(.cves | join(","))"' "$OUT"
echo "Report saved to: $OUT"
