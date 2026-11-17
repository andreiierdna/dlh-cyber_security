#!/bin/bash
# =============================================================================
# Name:    2-segmentation_rules.sh
# Purpose: Emit segmentation_rules.json - the zone/flow contract that the
#          nftables (T4) and Windows Firewall (T6) tasks must both implement.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 2
# Four zones, explicit cross-zone allow flows, explicit deny for every pair
# without an allow. Nothing is implicit: every line below is a decision.
#
# Zone addressing note: the lab ships two address plans that must coexist -
# 10.10.0.0/16 for the Central hospital (servers 10.10.1.0/24, clinical
# 10.10.2.0/24, MEDDEV 10.10.4.0/24, guest 10.10.5.0/24) and the 172.16.x
# ranges used by probes.json (DMZ 172.16.10.0/24, MGMT 172.16.30.0/24,
# MEDDEV 172.16.40.0/24). Both are carried per zone (cidr = primary,
# cidrs = all), so no downstream task has to guess.
# Idempotent: writes the same deterministic file every run.
# =============================================================================
set -o pipefail
export LC_ALL=C

OUT=${1:-segmentation_rules.json}
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }

jq -n --arg ts "$(date -Iseconds)" '
	def flow($src;$dst;$proto;$port;$just;$ex;$tag): {
		src_zone: $src, dst_zone: $dst, proto: $proto, dport: $port,
		justification: $just, exception_for: $tag, action: "allow" };

	def deny($src;$dst;$just): {
		src_zone: $src, dst_zone: $dst, proto: "any", dport: "any",
		justification: $just, exception_for: null, action: "deny_all" };

	{
	 zones: [
	  {name: "DMZ",      cidr: "172.16.10.0/24", cidrs: ["172.16.10.0/24","10.10.5.0/24"],
	   purpose: "Public-facing and guest-facing services (portal, guest Wi-Fi edge)",
	   default_inbound: "drop", default_outbound: "accept"},
	  {name: "INTERNAL", cidr: "10.10.0.0/16", cidrs: ["10.10.0.0/16","172.16.20.0/24"],
	   purpose: "Clinical applications, workstations and server hosts",
	   default_inbound: "drop", default_outbound: "accept"},
	  {name: "MGMT",     cidr: "172.16.30.0/24", cidrs: ["172.16.30.0/24"],
	   purpose: "Administration workstations, jump host and DNS resolver",
	   default_inbound: "drop", default_outbound: "accept"},
	  {name: "MEDDEV",   cidr: "10.10.4.0/24", cidrs: ["10.10.4.0/24","172.16.40.0/24"],
	   purpose: "Medical device / imaging VLAN (monitors, pumps, PACS, lab PCs)",
	   default_inbound: "drop", default_outbound: "accept-with-restrictions"}
	 ],
	 flows: [
	  flow("MGMT";"INTERNAL";"tcp";22;"Administrative SSH to internal hosts";null;null),
	  flow("MGMT";"DMZ";"tcp";22;"Administrative SSH to DMZ hosts";null;null),
	  flow("INTERNAL";"INTERNAL";"tcp";443;"Clinical workstation to application server (HTTPS)";null;"clinical_workstation->server_host"),
	  flow("INTERNAL";"INTERNAL";"tcp";3306;"Clinical application to authorized billing database";null;"clinical_workstation->authorized_database"),
	  flow("DMZ";"INTERNAL";"tcp";3306;"Named DMZ application hosts only, to the internal database";null;"named_dmz_application_host->database"),
	  flow("MEDDEV";"INTERNAL";"tcp";4242;"DICOM imaging to PACS";null;null),
	  flow("MEDDEV";"INTERNAL";"tcp";443;"EHR web integration for device display";null;null),
	  flow("ALL";"MGMT";"udp";53;"DNS resolution through the management resolver";null;null),
	  flow("ALL";"MGMT";"tcp";53;"DNS fallback through the management resolver";null;null),
	  flow("MGMT";"MEDDEV";"tcp";22;"The only inbound administration path allowed into MEDDEV";null;null),
	  flow("MGMT";"MEDDEV";"tcp";4242;"DICOM maintenance access for imaging support";null;null)
	 ],
	 deny_all: [
	  deny("MEDDEV";"DMZ";"No medical device traffic to the public-facing zone"),
	  deny("MEDDEV";"EXTERNAL";"No medical device traffic to the Internet (except udp/123 NTP)"),
	  deny("DMZ";"MEDDEV";"DMZ hosts must not initiate sessions to medical devices"),
	  deny("INTERNAL";"MEDDEV";"Only MGMT may administer medical devices"),
	  deny("DMZ";"MGMT";"DMZ hosts must not reach management systems"),
	  deny("MGMT";"EXTERNAL";"Management egress restricted to approved update hosts"),
	  deny("INTERNAL";"EXTERNAL";"General internal egress denied except approved proxies")
	 ],
	 policy_notes: [
	  "MEDDEV outbound is allow-with-restrictions: only udp/123 (NTP) to the management resolver and no Internet destinations",
	  "INTERNAL->INTERNAL 3306 is limited to the authorized billing database host (10.10.1.10)",
	  "DMZ->INTERNAL 3306 is limited to named DMZ application hosts (exception_for tag)"
	 ],
	 generated_at: $ts
	}
	| .summary = {
		zone_count: (.zones | length),
		flow_count: (.flows + .deny_all | length),
		allow_count: (.flows | length),
		deny_count: (.deny_all | length),
		cross_zone_pairs: ([ .flows[] | select(.src_zone != .dst_zone) | "\(.src_zone)->\(.dst_zone)" ] | unique | length),
		zone_pairs_with_deny: ([ .deny_all[] | "\(.src_zone)->\(.dst_zone)" ] | unique | length)
	  }' > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Zones: $(jq '.summary.zone_count' "$OUT")   Flows: $(jq '.summary.flow_count' "$OUT") (allow $(jq '.summary.allow_count' "$OUT"), deny $(jq '.summary.deny_count' "$OUT"))"
echo "Cross-zone pairs with allow: $(jq '.summary.cross_zone_pairs' "$OUT")   pairs explicitly denying: $(jq '.summary.zone_pairs_with_deny' "$OUT")"
jq -r '.flows[] | "  \(.src_zone) -> \(.dst_zone) \(.proto)/\(.dport)  \(.justification)"' "$OUT"
echo "Report saved to: $OUT"
