#!/bin/bash
# =============================================================================
# Name:    0-network_baseline.sh
# Purpose: Capture the host's own view of the network (interfaces, routes,
#          neighbours, listeners, established connections, resolvers) into
#          network_baseline.json. Read-only baseline for every later task.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 0
# Mike Torres says the network is flat. This is the data, not the opinion.
# Idempotent: read-only.
# =============================================================================
set -o pipefail
export LC_ALL=C

OUT=${1:-network_baseline.json}
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required" >&2; exit 1; }
[ "$EUID" -eq 0 ] || echo "[!] not running as root: socket->process resolution will be partial" >&2

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 1. Interfaces (ip -j gives JSON directly)
ip -j addr show > "$TMP/addr.json" 2>/dev/null || echo '[]' > "$TMP/addr.json"

# 2. Routes
ip -j route show > "$TMP/route.json" 2>/dev/null || echo '[]' > "$TMP/route.json"

# 3. Neighbours (ARP/NDP)
ip -j neigh show > "$TMP/neigh.json" 2>/dev/null || echo '[]' > "$TMP/neigh.json"

# 4. Listening sockets: ss -tulnpH, parsed (ss -j is not available on 22.04)
#    "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"apache2\",pid=826,fd=4),...)"
ss -tulnpH 2>/dev/null | awk '{
	proto=$1; local=$5; peer=$6; proc=""; pid=0
	if (match($0, /users:\(\(/)) { proc=substr($0, RSTART+9); sub(/\).*/, "", proc)
		if (match(proc, /pid=[0-9]+/)) pid=substr(proc, RSTART+4, RLENGTH-4)+0
		sub(/,.*/, "", proc); gsub(/"/, "", proc) }
	addr=local; sub(/:[0-9]+$/, "", addr); port=local; sub(/.*:/, "", port)
	printf "%s\t%s\t%s\t%s\t%s\t%s\n", proto, addr, port, proc, pid, peer
}' > "$TMP/listen.tsv"
jq -R -s 'split("\n") | map(select(length>0) | split("\t")
	| {proto:.[0], bind_addr:.[1], port:(.[2]|tonumber), process:.[3],
	   pid:(.[4]|tonumber), peer:.[5]})' "$TMP/listen.tsv" > "$TMP/listen.json"

# 5. Established outbound connections
ss -tnpH state established 2>/dev/null | awk '{
	local=$4; peer=$5; proc=""; pid=0
	if (match($0, /users:\(\(/)) { proc=substr($0, RSTART+9); sub(/\).*/, "", proc)
		if (match(proc, /pid=[0-9]+/)) pid=substr(proc, RSTART+4, RLENGTH-4)+0
		sub(/,.*/, "", proc); gsub(/"/, "", proc) }
	laddr=local; sub(/:[0-9]+$/, "", laddr); lport=local; sub(/.*:/, "", lport)
	paddr=peer; sub(/:[0-9]+$/, "", paddr); pport=peer; sub(/.*:/, "", pport)
	printf "%s\t%s\t%s\t%s\t%s\t%s\n", laddr, lport, paddr, pport, proc, pid
}' > "$TMP/est.tsv"
jq -R -s 'split("\n") | map(select(length>0) | split("\t")
	| {local_addr:.[0], local_port:(.[1]|tonumber), remote_addr:.[2],
	   remote_port:(.[3]|tonumber), process:.[4], pid:(.[5]|tonumber)})' "$TMP/est.tsv" > "$TMP/est.json"

# 6. DNS configuration
RESOLV=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | jq -R . | jq -s .)
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
	resolvectl status --no-pager > "$TMP/resolvectl.txt" 2>/dev/null || true
else
	: > "$TMP/resolvectl.txt"
fi

jq -n --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--slurpfile addr "$TMP/addr.json" --slurpfile route "$TMP/route.json" \
	--slurpfile neigh "$TMP/neigh.json" --slurpfile listen "$TMP/listen.json" \
	--slurpfile est "$TMP/est.json" --argjson resolv "$RESOLV" \
	--rawfile resolvectl "$TMP/resolvectl.txt" '
	def links: [ $addr[0][] | select(.link_index != null) ];
	{timestamp: $ts, hostname: $host,
	 up_interfaces: [ $addr[0][] | select(.operstate == "UP") | .ifname ],
	 interfaces: [ $addr[0][] | {name: .ifname, mac: (.address // null),
	                             state: .operstate,
	                             addresses: [ (.addr_info // [])[] | "\(.local)/\(.prefixlen)" ] } ],
	 routes: [ $route[0][] | {dst: (.dst // "default"), gateway: (.gateway // null),
	                          dev: (.dev // null), prefsrc: (.prefsrc // null), table: (.table // "main")} ],
	 neighbors: [ $neigh[0][] | {ip: (.dst // .to // null), mac: (.lladdr // null), state: (.state // [] | if type=="array" then join(",") else . end), dev: (.dev // null)} ],
	 listening_sockets: $listen[0],
	 listeners: ($listen[0] | length),
	 established_connections: $est[0],
	 dns_resolvers: {nameservers: $resolv, resolvectl_status: $resolvectl} }
	| .default_gateway = ([ .routes[] | select(.dst == "default") | .gateway ] | first)' > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Host: $(jq -r .hostname "$OUT")"
echo "Up interfaces: $(jq -r '.up_interfaces | join(", ")' "$OUT")"
echo "Default gateway: $(jq -r '.default_gateway // "none"' "$OUT")"
echo "Listening sockets: $(jq '.listeners' "$OUT")   Established: $(jq '.established_connections | length' "$OUT")"
echo "Neighbours: $(jq '.neighbors | length' "$OUT")   Nameservers: $(jq -r '.dns_resolvers.nameservers | join(", ")' "$OUT")"
echo "Report saved to: $OUT"
