#!/bin/bash
# =============================================================================
# Name:    11-pcap_investigation.sh
# Purpose: Investigate a PCAP with tshark and produce pcap_findings.json:
#          conversations, DNS, HTTP, TLS SNI, file transfers, protocols.
# Author:  Andrei
# =============================================================================
# MedDefense 2x04 "Perimeter Defense" - Task 11
# An alert is a pointer, not a finding. This walks the bytes: who talked to whom,
# what names were resolved, what was uploaded, which TLS hosts were contacted.
# Every field is present even when the query returns nothing (empty array), so
# the consumer never has to special-case a missing key.
#
# Usage: sudo ./11-pcap_investigation.sh [pcap] [output.json]
# Idempotent: read-only analysis.
# =============================================================================
set -o pipefail
export LC_ALL=C

LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
PCAP=${1:-$LAB/PCAPs/suspicious_session.pcap}
OUT=${2:-pcap_findings.json}

[ -r "$PCAP" ] || { echo "Error: $PCAP not found" >&2; exit 1; }
command -v tshark >/dev/null && command -v jq >/dev/null \
	|| { echo "Error: tshark and jq are required" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# conv <proto>: top conversations by bytes -> JSON array
conv() {
	local proto="$1"
	tshark -r "$PCAP" -q -z "conv,$proto" 2>/dev/null \
		| awk -v p="$proto" '
			/^[0-9]+/ {
				# A <-> B  frames  bytes  ...
				a=$1; b=$3; frames=$4; bytes=$5
				printf "%s\t%s\t%s\t%s\t%s\n", a, b, frames, bytes, p
			}' \
		| sort -t$'\t' -k4,4nr | head -10 \
		| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
			| {endpoint_a: .[0], endpoint_b: .[1],
			   frames: (.[2]|tonumber?), bytes: (.[3]|tonumber?), proto: .[4]})'
}

echo "[*] PCAP: $PCAP"
DURATION=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | awk 'NR==1{f=$1} {l=$1} END{if (NR>0) printf "%.2f", l-f; else print "0"}')
PACKETS=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
echo "[*] Duration: ${DURATION} s     Packets: $PACKETS"

echo "[*] Extracting TCP conversations..."
conv tcp > "$TMP/conv_tcp.json"
echo "    ($(jq length "$TMP/conv_tcp.json"))"
echo "[*] Extracting UDP conversations..."
conv udp > "$TMP/conv_udp.json"
echo "    ($(jq length "$TMP/conv_udp.json"))"

echo "[*] Extracting DNS queries..."
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null \
	| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
		| {time_epoch: (.[0]|tonumber?), src_ip: .[1], query: .[2], qtype: .[3]})' > "$TMP/dns.json"
echo "    ($(jq length "$TMP/dns.json"))"

echo "[*] Extracting HTTP requests..."
tshark -r "$PCAP" -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null \
	| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
		| {time_epoch: (.[0]|tonumber?), src_ip: .[1], dst_ip: .[2], host: .[3], method: .[4], uri: .[5]})' > "$TMP/http.json"
echo "    ($(jq length "$TMP/http.json"))"

echo "[*] Extracting TLS SNI..."
tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
	| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
		| {time_epoch: (.[0]|tonumber?), src_ip: .[1], dst_ip: .[2], sni: .[3]})' > "$TMP/tls.json"
echo "    ($(jq length "$TMP/tls.json"))"

echo "[*] Extracting file transfers..."
tshark -r "$PCAP" -Y 'http.content_type or smb2.filename' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.content_type -e smb2.filename -e http.file_data 2>/dev/null \
	| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
		| {time_epoch: (.[0]|tonumber?), src_ip: .[1], dst_ip: .[2],
		   http_content_type: (if .[3]=="" then null else .[3] end),
		   smb_filename: (if .[4]=="" then null else .[4] end),
		   has_file_data: (.[5] != "")})' > "$TMP/files.json"
echo "    ($(jq length "$TMP/files.json"))"

echo "[*] Protocol distribution..."
# io,phs lines look like: "    tls      frames:120 bytes:16320"
# (protocol names may contain '.', '_' and '/', so parse by field, not by regex on the name)
tshark -r "$PCAP" -q -z io,phs 2>/dev/null \
	| awk '$0 ~ /frames:[0-9]+ bytes:[0-9]+/ {
		proto=$1; f=""; b=""
		if (match($0, /frames:[0-9]+/)) f=substr($0, RSTART+7, RLENGTH-7)
		if (match($0, /bytes:[0-9]+/)) b=substr($0, RSTART+6, RLENGTH-6)
		print proto"\t"f"\t"b
	}' > "$TMP/proto.tsv"
TOTAL_FRAMES=$(awk -F'\t' '$1 == "eth" {print $2; exit}' "$TMP/proto.tsv")
[ -z "$TOTAL_FRAMES" ] && TOTAL_FRAMES=$(awk -F'\t' '{s+=$2} END{print s+0}' "$TMP/proto.tsv")
jq -R -s --argjson total "${TOTAL_FRAMES:-0}" 'split("\n") | map(select(length>0) | split("\t")
	| {protocol: .[0], frames: (.[1]|tonumber?), bytes: (.[2]|tonumber?)})
	| map(. + {share_pct: (if $total > 0 then (((.frames // 0) * 1000 / $total)|round)/10 else null end)})' \
	"$TMP/proto.tsv" > "$TMP/proto.json"

# Long DNS labels: the tunnel signature
jq '[ .[] | (.query // "") | split(".") | .[0]
      | select(length > 50) | {label: ., length: length} ] | unique_by(.label)' "$TMP/dns.json" > "$TMP/long.json"

jq -n --arg ts "$(date -Iseconds)" --arg host "$(hostname)" --arg pcap "$PCAP" \
	--argjson duration "$DURATION" --argjson packets "$PACKETS" \
	--slurpfile tcp "$TMP/conv_tcp.json" --slurpfile udp "$TMP/conv_udp.json" \
	--slurpfile dns "$TMP/dns.json" --slurpfile http "$TMP/http.json" \
	--slurpfile tls "$TMP/tls.json" --slurpfile files "$TMP/files.json" \
	--slurpfile proto "$TMP/proto.json" --slurpfile long "$TMP/long.json" '
	{generated_at: $ts, hostname: $host, pcap: $pcap,
	 duration_seconds: $duration, packets: $packets,
	 conversations: {tcp: $tcp[0], udp: $udp[0]},
	 dns_queries: $dns[0],
	 http_requests: $http[0],
	 tls_sni: $tls[0],
	 file_transfers: $files[0],
	 protocol_distribution: $proto[0],
	 long_dns_labels: $long[0],
	 summary: {tcp_conversations: ($tcp[0]|length), udp_conversations: ($udp[0]|length),
	           dns_queries: ($dns[0]|length), http_requests: ($http[0]|length),
	           tls_sni: ($tls[0]|length), file_transfers: ($files[0]|length),
	           long_dns_labels: ($long[0]|length)}}' > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Top conversations:"
jq -r '(.conversations.tcp + .conversations.udp) | sort_by(-(.bytes // 0)) | .[0:5][]
	| "  \(.endpoint_a) <-> \(.endpoint_b)  \(.proto)  \(.frames // 0) pkts  \(.bytes // 0) B"' "$OUT"
echo "Protocol distribution:"
jq -r '.protocol_distribution | sort_by(-(.frames // 0)) | .[0:6][]
	| "  \(.protocol)  \(.share_pct // 0)% (\(.frames // 0) frames)"' "$OUT"
echo "Long DNS labels (> 50 chars):"
jq -r '.long_dns_labels[] | "  \(.label).  (\(.length) chars)"' "$OUT" | head -5
[ "$(jq '.long_dns_labels | length' "$OUT")" -eq 0 ] && echo "  none"
echo "Report saved to: $OUT"
