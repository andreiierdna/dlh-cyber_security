#!/bin/bash
# =============================================================================
# Name:    0-environment_intake.sh
# Purpose: Capture the pre-hardening state of hawthorne-app-01 as structured
#          data so every later task can be measured against it.
# Author:  MedDefense blue team (Holberton 2x05 capstone - Task 0)
# =============================================================================
# Output: capstone/intake/linux_intake.json
# Exit: 0 success, 1 a required collector failed, 2 environment error.
# Idempotent: read-only.
# =============================================================================
set -o pipefail
export LC_ALL=C

CAP=${CAPSTONE_DIR:-capstone}
OUT="$CAP/intake/linux_intake.json"

[ "$EUID" -eq 0 ] || { echo "Error: run as root (sudo $0)" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq required" >&2; exit 2; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$CAP/intake"

# --- collectors ---------------------------------------------------------------
hostname -f > "$TMP/hostname" 2>/dev/null || hostname > "$TMP/hostname"
uname -r > "$TMP/kernel"
( . /etc/os-release && printf '%s %s\n' "$NAME" "$VERSION_ID" ) > "$TMP/distro"
apt list --upgradable 2>/dev/null | grep -c . > "$TMP/upgradable" || echo 0 > "$TMP/upgradable"

dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' 2>/dev/null \
	| awk -F'\t' '$3 ~ /install ok installed/ {print $1"\t"$2}' > "$TMP/packages.tsv"
ss -tulnpH 2>/dev/null > "$TMP/ss.txt"
systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
	| awk '{print $1}' > "$TMP/services.txt"
grep -vE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config 2>/dev/null > "$TMP/sshd.txt"

# sysctl security parameters that the target state cares about
: > "$TMP/sysctl.jsonl"
for k in net.ipv4.ip_forward kernel.randomize_va_space fs.suid_dumpable \
	kernel.dmesg_restrict kernel.kptr_restrict net.ipv4.tcp_syncookies \
	net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.log_martians; do
	v=$(sysctl -n "$k" 2>/dev/null || echo unavailable)
	jq -n --arg k "$k" --arg v "$v" '{($k): $v}' >> "$TMP/sysctl.jsonl"
done

# SUID/SGID and world-writable counts (volatile/pseudo filesystems excluded)
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
	-type f -perm /6000 -print 2>/dev/null > "$TMP/suid.txt"
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
	-type f -perm -0002 -print 2>/dev/null > "$TMP/ww.txt"

# firewall and telemetry presence
nft list ruleset 2>/dev/null | grep -c . > "$TMP/nft_lines" || echo 0 > "$TMP/nft_lines"
auditd_state=$(systemctl is-active auditd 2>/dev/null); [ -z "$auditd_state" ] && auditd_state=unknown
rsyslog_state=$(systemctl is-active rsyslog 2>/dev/null); [ -z "$rsyslog_state" ] && rsyslog_state=unknown
sysmon_state=$(systemctl is-active sysmon 2>/dev/null); [ -z "$sysmon_state" ] && sysmon_state=not-installed
apparmor_state=$(systemctl is-active apparmor 2>/dev/null); [ -z "$apparmor_state" ] && apparmor_state=unknown

jq -n \
	--arg ts "$(date -Iseconds)" --arg host "$(cat "$TMP/hostname")" \
	--arg kernel "$(cat "$TMP/kernel")" --arg distro "$(cat "$TMP/distro")" \
	--argjson upgradable "$(cat "$TMP/upgradable")" \
	--argjson pkgn "$(grep -c . "$TMP/packages.tsv")" \
	--argjson svcn "$(grep -c . "$TMP/services.txt")" \
	--arg suid "$(grep -c . "$TMP/suid.txt")" --arg ww "$(grep -c . "$TMP/ww.txt")" \
	--argjson nft "$(cat "$TMP/nft_lines")" \
	--arg auditd "$auditd_state" --arg rsyslog "$rsyslog_state" \
	--arg sysmon "$sysmon_state" --arg apparmor "$apparmor_state" \
	--slurpfile sysctl <(jq -s 'add' "$TMP/sysctl.jsonl") \
	--argjson services "$(jq -R . < "$TMP/services.txt" | jq -s .)" \
	--argjson listening "$(awk '{proto=$1; a=$5; p=a; sub(/.*:/,"",p); ad=a; sub(/:[0-9]+$/,"",ad);
		proc=""; pid=0; if (match($0,/users:\(\(/)) { proc=substr($0,RSTART+9); sub(/\).*/,"",proc);
		if (match(proc,/pid=[0-9]+/)) pid=substr(proc,RSTART+4,RLENGTH-4)+0; sub(/,.*/,"",proc); gsub(/"/,"",proc) }
		printf "%s\t%s\t%s\t%s\t%s\n", proto, ad, p, proc, pid }' "$TMP/ss.txt" \
		| jq -R -s 'split("\n") | map(select(length>0) | split("\t")
			| {proto:.[0], bind_addr:.[1], port:(.[2]|tonumber), process:.[3], pid:(.[4]|tonumber)})')" \
	--argjson sshd "$(awk '{k=$1; $1=""; sub(/^ /,"",$0); if (k !~ /^#/) printf "%s\t%s\n", k, $0}' "$TMP/sshd.txt" \
		| jq -R -s 'split("\n") | map(select(length>0) | split("\t") | {(.[0]): .[1]}) | add // {}')" '
	{timestamp: $ts, hostname: $host, platform: "linux",
	 kernel: $kernel, distribution: $distro, pending_updates: $upgradable,
	 installed_packages: $pkgn,
	 active_services: $services, active_service_count: $svcn,
	 listening_sockets: $listening,
	 sshd_config: $sshd,
	 sysctl: $sysctl[0],
	 suid_sgid_count: ($suid | tonumber), world_writable_count: ($ww | tonumber),
	 firewall: {nft_ruleset_lines: $nft, active: ($nft > 0)},
	 telemetry_presence: {auditd: $auditd, rsyslog: $rsyslog, sysmon_for_linux: $sysmon, apparmor: $apparmor}}' \
	> "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Intake written: $OUT"
jq -r '"  host=\(.hostname) kernel=\(.kernel) pkgs=\(.installed_packages) listeners=\(.listening_sockets|length) suid=\(.suid_sgid_count) ww=\(.world_writable_count)"' "$OUT"
jq -r '"  auditd=\(.telemetry_presence.auditd) rsyslog=\(.telemetry_presence.rsyslog) apparmor=\(.telemetry_presence.apparmor) nft_lines=\(.firewall.nft_ruleset_lines)"' "$OUT"
exit 0
