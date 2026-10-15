#!/bin/bash
# 0-baseline_snapshot.sh - Capture the security baseline of a Linux host before hardening.
#
# MedDefense 2x00 "Locking the Gates" - Task 0
# Read-only: this script changes nothing on the system. It records the "before" state that
# every later hardening task (4-13) is measured against ("show the delta").
#
# Usage: sudo ./0-baseline_snapshot.sh [output.json]
#   Summary  -> stdout
#   Full JSON -> baseline_snapshot.json (or the path given as $1)
#
# Scope notes (justified deviations):
#   - /proc, /sys, /dev and /run are pseudo/volatile filesystems and are excluded from file scans.
#   - /snap is excluded: snap images are read-only, signature-verified squashfs mounts that
#     cannot be altered on the host; their SUID helpers are confined by snapd/AppArmor.

set -o pipefail
export LC_ALL=C

OUT="${1:-baseline_snapshot.json}"

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
	echo "Error: jq is required (apt-get install -y jq)" >&2
	exit 1
fi

# Pruned paths for filesystem scans (see scope notes above)
PRUNE=( \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o )

# Print newline-separated input as a JSON string array
lines_to_json() {
	jq -R -s 'split("\n") | map(select(length > 0))'
}

# --- 1. System identification -------------------------------------------------
HOSTNAME_VAL=$(hostname)
OS_VAL=$( . /etc/os-release && echo "$PRETTY_NAME")
KERNEL_VAL=$(uname -r)
UPTIME_VAL=$(uptime -p)

# --- 2. Services (running units + enabled unit files) ------------------------
# Attack surface inventory - Crimson Tide Phase 1: every running service is an entry point.
SERVICES_RUNNING=$(systemctl list-units --type=service --state=running --no-legend --plain \
	| awk '{print $1}')
SERVICES_JSON=$(systemctl list-units --type=service --all --no-legend --plain \
	| awk '{print $1"\t"$2"\t"$3"\t"$4}' \
	| jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
		| {unit: .[0], load: .[1], active: .[2], sub: .[3]})')
ENABLED_JSON=$(systemctl list-unit-files --type=service --state=enabled --no-legend --plain \
	| awk '{print $1}' | lines_to_json)
RUNNING_COUNT=$(printf '%s\n' "$SERVICES_RUNNING" | grep -c .)

# --- 3. Open ports / listening sockets ---------------------------------------
# 1x02 Finding 006: MySQL listening on 0.0.0.0 - exposure must be measured before it is fixed.
SOCKETS=$(ss -H -tulpn | awk '{
	proc = ""; for (i = 7; i <= NF; i++) proc = proc (proc ? " " : "") $i
	print $1"\t"$5"\t"proc }')
PORTS_JSON=$(printf '%s\n' "$SOCKETS" \
	| jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
		| {proto: .[0], local_address: .[1], process: .[2]})')
PORTS_COUNT=$(printf '%s\n' "$SOCKETS" | grep -c .)

# --- 4. SUID / SGID binaries --------------------------------------------------
# Privilege escalation vectors (Crimson Tide Phase 3).
SUID_LIST=$(find / "${PRUNE[@]}" -type f -perm -4000 -print 2>/dev/null | sort)
SGID_LIST=$(find / "${PRUNE[@]}" -type f -perm -2000 -print 2>/dev/null | sort)
SUID_COUNT=$(printf '%s\n' "$SUID_LIST" | grep -c .)
SGID_COUNT=$(printf '%s\n' "$SGID_LIST" | grep -c .)

# --- 5. World-writable files --------------------------------------------------
# World-writable regular files, plus world-writable directories WITHOUT the sticky bit
# (sticky dirs like /tmp are writable by design; non-sticky ones let anyone replace files).
WW_LIST=$(find / "${PRUNE[@]}" \( -type f -perm -0002 -o -type d -perm -0002 ! -perm -1000 \) \
	-print 2>/dev/null | sort)
WW_COUNT=$(printf '%s\n' "$WW_LIST" | grep -c .)

# --- 6. Security-relevant sysctl parameters ----------------------------------
SYSCTL_KEYS=(
	net.ipv4.ip_forward
	net.ipv4.conf.all.accept_redirects
	net.ipv4.conf.default.accept_redirects
	net.ipv4.conf.all.send_redirects
	net.ipv4.conf.all.accept_source_route
	net.ipv4.conf.all.log_martians
	net.ipv4.tcp_syncookies
	net.ipv4.icmp_echo_ignore_broadcasts
	net.ipv6.conf.all.disable_ipv6
	net.ipv6.conf.default.disable_ipv6
	kernel.randomize_va_space
	fs.suid_dumpable
	kernel.dmesg_restrict
	kernel.kptr_restrict
)
SYSCTL_JSON=$(for k in "${SYSCTL_KEYS[@]}"; do
	printf '%s\t%s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo unavailable)"
done | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add')

# --- 7. SSH configuration -----------------------------------------------------
# 1x02 Finding 009: SSH password authentication enabled. Effective config via sshd -T.
SSH_KEYS='^(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|maxauthtries|clientaliveinterval|clientalivecountmax|allowusers|logingracetime|banner|pubkeyauthentication|kbdinteractiveauthentication|usepam|port|listenaddress) '
SSH_JSON=$(sshd -T 2>/dev/null | grep -E "$SSH_KEYS" \
	| awk '{k=$1; $1=""; sub(/^ /, ""); print k"\t"$0}' \
	| jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}')

# --- 8. User accounts and sudo membership ------------------------------------
# Harvested credentials drove lateral movement in 3 of 5 Crimson Tide breaches.
USERS_JSON=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /(nologin|false)$/ {print $1"\t"$3"\t"$6"\t"$7}' /etc/passwd \
	| jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
		| {user: .[0], uid: (.[1] | tonumber), home: .[2], shell: .[3]})')
SUDO_JSON=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | lines_to_json)

# --- JSON report ---------------------------------------------------------------
jq -n \
	--arg ts "$(date -Iseconds)" \
	--arg hostname "$HOSTNAME_VAL" --arg os "$OS_VAL" \
	--arg kernel "$KERNEL_VAL" --arg uptime "$UPTIME_VAL" \
	--argjson services "$SERVICES_JSON" \
	--argjson running "$(printf '%s\n' "$SERVICES_RUNNING" | lines_to_json)" \
	--argjson enabled "$ENABLED_JSON" \
	--argjson ports "$PORTS_JSON" \
	--argjson suid "$(printf '%s\n' "$SUID_LIST" | lines_to_json)" \
	--argjson sgid "$(printf '%s\n' "$SGID_LIST" | lines_to_json)" \
	--argjson ww "$(printf '%s\n' "$WW_LIST" | lines_to_json)" \
	--argjson sysctl "$SYSCTL_JSON" \
	--argjson ssh "$SSH_JSON" \
	--argjson users "$USERS_JSON" \
	--argjson sudo "$SUDO_JSON" \
	'{
		timestamp: $ts,
		system: {hostname: $hostname, os: $os, kernel: $kernel, uptime: $uptime},
		summary: {
			running_services: ($running | length),
			enabled_services: ($enabled | length),
			open_ports: ($ports | length),
			suid_binaries: ($suid | length),
			sgid_binaries: ($sgid | length),
			world_writable_files: ($ww | length)
		},
		services: {running: $running, enabled: $enabled, all: $services},
		listening_sockets: $ports,
		suid_binaries: $suid,
		sgid_binaries: $sgid,
		world_writable_files: $ww,
		sysctl: $sysctl,
		ssh_config: $ssh,
		users: {login_accounts: $users, sudo_group: $sudo}
	}' > "$OUT" || { echo "Error: failed to write $OUT" >&2; exit 1; }

# --- Summary -------------------------------------------------------------------
echo "Hostname: $HOSTNAME_VAL"
echo "OS: $OS_VAL"
echo "Running services: $RUNNING_COUNT"
echo "Open ports: $PORTS_COUNT"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WW_COUNT"
echo "[*] Full snapshot saved to: $OUT (kernel $KERNEL_VAL, $UPTIME_VAL)" >&2
