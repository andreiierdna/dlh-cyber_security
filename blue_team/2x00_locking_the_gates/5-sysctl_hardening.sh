#!/bin/bash
# 5-sysctl_hardening.sh - Kernel network stack and memory protection hardening via sysctl.
#
# MedDefense 2x00 "Locking the Gates" - Task 5
# Crimson Tide Phase 3: the attacker pivoted across a flat network. A compromised server that
# forwards packets or obeys ICMP redirects becomes the attacker's router; disabled ASLR makes
# memory-corruption exploits reliable.
#
# Idempotent: managed parameters live in one marked block in /etc/sysctl.conf that is rewritten
# on every run; other active lines for the same keys in that file are removed. /etc/sysctl.conf
# is loaded last at boot (/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf), so these values win
# over earlier drop-ins and persist across reboots.
#
# CIS items intentionally NOT applied here (justified deviations):
#   - net.ipv4.conf.*.rp_filter: Ubuntu already ships rp_filter=2 (loose) in
#     /etc/sysctl.d/10-network-security.conf; strict mode (1) can drop legitimate traffic on the
#     multi-homed billing host (NAT + meddefense-net). Compensating control: UFW default-deny (Task 13).
#   - net.ipv4.conf.*.secure_redirects / default.send_redirects / default.accept_source_route:
#     out of the agreed 14-parameter scope; the "all" variants below already override per-interface
#     behaviour for redirects and source routing on existing interfaces.

export LC_ALL=C

SYSCTL_CONF=/etc/sysctl.conf
BACKUP="${SYSCTL_CONF}.bak"
ORIGINAL="${SYSCTL_CONF}.orig"
BEGIN_MARK="# BEGIN MedDefense kernel hardening (managed by 5-sysctl_hardening.sh - do not edit)"
END_MARK="# END MedDefense kernel hardening"

PARAMS=(
	# Not a router: stop the host being used to forward attacker traffic between segments - Crimson Tide Phase 3 pivot
	"net.ipv4.ip_forward=0"
	# Ignore ICMP redirects: prevents route injection / MITM of billing traffic - CIS 3.3.2
	"net.ipv4.conf.all.accept_redirects=0"
	"net.ipv4.conf.default.accept_redirects=0"
	# Hosts must not tell peers to reroute (only routers send redirects) - CIS 3.2.2
	"net.ipv4.conf.all.send_redirects=0"
	# Source-routed packets let an attacker choose the path and bypass filtering - CIS 3.3.1
	"net.ipv4.conf.all.accept_source_route=0"
	# Log spoofed/impossible source addresses so the SOC sees spoofing attempts - CIS 3.3.4, Finding: no IDS (1x00)
	"net.ipv4.conf.all.log_martians=1"
	# SYN flood resilience for the internet-reachable Apache front end - CIS 3.3.8
	"net.ipv4.tcp_syncookies=1"
	# Do not answer broadcast pings (smurf amplification) - CIS 3.3.5
	"net.ipv4.icmp_echo_ignore_broadcasts=1"
	# MedDefense networks are IPv4-only; an unused IPv6 stack is unmonitored and unfiltered attack
	# surface (firewall rules and network monitoring cover IPv4 only) - CIS 3.1.1
	"net.ipv6.conf.all.disable_ipv6=1"
	"net.ipv6.conf.default.disable_ipv6=1"
	# Full ASLR (stack, mmap, heap): makes memory-corruption exploits unreliable - CIS 1.5.3
	"kernel.randomize_va_space=2"
	# No core dumps from SUID programs: they can leak password hashes / PHI from memory - CIS 1.5.1
	"fs.suid_dumpable=0"
	# Kernel ring buffer readable by root only: hides addresses useful for kernel exploits
	"kernel.dmesg_restrict=1"
	# Hide kernel pointers from everyone (incl. root via %pK): defeats KASLR leaks - 1x02 Finding 026 (kernel CVEs)
	"kernel.kptr_restrict=2"
)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi

# --- Backup ---------------------------------------------------------------------
echo "[*] Backing up $SYSCTL_CONF"
touch "$SYSCTL_CONF"
[ -f "$ORIGINAL" ] || cp -p "$SYSCTL_CONF" "$ORIGINAL"
cp -p "$SYSCTL_CONF" "$BACKUP"

# --- Apply ----------------------------------------------------------------------
echo "[*] Applying kernel hardening parameters..."
KEYS=""
for p in "${PARAMS[@]}"; do
	KEYS="$KEYS ${p%%=*}"
done

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
{
	# Drop the previous managed block and any other active line setting a managed key
	awk -v keys="$KEYS" -v begin="$BEGIN_MARK" -v end="$END_MARK" '
		BEGIN { n = split(keys, a, " "); for (i = 1; i <= n; i++) managed[a[i]] = 1 }
		$0 == begin { skip = 1; next }
		$0 == end   { skip = 0; next }
		skip        { next }
		{
			line = $0
			sub(/^[ \t]*/, "", line)
			split(line, kv, "=")
			key = kv[1]; gsub(/[ \t]/, "", key)
			if (line !~ /^[#;]/ && (key in managed)) next
			print
		}
	' "$SYSCTL_CONF"
	echo "$BEGIN_MARK"
	for p in "${PARAMS[@]}"; do
		echo "${p%%=*} = ${p#*=}"
	done
	echo "$END_MARK"
} > "$TMP" && cat "$TMP" > "$SYSCTL_CONF"

# apport (Ubuntu crash reporter) writes fs.suid_dumpable=2 every time it starts
# (/etc/init.d/apport), silently undoing the setting above at each boot. Crash dumps of
# privileged processes can contain password hashes and PHI, and MedDefense servers do not send
# crash reports to Canonical, so apport is switched off (enabled=0 makes its init script a no-op).
if [ -f /etc/default/apport ]; then
	if grep -q '^enabled=1' /etc/default/apport || systemctl is-active --quiet apport.service; then
		echo "[*] Disabling apport (resets fs.suid_dumpable=2 at boot)"
	fi
	sed -i 's/^enabled=1/enabled=0/' /etc/default/apport
	systemctl stop apport.service >/dev/null 2>&1
	systemctl disable apport.service apport-forward.socket apport-autoreport.path \
		apport-autoreport.timer >/dev/null 2>&1
fi

# Load /etc/sysctl.conf immediately
if ! sysctl -p "$SYSCTL_CONF" >/dev/null 2>"$TMP"; then
	sed 's/^/    sysctl -p: /' "$TMP" >&2
fi

# --- Verify against the live kernel (/proc/sys) -----------------------------------
pass=0
fail=0
for p in "${PARAMS[@]}"; do
	key="${p%%=*}"
	want="${p#*=}"
	have=$(cat "/proc/sys/${key//.//}" 2>/dev/null)
	if [ "$have" = "$want" ]; then
		status="[PASS]"
		pass=$((pass + 1))
	else
		status="[FAIL] (actual: ${have:-unavailable})"
		fail=$((fail + 1))
	fi
	printf '%-42s %s\n' "$key = $want" "$status"
done

echo "Parameters applied: ${#PARAMS[@]}"
echo "Verified PASS: $pass"
echo "Verified FAIL: $fail"
[ "$fail" -eq 0 ]
