#!/bin/bash
# 13-firewall_baseline.sh - Host firewall: default-deny inbound, only MedDefense-required services.
#
# MedDefense 2x00 "Locking the Gates" - Task 13
# 1x02: billing-srv-01 had 11 reachable ports and MySQL listening on 0.0.0.0 (Finding 006) on a
# flat network where any workstation, medical device or VPN user can reach any server (1x01
# attack surface map). The host firewall enforces least privilege at the network layer,
# independently of how each service is configured.
#
# Idempotent: ufw skips existing rules; any allow rule outside the baseline is deleted so the
# ruleset always equals the baseline below.
#
# LOCKOUT WARNING: SSH is only reachable from $MGMT_NET afterwards. Established sessions survive
# activation (conntrack ESTABLISHED), new ones from other networks are dropped and logged.

export LC_ALL=C

# Management network allowed to administer the host. The billing server's management NIC sits in
# 10.10.1.0/24 today. The 1x03 segmentation design moves administration to VLAN 40 (10.10.4.0/24,
# jump host) - update this value when that VLAN goes live.
MGMT_NET=10.10.1.0/24
# Application network allowed to query the billing database (server zone, 1x03 VLAN 20)
APP_NET=10.10.2.0/24

# port/proto | source ("any" = anywhere) | description
RULES=(
	"22/tcp|$MGMT_NET|SSH - management only"        # Finding 009 / Crimson Tide Phase 3: no SSH from workstations
	"80/tcp|any|HTTP"                               # billing web front end (redirect to HTTPS)
	"443/tcp|any|HTTPS"                             # billing web front end
	"3306/tcp|$APP_NET|MySQL - app network only"    # Finding 006: MySQL must not be reachable network-wide
)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
if ! command -v ufw >/dev/null 2>&1; then
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null 2>&1 \
		|| { echo "Error: cannot install ufw" >&2; exit 1; }
fi

# ufw status form of a rule, e.g. "22/tcp ALLOW IN 10.10.1.0/24" / "80/tcp ALLOW IN Anywhere"
status_form() {
	local port="$1" src="$2"
	[ "$src" = any ] && src="Anywhere"
	echo "$port ALLOW IN $src"
}

# --- 1. Default policies ---------------------------------------------------------------------
echo "[*] Configuring UFW..."
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
# Routed traffic is denied as well: this host must never forward (see Task 5, ip_forward=0)
ufw default deny routed >/dev/null
echo "    Default incoming: deny"
echo "    Default outgoing: allow"
# UFW re-applies /etc/ufw/sysctl.conf every time it starts (IPT_SYSCTL), i.e. after
# systemd-sysctl at boot. Ubuntu ships it with log_martians=0, which silently reverts the
# Task 5 setting (spoofed-source logging). Align it with the kernel baseline.
UFW_SYSCTL=/etc/ufw/sysctl.conf
if [ -f "$UFW_SYSCTL" ] && grep -qE '^net/ipv4/conf/(all|default)/log_martians=0' "$UFW_SYSCTL"; then
	sed -i -E 's#^(net/ipv4/conf/(all|default)/log_martians)=0#\1=1#' "$UFW_SYSCTL"
	echo "    $UFW_SYSCTL: log_martians=1 (aligned with Task 5)"
fi

# --- 2. Allow rules ----------------------------------------------------------------------------
echo "[*] Adding allow rules..."
WANTED=()
for r in "${RULES[@]}"; do
	IFS='|' read -r port src desc <<< "$r"
	proto="${port#*/}"
	num="${port%/*}"
	WANTED+=("$(status_form "$port" "$src")")
	# ufw prints "Rule added" (active) / "Rules updated" (inactive) for new rules and
	# "Skipping adding existing rule" for rules already present
	if [ "$src" = any ]; then
		out=$(ufw allow "$port" comment "$desc" 2>&1)
		label="$port"
	else
		out=$(ufw allow proto "$proto" from "$src" to any port "$num" comment "$desc" 2>&1)
		label="$port from $src"
	fi
	if grep -qE "^Rules? (added|updated)" <<< "$out"; then
		state="[ADDED]"
	elif grep -q "^Skipping" <<< "$out"; then
		state="[OK]"
	else
		state="[FAILED: $out]"
	fi
	printf '    %-26s %s %s\n' "$label" "$state" "$desc"
done

# --- 3. Logging ----------------------------------------------------------------------------------
# Blocked connection attempts are logged (kern -> /var/log/ufw.log): scanning and lateral-movement
# attempts against the billing server become visible to the SOC.
echo "[*] Enabling logging..."
ufw logging low >/dev/null
echo "    Logging: on ($(sed -n 's/^LOGLEVEL=//p' /etc/ufw/ufw.conf))"

# --- 4. Activate and validate ---------------------------------------------------------------------
echo "[*] Activating firewall..."
systemctl is-enabled --quiet ufw.service || systemctl enable ufw.service >/dev/null 2>&1
ufw --force enable >/dev/null
# "enable" on an already active firewall does not re-run IPT_SYSCTL; reload does
ufw reload >/dev/null

# Remove allow rules that are not part of the baseline (numbered listing needs an active
# firewall; highest number first so the remaining numbers stay valid)
ufw status numbered 2>/dev/null | sed -E 's/ +/ /g; s/ #.*$//; s/ $//' \
	| grep -E '^\[ ?[0-9]+\]' | tac | while read -r line; do
		n=$(sed -E 's/^\[ ?([0-9]+)\].*/\1/' <<< "$line")
		rule=$(sed -E 's/^\[ ?[0-9]+\] //; s/ \(v6\)//g' <<< "$line")
		keep=0
		for w in "${WANTED[@]}"; do
			[ "$rule" = "$w" ] && keep=1
		done
		if [ "$keep" -eq 0 ]; then
			ufw --force delete "$n" >/dev/null \
				&& printf '    %-26s [REMOVED] not in baseline\n' "$(sed -E 's/^\[ ?[0-9]+\] //' <<< "$line")"
		fi
	done

STATUS=$(ufw status verbose)
echo "    UFW: $(sed -n 's/^Status: //p' <<< "$STATUS")"
echo "[*] Active ruleset:"
sed -n '/^To/,$p' <<< "$STATUS" | sed 's/^/    /'
ALLOW=$(grep 'ALLOW IN' <<< "$STATUS" | grep -vc '(v6)')
DEFAULT_IN=$(sed -nE 's/^Default: ([a-z]+) \(incoming\).*/\1/p' <<< "$STATUS")
echo "    Rules: $ALLOW allow, default $DEFAULT_IN"
grep -q '^Status: active' <<< "$STATUS" && [ "$DEFAULT_IN" = deny ]
