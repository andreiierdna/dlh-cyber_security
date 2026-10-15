#!/bin/bash
# 7-service_minimization.sh - Disable every enabled service that MedDefense does not require.
#
# MedDefense 2x00 "Locking the Gates" - Task 7
# CIS Benchmark Section 2: every running service is a potential entry point. 1x02 found
# billing-srv-01 exposing unnecessary services (Finding 006: MySQL on 0.0.0.0); Crimson Tide
# breaches started with a misconfigured, reachable service.
#
# Model: default-deny. Enabled services are compared against two allow-lists:
#   REQUIRED_SERVICES - what the billing server exists to do (verified running afterwards)
#   OS_CORE_SERVICES  - boot/storage/network/console plumbing; disabling these would brick the
#                       host or remove the out-of-band console. They are kept but not "required".
# Anything else is stopped and disabled, together with its socket units so socket activation
# cannot bring it back. Idempotent: a second run disables nothing.

export LC_ALL=C

# Services the MedDefense billing server needs
REQUIRED_SERVICES=(
	ssh.service               # remote administration (key-only, Task 4)
	apache2.service           # billing web front end
	mysql.service             # billing database (network access limited by UFW, Task 13)
	ufw.service               # host firewall (Task 13)
	auditd.service            # kernel audit trail for the SOC (Task 10)
	apparmor.service          # mandatory access control for exposed services (Task 9)
	cron.service              # scheduled maintenance (logrotate, backups)
	rsyslog.service           # auth/syslog collection and forwarding to log-srv-01 (Task 12)
	systemd-timesyncd.service # accurate timestamps - evidence correlation across hosts
)

# Operating-system plumbing that must stay enabled for the host to boot and be recoverable
OS_CORE_SERVICES=(
	systemd-networkd.service             # netplan network configuration (management + app NICs)
	systemd-networkd-wait-online.service # boot ordering: services start after the network
	networkd-dispatcher.service          # network state hooks used by netplan
	systemd-resolved.service             # local DNS resolver (127.0.0.53 only)
	systemd-pstore.service               # preserves kernel crash data (forensics)
	lvm2-monitor.service                 # root filesystem is on LVM
	blk-availability.service             # clean LVM/device shutdown
	e2scrub_reap.service                 # ext4 metadata check housekeeping
	finalrd.service                      # clean shutdown of root filesystem
	grub-common.service                  # boot success tracking
	grub-initrd-fallback.service         # boot fallback after failed initrd
	secureboot-db.service                # Secure Boot DB updates
	dmesg.service                        # saves boot kernel log to /var/log/dmesg (evidence)
	getty@.service                       # local console login: out-of-band recovery path
	keyboard-setup.service               # console keyboard
	console-setup.service                # console font/charset
	setvtrgb.service                     # console colours
	irqbalance.service                   # interrupt distribution (performance, no network exposure)
	unattended-upgrades.service          # automatic security patches - 1x02 Finding 026 (kernel CVEs)
	ubuntu-advantage.service             # Ubuntu Pro/ESM patch channel - 1x02 Finding 011
	ua-reboot-cmds.service               # completes Ubuntu Pro upgrade steps after reboot
)

# Socket units that would re-activate a disabled service (besides the same-named .socket)
declare -A COMPANION_UNITS=(
	[snapd.service]="snapd.socket"
	[snap.lxd.activate.service]="snap.lxd.daemon.unix.socket snap.lxd.user-daemon.unix.socket"
	[open-iscsi.service]="iscsid.socket"
	[multipathd.service]="multipathd.socket"
	[cloud-init.service]="cloud-init-hotplugd.socket"
)

# Expected to be disabled on this host (documented here so the reviewer sees why):
#   ModemManager             - no cellular modem; D-Bus exposed daemon
#   snmpd                    - SNMP not used for monitoring; v2c community strings are cleartext
#   cloud-init*              - not a cloud instance; datasource could reset SSH/password settings
#                              (it wrote "PasswordAuthentication yes", see Task 4)
#   snapd*, snap.lxd.*, lxd-agent - no snaps in use; lxd group membership = root escalation path
#   open-iscsi, multipathd   - no SAN storage
#   open-vm-tools, vgauth    - VMware guest tools on a non-VMware host
#   udisks2                  - desktop disk automount, history of local privilege escalation CVEs
#   gpu-manager, thermald    - no GPU / thermal hardware in a VM
#   pollinate                - boot-time outbound call to entropy.ubuntu.com
#   netfilter-persistent     - competing iptables loader; UFW is the single firewall manager

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi

in_list() {
	local needle="$1" item
	shift
	for item in "$@"; do
		[ "$item" = "$needle" ] && return 0
	done
	return 1
}

enabled_services() {
	systemctl list-unit-files --type=service --state=enabled --no-legend --plain | awk '{print $1}'
}

echo "[*] Scanning enabled services..."
mapfile -t ENABLED < <(enabled_services)
BEFORE=${#ENABLED[@]}
echo "    Enabled services found: $BEFORE"

echo "[*] Comparing against MedDefense whitelist (${#REQUIRED_SERVICES[@]} required services + ${#OS_CORE_SERVICES[@]} OS core services)..."
DISABLED=0
for svc in "${ENABLED[@]}"; do
	if in_list "$svc" "${REQUIRED_SERVICES[@]}" || in_list "$svc" "${OS_CORE_SERVICES[@]}"; then
		continue
	fi
	units=("$svc")
	sock="${svc%.service}.socket"
	systemctl cat "$sock" >/dev/null 2>&1 && units+=("$sock")
	for u in ${COMPANION_UNITS[$svc]}; do
		systemctl cat "$u" >/dev/null 2>&1 && units+=("$u")
	done
	systemctl stop "${units[@]}" >/dev/null 2>&1
	stopped="[STOPPED]"
	systemctl is-active --quiet "$svc" && stopped="[STOP FAILED]"
	if systemctl disable "${units[@]}" >/dev/null 2>&1; then
		disabled="[DISABLED]"
		DISABLED=$((DISABLED + 1))
	else
		disabled="[DISABLE FAILED]"
	fi
	printf '  %-36s %s %s\n' "$svc" "$stopped" "$disabled"
done

# Verify every required service is enabled and running; start it if not.
MISSING=0
for svc in "${REQUIRED_SERVICES[@]}"; do
	if ! systemctl cat "$svc" >/dev/null 2>&1; then
		printf '  %-36s %s\n' "$svc" "[NOT INSTALLED]"
		MISSING=$((MISSING + 1))
		continue
	fi
	systemctl is-enabled --quiet "$svc" || systemctl enable "$svc" >/dev/null 2>&1
	if systemctl is-active --quiet "$svc"; then
		state="[ACTIVE]"
	elif systemctl start "$svc" >/dev/null 2>&1 && systemctl is-active --quiet "$svc"; then
		state="[STARTED]"
	else
		state="[NOT RUNNING]"
		MISSING=$((MISSING + 1))
	fi
	printf '  %-36s %s\n' "$svc" "$state"
done

AFTER=$(enabled_services | grep -c .)
echo "Before: $BEFORE | After: $AFTER | Disabled: $DISABLED"
[ "$MISSING" -eq 0 ]
