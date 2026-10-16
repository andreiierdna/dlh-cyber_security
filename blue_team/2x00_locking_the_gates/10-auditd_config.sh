#!/bin/bash
# 10-auditd_config.sh - Deploy auditd with MedDefense audit rules.
#
# MedDefense 2x00 "Locking the Gates" - Task 10
# Marcus Webb, 1x00 incident notes: "No SIEM or IDS was deployed. Attacker moved undetected for
# 5 days." auditd records identity changes, privilege escalation, attacker tooling and tampering
# with MedDefense services at kernel level. These rules define what the SOC can see (Module 3).
#
# Idempotent: the rules file is rewritten with identical content and reloaded with augenrules;
# rules already active before the run are reported [OK].
#
# Justified deviations from CIS 4.1.x:
#   - The audit configuration is NOT made immutable (-e 2): that would require a reboot for every
#     rule change and break re-running this script and the Task 11 coverage test. Compensating
#     controls: changing rules requires root, and every sudo/su use is itself audited (priv_esc).
#   - The full CIS syscall rule set (time-change, mounts, module loading, ...) is out of scope for
#     this week; these rules cover the Crimson Tide techniques seen in the 1x00/1x01 analysis.
#   - Additions to the 14 baseline rules: the resolved netcat binary (see below) and cron
#     configuration watches, without which scheduled-task persistence (and the Task 11 cron
#     coverage test) would be invisible.

export LC_ALL=C

RULES_FILE=/etc/audit/rules.d/meddefense.rules

# MedDefense audit rules - each mapped to the threat it detects
RULES=(
	# Identity files: new/modified accounts are attacker persistence (Crimson Tide Phase 4)
	"-w /etc/passwd -p wa -k identity"
	"-w /etc/shadow -p wa -k identity"
	"-w /etc/group -p wa -k identity"
	# PAM stack tampering can disable lockout/password policy (Task 8) or plant a backdoor module
	"-w /etc/pam.d/ -p wa -k pam_config"
	# SSH daemon config: re-enabling password auth / root login (1x02 Finding 009)
	"-w /etc/ssh/sshd_config -p wa -k sshd_config"
	# Privilege escalation attempts (Crimson Tide Phase 3)
	"-w /usr/bin/sudo -p x -k priv_esc"
	"-w /usr/bin/su -p x -k priv_esc"
	"-w /etc/sudoers -p wa -k sudoers"
	# Tool download / payload staging - the 1x00 crypto-miner was fetched with a downloader
	"-w /usr/bin/wget -p x -k suspicious_download"
	"-w /usr/bin/curl -p x -k suspicious_download"
	# Netcat: reverse shells and data exfiltration
	"-w /usr/bin/nc -p x -k suspicious_netcat"
	# Billing database files: direct tampering outside MySQL (patient billing data integrity)
	"-w /var/lib/mysql/ -p wa -k meddefense_db"
	# Web server configuration: the 1x00 entry point
	"-w /etc/apache2/ -p wa -k meddefense_web"
	# Boot-time persistence via init scripts
	"-w /etc/init.d/ -p wa -k startup_scripts"
	# Scheduled-task persistence (Crimson Tide Phase 4); cron is restricted to admins in Task 6
	"-w /etc/crontab -p wa -k cron_config"
	"-w /etc/cron.d/ -p wa -k cron_config"
	"-w /var/spool/cron/crontabs/ -p wa -k cron_config"
)

# Execute watches match the inode actually executed. /usr/bin/nc is an alternatives symlink
# (-> nc.openbsd on Ubuntu), so the resolved binary is watched as well, otherwise netcat use
# would never be recorded.
NC_REAL=$(readlink -f /usr/bin/nc 2>/dev/null)
if [ -n "$NC_REAL" ] && [ "$NC_REAL" != /usr/bin/nc ]; then
	RULES+=("-w $NC_REAL -p x -k suspicious_netcat")
fi

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi

# --- 1. Install and enable auditd ---------------------------------------------------------
echo "[*] Enabling auditd service..."
if ! dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q "install ok installed"; then
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd >/dev/null 2>&1 \
		|| { echo "    auditd installation failed" >&2; exit 1; }
fi
systemctl is-enabled --quiet auditd.service || systemctl enable auditd.service >/dev/null 2>&1
systemctl is-active --quiet auditd.service || systemctl start auditd.service
if systemctl is-active --quiet auditd.service; then
	echo "    auditd.service: active (running)"
else
	echo "    auditd.service: FAILED to start" >&2
	exit 1
fi
if auditctl -s | grep -q '^enabled 2'; then
	echo "    Audit rules are immutable (enabled 2): reboot required to change them" >&2
	exit 1
fi

# --- 2. Deploy rules --------------------------------------------------------------------------
echo "[*] Deploying MedDefense audit rules..."
# Normalise "auditctl -l" style rules for comparison (directory watches lose the trailing slash)
normalize() { sed -E 's#^-w ([^ ]*[^/ ])/+ #-w \1 #'; }
BEFORE=$(auditctl -l 2>/dev/null | normalize)

{
	echo "## MedDefense audit rules - managed by 10-auditd_config.sh (do not edit by hand)"
	echo "## Threat mapping: see comments in 10-auditd_config.sh"
	printf '%s\n' "${RULES[@]}"
} > "$RULES_FILE"
chmod 640 "$RULES_FILE"

for r in "${RULES[@]}"; do
	if grep -qxF -- "$(echo "$r" | normalize)" <<< "$BEFORE"; then
		status="[OK]"
	else
		status="[ADDED]"
	fi
	printf '    %-45s %s\n' "$r" "$status"
done

# --- 3. Load and verify ----------------------------------------------------------------------
if augenrules --load >/dev/null 2>&1; then
	echo "[*] Loading rules... augenrules --load: OK"
else
	echo "[*] Loading rules... augenrules --load: FAILED" >&2
	exit 1
fi
ACTIVE=$(auditctl -l | normalize)
missing=0
for r in "${RULES[@]}"; do
	grep -qxF -- "$(echo "$r" | normalize)" <<< "$ACTIVE" || { echo "    not active: $r" >&2; missing=$((missing + 1)); }
done
echo "[*] Verifying... auditctl -l: $(grep -c . <<< "$ACTIVE") rules loaded ($(( ${#RULES[@]} - missing ))/${#RULES[@]} MedDefense rules active)"
[ "$missing" -eq 0 ] || exit 1

# --- 4. Trigger a test event ----------------------------------------------------------------
# The identity rules watch writes/attribute changes (-p wa), so a plain read would not be logged.
# A chmod to the file's current mode is a no-op that still issues the audited syscall.
echo "[*] Test: attribute change on /etc/shadow (chmod to current mode, no-op)..."
sleep 1   # keep the rule-load CONFIG_CHANGE records out of the search window
START=$(date +%H:%M:%S)
chmod "$(stat -c %a /etc/shadow)" /etc/shadow
sleep 2
# --input-logs: without it ausearch reads stdin whenever stdin is not a terminal (cron, pipes)
# -m SYSCALL: count the watched syscalls only, not rule-change records carrying the same key
EVENTS=$(ausearch --input-logs -m SYSCALL -ts "$START" -k identity 2>/dev/null | grep -c '^----')
if [ "$EVENTS" -gt 0 ]; then
	echo "    ausearch -ts $START -k identity: $EVENTS event(s) found [PASS]"
else
	echo "    ausearch -ts $START -k identity: 0 events found [FAIL]"
	exit 1
fi
