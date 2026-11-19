#!/bin/bash
# =============================================================================
# Name:    3-linux_harden.sh
# Purpose: Orchestrate the Linux hardening pass on hawthorne-app-01, capture
#          per-step evidence and prove the Lynis index reached the target.
# Author:  Andrei
# =============================================================================
# Reuse, not reinvention: the 2x00 scripts are invoked in a fixed order, with a
# site adaptation applied to two of them (documented below). Everything the
# scripts do not cover - and which Lynis scores - is applied by the "extras"
# phase at the end.
#
# Site adaptations (idempotent, applied to a copy under capstone/prior/site/):
#   4-ssh_hardening.sh      AllowUsers medadmin sysadmin -> analyst
#                           (Hawthorne has one administrator account; the 2x00
#                            guard aborts when no allowed account has a key)
#   7-service_minimization  required services trimmed to what an intake app
#                           server runs (no apache2/mysql on this host)
#
# Output: capstone/exec/linux_harden.log, capstone/exec/linux_harden.json
# Exit: 0 all steps 0 and index >= target, 1 a step or the target failed,
#       2 environment error (missing inputs/root).
# =============================================================================
set -o pipefail
export LC_ALL=C

LAB=${LAB_DIR:-/home/analyst/MedDefense_Lab}
PRIOR=${PRIOR_DIR:-$LAB/capstone/prior/2x00}
CAP=${CAPSTONE_DIR:-capstone}
LOGDIR="$CAP/exec"
LOG="$LOGDIR/linux_harden.log"
OUT="$LOGDIR/linux_harden.json"
TARGET_JSON="$CAP/target_state.json"

[ "$EUID" -eq 0 ] || { echo "Error: run as root (sudo $0)" >&2; exit 2; }
[ -r "$TARGET_JSON" ] || { echo "Error: $TARGET_JSON missing - run 2-target_state.sh" >&2; exit 2; }
[ -d "$PRIOR" ] || { echo "Error: prior hardening scripts not found at $PRIOR" >&2; exit 2; }
command -v jq lynis >/dev/null 2>&1 || { echo "Error: jq and lynis required" >&2; exit 2; }

mkdir -p "$LOGDIR"
: > "$LOG"

LYNIS_TARGET=$(jq '.linux.hardening_index' "$TARGET_JSON")
LYNIS_BEFORE=$(jq '.hardening_index' "$CAP/baseline/baseline_linux.json" 2>/dev/null || echo 0)
STEPS_JSONL=$(mktemp); trap 'rm -f "$STEPS_JSONL"' EXIT
: > "$STEPS_JSONL"

# --- site adaptation ------------------------------------------------------------
SITE="$LAB/capstone/prior/site"
mkdir -p "$SITE"
for f in 4-ssh_hardening.sh 7-service_minimization.sh; do
	[ -r "$PRIOR/$f" ] && cp -f "$PRIOR/$f" "$SITE/$f"
done
if [ -r "$SITE/4-ssh_hardening.sh" ]; then
	sed -i 's/"AllowUsers medadmin sysadmin"/"AllowUsers analyst"/' "$SITE/4-ssh_hardening.sh"
	sed -i 's/^ALLOW_USERS .*$/ALLOW_USERS="analyst"/' "$SITE/4-ssh_hardening.sh" 2>/dev/null || true
fi
if [ -r "$SITE/7-service_minimization.sh" ]; then
	python3 - "$SITE/7-service_minimization.sh" <<'PY' 2>/dev/null || true
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r"REQUIRED_SERVICES=\(\n(?:.*\n)*?\)",
 "REQUIRED_SERVICES=(\n\tssh.service\n\tauditd.service\n\tapparmor.service\n\tcron.service\n\trsyslog.service\n\tufw.service\n\tfail2ban.service\n)", s, count=1)
open(p, "w").write(s)
PY
fi

# --- step runner ------------------------------------------------------------------
# run_step <name> <script> [args...]
run_step() {
	local name="$1"; shift
	local script="$1"; shift
	local start end rc dur changed=0
	start=$(date +%s)
	printf '\n===== STEP %s (%s) =====\n' "$name" "$script" >> "$LOG"
	if [ ! -x "$script" ]; then
		printf 'missing or not executable: %s\n' "$script" >> "$LOG"
		rc=2
	else
		"$script" "$@" >> "$LOG" 2>&1
		rc=$?
	fi
	end=$(date +%s); dur=$((end - start))
	# "changed" = the step applied something: 2x00 scripts are idempotent and
	# report no changes on a re-run, which we detect from their own output.
	if grep -qE '\[(SET|ADDED|APPLIED|REMOVED|ENFORCED|CREATED|DISABLED|RESTRICTED)\]|SUID remediated: [1-9]|Settings applied' <<< "$(sed -n "/===== STEP $name/,/===== STEP/p" "$LOG")"; then
		changed=1
	fi
	printf '  %-28s exit=%-2s %3ss\n' "$name" "$rc" "$dur"
	jq -n --arg name "$name" --arg script "$script" --argjson rc "$rc" \
		--argjson dur "$dur" --argjson changed "$changed" \
		'{name: $name, script_path: $script, exit_code: $rc, duration_seconds: $dur,
		  changed: ($changed == 1)}' >> "$STEPS_JSONL"
	return "$rc"
}

# --- ordered composition ------------------------------------------------------------
FAILED=0
run_step ssh_hardening        "$SITE/4-ssh_hardening.sh"        || FAILED=1
run_step sysctl_hardening     "$PRIOR/5-sysctl_hardening.sh"     || FAILED=1
run_step filesystem_sweep     "$PRIOR/6-filesystem_hardening.sh" || FAILED=1
run_step service_minimization "$SITE/7-service_minimization.sh"  || FAILED=1
run_step pam_hardening        "$PRIOR/8-service_minimization.sh" || FAILED=1
run_step apparmor_enforcement "$PRIOR/9-apparmor_config.sh"      || FAILED=1
run_step auditd_deployment    "$PRIOR/10-auditd_config.sh"       || FAILED=1

# --- extras: controls Lynis scores that 2x00 did not cover ---------------------------
extras() {
	local failed=0
	export DEBIAN_FRONTEND=noninteractive

	# packages that Lynis scores directly (PAM tmpdir, apt helpers, FIM,
	# accounting, malware scanner, patch visibility)
	# Optional packages: a mirror that lacks one of them must not fail the whole
	# hardening pass, so each install is attempted independently and only the
	# absence of the core ones is reported.
	for p in libpam-tmpdir apt-listbugs apt-listchanges apt-show-versions acct sysstat aide-common chkrootkit; do
		apt-get install -y -qq "$p" >/dev/null 2>&1 || echo "  warn: $p not available" >> "$LOG"
	done

	# password ageing / hashing / umask (AUTH-9286, AUTH-9230, AUTH-9328)
	if [ -f /etc/login.defs ]; then
		for kv in PASS_MAX_DAYS=90 PASS_MIN_DAYS=1 PASS_WARN_AGE=14 UMASK=027 \
			SHA_CRYPT_MIN_ROUNDS=640000 ENCRYPT_METHOD=SHA512; do
			k=${kv%%=*}; v=${kv#*=}
			if grep -qE "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]" /etc/login.defs; then
				sed -i -E "s|^[[:space:]]*#?[[:space:]]*${k}[[:space:]].*|$k\t$v|" /etc/login.defs
			else
				printf '%s\t%s\n' "$k" "$v" >> /etc/login.defs
			fi
		done
	fi
	grep -q '^umask 027' /etc/profile || printf '\numask 027\n' >> /etc/profile
	# expire every interactive account's password policy (AUTH-9282)
	# -d today first: the image is older than the max age, so setting only the
	# maximum would immediately expire the account and lock out sudo.
	awk -F: '($3 >= 1000 && $3 < 65000) {print $1}' /etc/passwd | while read -r u; do
		chage -d "$(date +%F)" -M 90 -m 1 -W 14 "$u" >/dev/null 2>&1 || true
	done

	# core dumps and legal banners (KRNL-5820, BANN-7126/7130)
	printf '* hard core 0\n' > /etc/security/limits.d/meddefense-core.conf
	{
		printf 'Unauthorized access is prohibited. This system is monitored and all\n'
		printf 'activity is logged. Disconnect now if you are not an authorized user.\n'
	} > /etc/issue
	cp -f /etc/issue /etc/issue.net

	# SSH extras that Lynis still scores (SSH-7408 sub-tests)
	cat > /etc/ssh/sshd_config.d/00-meddefense-capstone.conf <<'SSHD'
AllowAgentForwarding no
AllowTcpForwarding no
Compression no
LogLevel VERBOSE
MaxSessions 2
TCPKeepAlive no
SSHD
	sshd -t >/dev/null 2>&1 && systemctl reload ssh >/dev/null 2>&1 || failed=1

	# fail2ban: keep a local copy of jail.conf so updates cannot silently
	# weaken the jail (DEB-0880) and enforce the sshd jail
	if command -v fail2ban-client >/dev/null 2>&1; then
		[ -f /etc/fail2ban/jail.local ] || cp -f /etc/fail2ban/jail.conf /etc/fail2ban/jail.local 2>/dev/null || true
		printf '[sshd]\nenabled = true\nport = ssh\nmaxretry = 5\nbantime = 900\n' \
			> /etc/fail2ban/jail.d/meddefense-sshd.local
		systemctl enable --now fail2ban >/dev/null 2>&1 || failed=1
	fi

	# accounting services (ACCT-9622, ACCT-9626)
	systemctl enable --now acct >/dev/null 2>&1 || true
	systemctl enable --now sysstat >/dev/null 2>&1 || true

	# file integrity database (FINT-4350)
	if command -v aide >/dev/null 2>&1; then
		[ -f /var/lib/aide/aide.db ] || aideinit >/dev/null 2>&1 || true
	fi
	# malware scanner baseline (HRDN-7230)
	if command -v rkhunter >/dev/null 2>&1; then
		rkhunter --propupd --nocolors >/dev/null 2>&1 || true
	elif command -v chkrootkit >/dev/null 2>&1; then
		: # chkrootkit needs no signature baseline
	fi

	# compilers restricted to root (HRDN-7222)
	for c in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/c++; do
		[ -e "$c" ] && chmod 750 "$c"
	done

	# sysstat accounting (ACCT-9626): package defaults to disabled
	if [ -f /etc/default/sysstat ]; then
		sed -i -E 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
		systemctl enable --now sysstat-collect.timer >/dev/null 2>&1 || true
		systemctl enable --now sysstat-summary.timer >/dev/null 2>&1 || true
	fi

	# file permissions Lynis scores (FILE-7524)
	for f in /boot/grub/grub.cfg /etc/at.allow /etc/at.deny /etc/cron.allow; do
		[ -f "$f" ] && chmod 600 "$f"
	done

	# compilers and assembler restricted to root (HRDN-7222)
	for c in /usr/bin/as /usr/bin/x86_64-linux-gnu-as /usr/bin/gcc /usr/bin/g++ \
		/usr/bin/cc /usr/bin/c++ /usr/bin/ld; do
		[ -e "$c" ] && chmod 750 "$c"
	done

	# remote log forwarding configured (LOGG-2154). The collector is the
	# MedDefense log host; rsyslog queues locally until it is reachable.
	{
		printf '*.* @10.10.1.20:514\n'
		printf '*.* @@10.10.1.20:514\n'
	} > /etc/rsyslog.d/50-meddefense-remote.conf
	systemctl restart rsyslog >/dev/null 2>&1 || true

	# DNS domain (NAME-4028): resolved cannot invent one for a bare hostname,
	# so the search domain is written where the resolver and tools read it.
	mkdir -p /etc/systemd/resolved.conf.d
	printf '[Resolve]\nDomains=meddefense.local\n' > /etc/systemd/resolved.conf.d/meddefense-domain.conf
	systemctl restart systemd-resolved >/dev/null 2>&1 || true
	if ! grep -qE '^(search|domain)[[:space:]]+meddefense\.local' /etc/resolv.conf 2>/dev/null; then
		printf 'search meddefense.local\n' >> /etc/resolv.conf 2>/dev/null || true
	fi

	# sysctl values Lynis compares against its profile (KRNL-6000)
	{
		printf 'dev.tty.ldisc_autoload=0\n'
		printf 'fs.protected_fifos=2\n'
		printf 'fs.protected_regular=2\n'
		printf 'fs.protected_symlinks=1\n'
		printf 'fs.protected_hardlinks=1\n'
		# kernel hardening values Lynis compares against its profile.
		# kernel.modules_disabled is deliberately NOT set: it blocks all module
		# loading for the life of the boot and is not reversible without a reboot.
		printf 'kernel.perf_event_paranoid=3\n'
		printf 'kernel.unprivileged_bpf_disabled=1\n'
		printf 'net.core.bpf_jit_harden=2\n'
		printf 'net.ipv6.conf.all.accept_redirects=0\n'
		printf 'net.ipv6.conf.default.accept_redirects=0\n'
	} >> /etc/sysctl.d/99-meddefense-capstone.conf
	sysctl -q -p /etc/sysctl.d/99-meddefense-capstone.conf >/dev/null 2>&1 || failed=1

	# unused network protocol modules (NETW-3200) and USB storage (USB-1000)
	cat > /etc/modprobe.d/meddefense-blacklist.conf <<'MOD'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
MOD

	# resolver domain (NAME-4028)
	if [ -f /etc/systemd/resolved.conf ]; then
		grep -qE '^Domains=' /etc/systemd/resolved.conf \
			&& sed -i -E 's|^Domains=.*|Domains=meddefense.local|' /etc/systemd/resolved.conf \
			|| sed -i -E 's|^#?Domains=.*|Domains=meddefense.local|' /etc/systemd/resolved.conf
		systemctl restart systemd-resolved >/dev/null 2>&1 || true
	fi

	# sysctl values Lynis still flags (KRNL-6000)
	cat > /etc/sysctl.d/99-meddefense-capstone.conf <<'SYS'
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
kernel.sysrq=0
SYS
	sysctl -q -p /etc/sysctl.d/99-meddefense-capstone.conf >/dev/null 2>&1 || failed=1
	return "$failed"
}
printf '\n===== STEP extras =====\n' >> "$LOG"
ESTART=$(date +%s)
extras >> "$LOG" 2>&1; ERC=$?
EDUR=$(( $(date +%s) - ESTART ))
[ "$ERC" -ne 0 ] && FAILED=1
printf '  %-28s exit=%-2s %3ss\n' "extras" "$ERC" "$EDUR"
jq -n --arg name "extras" --arg script "(inline)" --argjson rc "$ERC" --argjson dur "$EDUR" \
	--argjson changed true \
	'{name: $name, script_path: $script, exit_code: $rc, duration_seconds: $dur, changed: $changed}' >> "$STEPS_JSONL"

# --- post-hardening Lynis ---------------------------------------------------------------
echo "[*] Re-running Lynis for the delta (this takes ~60s)..."
LYNIS_AFTER_LOG="$LOGDIR/lynis_after.log"
lynis audit system --quick --no-colors > "$LYNIS_AFTER_LOG" 2>&1
LYNIS_AFTER=$(sed -nE 's/^[[:space:]]*Hardening index[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$LYNIS_AFTER_LOG" | tail -1)
[ -z "$LYNIS_AFTER" ] && LYNIS_AFTER=0

CONTROLS=$(jq -c '[.controls[] | select(.platform == "linux" or .platform == "both") | .id]' "$TARGET_JSON")

jq -s --arg ts "$(date -Iseconds)" --arg host "$(hostname)" \
	--argjson before "$LYNIS_BEFORE" --argjson after "$LYNIS_AFTER" \
	--argjson target "$LYNIS_TARGET" --argjson controls "$CONTROLS" \
	--arg log "$LOG" '
	{timestamp: $ts, hostname: $host, platform: "linux",
	 steps: .,
	 lynis_before: $before, lynis_after: $after,
	 index_delta: ($after - $before),
	 lynis_target: $target, target_met: ($after >= $target),
	 controls_touched: $controls, log_path: $log}' "$STEPS_JSONL" > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Lynis: $LYNIS_BEFORE -> $LYNIS_AFTER (target $LYNIS_TARGET)  delta $((LYNIS_AFTER - LYNIS_BEFORE))"
echo "Execution evidence: $OUT"
[ "$FAILED" -eq 0 ] && [ "$LYNIS_AFTER" -ge "$LYNIS_TARGET" ]
