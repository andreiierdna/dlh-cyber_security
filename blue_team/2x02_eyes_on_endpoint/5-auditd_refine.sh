#!/bin/bash
# =============================================================================
# Name:    5-auditd_refine.sh
# Purpose: Refine the 2x00 auditd rules with detection-focused rules (process
#          execution, network sockets, SSH keys, cron, sudoers.d, shadow reads)
#          and prove each new rule fires.
# Author:  MedDefense blue team (Holberton 2x02 - Task 5)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 5
# 2x00 covered identity files, privilege escalation and tool execution. The gap
# is behaviour: what runs (execve), what talks to the network (socket/connect),
# who touches SSH keys, cron and sudoers.d. Without these the SOC sees the
# consequences of an intrusion but not the intrusion itself.
#
# Idempotent: the refine rules file is regenerated with identical content and
# reloaded; rules already active before the run report [OK].
#
# Deviations from the task text (justified):
#   - "-w /home/*/.ssh/" is not valid for auditctl (no glob expansion: it fails
#     with "Invalid path"), so one watch is created per existing home directory.
#   - "cron_persist" covers /etc/cron.d/, /etc/crontab and /var/spool/cron/ so
#     every rename-and-run persistence path is covered.
#   - An extra read rule on /etc/shadow (key identity) is added: the 2x00 watch
#     uses -p wa, so reading the hash file - the step before offline cracking -
#     produced no event. Task 12 expects that action to be auditable.
#   - execve tracking intentionally has no auid filter: every command on the
#     host is recorded (Sysmon EID 1 equivalent). Volume is handled by log
#     rotation, not by dropping activity the SOC needs.
# =============================================================================

set -o pipefail
export LC_ALL=C

RULES_FILE=/etc/audit/rules.d/20-meddefense-refine.rules

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
for c in auditctl ausearch augenrules jq; do
	command -v "$c" >/dev/null 2>&1 || { echo "Error: $c not found" >&2; exit 1; }
done

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# --- Rules -------------------------------------------------------------------
RULES=(
	# Process execution - Linux equivalent of Sysmon EID 1: every execve with
	# exe, comm and arguments. The primary "what did the attacker run" source.
	"-a always,exit -F arch=b64 -S execve -k process_exec"
	# Socket creation and outbound connections: reverse shells, C2, exfiltration
	"-a always,exit -F arch=b64 -S socket -S connect -k network_connect"
	# Cron persistence - created, modified or removed
	"-w /etc/cron.d/ -p wa -k cron_persist"
	"-w /etc/crontab -p wa -k cron_persist"
	"-w /var/spool/cron/ -p wa -k cron_persist"
	# sudoers.d: a one-line drop-in is the standard passwordless-root trick
	"-w /etc/sudoers.d/ -p wa -k sudoers"
	# Reading the password database precedes offline hash cracking
	"-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=r -k identity"
)

# Expand the SSH key watch per home directory (auditctl cannot glob)
for d in /home/*/.ssh /root/.ssh; do
	[ -d "$d" ] && RULES+=("-w $d/ -p rwa -k ssh_keys")
done

# Human labels per audit key
declare -A LABEL=(
	[process_exec]="execve syscall tracking"
	[network_connect]="socket/connect syscall tracking"
	[cron_persist]="cron persistence monitoring"
	[sudoers]="sudoers.d monitoring"
	[ssh_keys]="SSH key file monitoring"
	[identity]="shadow read monitoring"
)
rule_key() { sed -nE 's/.*-k ([^ ]+).*/\1/p' <<< "$1"; }

# --- Rule matching ------------------------------------------------------------
# auditctl -l renders rules differently from how they are written:
#   -k KEY        ->  -F key=KEY
#   -S a -S b     ->  -S a,b
#   -F path=...   ->  gains "-S all", fields reordered
# so each rule is verified by its semantic parts (watch path / path+perm+key /
# key) instead of by exact string comparison.
rule_loaded() {
	local r="$1" path perm key
	key=$(rule_key "$r")
	if [[ "$r" == -w* ]]; then
		path=$(awk '{print $2}' <<< "$r")
		path="${path%/}"
		auditctl -l 2>/dev/null | awk -v p="$path" '
			$1 == "-w" { q = $2; sub(/\/+$/, "", q); if (q == p) f = 1 }
			END { exit(f ? 0 : 1) }'
		return
	fi
	if [[ "$r" == *"-F path="* ]]; then
		path=$(sed -nE 's/.*-F path=([^ ]+).*/\1/p' <<< "$r")
		perm=$(sed -nE 's/.*-F perm=([^ ]+).*/\1/p' <<< "$r")
		auditctl -l 2>/dev/null | grep -F "path=$path" | grep -F "perm=$perm" | grep -qF "key=$key"
		return
	fi
	auditctl -l 2>/dev/null | grep -qF "key=$key"
}

rule_label() {
	local key label
	key=$(rule_key "$1")
	label="${LABEL[$key]:-$key}"
	if [[ "$1" == -w* ]]; then
		label="$label ${2}"
	fi
	echo "$label"
}

echo "[*] Current auditd rules: $(auditctl -l 2>/dev/null | grep -c .)"

echo "[*] Adding detection-focused rules..."
{
	echo "## MedDefense detection refinement - managed by 5-auditd_refine.sh"
	printf '%s\n' "${RULES[@]}"
} > "$RULES_FILE"
chmod 640 "$RULES_FILE"

ADDED=0
for r in "${RULES[@]}"; do
	path=""
	[[ "$r" == -w* ]] && path=$(awk '{print $2}' <<< "$r")
	if rule_loaded "$r"; then
		state="[OK]"
	else
		state="[ADDED]"
		ADDED=$((ADDED + 1))
	fi
	printf '    %-34s %-24s %s\n' "$(rule_label "$r" "$path")" "$(rule_key "$r")" "$state"
done

# --- Load and verify ------------------------------------------------------------------
if augenrules --load >/dev/null 2>&1; then
	echo "[*] Loading rules... augenrules --load: OK"
else
	echo "[*] Loading rules... augenrules --load: FAILED" >&2
	exit 1
fi
MISSING=0
for r in "${RULES[@]}"; do
	rule_loaded "$r" || { echo "    not active: $r" >&2; MISSING=$((MISSING + 1)); }
done
echo "[*] Total rules: $(auditctl -l | grep -c .)"
[ "$MISSING" -eq 0 ] || { echo "Error: $MISSING rule(s) not loaded" >&2; exit 1; }

# --- Validation: every new rule must actually fire -------------------------------------
PASS=0
TOTAL=0
validate() {
	# validate <label> <audit key> <probe command> <detail regex>
	local label="$1" key="$2" probe="$3" detail="$4" d t events status out
	sleep 1   # ausearch resolution is one second
	d=$(date +%x)
	t=$(date +%T)
	bash -c "$probe" >/dev/null 2>&1
	sleep 2
	# Capture first: with pipefail, "ausearch | grep -q" fails on SIGPIPE (141) even
	# when grep matched, because grep exits as soon as it has a hit.
	out=$(ausearch --input-logs -m SYSCALL -k "$key" -ts "$d" "$t" -i 2>/dev/null)
	events=$(grep -c '^----' <<< "$out")
	if [ "$events" -gt 0 ]; then
		# -E: the patterns use "?" for the optional quotes around key= (auditd only
		# quotes in some versions) - plain grep would treat "?" literally
		if grep -Eqm1 -- "$detail" <<< "$out"; then
			status="[CAPTURED]"
			PASS=$((PASS + 1))
		else
			status="[PARTIAL]"
		fi
	else
		status="[MISSED]"
	fi
	TOTAL=$((TOTAL + 1))
	printf '    %-38s -> ausearch -k %-16s %s\n' "$label" "$key" "$status"
}

echo "[*] Validating new rules..."
validate "execve: ran /usr/bin/id" process_exec "/usr/bin/id -u" 'key="?process_exec|exe=/usr/bin/id'
validate "socket: curl localhost" network_connect "curl -s -m 2 -o /dev/null http://127.0.0.1/ || true" 'syscall=(socket|connect)'
validate "ssh_keys: touch ~/.ssh/test" ssh_keys "touch /home/analyst/.ssh/.audit-test && rm -f /home/analyst/.ssh/.audit-test" 'name=/home/analyst/.ssh/'
validate "cron: touch /etc/cron.d/test" cron_persist "touch /etc/cron.d/.audit-test && rm -f /etc/cron.d/.audit-test" 'name=/etc/cron.d/'
validate "sudoers: touch /etc/sudoers.d/test" sudoers "touch /etc/sudoers.d/.audit-test && rm -f /etc/sudoers.d/.audit-test" 'name=/etc/sudoers.d/'
validate "shadow read: read /etc/shadow" identity "head -1 /etc/shadow >/dev/null" 'name=/etc/shadow'

# Safety net: never leave probe artifacts behind
rm -f /home/analyst/.ssh/.audit-test /etc/cron.d/.audit-test /etc/sudoers.d/.audit-test

echo "Rules added: $ADDED | Validation: $PASS/$TOTAL PASS"
[ "$PASS" -eq "$TOTAL" ]
