#!/bin/bash
# 15-validation.sh - Read-only verification of every hardening control from Tasks 4-13.
#
# MedDefense 2x00 "Locking the Gates" - Task 15
# Configuration drift (a debug sysctl left on, a package upgrade rewriting sshd_config) silently
# reopens the doors closed this week. James Chen runs this every Monday: it changes NOTHING on the
# system, it only reads the live state, compares it with the expected value and reports.
#
# Usage: sudo ./15-validation.sh [report.json]
#   stdout     : one [PASS]/[FAIL] line per control + summary
#   report.json: optional machine-readable result (only written when a path is given)
# Exit code: 0 if every check passes, 1 if any check fails (2 = not run as root).

export LC_ALL=C

JSON_OUT="$1"
PASS=0
FAIL=0
RESULTS=()

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0) - sshd -T, auditctl and ufw need root to read state" >&2
	exit 2
fi

# check <task> <label> <actual> <expected>
check() {
	local task="$1" label="$2" actual="$3" expected="$4" status
	if [ "$actual" = "$expected" ]; then
		status=PASS
		PASS=$((PASS + 1))
		echo "[PASS] $label = $actual"
	else
		status=FAIL
		FAIL=$((FAIL + 1))
		echo "[FAIL] $label = ${actual:-<unset>} (expected: $expected)"
	fi
	RESULTS+=("$task"$'\t'"$label"$'\t'"$expected"$'\t'"$actual"$'\t'"$status")
}

# --- Task 4: SSH (effective configuration, includes drop-ins) ---------------------------------
SSHD=$(sshd -T 2>/dev/null)
sshd_val() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); v = (v ? v " " : "") $0 } END { print v }' <<< "$SSHD"; }
check 4 "PermitRootLogin" "$(sshd_val permitrootlogin)" "no"
check 4 "PasswordAuthentication" "$(sshd_val passwordauthentication)" "no"
check 4 "PermitEmptyPasswords" "$(sshd_val permitemptypasswords)" "no"
check 4 "X11Forwarding" "$(sshd_val x11forwarding)" "no"
check 4 "MaxAuthTries" "$(sshd_val maxauthtries)" "3"
check 4 "ClientAliveInterval" "$(sshd_val clientaliveinterval)" "300"
check 4 "ClientAliveCountMax" "$(sshd_val clientalivecountmax)" "2"
check 4 "AllowUsers" "$(sshd_val allowusers)" "medadmin sysadmin"
check 4 "LoginGraceTime" "$(sshd_val logingracetime)" "60"
check 4 "Banner" "$(sshd_val banner)" "/etc/issue.net"
check 4 "/etc/issue.net present" "$([ -s /etc/issue.net ] && echo yes || echo no)" "yes"
check 4 "ssh.service" "$(systemctl is-active ssh.service)" "active"

# --- Task 5: kernel parameters (live values) -----------------------------------------------------
for kv in net.ipv4.ip_forward=0 net.ipv4.conf.all.accept_redirects=0 \
	net.ipv4.conf.default.accept_redirects=0 net.ipv4.conf.all.send_redirects=0 \
	net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.all.log_martians=1 \
	net.ipv4.tcp_syncookies=1 net.ipv4.icmp_echo_ignore_broadcasts=1 \
	net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 \
	kernel.randomize_va_space=2 fs.suid_dumpable=0 kernel.dmesg_restrict=1 kernel.kptr_restrict=2; do
	check 5 "${kv%=*}" "$(cat "/proc/sys/$(tr . / <<< "${kv%=*}")" 2>/dev/null)" "${kv#*=}"
done

# --- Task 6: filesystem ----------------------------------------------------------------------
PRUNE=( \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o )
SUID_WHITELIST=" /usr/bin/chfn /usr/bin/chsh /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/gpasswd \
/usr/bin/mount /usr/bin/newgrp /usr/bin/passwd /usr/bin/pkexec /usr/bin/su /usr/bin/sudo /usr/bin/umount \
/usr/bin/at /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/openssh/ssh-keysign \
/usr/libexec/polkit-agent-helper-1 /usr/lib/policykit-1/polkit-agent-helper-1 /usr/lib/snapd/snap-confine \
/usr/lib/eject/dmcrypt-get-device /usr/sbin/pppd "
SGID_WHITELIST=" /usr/bin/chage /usr/bin/expiry /usr/bin/crontab /usr/bin/ssh-agent /usr/bin/wall /usr/bin/write \
/usr/bin/write.ul /usr/bin/bsd-write /usr/bin/dotlockfile /usr/bin/mlocate /usr/bin/plocate /usr/bin/at \
/usr/lib/x86_64-linux-gnu/utempter/utempter /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd "
unexpected() {
	local perm="$1" wl="$2" n=0 f
	while read -r f; do
		[ -n "$f" ] && [[ "$wl" != *" $f "* ]] && n=$((n + 1))
	done < <(find / "${PRUNE[@]}" -type f -perm "$perm" -print 2>/dev/null)
	echo "$n"
}
check 6 "Non-whitelisted SUID binaries" "$(unexpected -4000 "$SUID_WHITELIST")" "0"
check 6 "Non-whitelisted SGID binaries" "$(unexpected -2000 "$SGID_WHITELIST")" "0"
check 6 "World-writable files" "$(find / "${PRUNE[@]}" \( -type f -perm -0002 -o -type d -perm -0002 ! -perm -1000 \) -print 2>/dev/null | grep -c .)" "0"
for m in /tmp /var/tmp /dev/shm; do
	opts=",$(findmnt -n -o OPTIONS --mountpoint "$m" 2>/dev/null | tail -n 1),"
	have=""
	for o in noexec nosuid nodev; do
		[[ "$opts" == *",$o,"* ]] && have="${have:+$have,}$o"
	done
	check 6 "$m mount options" "$have" "noexec,nosuid,nodev"
done
check 6 "/etc/cron.allow present" "$([ -f /etc/cron.allow ] && echo yes || echo no)" "yes"
check 6 "/etc/cron.deny absent" "$([ -e /etc/cron.deny ] && echo no || echo yes)" "yes"

# --- Task 7: services ------------------------------------------------------------------------
for s in ssh apache2 mysql ufw auditd apparmor cron rsyslog systemd-timesyncd; do
	check 7 "$s.service" "$(systemctl is-active "$s.service" 2>/dev/null)" "active"
done
# Services that must never come back on the billing server
for s in avahi-daemon cups bluetooth ModemManager snmpd rpcbind; do
	state=$(systemctl is-enabled "$s.service" 2>/dev/null)
	case "$state" in
		enabled|enabled-runtime) ;;
		*) systemctl is-active --quiet "$s.service" 2>/dev/null && state="active" || state="disabled" ;;
	esac
	check 7 "$s.service" "$state" "disabled"
done

# --- Task 8: PAM -----------------------------------------------------------------------------------
conf_val() { sed -nE "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*([^[:space:]#]+).*/\1/p" "$1" 2>/dev/null | tail -n 1; }
check 8 "pwquality minlen" "$(conf_val /etc/security/pwquality.conf minlen)" "14"
for c in dcredit ucredit lcredit ocredit; do
	check 8 "pwquality $c" "$(conf_val /etc/security/pwquality.conf "$c")" "-1"
done
check 8 "pwquality maxrepeat" "$(conf_val /etc/security/pwquality.conf maxrepeat)" "3"
check 8 "pwquality usercheck (reject_username)" "$(conf_val /etc/security/pwquality.conf usercheck)" "1"
check 8 "faillock deny" "$(conf_val /etc/security/faillock.conf deny)" "5"
check 8 "faillock unlock_time" "$(conf_val /etc/security/faillock.conf unlock_time)" "900"
check 8 "faillock fail_interval" "$(conf_val /etc/security/faillock.conf fail_interval)" "900"
check 8 "common-auth pam_faillock" "$(grep -cE '^[^#].*pam_faillock\.so (preauth|authfail)' /etc/pam.d/common-auth)" "2"
check 8 "common-password pam_pwquality" "$(grep -cE '^[^#].*pam_pwquality\.so' /etc/pam.d/common-password)" "1"
check 8 "pwhistory remember" "$(sed -nE 's/^[^#].*pam_pwhistory\.so.*remember=([0-9]+).*/\1/p' /etc/pam.d/common-password)" "12"

# --- Task 9: AppArmor ------------------------------------------------------------------------------
check 9 "AppArmor module" "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" "Y"
check 9 "apparmor.service" "$(systemctl is-active apparmor.service)" "active"
profile_mode() {
	sed -nE "s/^$(sed 's/[][\/.*^$]/\\&/g' <<< "$1") \(([a-z]+)\)$/\1/p" /sys/kernel/security/apparmor/profiles 2>/dev/null
}
check 9 "AppArmor apache2 profile" "$(profile_mode apache2)" "enforce"
check 9 "AppArmor /usr/sbin/mysqld profile" "$(profile_mode /usr/sbin/mysqld)" "enforce"
check 9 "AppArmor meddefense-billing-app profile" "$(profile_mode meddefense-billing-app)" "enforce"
proc_label() {
	local pid
	pid=$(systemctl show -p MainPID --value "$1" 2>/dev/null)
	[ -n "$pid" ] && [ "$pid" != 0 ] && cat "/proc/$pid/attr/current" 2>/dev/null
}
check 9 "apache2 process confinement" "$(proc_label apache2.service)" "apache2 (enforce)"
check 9 "mysqld process confinement" "$(proc_label mysql.service)" "/usr/sbin/mysqld (enforce)"

# --- Task 10: auditd ----------------------------------------------------------------------------------
check 10 "auditd.service" "$(systemctl is-active auditd.service)" "active"
AUDIT_RULES=$(auditctl -l 2>/dev/null | sed -E 's#^-w ([^ ]*[^/ ])/+ #-w \1 #')
for r in "-w /etc/passwd -p wa -k identity" "-w /etc/shadow -p wa -k identity" \
	"-w /etc/group -p wa -k identity" "-w /etc/pam.d -p wa -k pam_config" \
	"-w /etc/ssh/sshd_config -p wa -k sshd_config" "-w /usr/bin/sudo -p x -k priv_esc" \
	"-w /usr/bin/su -p x -k priv_esc" "-w /etc/sudoers -p wa -k sudoers" \
	"-w /usr/bin/wget -p x -k suspicious_download" "-w /usr/bin/curl -p x -k suspicious_download" \
	"-w /usr/bin/nc -p x -k suspicious_netcat" "-w /var/lib/mysql -p wa -k meddefense_db" \
	"-w /etc/apache2 -p wa -k meddefense_web" "-w /etc/init.d -p wa -k startup_scripts"; do
	check 10 "audit rule [$r]" "$(grep -qxF -- "$r" <<< "$AUDIT_RULES" && echo loaded || echo missing)" "loaded"
done

# --- Task 12: logging -----------------------------------------------------------------------------------
check 12 "rsyslog.service" "$(systemctl is-active rsyslog.service)" "active"
for f in /var/log/auth.log /var/log/syslog; do
	check 12 "$f mode" "$(stat -c %a "$f" 2>/dev/null)" "640"
done
check 12 "rsyslog auth routing" "$(grep -cE '^auth,authpriv\.\* .*file="/var/log/auth\.log"' /etc/rsyslog.d/10-meddefense.conf 2>/dev/null)" "1"
LR=/etc/logrotate.d/meddefense-security-logs
check 12 "auth.log retention (days)" "$(awk '/^\/var\/log\/auth\.log/ { f = 1 } f && /rotate/ { print $2; exit }' "$LR" 2>/dev/null)" "90"
check 12 "syslog retention (days)" "$(awk '/^\/var\/log\/syslog/ { f = 1 } f && /rotate/ { print $2; exit }' "$LR" 2>/dev/null)" "60"

# --- Task 13: firewall ----------------------------------------------------------------------------------
UFW=$(ufw status verbose 2>/dev/null)
check 13 "UFW status" "$(sed -n 's/^Status: //p' <<< "$UFW")" "active"
check 13 "Default incoming" "$(sed -nE 's/^Default: ([a-z]+) \(incoming\).*/\1/p' <<< "$UFW")" "deny"
check 13 "Default outgoing" "$(sed -nE 's/^Default: .* ([a-z]+) \(outgoing\).*/\1/p' <<< "$UFW")" "allow"
check 13 "UFW logging" "$(sed -nE 's/^Logging: ([a-z]+).*/\1/p' <<< "$UFW")" "on"
RULES=$(sed -E 's/ +/ /g; s/ #.*$//' <<< "$UFW")
check 13 "SSH 22/tcp restricted to 10.10.1.0/24" "$(grep -E '^22/tcp ALLOW IN' <<< "$RULES" | awk '{print $4}' | paste -sd,)" "10.10.1.0/24"
check 13 "MySQL 3306/tcp restricted to 10.10.2.0/24" "$(grep -E '^3306/tcp ALLOW IN' <<< "$RULES" | awk '{print $4}' | paste -sd,)" "10.10.2.0/24"
check 13 "Allow rules (IPv4)" "$(grep 'ALLOW IN' <<< "$RULES" | grep -vc '(v6)')" "4"

# --- Summary ----------------------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo "Checks: $TOTAL | PASS: $PASS | FAIL: $FAIL"

if [ -n "$JSON_OUT" ] && command -v jq >/dev/null 2>&1; then
	printf '%s\n' "${RESULTS[@]}" | jq -R -s \
		--arg host "$(hostname)" --arg ts "$(date -Iseconds)" \
		--argjson pass "$PASS" --argjson fail "$FAIL" '
		{
			host: $host, timestamp: $ts,
			summary: {checks: ($pass + $fail), pass: $pass, fail: $fail, compliant: ($fail == 0)},
			checks: (split("\n") | map(select(length > 0) | split("\t")
				| {task: (.[0] | tonumber), control: .[1], expected: .[2], actual: .[3], status: .[4]}))
		}' > "$JSON_OUT"
	echo "Report saved to: $JSON_OUT"
fi

[ "$FAIL" -eq 0 ]
