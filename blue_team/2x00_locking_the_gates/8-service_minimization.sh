#!/bin/bash
# 8-service_minimization.sh - PAM hardening: password quality, account lockout, password history.
# (Task 8 "The PAM Fortress"; the file name is the one mandated by the project checker.)
#
# MedDefense 2x00 "Locking the Gates" - Task 8
# Crimson Tide: in 3 of 5 breaches the attacker used harvested credentials (Phase 2) and cracked
# service-account passwords (Kerberoasting, Phase 3). 1x02 Finding 009: no account lockout, so
# online brute force is unlimited. Weak, reused passwords are the root cause - PAM enforces policy.
#
# Implementation notes:
#   - Password quality lives in /etc/security/pwquality.conf (read by pam_pwquality).
#     "reject_username" is a pam_cracklib argument; libpwquality rejects it as an unknown setting
#     (which would break every password change), so the pwquality equivalent "usercheck = 1"
#     is used: passwords containing the user name (straight or reversed) are rejected.
#   - Lockout uses pam_faillock (/etc/security/faillock.conf) wired into common-auth/common-account
#     through pam-auth-update profiles, so future PAM package upgrades keep the configuration.
#   - libpam 1.4.0 (Ubuntu 22.04) has no pwhistory.conf; "remember" is a module argument set via
#     a pam-auth-update profile. History is stored in /etc/security/opasswd.
#   - Lockout is not applied to root (no even_deny_root): root cannot SSH in (Task 4) and local
#     console root access is the recovery path if an attacker locks out every admin. Compensating
#     control: root/sudo use is audited by auditd (Task 10).
# Idempotent: settings are rewritten in place; profiles and pam-auth-update produce the same files.

export LC_ALL=C

PWQ_CONF=/etc/security/pwquality.conf
FAILLOCK_CONF=/etc/security/faillock.conf
PAM_CONFIGS=/usr/share/pam-configs
REMEMBER=12

# Password quality - "key value" (value empty for flags)
PWQ_SETTINGS=(
	"minlen 14"     # 14+ chars: resists offline cracking of stolen hashes (CIS 5.3.3.2.2)
	"dcredit -1"    # at least one digit
	"ucredit -1"    # at least one upper-case letter
	"lcredit -1"    # at least one lower-case letter
	"ocredit -1"    # at least one symbol
	"maxrepeat 3"   # no "aaaa"-style padding to reach the length
	"usercheck 1"   # reject_username: password must not contain the account name
)

# Account lockout - Finding 009 (unlimited SSH/console guessing)
FAILLOCK_SETTINGS=(
	"deny 5"            # lock after 5 consecutive failures
	"unlock_time 900"   # locked for 15 minutes (slows brute force to ~20 guesses/hour)
	"fail_interval 900" # failures counted within a 15-minute window
)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi

# One-time backup of the pre-hardening PAM configuration (rollback: tar xzf <file> -C /)
PAM_BACKUP=/var/backups/meddefense-pam.orig.tar.gz
[ -f "$PAM_BACKUP" ] || tar czf "$PAM_BACKUP" -C / etc/pam.d etc/security 2>/dev/null

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# set_conf <file> <key> <value>: "key = value" (or bare "key" if value empty). Replaces the first
# active or commented occurrence, removes later active duplicates, appends if absent.
set_conf() {
	local file="$1" key="$2" value="$3" line
	if [ -n "$value" ]; then line="$key = $value"; else line="$key"; fi
	touch "$file"
	awk -v key="$key" -v line="$line" '
		function k(s) { sub(/^[ \t]*#?[ \t]*/, "", s); sub(/[ \t]*=.*/, "", s); sub(/[ \t].*/, "", s); return s }
		!done && k($0) == key && ($0 !~ /^[ \t]*#/ || $0 ~ /^#[ \t]*[a-z_]+[ \t]*(=|$)/) { print line; done = 1; next }
		done && $0 !~ /^[ \t]*#/ && k($0) == key { next }
		{ print }
		END { if (!done) print line }
	' "$file" > "$TMP" && cat "$TMP" > "$file"
}

# write_profile <name> <content>: pam-auth-update profile (rewritten every run)
write_profile() {
	printf '%s\n' "$2" > "$PAM_CONFIGS/$1"
	chmod 644 "$PAM_CONFIGS/$1"
}

# --- 1. libpam-pwquality ------------------------------------------------------------
echo "[*] Checking libpam-pwquality..."
if dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
	echo "    Already installed: libpam-pwquality $(dpkg-query -W -f='${Version}' libpam-pwquality)"
else
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-pwquality >/dev/null 2>&1 \
		|| { echo "    Installation failed" >&2; exit 1; }
	echo "    Installed: libpam-pwquality $(dpkg-query -W -f='${Version}' libpam-pwquality)"
fi

# --- 2. Password quality ------------------------------------------------------------------
echo "[*] Configuring password quality ($PWQ_CONF)..."
for s in "${PWQ_SETTINGS[@]}"; do
	key="${s%% *}"
	value="${s#* }"
	set_conf "$PWQ_CONF" "$key" "$value"
	label="$key = $value"
	[ "$key" = usercheck ] && label="reject_username"
	printf '    %-32s %s\n' "$label" "[SET]"
done

# --- 3. Account lockout -------------------------------------------------------------------
echo "[*] Configuring account lockout (pam_faillock)..."
for s in "${FAILLOCK_SETTINGS[@]}"; do
	set_conf "$FAILLOCK_CONF" "${s%% *}" "${s#* }"
	printf '    %-32s %s\n' "${s%% *} = ${s#* }" "[SET]"
done
# preauth (before pam_unix) refuses locked accounts; authfail (after pam_unix) records failures;
# account phase resets the counter after a successful login.
write_profile faillock "Name: Enable pam_faillock to deny access after repeated failures
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail"
write_profile faillock_notify "Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so"

# --- 4. Password history ------------------------------------------------------------------
echo "[*] Configuring password history..."
# Priority 1023: after pam_pwquality (1024) which collects the new password, before pam_unix (256)
write_profile pwhistory "Name: Password history - reject the last $REMEMBER passwords
Default: yes
Priority: 1023
Password-Type: Primary
Password:
	requisite	pam_pwhistory.so remember=$REMEMBER enforce_for_root use_authtok"
touch /etc/security/opasswd
chown root:root /etc/security/opasswd
chmod 600 /etc/security/opasswd
printf '    %-32s %s\n' "remember = $REMEMBER" "[SET]"

# Regenerate /etc/pam.d/common-* from the profiles
DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock faillock_notify pwhistory pwquality \
	|| { echo "pam-auth-update failed" >&2; exit 1; }

# --- 5. Validation --------------------------------------------------------------------------
fail=0
check() {
	# check <file> <regex> <description>
	if grep -Eq "$2" "$1"; then return 0; fi
	echo "    [FAIL] $3 ($1)" >&2
	fail=1
}
check "$PWQ_CONF" '^minlen = 14$' "minlen"
check "$PWQ_CONF" '^usercheck = 1$' "usercheck"
check "$FAILLOCK_CONF" '^deny = 5$' "faillock deny"
check "$FAILLOCK_CONF" '^unlock_time = 900$' "faillock unlock_time"
check /etc/pam.d/common-auth 'pam_faillock\.so preauth' "faillock preauth"
check /etc/pam.d/common-auth 'pam_faillock\.so authfail' "faillock authfail"
check /etc/pam.d/common-account 'pam_faillock\.so' "faillock account"
check /etc/pam.d/common-password 'pam_pwquality\.so' "pwquality module"
check /etc/pam.d/common-password "pam_pwhistory\.so .*remember=$REMEMBER" "pwhistory remember"
# pwhistory must come after pwquality and before pam_unix in the password stack
order=$(grep -oE 'pam_(pwquality|pwhistory|unix)\.so' /etc/pam.d/common-password | tr '\n' ' ')
[ "$order" = "pam_pwquality.so pam_pwhistory.so pam_unix.so " ] \
	|| { echo "    [FAIL] password stack order: $order" >&2; fail=1; }
# libpwquality must parse the config (an unknown key breaks every password change).
# pwscore (libpwquality-tools) is optional; the check runs only where it is installed.
if command -v pwscore >/dev/null 2>&1 \
	&& echo "MedDefense-Validation-9x!" | pwscore 2>&1 | grep -q "Unknown setting"; then
	echo "    [FAIL] $PWQ_CONF contains an unknown setting" >&2
	fail=1
fi
[ "$fail" -eq 0 ] || { echo "PAM validation FAILED" >&2; exit 1; }

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: $REMEMBER"
