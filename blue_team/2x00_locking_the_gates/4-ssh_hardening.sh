#!/bin/bash
# 4-ssh_hardening.sh - Harden OpenSSH server configuration.
#
# MedDefense 2x00 "Locking the Gates" - Task 4
# Addresses 1x02 Finding 009 (SSH password auth + no lockout = brute force) and
# Crimson Tide Phase 3 (harvested credentials reused for SSH lateral movement).
#
# Idempotent: managed settings live in one marked block in /etc/ssh/sshd_config that is
# rewritten on every run; any other active occurrence of a managed keyword (outside Match
# blocks) is removed, and conflicting directives in /etc/ssh/sshd_config.d/*.conf are
# commented out (drop-ins are Included first and OpenSSH keeps the FIRST value it reads,
# so e.g. cloud-init's "PasswordAuthentication yes" would silently win otherwise).
#
# LOCKOUT GUARD: PasswordAuthentication no + AllowUsers medadmin sysadmin means only those two
# accounts can log in, and only with a public key. Before touching anything the script checks
# that at least one AllowUsers account has a usable key (parsed by ssh-keygen, file permissions
# acceptable to sshd StrictModes) and aborts without changes otherwise.

export LC_ALL=C

SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d
BACKUP="${SSHD_CONFIG}.bak"
ORIGINAL="${SSHD_CONFIG}.orig"
BANNER_FILE=/etc/issue.net
BEGIN_MARK="# BEGIN MedDefense SSH hardening (managed by 4-ssh_hardening.sh - do not edit)"
END_MARK="# END MedDefense SSH hardening"

# Hardening settings: "Keyword Value" - each with the threat it addresses.
SETTINGS=(
	# Direct root login gives an attacker full control with one stolen password - 1x02 Finding 009
	"PermitRootLogin no"
	# Passwords are brute-forceable and were harvested in Crimson Tide Phase 2; keys only - 1x02 Finding 009
	"PasswordAuthentication no"
	# Accounts with empty passwords would be an unauthenticated door - CIS 5.2.11
	"PermitEmptyPasswords no"
	# X11 forwarding exposes the client display / adds a tunnelling channel - CIS 5.2.6
	"X11Forwarding no"
	# Limit guesses per connection to slow online brute force - 1x02 Finding 009
	"MaxAuthTries 3"
	# Drop idle sessions after 300s x 2 probes = 10 minutes: abandoned admin shells are hijack targets
	"ClientAliveInterval 300"
	"ClientAliveCountMax 2"
	# Only the two named administrators may use SSH; service/user accounts (e.g. mike, www-data)
	# can never become an SSH lateral-movement foothold - Crimson Tide Phase 3
	"AllowUsers medadmin sysadmin"
	# SSHv1 is cryptographically broken. OpenSSH >= 7.4 is v2-only and treats this keyword as
	# deprecated/ignored; kept for auditors and older builds - CIS 5.2.4
	"Protocol 2"
	# Shorten the unauthenticated window to limit connection-exhaustion / slow brute force - CIS 5.2.17
	"LoginGraceTime 60"
	# Legal warning banner: authorized-use notice supports prosecution and HIPAA policy - CIS 1.7
	"Banner $BANNER_FILE"
)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
if [ ! -f "$SSHD_CONFIG" ]; then
	echo "Error: $SSHD_CONFIG not found (is openssh-server installed?)" >&2
	exit 1
fi

# --- Pre-flight: key-based access must already work ------------------------------
# Nothing has been changed yet. Disabling passwords while no allowed account has a usable key
# would make new SSH logins impossible, so the script stops here in that case.
ALLOW_USERS=""
for s in "${SETTINGS[@]}"; do
	[ "${s%% *}" = AllowUsers ] && ALLOW_USERS="${s#* }"
done
mkdir -p /run/sshd   # sshd -T needs the privilege separation directory
CURRENT=$(sshd -T 2>/dev/null)
AUTH_KEYS_FILES=$(awk '$1 == "authorizedkeysfile" { $1 = ""; print }' <<< "$CURRENT")
[ -n "$AUTH_KEYS_FILES" ] || AUTH_KEYS_FILES=".ssh/authorized_keys .ssh/authorized_keys2"
STRICT_MODES=$(awk '$1 == "strictmodes" { print $2 }' <<< "$CURRENT")

# private_group <gid> <user>: true if the group is the user's personal group (no other member,
# no other account using it as primary group)
private_group() {
	local gid="$1" user="$2" members others
	members=$(getent group "$gid" | cut -d: -f4)
	others=$(awk -F: -v g="$gid" -v u="$user" '$4 == g && $1 != u' /etc/passwd)
	[ "$gid" = "$(id -g "$user")" ] && { [ -z "$members" ] || [ "$members" = "$user" ]; } && [ -z "$others" ]
}

# strict_ok <path> <user> <home>: sshd (StrictModes yes) ignores a key file if the file or any
# directory up to the home directory is world-writable, group-writable (except by the user's
# personal group - Debian/Ubuntu "user-group-modes" patch) or owned by another user than the
# account owner or root
strict_ok() {
	local path="$1" user="$2" home="$3" owner perm
	[ "$STRICT_MODES" = no ] && return 0
	while :; do
		owner=$(stat -c %U "$path") || return 1
		perm=$(stat -c %a "$path") || return 1
		[ "$owner" = "$user" ] || [ "$owner" = root ] || return 1
		(( 8#$perm & 8#002 )) && return 1
		if (( 8#$perm & 8#020 )) && ! private_group "$(stat -c %g "$path")" "$user"; then
			return 1
		fi
		if [ "$path" = "$home" ] || [ "$path" = / ]; then
			return 0
		fi
		path=$(dirname "$path")
	done
}

echo "[*] Checking key-based access for AllowUsers ($ALLOW_USERS)..."
KEY_USERS=0
for u in $ALLOW_USERS; do
	home=$(getent passwd "$u" | cut -d: -f6)
	if [ -z "$home" ]; then
		printf '    %-10s no such account          [NO ACCESS]\n' "$u"
		continue
	fi
	keys=0
	note=""
	for f in $AUTH_KEYS_FILES; do
		f="${f//%h/$home}"
		f="${f//%u/$u}"
		f="${f//%%/%}"
		[[ "$f" = /* ]] || f="$home/$f"
		[ -f "$f" ] || continue
		if ! strict_ok "$f" "$u" "$home"; then
			note=" ($f ignored: unsafe ownership/permissions)"
			continue
		fi
		# ssh-keygen -l parses every line (key options allowed) and prints one fingerprint per
		# valid key; placeholders such as a bare "ssh-rsa" are rejected
		keys=$((keys + $(ssh-keygen -l -f "$f" 2>/dev/null | grep -c .)))
	done
	if [ "$keys" -gt 0 ]; then
		printf '    %-10s %d valid public key(s)     [OK]\n' "$u" "$keys"
		KEY_USERS=$((KEY_USERS + 1))
	else
		printf '    %-10s no valid public key       [NO ACCESS]%s\n' "$u" "$note"
	fi
done
if [ "$KEY_USERS" -eq 0 ]; then
	echo "[!] Aborting: no AllowUsers account ($ALLOW_USERS) has a valid public key." >&2
	echo "    With PasswordAuthentication no, nobody could open a new SSH session." >&2
	echo "    Deploy a key first (e.g. ssh-copy-id medadmin@<host>), then re-run. No changes were made." >&2
	exit 1
fi

# Restore sshd_config and drop-ins from this run's backups
restore_backup() {
	cp -p "$BACKUP" "$SSHD_CONFIG"
	local f
	for f in "$SSHD_DROPIN_DIR"/*.conf; do
		[ -f "$f.bak" ] && cp -p "$f.bak" "$f"
	done
}

# --- Backup ---------------------------------------------------------------------
echo "[*] Backing up $SSHD_CONFIG"
# Keep the pristine pre-hardening file once; .bak always holds the config from before this run.
[ -f "$ORIGINAL" ] || cp -p "$SSHD_CONFIG" "$ORIGINAL"
cp -p "$SSHD_CONFIG" "$BACKUP"

# --- Apply settings -------------------------------------------------------------
echo "[*] Applying SSH hardening settings..."
KEYS=""
for s in "${SETTINGS[@]}"; do
	KEYS="$KEYS ${s%% *}"
done

BLOCK=$(mktemp)
TMP=$(mktemp)
trap 'rm -f "$BLOCK" "$TMP"' EXIT
{
	echo "$BEGIN_MARK"
	printf '%s\n' "${SETTINGS[@]}"
	echo "$END_MARK"
} > "$BLOCK"

# 1) Drop the previous managed block and any other active global occurrence of managed keys.
#    Lines inside Match blocks are left untouched.
# 2) Insert the managed block before the first Match block (global scope) or at the end.
awk -v keys="$KEYS" -v begin="$BEGIN_MARK" -v end="$END_MARK" -v blockfile="$BLOCK" '
	BEGIN {
		n = split(tolower(keys), a, " ")
		for (i = 1; i <= n; i++) managed[a[i]] = 1
	}
	function emit_block(   line) {
		while ((getline line < blockfile) > 0) print line
		close(blockfile)
		done = 1
	}
	$0 == begin { skip = 1; next }
	$0 == end   { skip = 0; next }
	skip        { next }
	tolower($1) == "match" { if (!done) emit_block(); inmatch = 1 }
	!inmatch && (tolower($1) in managed) { next }
	{ print }
	END { if (!done) emit_block() }
' "$SSHD_CONFIG" > "$TMP" && cat "$TMP" > "$SSHD_CONFIG"

# Neutralise conflicting directives in drop-ins (they are read before our block).
for f in "$SSHD_DROPIN_DIR"/*.conf; do
	[ -f "$f" ] || continue
	cp -p "$f" "$f.bak"
	awk -v keys="$KEYS" '
		BEGIN { n = split(tolower(keys), a, " "); for (i = 1; i <= n; i++) managed[a[i]] = 1 }
		tolower($1) == "match" { inmatch = 1 }
		!inmatch && (tolower($1) in managed) { print "# [disabled by 4-ssh_hardening.sh] " $0; next }
		{ print }
	' "$f" > "$TMP" && cat "$TMP" > "$f"
done

for s in "${SETTINGS[@]}"; do
	echo "    $s"
done

# --- Banner ---------------------------------------------------------------------
cat > "$BANNER_FILE" <<'EOF'
***************************************************************************
                MedDefense Health Systems - AUTHORIZED ACCESS ONLY
This system processes protected health information (PHI). Access is
restricted to authorized personnel. All activity is monitored and logged.
Unauthorized access or use is prohibited and may result in disciplinary
action and civil and/or criminal penalties (HIPAA, 18 U.S.C. 1030).
Disconnect immediately if you are not an authorized user.
***************************************************************************
EOF
chmod 644 "$BANNER_FILE"

# --- Validate -------------------------------------------------------------------
echo "[*] Validating SSH configuration..."
mkdir -p /run/sshd
if ERR=$(sshd -t 2>&1); then
	echo "    sshd -t: OK"
else
	echo "    sshd -t: FAILED"
	echo "$ERR" | sed 's/^/    /'
	echo "[!] Restoring backup $BACKUP"
	restore_backup
	exit 1
fi

# --- Restart --------------------------------------------------------------------
echo "[*] Restarting SSH service..."
SERVICE=ssh.service
systemctl cat "$SERVICE" >/dev/null 2>&1 || SERVICE=sshd.service
# Existing sessions survive a restart (KillMode=process); only new logins see the new policy.
systemctl restart "$SERVICE"
if systemctl is-active --quiet "$SERVICE"; then
	echo "    $SERVICE: active (running)"
else
	echo "    $SERVICE: FAILED - restoring backup"
	restore_backup
	systemctl restart "$SERVICE"
	exit 1
fi

echo "Settings applied: ${#SETTINGS[@]}"
