#!/bin/bash
# 6-filesystem_hardening.sh - Remove dangerous filesystem permissions (SUID/SGID, world-writable),
# harden temporary filesystem mount options and restrict cron.
#
# MedDefense 2x00 "Locking the Gates" - Task 6
# Crimson Tide Phase 3 (privilege escalation): after initial access the affiliate escalates via
# unexpected SUID binaries and tampers with world-writable files executed by root. The 1x00
# crypto-miner on billing-srv-01 ran its payload from a temp directory.
#
# Idempotent: second run finds nothing to remediate and reports mounts as [OK].
# Original modes of every file changed are appended to $PERM_LOG for rollback.
#
# Scope notes / justified deviations:
#   - /proc, /sys, /dev, /run (pseudo/volatile) and /snap (read-only, signature-verified squashfs
#     that cannot be modified; snap helpers are confined by snapd/AppArmor) are excluded from scans.
#   - Whitelisted SUID binaries keep their bit even where CIS suggests reviewing them (e.g. pkexec,
#     chfn/chsh): they are distro-maintained, patched by unattended-upgrades (PwnKit CVE-2021-4034
#     is fixed in the installed polkit), and removing the bit from packaged files is reverted on
#     upgrade unless pinned with dpkg-statoverride (which this script does for any packaged binary
#     it strips).
#   - /tmp and /var/tmp are not separate partitions on this host (Lynis FILE-6310). Re-partitioning
#     a production server is out of scope; compensating control: each is bind-mounted onto itself
#     with nodev,nosuid,noexec (persisted in /etc/fstab), which gives the same execution controls.

export LC_ALL=C

PERM_LOG=/var/backups/meddefense-fs-permissions.log
PRUNE=( \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o )
MOUNT_OPTS=(nodev nosuid noexec)
CRON_USERS=(root medadmin sysadmin)   # only administrators may schedule jobs (persistence vector)

# Known-safe SUID binaries shipped by Ubuntu 22.04 packages
SUID_WHITELIST=(
	/usr/bin/chfn                        # passwd: users update their own GECOS
	/usr/bin/chsh                        # passwd: users change their own shell
	/usr/bin/fusermount                  # fuse: unprivileged FUSE mounts
	/usr/bin/fusermount3                 # fuse3: unprivileged FUSE mounts
	/usr/bin/gpasswd                     # passwd: group password administration
	/usr/bin/mount                       # util-linux: user mounts from fstab
	/usr/bin/newgrp                      # login: switch group
	/usr/bin/passwd                      # passwd: users change their own password
	/usr/bin/pkexec                      # policykit-1: privileged actions (patched for PwnKit)
	/usr/bin/su                          # util-linux: switch user (audited, Task 10)
	/usr/bin/sudo                        # sudo: admin privilege escalation (audited, Task 10)
	/usr/bin/umount                      # util-linux: user unmounts
	/usr/bin/at                          # at: job scheduling (restricted like cron)
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper  # dbus: system bus activation
	/usr/lib/openssh/ssh-keysign         # openssh-client: host-based auth helper
	/usr/libexec/polkit-agent-helper-1   # polkit: authentication agent
	/usr/lib/policykit-1/polkit-agent-helper-1   # polkit (older path)
	/usr/lib/snapd/snap-confine          # snapd: snap sandbox setup
	/usr/lib/eject/dmcrypt-get-device    # eject: dm-crypt device lookup
	/usr/sbin/pppd                       # ppp: dial-up (if installed)
)

# Known-safe SGID binaries shipped by Ubuntu 22.04 packages
SGID_WHITELIST=(
	/usr/bin/chage                       # passwd (group shadow): password ageing info
	/usr/bin/expiry                      # passwd (group shadow): expiry check
	/usr/bin/crontab                     # cron (group crontab): edit spool
	/usr/bin/ssh-agent                   # openssh-client: blocks ptrace of agent
	/usr/bin/wall                        # bsdutils (group tty): broadcast messages
	/usr/bin/write                       # bsdutils (group tty)
	/usr/bin/write.ul                    # bsdutils (group tty)
	/usr/bin/bsd-write                   # bsd-mailx (group tty)
	/usr/bin/dotlockfile                 # liblockfile (group mail)
	/usr/bin/mlocate                     # mlocate (group mlocate)
	/usr/bin/plocate                     # plocate (group plocate)
	/usr/bin/at                          # at (group daemon)
	/usr/lib/x86_64-linux-gnu/utempter/utempter  # libutempter (group utmp)
	/usr/sbin/unix_chkpwd                # libpam-modules (group shadow): PAM password check
	/usr/sbin/pam_extrausers_chkpwd      # libpam-extrausers (group shadow)
)

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
mkdir -p "$(dirname "$PERM_LOG")"

in_list() {
	local needle="$1" item
	shift
	for item in "$@"; do
		[ "$item" = "$needle" ] && return 0
	done
	return 1
}

# Record original mode, then apply chmod. Packaged files get a dpkg-statoverride so the
# change survives package upgrades.
remediate() {
	local mode="$1" path="$2"
	echo "$(date -Iseconds) $(stat -c '%a %U:%G' "$path") $path chmod $mode" >> "$PERM_LOG"
	chmod "$mode" "$path" || return 1
	if [ -f "$path" ] && dpkg-query -S "$path" >/dev/null 2>&1; then
		dpkg-statoverride --quiet --remove "$path" 2>/dev/null
		dpkg-statoverride --add "$(stat -c %U "$path")" "$(stat -c %G "$path")" \
			"$(stat -c %a "$path")" "$path" 2>/dev/null
	fi
}

# scan_special <perm> <bit-name> <chmod-mode> <whitelist...>; sets REMEDIATED
scan_special() {
	local perm="$1" name="$2" mode="$3"
	shift 3
	local list=() f wl=0 nwl=()
	mapfile -t list < <(find / "${PRUNE[@]}" -type f -perm "$perm" -print 2>/dev/null | sort)
	for f in "${list[@]}"; do
		if in_list "$f" "$@"; then
			wl=$((wl + 1))
		else
			nwl+=("$f")
		fi
	done
	echo "Found ${#list[@]} $name binaries"
	echo "Whitelisted: $wl"
	echo "Non-whitelisted: ${#nwl[@]}"
	REMEDIATED=0
	for f in "${nwl[@]}"; do
		if remediate "$mode" "$f"; then
			printf '  %-24s [%s REMOVED]\n' "$f" "$name"
			REMEDIATED=$((REMEDIATED + 1))
		else
			printf '  %-24s [%s REMOVAL FAILED]\n' "$f" "$name"
		fi
	done
}

# --- 1. SUID --------------------------------------------------------------------
scan_special -4000 SUID u-s "${SUID_WHITELIST[@]}"
SUID_FIXED=$REMEDIATED

# --- 2. SGID --------------------------------------------------------------------
scan_special -2000 SGID g-s "${SGID_WHITELIST[@]}"
SGID_FIXED=$REMEDIATED

# --- 3. World-writable files ----------------------------------------------------
# Regular files writable by anyone, and world-writable directories without the sticky bit
# (anyone could delete/replace files inside, e.g. a web uploads dir or a script dir run by root).
mapfile -t WW < <(find / "${PRUNE[@]}" \( -type f -perm -0002 -o -type d -perm -0002 ! -perm -1000 \) \
	-print 2>/dev/null | sort)
echo "Found ${#WW[@]} world-writable files"
WW_FIXED=0
for f in "${WW[@]}"; do
	label="$f"
	[ -d "$f" ] && label="$f/"
	if remediate o-w "$f"; then
		printf '  %-24s [FIXED]\n' "$label"
		WW_FIXED=$((WW_FIXED + 1))
	else
		printf '  %-24s [FAILED]\n' "$label"
	fi
done

# --- 4. Temporary filesystem mount options ---------------------------------------
# noexec: payloads dropped in temp dirs cannot run (1x00 crypto-miner); nosuid: no SUID planting;
# nodev: no device-node tricks. Persisted in /etc/fstab and applied live with a remount.

# Add missing options to an existing fstab entry for $1, or append a new entry ($2)
fstab_ensure() {
	local mnt="$1" newline="$2" tmp
	if awk -v m="$mnt" '$1 !~ /^#/ && $2 == m { found = 1 } END { exit !found }' /etc/fstab; then
		tmp=$(mktemp)
		awk -v m="$mnt" -v want="$(IFS=,; echo "${MOUNT_OPTS[*]}")" '
			BEGIN { n = split(want, w, ",") }
			$1 !~ /^#/ && $2 == m {
				for (i = 1; i <= n; i++) if (("," $4 ",") !~ ("," w[i] ",")) $4 = $4 "," w[i]
			}
			{ print }
		' /etc/fstab > "$tmp" && cat "$tmp" > /etc/fstab
		rm -f "$tmp"
	else
		echo "$newline" >> /etc/fstab
	fi
}

has_all_opts() {
	local opts=",$1," o
	for o in "${MOUNT_OPTS[@]}"; do
		[[ "$opts" == *",$o,"* ]] || return 1
	done
	return 0
}

OPTS_CSV=$(IFS=,; echo "${MOUNT_OPTS[*]}")
for mnt in /tmp /var/tmp /dev/shm; do
	[ -d "$mnt" ] || continue
	current=$(findmnt -n -o OPTIONS --mountpoint "$mnt" 2>/dev/null | tail -n 1)
	if [ -n "$current" ]; then
		# Already a mount point: ensure options persisted and active
		if [ "$mnt" = /dev/shm ]; then
			fstab_ensure "$mnt" "tmpfs /dev/shm tmpfs defaults,$OPTS_CSV 0 0"
		else
			fstab_ensure "$mnt" "$mnt $mnt none bind,$OPTS_CSV 0 0"
		fi
		if has_all_opts "$current"; then
			status="[OK]"
		elif [ "$(findmnt -n -o FSROOT --mountpoint "$mnt" | tail -n 1)" != "/" ]; then
			# bind mount: per-mount flags are changed with remount,bind
			mount -o "remount,bind,$OPTS_CSV" "$mnt" && status="[APPLIED]" || status="[FAILED]"
		else
			mount -o "remount,$OPTS_CSV" "$mnt" && status="[APPLIED]" || status="[FAILED]"
		fi
	else
		# Not a separate filesystem: bind-mount onto itself with restrictive options
		fstab_ensure "$mnt" "$mnt $mnt none bind,$OPTS_CSV 0 0"
		if mount --bind "$mnt" "$mnt" && mount -o "remount,bind,$OPTS_CSV" "$mnt"; then
			status="[APPLIED]"
		else
			status="[FAILED]"
		fi
	fi
	printf '%-9s %-20s %s\n' "$mnt:" "noexec,nosuid,nodev" "$status"
done
systemctl daemon-reload 2>/dev/null   # regenerate mount units from the updated fstab

# --- 5. Cron / at access ------------------------------------------------------------
# Cron is a persistence mechanism (Crimson Tide Phase 4). Allow-list only administrators;
# cron.deny is removed so the allow-list is authoritative (CIS 5.1.8 / 5.1.9).
for f in /etc/cron.allow /etc/at.allow; do
	printf '%s\n' "${CRON_USERS[@]}" > "$f"
	chown root:root "$f"
	chmod 640 "$f"
done
# crontab(1) is SGID crontab and must be able to read the allow-list
getent group crontab >/dev/null && chgrp crontab /etc/cron.allow
getent group daemon >/dev/null && chgrp daemon /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny
# Only root may read/modify system cron definitions (CIS 5.1.2 - 5.1.7)
[ -f /etc/crontab ] && chown root:root /etc/crontab && chmod 600 /etc/crontab
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
	[ -d "$d" ] && chown root:root "$d" && chmod 700 "$d"
done
echo "Cron access: /etc/cron.allow (${CRON_USERS[*]})  [RESTRICTED]"

echo "SUID remediated: $SUID_FIXED | SGID remediated: $SGID_FIXED | World-writable fixed: $WW_FIXED"
