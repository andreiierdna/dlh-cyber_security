#!/bin/bash
# 12-log_config.sh - rsyslog routing/formatting, retention and log file permissions.
#
# MedDefense 2x00 "Locking the Gates" - Task 12
# auth.log is where SSH logins, sudo use and PAM lockouts (Tasks 4, 8) are recorded. 1x00: the
# attacker went unnoticed for 5 days; with Ubuntu's default weekly rotation x4 the evidence of a
# slow intrusion is gone after a month. This script makes the logs precise, retained and private,
# ready for the telemetry export of 2x02.
#
# Changes:
#   - /etc/rsyslog.d/10-meddefense.conf: auth/authpriv -> /var/log/auth.log and everything else
#     at info+ (auth and authpriv excluded) -> /var/log/syslog, both with RFC 3339 timestamps
#     (year, microseconds, timezone) plus facility.severity: unambiguous for correlation across
#     hosts and directly parseable by the SIEM. The equivalent lines in 50-default.conf are
#     commented out so nothing is written twice.
#   - /etc/logrotate.d/meddefense-security-logs: daily rotation, auth.log kept 90 days, syslog
#     60 days, rotated files compressed once older than 7 days (recent week stays grep-able for
#     incident response). Both files are removed from the stock /etc/logrotate.d/rsyslog block
#     (logrotate rejects duplicate entries).
#   - permissions 0640, no world access.
#
# Justified deviation: files are owned syslog:adm, not root:adm. Ubuntu's rsyslog drops
# privileges to the unprivileged "syslog" user ($PrivDropToUser), which could no longer write a
# root-owned 0640 file. Running rsyslog as root to get root ownership would widen the impact of an
# rsyslog vulnerability. Owner = the logging daemon only (no human login), read = adm group
# (administrators/analysts), world = none - equivalent confidentiality, better privilege separation.
#
# Idempotent: managed files are rewritten with the same content; stock lines are only commented once.

export LC_ALL=C

RSYSLOG_CONF=/etc/rsyslog.d/10-meddefense.conf
RSYSLOG_DEFAULT=/etc/rsyslog.d/50-default.conf
LOGROTATE_CONF=/etc/logrotate.d/meddefense-security-logs
LOGROTATE_STOCK=/etc/logrotate.d/rsyslog
LOG_OWNER=syslog
LOG_GROUP=adm
LOG_MODE=640
MARK="# [moved to 10-meddefense.conf by 12-log_config.sh]"

# file|selector|retention days
LOGS=(
	"/var/log/auth.log|auth,authpriv.*|90"
	"/var/log/syslog|*.info;auth,authpriv.none|60"
)
COMPRESS_AFTER_DAYS=7

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi
for p in rsyslog logrotate; do
	if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$p" >/dev/null 2>&1 \
			|| { echo "Error: cannot install $p" >&2; exit 1; }
	fi
done
id "$LOG_OWNER" >/dev/null 2>&1 || LOG_OWNER=root   # distributions where rsyslog runs as root

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# --- 1. rsyslog routing -------------------------------------------------------------------
echo "[*] Configuring rsyslog..."
{
	echo "# MedDefense log routing - managed by 12-log_config.sh (do not edit by hand)"
	echo "# RFC 3339 timestamps + facility.severity for cross-host correlation (SIEM export, 2x02)"
	echo 'template(name="MedDefenseFormat" type="string"'
	echo '  string="%timestamp:::date-rfc3339% %hostname% %syslogfacility-text%.%syslogseverity-text% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")'
	for l in "${LOGS[@]}"; do
		IFS='|' read -r file selector _ <<< "$l"
		echo "$selector action(type=\"omfile\" file=\"$file\" template=\"MedDefenseFormat\" fileCreateMode=\"0$LOG_MODE\")"
	done
} > "$RSYSLOG_CONF"
chmod 644 "$RSYSLOG_CONF"

# Comment out the stock actions for the same files (they would duplicate every message)
if [ -f "$RSYSLOG_DEFAULT" ]; then
	awk -v mark="$MARK" '
		$0 !~ /^[ \t]*#/ && ($NF ~ /^-?\/var\/log\/(auth\.log|syslog)$/) { print mark " " $0; next }
		{ print }
	' "$RSYSLOG_DEFAULT" > "$TMP" && cat "$TMP" > "$RSYSLOG_DEFAULT"
fi

if ! rsyslogd -N1 >"$TMP" 2>&1; then
	echo "    rsyslog configuration invalid:" >&2
	sed 's/^/    /' "$TMP" >&2
	exit 1
fi
systemctl restart rsyslog.service
for l in "${LOGS[@]}"; do
	IFS='|' read -r file selector _ <<< "$l"
	printf '    %-26s -> %-20s [CONFIGURED]\n' "$selector" "$file"
done

# --- 2. Rotation / retention ----------------------------------------------------------------
echo "[*] Setting log rotation policies..."
# Remove the two files from the stock rsyslog logrotate block
if [ -f "$LOGROTATE_STOCK" ]; then
	grep -vxE '/var/log/(auth\.log|syslog)' "$LOGROTATE_STOCK" > "$TMP" && cat "$TMP" > "$LOGROTATE_STOCK"
fi
{
	echo "# MedDefense security log retention - managed by 12-log_config.sh"
	echo "# Daily, date-stamped rotation. Rotated files stay uncompressed for $COMPRESS_AFTER_DAYS days (fast"
	echo "# incident-response grep), are then gzip'ed, and are deleted after the retention period."
	echo "# Compression and expiry run in postrotate because logrotate has no 'compress after N days'."
	for l in "${LOGS[@]}"; do
		IFS='|' read -r file _ days <<< "$l"
		base=$(basename "$file")
		cat <<EOF
$file
{
	daily
	rotate $days
	maxage $days
	dateext
	dateformat -%Y%m%d
	missingok
	notifempty
	su root adm
	nocompress
	create 0$LOG_MODE $LOG_OWNER $LOG_GROUP
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
		find /var/log -maxdepth 1 -type f \\( -name '$base-*' -o -name '$base.[0-9]*' \\) ! -name '*.gz' -mtime +$((COMPRESS_AFTER_DAYS - 1)) -exec gzip -9 {} +
		find /var/log -maxdepth 1 -type f \\( -name '$base-*.gz' -o -name '$base.[0-9]*.gz' \\) -mtime +$((days - 1)) -delete
	endscript
}
EOF
	done
} > "$LOGROTATE_CONF"
chmod 644 "$LOGROTATE_CONF"

if ! logrotate -d /etc/logrotate.conf >"$TMP" 2>&1 || grep -qiE '^error' "$TMP"; then
	echo "    logrotate configuration invalid:" >&2
	grep -iE '^error' "$TMP" | sed 's/^/    /' >&2
	exit 1
fi
for l in "${LOGS[@]}"; do
	IFS='|' read -r file _ days <<< "$l"
	printf '    %-18s rotate %s, compress after %sd  [SET]\n' "$file:" "$days" "$COMPRESS_AFTER_DAYS"
done

# --- 3. Verify that both files receive events --------------------------------------------------
echo "[*] Verifying log activity..."
NONCE="meddefense-logtest-$(date +%s)-$$"
logger -p authpriv.notice -t meddefense-logtest "auth channel test $NONCE"
logger -p user.info -t meddefense-logtest "syslog channel test $NONCE"
sleep 2
ok=0
check_log() {
	# check_log <file> <expected pattern> <pattern that must NOT appear>
	if grep -q "$2" "$1" 2>/dev/null && ! grep -q "$3" "$1" 2>/dev/null; then
		printf '    %-18s receiving events       [OK]\n' "$1:"
		ok=$((ok + 1))
	else
		printf '    %-18s NOT receiving events   [FAIL]\n' "$1:"
	fi
}
# auth messages must reach auth.log and must not leak into syslog
check_log /var/log/auth.log "auth channel test $NONCE" "syslog channel test $NONCE"
check_log /var/log/syslog "syslog channel test $NONCE" "auth channel test $NONCE"

# --- 4. Permissions -----------------------------------------------------------------------------
echo "[*] Securing log file permissions..."
for l in "${LOGS[@]}"; do
	IFS='|' read -r file _ _ <<< "$l"
	touch "$file"
	chown "$LOG_OWNER:$LOG_GROUP" "$file"
	chmod "$LOG_MODE" "$file"
	# rotated generations as well: no world access
	find /var/log -maxdepth 1 -type f -name "$(basename "$file")?*" -exec chmod o-rwx {} +
	printf '    %-18s %s %s           [OK]\n' "$file:" "$(stat -c %a "$file")" "$(stat -c %U:%G "$file")"
done

echo "Log sources configured: ${#LOGS[@]} | Rotation policies: ${#LOGS[@]} | Permissions: secured"
[ "$ok" -eq "${#LOGS[@]}" ]
