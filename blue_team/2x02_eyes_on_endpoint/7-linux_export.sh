#!/bin/bash
# =============================================================================
# Name:    7-linux_export.sh
# Purpose: Export auth.log, auditd and syslog into analyst-ready JSON with
#          normalized timestamps and consistent fields (linux_events_export.json).
# Author:  MedDefense blue team (Holberton 2x02 - Task 7)
# =============================================================================
# MedDefense 2x02 "Eyes on Endpoint" - Task 7
# The Linux half of the telemetry handoff. auth.log answers "who logged in",
# auditd answers "what ran and what was touched", syslog answers "what services
# changed". All three are parsed into the same record shape used by the Windows
# export (Task 3) so the SOC can query both with jq.
#
# Usage: sudo ./7-linux_export.sh [hours]      (default window: last 24 hours)
# Output: linux_events_export.json
#
# Record shape:
#   timestamp (UTC ISO 8601), hostname, platform, source_type, channel,
#   event_id, event_category, provider, raw_message + category-specific fields
#
# Deviations (justified):
#   - auditd is read through "ausearch -i" so syscall arguments are interpreted
#     (hex EXECVE arguments decoded) instead of parsing the binary-ish raw log.
#   - Timestamps from syslog-style files carry no year; the current year is
#     assumed and the value is converted with the host's timezone to UTC.
#   - The execve rule added in Task 5 records every command, so auditd volume
#     dominates the export. That is intended: dropping commands would blind the
#     SOC. Rotation keeps the log bounded.
# =============================================================================

set -o pipefail
export LC_ALL=C

HOURS=${1:-24}
OUT=${2:-linux_events_export.json}
AUTH_LOG=/var/log/auth.log
AUDIT_LOG=/var/log/audit/audit.log
SYSLOG=/var/log/syslog

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0) - audit.log is root-only" >&2
	exit 1
fi
for f in "$AUTH_LOG" "$SYSLOG"; do
	[ -r "$f" ] || { echo "Error: cannot read $f" >&2; exit 1; }
done
command -v ausearch >/dev/null 2>&1 || { echo "Error: ausearch not found (auditd)" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq not required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

WINDOW_START=$(date -d "$HOURS hours ago" +%x)
WINDOW_START_T=$(date -d "$HOURS hours ago" +%T)
HOST=$(hostname)
TODAY=$(date +%Y)

# iso <"Nov  3 23:10:57"> -> ISO 8601 UTC
iso() {
	local d
	d=$(date -d "$1 $TODAY" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || d=""
	echo "$d"
}
# iso_num <"11/04/26 00:10:01"> (ausearch format) -> ISO 8601 UTC
iso_num() {
	local d
	d=$(date -d "$1" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || d=""
	echo "$d"
}

# =============================================================================
# 1+3. rsyslog sources - auth.log and syslog
# =============================================================================
# The host writes two formats: classic syslog ("Nov  3 23:10:57 host tag: msg")
# and RFC 3339 (MedDefenseFormat from 2x00 Task 12: "2026-11-04T00:06:32+01:00
# host facility.severity tag: msg"). Both are handled.
#
# Output TSV: rawts, category, event_id, provider, user, message, host
parse_rsyslog() {   # parse_rsyslog <file> <auth|syslog> <out>
	local file="$1" kind="$2" out="$3"
	awk -v kind="$kind" '
		function jesc(s) { gsub(/[\t\n]/, " ", s); return s }
		NF < 4 { next }
		{
			if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
				# RFC 3339: ts host facility.severity tag: message
				ts = $1; h = $2; msg = $0
				sub(/^[^ ]+ +[^ ]+ +[^ ]+ +/, "", msg)
			} else {
				# classic: Mon DD HH:MM:SS host tag: message
				ts = $1 " " $2 " " $3; h = $4; msg = $0
				sub(/^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", msg)
			}
			prov = ""
			if (msg ~ /^[A-Za-z0-9_.\/-]+\[[0-9]+\]:/) { prov = msg; sub(/\[.*/, "", prov) }
			else if (msg ~ /^[A-Za-z0-9_.\/-]+:/) { prov = msg; sub(/:.*/, "", prov) }

			if (kind == "auth") {
				cat = "other"; eid = prov; user = ""
				if (msg ~ /sshd\[[0-9]+\]: Accepted/) {
					cat = "ssh_login"; eid = "sshd-accepted"
					user = msg; sub(/.* for /, "", user); sub(/ .*/, "", user)
				} else if (msg ~ /sshd\[[0-9]+\]: Failed/) {
					cat = "ssh_login_failed"; eid = "sshd-failed"
					user = msg; sub(/.* for (invalid user )?/, "", user); sub(/ from .*/, "", user)
				} else if (msg ~ /sshd\[[0-9]+\]: Invalid user/) {
					cat = "ssh_login_failed"; eid = "sshd-invalid-user"
					user = msg; sub(/.*Invalid user /, "", user); sub(/ from .*/, "", user)
				} else if (msg ~ /pam_unix|pam_faillock|pam_pwquality|pam_env|pam_limits/) {
					# checked before sudo: "sudo: pam_unix(...)" is a PAM event, not a command
					cat = "pam"; eid = "pam"
				} else if (msg ~ /sudo: /) {
					cat = "sudo"; eid = "sudo-command"
					user = msg; sub(/.*sudo: /, "", user); sub(/ :.*/, "", user)
					gsub(/^ +| +$/, "", user)
				} else if (msg ~ /(^|[^a-z])su(\[|:)/) {
					cat = "su"; eid = "su"
				}
			} else {
				cat = "other"; eid = "syslog"
				if (msg ~ /systemd\[1\]: (Started|Stopped|Starting|Stopping|Reloaded|Failed to start)/) {
					cat = "service"; eid = "systemd-unit"
				} else if (msg ~ /([Ee]rror|[Ff]ailed|[Ff]ailure|refused|denied|CRIT)/) {
					cat = "error"; eid = "syslog-error"
				}
			}
			printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, cat, eid, prov, jesc(user), jesc(msg), h
		}' "$file" > "$out"
}

echo "[*] Parsing auth.log..."
parse_rsyslog "$AUTH_LOG" auth "$TMP/auth.tsv"
AUTH_COUNT=$(grep -c . "$TMP/auth.tsv" || true)

echo "[*] Parsing syslog..."
parse_rsyslog "$SYSLOG" syslog "$TMP/syslog.tsv"
SYSLOG_COUNT=$(grep -c . "$TMP/syslog.tsv" || true)

# =============================================================================
# 2. audit.log - syscalls (execve, file access, network)
# =============================================================================
echo "[*] Parsing audit.log..."
ausearch --input-logs -ts "$WINDOW_START" "$WINDOW_START_T" -i > "$TMP/audit.txt" 2>/dev/null || true

# Output TSV: rawts, category, syscall, exe, cmdline, path, auid, key
awk '
	function flush() {
		if (ts == "") return
		cat = "other"
		if (syscall == "execve" || syscall == "execveat") cat = "process_exec"
		else if (syscall ~ /^(socket|connect|bind|sendto|sendmsg|accept|accept4)$/) cat = "network"
		else if (path != "" || items > 0) cat = "file_access"
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, cat, syscall, exe, cmdline, path, auid, key
	}
	/^----/ { flush(); ts = ""; syscall = ""; exe = ""; cmdline = ""; path = ""; auid = ""; key = ""; items = 0; next }
	/type=SYSCALL/ {
		if (match($0, /audit\([^)]*\)/)) {
			ts = substr($0, RSTART + 6, RLENGTH - 7)
			sub(/\.[0-9]+:[0-9]+$/, "", ts)   # drop ".123:4567" - keep "MM/DD/YY HH:MM:SS"
		}
		if (match($0, /syscall=[a-z_0-9]+/)) { syscall = substr($0, RSTART + 8, RLENGTH - 8) }
		if (match($0, / exe=[^ ]+/)) { exe = substr($0, RSTART + 5, RLENGTH - 5) }
		if (match($0, / auid=[^ ]+/)) { auid = substr($0, RSTART + 6, RLENGTH - 6) }
		if (match($0, / key="?[^" ]*"?/)) { key = substr($0, RSTART + 5, RLENGTH - 5); gsub(/"/, "", key) }
		if (match($0, /items=[0-9]+/)) { items = substr($0, RSTART + 6, RLENGTH - 6) + 0 }
		next
	}
	/type=EXECVE/ {
		for (i = 2; i <= NF; i++) {
			if ($i ~ /^a[0-9]+=/) {
				v = $i; sub(/^a[0-9]+=/, "", v); gsub(/^"|"$/, "", v)
				cmdline = cmdline (cmdline == "" ? "" : " ") v
			}
		}
		next
	}
	/type=PATH/ {
		if (path == "") {
			if (match($0, /name=[^ ]+/)) {
				path = substr($0, RSTART + 5, RLENGTH - 5); gsub(/"/, "", path)
			}
		}
		next
	}
' "$TMP/audit.txt" > "$TMP/audit.tsv"
AUDIT_COUNT=$(grep -c . "$TMP/audit.tsv" || true)

# =============================================================================
# 4. Normalize timestamps and build JSON
# =============================================================================
# Convert every distinct timestamp once (date(1) handles the timezone/DST), then
# join. RFC 3339 values are already unambiguous; classic values get the current year.
to_iso() {
	local s="$1" d
	case "$s" in
		[0-9][0-9][0-9][0-9]-*) d=$(date -u -d "$s" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) ;;
		[0-9][0-9]/[0-9][0-9]/[0-9][0-9]*) d=$(date -u -d "$s" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) ;;
		*) d=$(date -u -d "$s $TODAY" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) ;;
	esac
	[ -n "$d" ] || d=$(date -u -d "$TODAY $s" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
	echo "$d"
}

cut -f1 "$TMP/auth.tsv" "$TMP/syslog.tsv" "$TMP/audit.tsv" 2>/dev/null \
	| grep -v '^$' | sort -u > "$TMP/stamps.txt"
: > "$TMP/stamp_map.tsv"
while IFS= read -r s; do
	iso_ts=$(to_iso "$s")
	[ -n "$iso_ts" ] && printf '%s\t%s\n' "$s" "$iso_ts" >> "$TMP/stamp_map.tsv"
done < "$TMP/stamps.txt"

# Uniform 13 columns for jq:
#  1 ts 2 host 3 source 4 channel 5 category 6 event_id 7 provider 8 audit_key
#  9 exe 10 command_line 11 path 12 user 13 raw_message
{
	awk -F'\t' -v OFS='\t' -v host="$HOST" 'NR == FNR { m[$1] = $2; next }
		{ if (!($1 in m)) next
		  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\t\t\t\t%s\t%s\n", m[$1], host, "auth", "/var/log/auth.log", $2, $3, $4, $5, $6 }' \
		"$TMP/stamp_map.tsv" "$TMP/auth.tsv"
	awk -F'\t' -v OFS='\t' -v host="$HOST" 'NR == FNR { m[$1] = $2; next }
		{ if (!($1 in m)) next
		  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\t\t\t\t%s\t%s\n", m[$1], host, "syslog", "/var/log/syslog", $2, $3, $4, $5, $6 }' \
		"$TMP/stamp_map.tsv" "$TMP/syslog.tsv"
	awk -F'\t' -v OFS='\t' -v host="$HOST" 'NR == FNR { m[$1] = $2; next }
		{ if (!($1 in m)) next
		  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n", m[$1], host, "audit", "/var/log/audit/audit.log", $2, $3, "auditd", $8, $4, $5, $6, $7 }' \
		"$TMP/stamp_map.tsv" "$TMP/audit.tsv"
} | sort -t$'\t' -k1,1 > "$TMP/all.tsv"

cat > "$TMP/prog.jq" <<'JQ'
def cat_fields:
    if .event_category == "process_exec" then {process: ._exe, command_line: ._cmd, user: ._user}
    elif .event_category == "network" then {syscall: ._sys, process: ._exe, user: ._user}
    elif .event_category == "file_access" then {path: ._path, process: ._exe, user: ._user}
    else {user: ._user} end;
split("\n")
| map(select(length > 0) | split("\t")) as $rows
| [ $rows[]
    | {timestamp: .[0], hostname: .[1], platform: "linux", source_type: .[2],
       channel: .[3], event_category: .[4], event_id: .[5], provider: .[6],
       audit_key: (.[7] | if . == "" then null else . end),
       raw_message: (.[12] | if . == "" then null else . end),
       _sys: .[5], _exe: .[8], _cmd: .[9], _path: .[10], _user: .[11] }
    | . + (. | cat_fields)
    | del(._sys, ._exe, ._cmd, ._path, ._user) ]
| {platform: "linux", host: $host, exported_at: $window_end,
   window: {hours: $hours, start: $start, end: $window_end},
   counts: {total: length,
            by_source: (group_by(.source_type) | map({key: .[0].source_type, value: length}) | from_entries),
            by_category: (group_by(.event_category) | map({key: .[0].event_category, value: length}) | from_entries)},
   events: .}
JQ

jq -R -s --arg host "$HOST" \
	--arg start "$(date -u -d "$HOURS hours ago" +%Y-%m-%dT%H:%M:%SZ)" \
	--arg window_end "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson hours "$HOURS" \
	-f "$TMP/prog.jq" "$TMP/all.tsv" > "$OUT" \
	|| { echo "Error: cannot build $OUT" >&2; exit 1; }

# --- Summary ------------------------------------------------------------------
printf '[*] Parsing auth.log... %s events\n' "$AUTH_COUNT"
printf '    SSH logins: %s | sudo: %s | su: %s | PAM: %s\n' \
	"$(jq '[.events[] | select(.event_category=="ssh_login")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="sudo")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="su")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="pam")] | length' "$OUT")"
printf '[*] Parsing audit.log... %s events\n' "$AUDIT_COUNT"
printf '    execve: %s | file_access: %s | network: %s | other: %s\n' \
	"$(jq '[.events[] | select(.event_category=="process_exec")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="file_access")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="network")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.event_category=="other" and .source_type=="audit")] | length' "$OUT")"
printf '[*] Parsing syslog... %s events\n' "$SYSLOG_COUNT"
printf '    service: %s | error: %s | other: %s\n' \
	"$(jq '[.events[] | select(.source_type=="syslog" and .event_category=="service")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.source_type=="syslog" and .event_category=="error")] | length' "$OUT")" \
	"$(jq '[.events[] | select(.source_type=="syslog" and .event_category=="other")] | length' "$OUT")"
echo "Total events: $(jq '.counts.total' "$OUT")"
echo "Time range: $(jq -r '.events[0].timestamp // "n/a"' "$OUT") to $(jq -r '.events[-1].timestamp // "n/a"' "$OUT")"
echo "Output: $OUT"
