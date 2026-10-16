#!/bin/bash
# 9-apparmor_config.sh - Enforce AppArmor mandatory access control on network-exposed services.
#
# MedDefense 2x00 "Locking the Gates" - Task 9
# 1x00 incident: the crypto-miner entered through Apache and, running as www-data, could read and
# execute anything www-data could. An enforced profile turns "shell on the web server" into
# "a process that can only read /var/www and cannot spawn a shell". Same idea for MySQL (patient
# billing data) and for the MedDefense billing application.
#
# Actions:
#   1. verify AppArmor (kernel module + service); install apparmor-utils if missing
#   2. list every loaded profile and its mode
#   3. Apache + MySQL: complain -> enforce. Ubuntu 22.04 ships no Apache profile (not even in
#      apparmor-profiles), so a MedDefense profile for /usr/sbin/apache2 + mod_php is deployed.
#      After enforcing, the service is restarted if needed and health-checked; on failure the
#      profile is put back in complain mode so billing stays up (and the failure is reported).
#   4. custom profile for /opt/meddefense/billing-app (default-deny, required directories only)
#   5. report network-exposed processes that are still unconfined
#
# Justified deviations:
#   - sshd stays unconfined: it must spawn arbitrary login shells for administrators, so a useful
#     profile is impractical and a wrong one locks out remote administration. Compensating
#     controls: key-only auth + AllowUsers (Task 4), UFW management-network rule (Task 13),
#     auditd privilege-escalation rules (Task 10).
#   - systemd-networkd / systemd-resolved: no upstream profiles; they run with systemd sandboxing
#     (ProtectSystem, dedicated users) and resolved listens on 127.0.0.53 only.
#   - rsyslogd's Ubuntu profile is left in complain mode: it is an internal (non-listening) service
#     here and enforcing it requires per-site rules for the forwarding setup of Task 12/2x02.
# Idempotent: profiles are rewritten only when their content changes; already-enforced profiles
# are reported [OK].

export LC_ALL=C

APPARMOR_DIR=/etc/apparmor.d
APACHE_PROFILE=$APPARMOR_DIR/usr.sbin.apache2
BILLING_DIR=/opt/meddefense/billing-app
BILLING_PROFILE=$APPARMOR_DIR/opt.meddefense.billing-app
BILLING_PROFILE_NAME=meddefense-billing-app

# Services to enforce: binary | profile name | profile file | systemd unit | health check
TARGETS=(
	"/usr/sbin/apache2|apache2|$APACHE_PROFILE|apache2.service|curl -fsS -o /dev/null --max-time 5 http://127.0.0.1/"
	"/usr/sbin/mysqld|/usr/sbin/mysqld|$APPARMOR_DIR/usr.sbin.mysqld|mysql.service|mysqladmin --connect-timeout=5 ping"
)
# Exposed services reported only (no profile is created for them - see deviations above)
REPORT_ONLY=("/usr/sbin/sshd|/usr/sbin/sshd")

if [ "$EUID" -ne 0 ]; then
	echo "Error: run as root (sudo $0)" >&2
	exit 1
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# --- Profile contents ------------------------------------------------------------------------

apache_profile() {
	cat <<'EOF'
# MedDefense AppArmor profile for Apache 2.4 (+ mod_php) - managed by 9-apparmor_config.sh
# Site-specific additions: /etc/apparmor.d/local/usr.sbin.apache2
abi <abi/3.0>,

include <tunables/global>

# attach_disconnected: apache2.service uses PrivateTmp (own mount namespace)
profile apache2 /usr/sbin/apache2 flags=(attach_disconnected) {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/openssl>
  include <abstractions/apache2-common>
  include <abstractions/php>

  # root parent: bind :80/:443, open logs, drop to www-data, manage children
  capability chown,
  capability dac_override,
  capability kill,
  capability net_bind_service,
  capability setgid,
  capability setuid,

  network inet stream,
  network inet6 stream,
  network unix stream,

  /usr/sbin/apache2 mr,
  /usr/lib/apache2/modules/*.so mr,
  /usr/lib/php/** mr,
  /etc/apache2/** r,
  /etc/mime.types r,
  /var/lib/apache2/** r,

  # Web content is read-only: a compromised worker cannot plant or modify pages
  /var/www/ r,
  /var/www/** r,

  /var/log/apache2/ r,
  /var/log/apache2/** rwl,
  /{,var/}run/apache2/ rw,
  /{,var/}run/apache2/** rwlk,
  /{,var/}run/lock/apache2/ rw,
  /{,var/}run/lock/apache2/** rwlk,
  /var/cache/apache2/ r,
  /var/cache/apache2/** rwlk,

  # PHP uploads / temporary files (private /tmp of the service)
  owner /tmp/** rwk,

  # MPM scoreboard: anonymous shared memory shows up as disconnected "/"
  / rw,

  # No exec rules at all: webshells cannot spawn /bin/sh, curl, wget or a miner (1x00 incident).
  # Explicit denials (silenced) for the data an attacker is after:
  deny /var/lib/mysql/** rwklmx,
  deny /etc/shadow rwkl,
  deny /etc/gshadow rwkl,
  deny /root/** rwklmx,
  deny /home/** rwklmx,

  include if exists <local/usr.sbin.apache2>
}
EOF
}

billing_profile() {
	cat <<EOF
# MedDefense billing application - managed by 9-apparmor_config.sh
# Default-deny: the application may only touch the directories listed here. Even a zero-day in
# the application cannot reach patient data stored outside them (raw MySQL files, home dirs).
abi <abi/3.0>,

include <tunables/global>

profile $BILLING_PROFILE_NAME $BILLING_DIR/** {
  include <abstractions/base>
  include <abstractions/bash>
  include <abstractions/consoles>
  include <abstractions/nameservice>

  # Shell interpreter for the application scripts (inherits this profile)
  /usr/bin/bash ix,

  # Application code: read/execute only - the running app cannot modify itself
  $BILLING_DIR/ r,
  $BILLING_DIR/** rix,

  # Configuration (read-only), working data and logs
  /etc/meddefense/billing-app/ r,
  /etc/meddefense/billing-app/** r,
  /var/lib/meddefense/billing-app/ rw,
  /var/lib/meddefense/billing-app/** rwk,
  /var/log/meddefense/billing-app/ rw,
  /var/log/meddefense/billing-app/** rw,

  # Database access only through MySQL (socket or TCP), never through the raw files
  /{,var/}run/mysqld/mysqld.sock rw,
  network inet stream,
  network inet6 stream,

  deny /var/lib/mysql/** rwklmx,
  deny /etc/shadow rwkl,
  deny /etc/gshadow rwkl,
  deny /etc/sudoers rwkl,
  deny /etc/sudoers.d/** rwkl,
  deny /root/** rwklmx,
  deny /home/** rwklmx,
  deny /var/www/** wkl,

  include if exists <local/opt.meddefense.billing-app>
}
EOF
}

# install_profile <file> <generator>: write only when content differs. Prints CREATED/UPDATED/OK.
install_profile() {
	local file="$1" gen="$2"
	"$gen" > "$TMP"
	if [ ! -f "$file" ]; then
		cp "$TMP" "$file" && echo "CREATED"
	elif ! cmp -s "$TMP" "$file"; then
		cp "$TMP" "$file" && echo "UPDATED"
	else
		echo "OK"
	fi
	chmod 644 "$file"
}

# Loaded profiles as "name<TAB>mode", read from securityfs (aa-status --json emits invalid JSON
# for some process names in apparmor-utils 3.0.4)
AA_PROFILES=/sys/kernel/security/apparmor/profiles
list_profiles() {
	sed -E 's/^(.*) \(([a-z]+)\)$/\1\t\2/' "$AA_PROFILES" | sort
}

# profile_mode <name>: enforce | complain | kill | unconfined | none
profile_mode() {
	list_profiles | awk -F'\t' -v p="$1" '$1 == p { m = $2 } END { print (m ? m : "none") }'
}

# --- 1. AppArmor status ----------------------------------------------------------------------
echo "[*] Checking AppArmor status..."
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
	echo "    AppArmor module: loaded"
else
	echo "    AppArmor module: NOT loaded (boot with apparmor=1 security=apparmor)"
	exit 1
fi
if ! dpkg-query -W -f='${Status}' apparmor 2>/dev/null | grep -q "install ok installed"; then
	echo "    apparmor package missing - installing"
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor >/dev/null 2>&1 || exit 1
fi
if ! command -v aa-enforce >/dev/null 2>&1; then
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor-utils >/dev/null 2>&1 \
		|| { echo "    apparmor-utils installation failed" >&2; exit 1; }
fi
systemctl is-enabled --quiet apparmor.service || systemctl enable apparmor.service >/dev/null 2>&1
systemctl is-active --quiet apparmor.service || systemctl start apparmor.service
echo "    AppArmor service: $(systemctl is-active apparmor.service)"

# --- 2. Current profiles --------------------------------------------------------------------
echo "[*] Loaded profiles:"
list_profiles | awk -F'\t' '{printf "    %-56s %s\n", $1, $2}'

# --- 3. Enforce Apache and MySQL ------------------------------------------------------------
echo "[*] Profile enforcement:"
# Deploy/refresh the MedDefense Apache profile unless a non-managed (e.g. vendor) profile exists
APACHE_STATE=""
if [ ! -f "$APACHE_PROFILE" ] || grep -q "managed by 9-apparmor_config.sh" "$APACHE_PROFILE"; then
	APACHE_STATE=$(install_profile "$APACHE_PROFILE" apache_profile)
fi

for t in "${TARGETS[@]}"; do
	IFS='|' read -r bin name file unit check <<< "$t"
	label=$(printf '    %-24s' "$bin")
	if [ ! -x "$bin" ]; then
		echo "$label not installed            [SKIPPED]"
		continue
	fi
	if [ ! -f "$file" ]; then
		echo "$label no profile ($file)        [MISSING]"
		continue
	fi
	before=$(profile_mode "$name")
	created=""
	[ "$file" = "$APACHE_PROFILE" ] && [ "$APACHE_STATE" = "CREATED" ] && created=" [CREATED]"
	# aa-enforce drops the complain flag and (re)loads the profile - also picks up content updates
	aa-enforce "$file" >/dev/null 2>&1
	# Running processes started before the profile existed stay unconfined until restarted
	pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
	cur=$(cat "/proc/$pid/attr/current" 2>/dev/null)
	if systemctl is-active --quiet "$unit" && [ "$cur" != "$name (enforce)" ]; then
		systemctl restart "$unit"
		sleep 2
	fi
	if [ "$(profile_mode "$name")" = "enforce" ] && bash -c "$check" >/dev/null 2>&1; then
		if [ "$before" = "enforce" ]; then
			echo "$label enforce              [OK]"
		else
			echo "$label $before -> enforce $created [ENFORCED]"
		fi
	else
		# Service broke under enforcement: fall back to complain to keep billing online
		aa-complain "$file" >/dev/null 2>&1
		systemctl restart "$unit"
		echo "$label $before -> enforce  [FAILED - reverted to complain, check audit.log]"
	fi
done
for t in "${REPORT_ONLY[@]}"; do
	IFS='|' read -r bin name <<< "$t"
	mode=$(profile_mode "$name")
	[ "$mode" = "none" ] && continue
	printf '    %-24s %-21s %s\n' "$bin" "$mode" "$([ "$mode" = enforce ] && echo '[OK]' || echo '[REVIEW]')"
done

# --- 4. Custom MedDefense billing application profile ---------------------------------------
state=$(install_profile "$BILLING_PROFILE" billing_profile)
if apparmor_parser -r -W "$BILLING_PROFILE" 2>"$TMP" && aa-enforce "$BILLING_PROFILE" >/dev/null 2>&1 \
	&& [ "$(profile_mode "$BILLING_PROFILE_NAME")" = "enforce" ]; then
	enforced="[ENFORCED]"
else
	enforced="[LOAD FAILED: $(head -1 "$TMP")]"
fi
printf '[*] Custom profile: %-28s [%s] %s\n' "$BILLING_DIR" "$state" "$enforced"
# Prove confinement: allowed directory readable, patient data / credentials not
if [ "$enforced" = "[ENFORCED]" ]; then
	MYSQL_PROBE=$(find /var/lib/mysql -maxdepth 1 -type f -print -quit 2>/dev/null)
	if ! aa-exec -p "$BILLING_PROFILE_NAME" -- /usr/bin/bash -c "read -r _ < $BILLING_DIR/app.sh" 2>/dev/null; then
		echo "    Confinement test: application directory not readable   [FAIL]"
	elif aa-exec -p "$BILLING_PROFILE_NAME" -- /usr/bin/bash -c "read -r _ < /etc/shadow" 2>/dev/null \
		|| { [ -n "$MYSQL_PROBE" ] && aa-exec -p "$BILLING_PROFILE_NAME" -- /usr/bin/bash -c "read -r _ < '$MYSQL_PROBE'" 2>/dev/null; }; then
		echo "    Confinement test: sensitive files reachable   [FAIL]"
	else
		echo "    Confinement test: /etc/shadow, /var/lib/mysql denied   [PASS]"
	fi
fi

# --- 5. Unconfined network-exposed processes ------------------------------------------------
echo "[*] Unconfined network-exposed processes:"
mapfile -t UNCONFINED < <(aa-unconfined 2>/dev/null | awk '/not confined/ {print $2}' | sort -u)
for p in "${UNCONFINED[@]}"; do
	printf '    %-24s [UNCONFINED - Profile recommended]\n' "$p"
done
[ "${#UNCONFINED[@]}" -eq 0 ] && echo "    none"

# --- Summary ----------------------------------------------------------------------------------
read -r ENF CMP < <(list_profiles | awk -F'\t' '$2 == "enforce" { e++ } $2 == "complain" { c++ } END { print e + 0, c + 0 }')
echo "Profiles in enforce: $ENF | Complain: $CMP | Unconfined: ${#UNCONFINED[@]}"
