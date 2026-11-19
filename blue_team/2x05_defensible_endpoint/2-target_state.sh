#!/bin/bash
# =============================================================================
# Name:    2-target_state.sh
# Purpose: Emit capstone/target_state.json - the machine-readable finish line
#          every downstream task and the final validation suite are graded against.
# Author:  Andrei
# =============================================================================
# Usage: ./2-target_state.sh [--force]
# Exit: 0 written, 1 refused (file exists without --force), 2 environment error.
# =============================================================================
set -o pipefail
export LC_ALL=C

CAP=${CAPSTONE_DIR:-capstone}
OUT="$CAP/target_state.json"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

command -v jq >/dev/null 2>&1 || { echo "Error: jq required" >&2; exit 2; }
if [ -f "$OUT" ] && [ "$FORCE" -ne 1 ]; then
	echo "Refusing to overwrite $OUT (use --force to regenerate)" >&2
	exit 1
fi
mkdir -p "$CAP"

jq -n --arg ts "$(date -Iseconds)" '
	def c($id;$platform;$family;$desc;$type;$target;$expect;$src;$sev):
		{id:$id, platform:$platform, family:$family, description:$desc,
		 check_type:$type, check_target:$target, expected_value:$expect,
		 source_project:$src, severity:$sev};

	# linux target thresholds live next to the controls so T3/T4 can read them
	# without a second contract.
	{ schema_version: "meddefense-capstone-target-v1",
	  generated_at: $ts,
	  site: "hawthorne",
	  linux: { hardening_index: 80, host: "hawthorne-app-01" },
	  windows: { pass_rate: 85, host: "hawthorne-adm-01" },
	  controls: [
	  # ---- hardening / linux -------------------------------------------------
	  c("LNX-SSH-01";"linux";"hardening";"SSH must refuse direct root login";"command_exit_zero";"sshd -T | grep -qx \"permitrootlogin no\"";"no";"2x00";"critical"),
	  c("LNX-SSH-02";"linux";"hardening";"SSH must refuse password authentication";"command_exit_zero";"sshd -T | grep -qx \"passwordauthentication no\"";"no";"2x00";"critical"),
	  c("LNX-SYS-01";"linux";"hardening";"Kernel must not forward packets";"command_exit_zero";"test \"$(sysctl -n net.ipv4.ip_forward)\" = 0";"0";"2x00";"high"),
	  c("LNX-SYS-02";"linux";"hardening";"ASLR must be fully enabled";"command_exit_zero";"test \"$(sysctl -n kernel.randomize_va_space)\" = 2";"2";"2x00";"high"),
	  c("LNX-AUD-01";"linux";"telemetry";"auditd must be active";"command_exit_zero";"systemctl is-active --quiet auditd";"active";"2x02";"critical"),
	  c("LNX-APP-01";"linux";"hardening";"AppArmor must be enabled with profiles in enforce mode";"command_exit_zero";"test $(aa-status --enforced 2>/dev/null | wc -l) -ge 1";"enforced>=1";"2x00";"high"),
	  c("LNX-LYN-01";"linux";"hardening";"Lynis hardening index must reach the target";"json_field_gte";"capstone/exec/linux_harden.json#lynis_after";"80";"2x00";"high"),
	  # ---- hardening / windows -----------------------------------------------
	  c("WIN-FW-01";"windows";"hardening";"Windows Firewall must default-deny inbound on every profile";"json_field_equals";"capstone/exec/windows_harden.json#firewall_default_deny";"Block";"2x01";"critical"),
	  c("WIN-PS-01";"windows";"telemetry";"PowerShell Script Block Logging must be enabled";"json_field_equals";"capstone/exec/windows_harden.json#sbl_enabled";"1";"2x01";"critical"),
	  c("WIN-SYSMON-01";"windows";"telemetry";"Sysmon must be installed and running";"json_field_equals";"capstone/exec/windows_harden.json#sysmon_running";"Running";"2x01";"critical"),
	  c("WIN-AUD-01";"windows";"telemetry";"Audit policy must cover Account Logon, Logon, Object Access and Privilege Use";"json_field_gte";"capstone/exec/windows_harden.json#audit_subcategories_covered";"4";"2x01";"high"),
	  c("WIN-CIS-01";"windows";"hardening";"CIS Level 1 pass rate must reach the target";"json_field_gte";"capstone/exec/windows_harden.json#pass_rate_after";"85";"2x01";"high"),
	  # ---- telemetry ---------------------------------------------------------
	  c("TEL-LNX-01";"linux";"telemetry";"Linux auditd rules file must be present and loaded";"command_exit_zero";"test -s /etc/audit/rules.d/meddefense.rules && auditctl -l | grep -q meddefense";"-";"2x00";"high"),
	  c("TEL-LNX-02";"linux";"telemetry";"Structured Linux telemetry export must exist";"file_exists";"capstone/telemetry/linux_events.json";"exists";"2x02";"high"),
	  c("TEL-WIN-01";"windows";"telemetry";"Sysmon must have produced events in the last 10 minutes";"json_field_gte";"capstone/telemetry/windows_coverage.json#export_events";"1";"2x02";"high"),
	  c("TEL-WIN-02";"windows";"telemetry";"Script Block Logging channel must contain events";"json_field_gte";"capstone/telemetry/windows_coverage.json#tests_passed";"4";"2x02";"high"),
	  # ---- patching ----------------------------------------------------------
	  c("PAT-01";"linux";"patching";"Vulnerability inventory artifact must exist";"file_exists";"capstone/patch/vulnerability_inventory.json";"exists";"2x03";"high"),
	  c("PAT-02";"linux";"patching";"Patch plan artifact must exist";"file_exists";"capstone/patch/patch_plan.json";"exists";"2x03";"high"),
	  c("PAT-03";"linux";"patching";"Patch execution log must contain zero failed entries";"json_field_equals";"capstone/patch/pipeline_summary.json#failed_entries";"0";"2x03";"critical"),
	  c("PAT-04";"linux";"patching";"unattended-upgrades must be configured with the mandated blacklist";"grep_match";"/etc/apt/apt.conf.d/51-meddefense-unattended-upgrades";"Package-Blacklist";"2x03";"medium"),
	  # ---- network -----------------------------------------------------------
	  c("NET-NFT-01";"network";"network";"nftables input chain must default to drop";"grep_match";"capstone/network/nftables.conf";"policy drop";"2x04";"critical"),
	  c("NET-SEG-01";"linux";"network";"Capstone segmentation file must be present";"file_exists";"/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json";"exists";"2x04";"high"),
	  c("NET-SUR-01";"linux";"network";"Custom Suricata ruleset must load at least six rules";"json_field_gte";"capstone/network/rule_validation.json#rules_declared";"6";"2x04";"high"),
	  c("NET-SUR-02";"linux";"network";"Every custom Suricata rule must fire against its target PCAP";"json_field_equals";"capstone/network/rule_validation.json#summary.failed";"0";"2x04";"critical"),
	  c("NET-DNS-01";"linux";"network";"Local DNS filter must be active";"command_exit_zero";"systemctl is-active --quiet dnsmasq";"active";"2x04";"high"),
	  # ---- handoff -----------------------------------------------------------
	  c("HND-01";"both";"handoff";"compliance report must exist";"file_exists";"capstone/compliance.json";"exists";"2x05";"high"),
	  c("HND-02";"both";"handoff";"manifest with SHA-256 per file must exist";"file_exists";"capstone/manifest.json";"exists";"2x05";"high"),
	  c("HND-03";"both";"handoff";"telemetry package must be tarballed";"file_exists";"capstone/hawthorne_telemetry.tar.gz";"exists";"2x05";"high"),
	  c("HND-04";"both";"handoff";"runbook script must be present and executable";"command_exit_zero";"test -x capstone/runbook.sh";"executable";"2x05";"high")
	  ] }
	| .summary = {controls: (.controls | length),
	              by_platform: (.controls | group_by(.platform) | map({key: .[0].platform, value: length}) | from_entries),
	              by_family: (.controls | group_by(.family) | map({key: .[0].family, value: length}) | from_entries),
	              by_severity: (.controls | group_by(.severity) | map({key: .[0].severity, value: length}) | from_entries)}' > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Target state written: $OUT"
jq -r '"  controls=\(.summary.controls) platforms=\(.summary.by_platform) families=\(.summary.by_family)"' "$OUT"
echo "  linux target index: $(jq '.linux.hardening_index' "$OUT")   windows target pass rate: $(jq '.windows.pass_rate' "$OUT")%"
exit 0
