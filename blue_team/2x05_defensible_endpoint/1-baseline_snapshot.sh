#!/bin/bash
# =============================================================================
# Name:    1-baseline_snapshot.sh
# Purpose: Run the Lynis audit on hawthorne-app-01 and persist the raw log plus
#          the extracted hardening index.
# Author:  Andrei
# =============================================================================
# Output: capstone/baseline/lynis_baseline.log, capstone/baseline/baseline_linux.json
# Exit: 0 audit completed and index parsed, 1 index not found, 2 environment error.
# Idempotent: re-running overwrites the same two files with a fresh audit.
# =============================================================================
set -o pipefail
export LC_ALL=C

CAP=${CAPSTONE_DIR:-capstone}
BASE="$CAP/baseline"
LOG="$BASE/lynis_baseline.log"
OUT="$BASE/baseline_linux.json"

[ "$EUID" -eq 0 ] || { echo "Error: run as root (sudo $0)" >&2; exit 2; }
command -v lynis >/dev/null 2>&1 || { echo "Error: lynis not installed (apt-get install lynis)" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq required" >&2; exit 2; }

mkdir -p "$BASE"
echo "[*] Running Lynis (this takes ~60s)..."
lynis audit system --quick --no-colors > "$LOG" 2>&1
LYNIS_RC=$?

INDEX=$(sed -nE 's/^[[:space:]]*Hardening index[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$LOG" | tail -1)
[ -z "$INDEX" ] && INDEX=$(grep -oE 'hardening_index=[0-9]+' /var/log/lynis-report.dat 2>/dev/null | tail -1 | cut -d= -f2)
if [ -z "$INDEX" ]; then
	echo "Error: hardening index not found in $LOG" >&2
	exit 1
fi
WARN=$(grep -cE '^\s*\[WARNING\]|^\s*Warning:' "$LOG" || true)
SUGG=$(grep -cE '^\s*\* |^\s*\[SUGGESTION\]' "$LOG" || true)
VERSION=$(lynis --version 2>/dev/null | awk '{print $NF}' | head -1)

jq -n --arg ts "$(date -Iseconds)" --arg host "$(hostname)" --arg ver "${VERSION:-unknown}" \
	--argjson index "$INDEX" --argjson warn "${WARN:-0}" --argjson sugg "${SUGG:-0}" \
	--arg log "$LOG" --argjson rc "$LYNIS_RC" '
	{timestamp: $ts, hostname: $host, platform: "linux", lynis_version: $ver,
	 hardening_index: $index, warnings_count: $warn, suggestions_count: $sugg,
	 log_path: $log, lynis_exit_code: $rc}' > "$OUT" \
	|| { echo "Error: cannot write $OUT" >&2; exit 1; }

echo "Lynis hardening index: $INDEX (warnings $WARN, suggestions $SUGG)"
echo "Baseline written: $OUT"
exit 0
