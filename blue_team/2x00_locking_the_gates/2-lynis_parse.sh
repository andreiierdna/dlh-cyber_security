#!/bin/bash
# 2-lynis_parse.sh - Convert a Lynis report (lynis-report.dat) into a JSON summary.
#
# MedDefense 2x00 "Locking the Gates" - Task 2
# The hardening index is the headline metric of the before/after delta (baseline billing-srv-01
# scored in the 50s); the findings list drives the hardening backlog for Tasks 4-13.
#
# Usage: ./2-lynis_parse.sh /var/log/lynis-report.dat | jq '.' > lynis_findings.json
#
# Report lines parsed (value fields are pipe-separated: TEST-ID|message|details|solution|):
#   hardening_index=NN
#   warning[]=...          -> severity "warning"
#   suggestion[]=...       -> severity "suggestion"
#   manual_check[]=...     -> severity "manual_check"
#   manual[]=free text     -> severity "manual_check" (Lynis 3.x writes manual checks as plain
#                             text without a test id; test_id is reported as "MANUAL")

REPORT="$1"

if [ -z "$REPORT" ]; then
	echo "Usage: $0 <lynis-report.dat>" >&2
	exit 1
fi
if [ ! -r "$REPORT" ]; then
	echo "Error: cannot read $REPORT (Lynis reports are root-only: try sudo)" >&2
	exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
	echo "Error: jq is required (apt-get install -y jq)" >&2
	exit 1
fi

jq -R -n '
	[inputs] as $lines
	| {
		hardening_index: (
			$lines
			| map(select(startswith("hardening_index=")) | ltrimstr("hardening_index=") | tonumber? )
			| first // null
		),
		findings: [
			$lines[]
			| capture("^(?<type>warning|suggestion|manual_check|manual)\\[\\]=(?<value>.*)$")?
			| (if .type == "manual" or .type == "manual_check" then "manual_check" else .type end) as $severity
			| (.value | split("|")) as $f
			| if ($f | length) > 1 then
				{severity: $severity, test_id: $f[0], message: $f[1]}
			  else
				{severity: $severity, test_id: "MANUAL", message: $f[0]}
			  end
		]
	}
' "$REPORT"
