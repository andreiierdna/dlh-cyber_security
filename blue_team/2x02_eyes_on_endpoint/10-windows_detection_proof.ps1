<#
Name    : 10-windows_detection_proof.ps1
Purpose : Correlate the ground truth from Task 9 (windows_attack_log.json)
          against the Security, Sysmon and PowerShell event logs. For every
          simulated action, search a window around its timestamp and record
          which source(s) captured it, the Event ID, and the detail level.
          Read-only: it only reads event logs and the ground-truth file.
Author  : Andrei
#>

[CmdletBinding()]
param(
    [string]$GroundTruthPath,
    [string]$ReportPath,
    [int]$WindowSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $GroundTruthPath) { $GroundTruthPath = Join-Path $scriptDir 'windows_attack_log.json' }
if (-not $ReportPath) { $ReportPath = Join-Path $scriptDir 'windows_detection_matrix.json' }

if (-not (Test-Path $GroundTruthPath)) { throw "Ground truth file not found: $GroundTruthPath (run 9-windows_attack_sim.ps1 first)" }
$truth = Get-Content -Path $GroundTruthPath -Raw | ConvertFrom-Json
$actions = @($truth.actions)
Write-Output "[*] Loading ground truth ($($actions.Count) actions)..."

# Per action-number: which (channel, EventId) pairs are plausible hits. "Fields" are
# literal substrings required in the event text before a match counts as "Full" - not
# generic field labels (which exist on nearly every event of that ID and would match
# coincidental, unrelated events), but the actual entity this specific action touched:
# the username, the base64 blob, the task name, the destination IP, the file name.
# $Entity is filled in per action below from the ground truth's "entity" field.
$sourceMap = @{
    1 = @(
        @{ Label = 'Security'; Channel = 'Security'; EventId = 4720; Fields = @('$Entity') }
    )
    2 = @(
        @{ Label = 'Security'; Channel = 'Security'; EventId = 4732; Fields = @('$Entity') }
    )
    3 = @(
        @{ Label = 'PS ScriptBlock'; Channel = 'PowerShell'; EventId = 4104; Fields = @('C2 beacon') }
        @{ Label = 'Sysmon';         Channel = 'Sysmon';     EventId = 1;    Fields = @('$Entity') }
    )
    4 = @(
        @{ Label = 'Sysmon'; Channel = 'Sysmon'; EventId = 1; Fields = @('schtasks', '$Entity') }
    )
    5 = @(
        @{ Label = 'Sysmon'; Channel = 'Sysmon'; EventId = 3; Fields = @('$Entity') }
    )
    6 = @(
        @{ Label = 'Sysmon'; Channel = 'Sysmon'; EventId = 11; Fields = @('$Entity') }
    )
}
$logNames = @{ 'Security' = 'Security'; 'Sysmon' = 'Microsoft-Windows-Sysmon/Operational'; 'PowerShell' = 'Microsoft-Windows-PowerShell/Operational' }

function Find-MatchingEvent {
    param([string]$LogName, [int]$EventId, [datetime]$Start, [datetime]$End, [string[]]$Fields)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventId; StartTime = $Start; EndTime = $End } -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $matchedAll = $true
        foreach ($f in $Fields) { if ($e.Message -notmatch [regex]::Escape($f)) { $matchedAll = $false; break } }
        if ($matchedAll) { return [pscustomobject]@{ Event = $e; Detail = 'Full' } }
    }
    if ($events.Count -gt 0) { return [pscustomobject]@{ Event = $events[0]; Detail = 'Partial' } }
    return $null
}

Write-Output "[*] Searching telemetry for each action..."
$rows = New-Object System.Collections.Generic.List[object]
foreach ($a in $actions) {
    # Ground truth timestamps are UTC ("...Z"). Get-WinEvent's -FilterHashtable
    # StartTime/EndTime ignore the DateTime.Kind flag and treat the clock value as
    # local time, so a UTC-kind value here would search the wrong hour on any host
    # not at UTC+0. Convert to local time before building the search window.
    $tsUtc = [datetime]::Parse($a.timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $ts    = $tsUtc.ToLocalTime()
    $start = $ts.AddSeconds(-$WindowSeconds)
    $end   = $ts.AddSeconds($WindowSeconds)
    $entity = [string]$a.entity
    $sources = @($sourceMap[[int]$a.action_number])
    $hitsForAction = 0
    foreach ($src in $sources) {
        # Resolve the '$Entity' placeholder to this action's actual entity string.
        $fields = @($src.Fields | ForEach-Object { if ($_ -eq '$Entity') { $entity } else { $_ } } | Where-Object { $_ })
        $found = Find-MatchingEvent -LogName $logNames[$src.Channel] -EventId $src.EventId -Start $start -End $end -Fields $fields
        $status = if ($found) { '[CAPTURED]' } else { '[MISSED]' }
        $detail = if ($found) { $found.Detail } else { 'Missed' }
        if ($found) { $hitsForAction++ }
        $rows.Add([pscustomobject]@{
            ActionNumber = $a.action_number
            Action       = $a.description
            Source       = $src.Label
            EventId      = $src.EventId
            Detail       = $detail
            Status       = $status
        })
    }
    if ($hitsForAction -eq 0) {
        # No source matched at all: still record the action so the matrix accounts for every row.
        $rows.Add([pscustomobject]@{ ActionNumber = $a.action_number; Action = $a.description; Source = '-'; EventId = 0; Detail = 'Missed'; Status = '[MISSED]' })
    }
}

# --------------------------------------------------------------------------- Print
$fmt = "{0,-26} {1,-14} {2,-10} {3,-9} {4}"
Write-Output ($fmt -f 'Action', 'Source', 'Event ID', 'Detail', 'Status')
Write-Output ($fmt -f '------', '------', '--------', '------', '------')
$lastAction = $null
foreach ($r in $rows) {
    $label = if ($r.Action -ne $lastAction) { $r.Action } else { '' }
    Write-Output ($fmt -f $label, $r.Source, $r.EventId, $r.Detail, $r.Status)
    $lastAction = $r.Action
}

$capturedActions = @($actions | Where-Object { $a = $_; @($rows | Where-Object { $_.ActionNumber -eq $a.action_number -and $_.Status -eq '[CAPTURED]' }).Count -gt 0 })
$multiSource = @($actions | Where-Object { $a = $_; @($rows | Where-Object { $_.ActionNumber -eq $a.action_number -and $_.Status -eq '[CAPTURED]' }).Count -gt 1 })
$pct = if ($actions.Count -gt 0) { [math]::Round(100 * $capturedActions.Count / $actions.Count) } else { 0 }
Write-Output "Actions: $($actions.Count) | Captured: $($capturedActions.Count)/$($actions.Count) ($pct%) | Multi-source: $($multiSource.Count)"

$report = [ordered]@{
    generated   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    window_seconds = $WindowSeconds
    ground_truth_file = $GroundTruthPath
    rows        = $rows
    summary     = [ordered]@{ total_actions = $actions.Count; captured = $capturedActions.Count; captured_pct = $pct; multi_source = $multiSource.Count }
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Output "Report saved to: $ReportPath"
if ($capturedActions.Count -lt $actions.Count) { exit 1 }
