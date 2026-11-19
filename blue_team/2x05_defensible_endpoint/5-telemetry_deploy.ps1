<#
.SYNOPSIS
    5-telemetry_deploy.ps1 - Sysmon/Script Block Logging coverage proof and
    30-minute Windows telemetry export for hawthorne-adm-01.
.DESCRIPTION
    Runs an authorized test sequence, verifies each action produced the expected
    record, exports the last 30 minutes of Sysmon/PowerShell/Security events with
    the same normalised fields as linux_events.json, and writes windows_coverage.json
    using the same per-action schema as the Linux sibling.
    Exit: 0 all actions captured, 1 a miss, 2 environment error.
.NOTES
    Author: Andrei
#>
[CmdletBinding()]
param([string]$CapRoot = 'C:\MedDefense_Lab\capstone')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$tel = Join-Path $CapRoot 'telemetry'
if (-not (Test-Path $tel)) { New-Item -ItemType Directory -Force -Path $tel | Out-Null }

# --- prerequisites ------------------------------------------------------------
$sysmon = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sysmon) { Write-Output 'ERROR: Sysmon not installed - run 4-windows_harden.ps1'; exit 2 }
$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
Write-Output ("[*] Sysmon: {0}   ScriptBlockLogging: {1}" -f $sysmon.Status, $sbl)

$since = (Get-Date).AddMinutes(-10)
$actions = New-Object System.Collections.Generic.List[object]
$fail = 0

function Test-Captured {
    param([string]$LogName, [int[]]$Ids, [datetime]$Since, [string]$Marker)
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $Since } -ErrorAction Stop
        $hit = $ev | Where-Object { $Ids -contains $_.Id -and ($Marker -eq '' -or $_.Message -match [regex]::Escape($Marker)) }
        return @($hit).Count
    } catch { return 0 }
}

function Wait-Captured {
    # event ingestion is asynchronous: poll instead of sampling once
    param([string]$LogName, [int[]]$Ids, [datetime]$Since, [string]$Marker)
    for ($i = 0; $i -lt 5; $i++) {
        $n = Test-Captured $LogName $Ids $Since $Marker
        if ($n -gt 0) { return $n }
        Start-Sleep -Seconds 3
    }
    return 0
}

function Add-Result {
    param([string]$Action, [string]$Source, $Ids, [int]$Hits)
    $status = 'fail'
    if ($Hits -gt 0) { $status = 'pass' }
    [Console]::WriteLine(("  {0,-30} {1,-22} {2} [{3}]" -f $Action, $Source, $status, $Hits))
    if ($status -eq 'fail') { $script:fail++ }
    $actions.Add([pscustomobject]@{
        action = $Action; source = $Source; event_ids = @($Ids); status = $status
        events = $Hits; timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    })
}

# --- authorized test sequence ---------------------------------------------------
Write-Output '[*] Running authorized test sequence...'
$userName = 'meddefense-telemetry'
$taskName = 'MedDefense-Telemetry-Test'

$t0 = Get-Date
if (-not (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $userName -Password (ConvertTo-SecureString 'Telemetry-Test-2026!' -AsPlainText -Force) `
        -AccountNeverExpires -PasswordNeverExpires | Out-Null
}
Start-Sleep -Seconds 3
Add-Result 'create local user' 'Security' @(4720,4722) (Wait-Captured 'Security' @(4720,4722) $t0 $userName)

$t1 = Get-Date
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo meddefense-telemetry-test'
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5))
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 4
Add-Result 'scheduled task' 'Security/Sysmon' @(4698,1) (Wait-Captured 'Security' @(4698) $t1 $taskName)

$t2 = Get-Date
# sc.exe (not Restart-Service): a real service transition, and Sysmon records it
& sc.exe stop Spooler | Out-Null
Start-Sleep -Seconds 2
& sc.exe start Spooler | Out-Null
Start-Sleep -Seconds 3
# This image emits no System 7036 for sc.exe transitions; the expected trace is
# Sysmon process creation (EID 1) of sc.exe. System 7036 is the fallback.
$svcHits = Wait-Captured 'Microsoft-Windows-Sysmon/Operational' @(1) $t2 'Spooler'
if ($svcHits -eq 0) { $svcHits = Wait-Captured 'System' @(7036) $t2 'spooler' }
Add-Result 'service management' 'Sysmon EID 1' @(1,7036) $svcHits

$t3 = Get-Date
& { 'meddefense-telemetry-probe' } | Out-Null
Start-Sleep -Seconds 4
Add-Result 'powershell command' 'PowerShell' @(4104) (Wait-Captured 'Microsoft-Windows-PowerShell/Operational' @(4104) $t3 'meddefense-telemetry-probe')

# --- cleanup ---------------------------------------------------------------------
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
Write-Output '[*] Test artefacts removed'

# --- 30-minute export --------------------------------------------------------------
Write-Output '[*] Exporting last 30 minutes of Windows telemetry...'
$exportSince = (Get-Date).AddMinutes(-30)
$events = New-Object System.Collections.Generic.List[object]

function Add-Events {
    param([string]$LogName, [string]$SourceType, [string]$Channel)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $exportSince } -MaxEvents 2000 -ErrorAction Stop |
        ForEach-Object {
            $events.Add([pscustomobject]@{
                timestamp      = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                hostname       = $env:COMPUTERNAME
                platform       = 'windows'
                source_type    = $SourceType
                channel        = $Channel
                event_id       = $_.Id
                event_category = if ($_.LevelDisplayName) { $_.LevelDisplayName } else { 'Information' }
                provider       = $_.ProviderName
                raw_message    = ($_.Message -replace "`r?`n", ' ')
            })
        }
    } catch { }
}

Add-Events 'Microsoft-Windows-Sysmon/Operational' 'sysmon' 'Microsoft-Windows-Sysmon/Operational'
Add-Events 'Microsoft-Windows-PowerShell/Operational' 'powershell' 'Microsoft-Windows-PowerShell/Operational'
Add-Events 'Security' 'security' 'Security'

$json = ConvertTo-Json -InputObject @($events) -Depth 4 -Compress
$eventsPath = Join-Path $tel 'windows_events.json'
Set-Content -Path $eventsPath -Value $json -Encoding UTF8

$coverage = @{}
$coverage['generated_at'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$coverage['hostname'] = $env:COMPUTERNAME
$coverage['platform'] = 'windows'
$coverage['source'] = 'sysmon + powershell + security'
$coverage['tests_total'] = $actions.Count
$coverage['tests_passed'] = ($actions.Count - $fail)
$coverage['tests_failed'] = $fail
$coverage['verdict'] = 'FAIL'
if ($fail -eq 0) { $coverage['verdict'] = 'PASS' }
$coverage['export_path'] = $eventsPath
$coverage['export_events'] = $events.Count
$coverage['actions'] = @($actions)
$covPath = Join-Path $tel 'windows_coverage.json'
Set-Content -Path $covPath -Value (ConvertTo-Json -InputObject $coverage -Depth 5) -Encoding UTF8

Write-Output ("Coverage: {0}/{1} actions captured; exported events: {2}" -f ($actions.Count - $fail), $actions.Count, $events.Count)
Write-Output ("Artifacts: {0}, {1}" -f $eventsPath, $covPath)
if ($fail -eq 0) { exit 0 } else { exit 1 }
