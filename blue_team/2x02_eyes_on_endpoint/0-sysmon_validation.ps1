<#
Name    : 0-sysmon_validation.ps1
Purpose : Validate that Sysmon is actually capturing the five critical event
          types (process creation, network connection, file creation, registry
          modification, DNS query) by triggering a controlled action for each
          and confirming the expected Event ID shows up with the right detail.
          Read-only against the domain: it only creates and removes its own
          test artifacts on the local machine.
Author  : Andrei
#>

[CmdletBinding()]
param(
    [string]$ReportPath,
    [int]$WaitSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $scriptDir 'sysmon_validation_report.json'
}

$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'

function Wait-ForEvent {
    # Polls instead of a single fixed sleep: Sysmon events can lag a couple of seconds
    # behind the action that caused them.
    param([int]$Id, [datetime]$Since, [scriptblock]$Match, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $hit = Get-WinEvent -FilterHashtable @{ LogName = $sysmonLog; Id = $Id; StartTime = $Since.AddSeconds(-1) } -ErrorAction SilentlyContinue |
               Where-Object $Match | Select-Object -First 1
        if ($hit) { return $hit }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([int]$Step, [string]$Action, [int]$EventId, [string]$Detail, [bool]$Pass, [string]$Note = '')
    $results.Add([pscustomobject]@{ Step = $Step; Action = $Action; EventId = $EventId; Detail = $Detail; Pass = $Pass; Note = $Note })
}

Write-Output "[*] Running Sysmon telemetry validation..."

# ------------------------------------------------- 1/5 Process creation (EID 1)
Write-Output "    [1/5] Process creation (Event ID 1)..."
$t1 = Get-Date
$null = cmd.exe /c whoami
$ev1 = Wait-ForEvent -Id 1 -Since $t1 -TimeoutSeconds $WaitSeconds -Match { $_.Message -match 'CommandLine:\s*.*whoami' -and $_.Message -match 'cmd\.exe' }
if ($ev1 -and $ev1.Message -match 'CommandLine:\s*(.+)') {
    Write-Output "          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]"
    Add-Result 1 'Process creation' 1 'Full' $true "CommandLine: $($Matches[1].Trim())"
} else {
    Write-Output "          cmd.exe /c whoami -> Sysmon EID 1 NOT captured                [FAIL]"
    Add-Result 1 'Process creation' 1 'Missed' $false
}

# ---------------------------------------------- 2/5 Network connection (EID 3)
Write-Output "    [2/5] Network connection (Event ID 3)..."
$t2 = Get-Date
$dest = '8.8.8.8'; $port = 443
$null = Test-NetConnection -ComputerName $dest -Port $port -WarningAction SilentlyContinue
$ev3 = Wait-ForEvent -Id 3 -Since $t2 -TimeoutSeconds $WaitSeconds -Match { $_.Message -match [regex]::Escape($dest) -and $_.Message -match "DestinationPort:\s*$port" }
if ($ev3 -and $ev3.Message -match 'Image:\s*(.+)') {
    Write-Output "          Outbound TCP -> Sysmon EID 3 captured, dest IP/port present   [PASS]"
    Add-Result 2 'Network connection' 3 'Full' $true "Destination: $dest`:$port, Process: $($Matches[1].Trim())"
} else {
    Write-Output "          Outbound TCP -> Sysmon EID 3 NOT captured                     [FAIL]"
    Add-Result 2 'Network connection' 3 'Missed' $false
}

# -------------------------------------------------- 3/5 File creation (EID 11)
# Sysmon's FileCreate rule is a narrow whitelist (Startup folder, Start Menu, Outlook
# attachments, plus the MedDefense self-test marker) - creating a file anywhere else in
# C:\Windows\Temp proves nothing, since it is outside every include rule. The test
# target has to begin with "sysmon_test" to match the deployed marker rule.
Write-Output "    [3/5] File creation (Event ID 11)..."
$t3 = Get-Date
$testFile = 'C:\Windows\Temp\sysmon_test_validate.txt'
Set-Content -Path $testFile -Value "sysmon validation $(Get-Date -Format o)"
$ev11 = Wait-ForEvent -Id 11 -Since $t3 -TimeoutSeconds $WaitSeconds -Match { $_.Message -match [regex]::Escape($testFile) }
if ($ev11) {
    Write-Output "          $testFile -> Sysmon EID 11 captured            [PASS]"
    Add-Result 3 'File creation' 11 'Full' $true "TargetFilename: $testFile"
} else {
    Write-Output "          $testFile -> Sysmon EID 11 NOT captured        [FAIL]"
    Add-Result 3 'File creation' 11 'Missed' $false
}
Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue

# --------------------------------------------- 4/5 Registry modification (EID 13)
# Same reasoning as above: RegistryEvent is whitelisted to persistence-relevant keys
# (Run, Winlogon, Explorer\Run, logon scripts). An arbitrary HKCU test key is outside
# every include rule, so the test instead writes to the Run key - the single most
# common registry persistence location, and a realistic thing to validate.
Write-Output "    [4/5] Registry modification (Event ID 13)..."
$t4 = Get-Date
$runKey  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valName = 'SysmonValidationTest'
New-ItemProperty -Path $runKey -Name $valName -Value 'C:\Windows\System32\cmd.exe /c exit' -PropertyType String -Force | Out-Null
$ev13 = Wait-ForEvent -Id 13 -Since $t4 -TimeoutSeconds $WaitSeconds -Match { $_.Message -match [regex]::Escape($valName) }
if ($ev13) {
    Write-Output "          HKCU\...\Run\$valName -> Sysmon EID 13 captured            [PASS]"
    Add-Result 4 'Registry modification' 13 'Full' $true "TargetObject: $runKey\$valName"
} else {
    Write-Output "          HKCU\...\Run\$valName -> Sysmon EID 13 NOT captured        [FAIL]"
    Add-Result 4 'Registry modification' 13 'Missed' $false
}
Remove-ItemProperty -Path $runKey -Name $valName -Force -ErrorAction SilentlyContinue

# --------------------------------------------------------- 5/5 DNS query (EID 22)
Write-Output "    [5/5] DNS query (Event ID 22)..."
$t5 = Get-Date
$domain = 'www.iana.org'
Clear-DnsClientCache
# NOTE: nslookup.exe and Resolve-DnsName send DNS packets directly and bypass the
# Windows DNS client API (dnsapi.dll) that Sysmon hooks for Event ID 22, so neither
# reliably triggers it on this host. [System.Net.Dns]::GetHostEntry() goes through the
# standard resolver and does trigger it; it is used here for a reliable, side-effect
# free (no ping, no extra network connection) DNS-only test.
try { [void][System.Net.Dns]::GetHostEntry($domain) } catch { }
$ev22 = Wait-ForEvent -Id 22 -Since $t5 -TimeoutSeconds $WaitSeconds -Match { $_.Message -match [regex]::Escape($domain) }
if ($ev22) {
    Write-Output "          Resolve $domain -> Sysmon EID 22 captured                [PASS]"
    Add-Result 5 'DNS query' 22 'Full' $true "QueryName: $domain"
} else {
    Write-Output "          Resolve $domain -> Sysmon EID 22 NOT captured            [FAIL]"
    Add-Result 5 'DNS query' 22 'Missed' $false
}

# ----------------------------------------------------------------------- Report
Write-Output "[*] Cleanup: removing test artifacts..."
$captured = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Output "Actions tested: $total | Captured: $captured | Missed: $($total - $captured)"

$report = [ordered]@{
    generated = (Get-Date).ToString('o')
    hostname  = $env:COMPUTERNAME
    waitSeconds = $WaitSeconds
    results   = $results
    summary   = [ordered]@{ total = $total; captured = $captured; missed = $total - $captured }
}
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Output "Report written: $ReportPath"
if ($captured -lt $total) { exit 1 }
