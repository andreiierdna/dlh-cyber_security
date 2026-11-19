<#
.SYNOPSIS
    1-baseline_snapshot.ps1 - CIS Level 1 baseline score for hawthorne-adm-01.
.DESCRIPTION
    Runs the audit helper, persists the raw output and emits the scored baseline
    (same field names as baseline_linux.json plus the Windows-specific counts).
    Exit: 0 audit ran, 1 score could not be computed, 2 environment error.
.NOTES
    Author: Andrei
#>
[CmdletBinding()]
param(
    [string]$AuditScript = 'C:\MedDefense_Lab\capstone\win_audit.ps1',
    [string]$BaseDir     = 'C:\MedDefense_Lab\capstone\baseline'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not (Test-Path $AuditScript)) { Write-Output "ERROR: $AuditScript missing"; exit 2 }
if (-not (Test-Path $BaseDir)) { New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null }

$logPath = Join-Path $BaseDir 'windows_baseline.log'
Set-ExecutionPolicy -Scope Process Bypass -Force
$lines = & $AuditScript
$lines | Set-Content -Path $logPath -Encoding UTF8

$pass = @($lines | Select-String '^PASS ').Count
$fail = @($lines | Select-String '^FAIL ').Count
$na = @($lines | Select-String '^NOT_APPLICABLE ').Count
$total = $pass + $fail + $na
if ($total -eq 0) { Write-Output 'ERROR: audit produced no control lines'; exit 1 }

$rate = [math]::Round(100.0 * $pass / $total, 1)
$result = [ordered]@{
    timestamp          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname           = $env:COMPUTERNAME
    platform           = 'windows'
    controls_total     = $total
    pass_count         = $pass
    fail_count         = $fail
    na_count           = $na
    pass_rate_percent  = $rate
    log_path           = $logPath
}
$out = Join-Path $BaseDir 'baseline_windows.json'
$result | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8
Write-Output ("Baseline: {0}/{1} controls pass ({2}%)  fail={3} na={4}" -f $pass, $total, $rate, $fail, $na)
Write-Output ("Baseline written: {0}" -f $out)
exit 0
