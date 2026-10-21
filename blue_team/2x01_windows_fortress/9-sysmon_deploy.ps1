<#
.SYNOPSIS
    9-sysmon_deploy.ps1

.DESCRIPTION
    Purpose : Download Sysmon (Microsoft Sysinternals) and the SwiftOnSecurity
              baseline configuration, append five MedDefense detection rules,
              write the result to sysmonconfig.xml (separate deliverable),
              install Sysmon with it, and verify service, driver, event flow
              and FileCreate (Event ID 11) detection.
              Changes the host: run elevated. Needs outbound HTTPS to
              download.sysinternals.com and raw.githubusercontent.com.
    Author  : Andrei
    Date    : 2026-10-20

.PARAMETER ConfigPath
    Where the finished configuration is written. Default: sysmonconfig.xml next to
    this script.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$WorkDir = (Join-Path $env:TEMP 'sysmon_deploy')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ConfigPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ConfigPath = Join-Path $scriptDir 'sysmonconfig.xml'
}

$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$configUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Five MedDefense rules appended to the baseline: lateral movement (PsExec, WMI),
# exfiltration (rclone), encoded PowerShell, and the deployment self-test.
$customRules = @'

  <!-- ===================== MedDefense custom rules ===================== -->
  <RuleGroup name="MedDefense" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image name="MedDefense-PsExec" condition="end with">\PsExec.exe;\PsExec64.exe;\PSEXESVC.exe</Image>
      <Image name="MedDefense-Rclone" condition="end with">\rclone.exe</Image>
      <CommandLine name="MedDefense-EncodedPowerShell" condition="contains any">-enc ;-EncodedCommand;-encodedcommand</CommandLine>
      <ParentImage name="MedDefense-WmiProcessSpawn" condition="end with">\WmiPrvSE.exe</ParentImage>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename name="MedDefense-DeploySelfTest" condition="begin with">C:\Windows\Temp\sysmon_test</TargetFilename>
    </FileCreate>
  </RuleGroup>
'@

# ------------------------------------------------------------------- Download
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$zip = Join-Path $WorkDir 'Sysmon.zip'
$baseline = Join-Path $WorkDir 'sysmonconfig-export.xml'

Write-Output "[*] Downloading Sysmon..."
Invoke-WebRequest -Uri $sysmonUrl -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $WorkDir -Force
$exe = Join-Path $WorkDir 'Sysmon64.exe'
if (-not (Test-Path $exe)) { throw "Sysmon64.exe not found after extracting $zip" }
Write-Output "    OK"

Write-Output "[*] Downloading SwiftOnSecurity config..."
Invoke-WebRequest -Uri $configUrl -OutFile $baseline -UseBasicParsing
[xml]$xml = Get-Content -Path $baseline -Raw   # throws if the download is not valid XML
Write-Output "    OK"

# ----------------------------------------------- Build sysmonconfig.xml and install
$text = Get-Content -Path $baseline -Raw
$marker = '</EventFiltering>'
if ($text -notmatch [regex]::Escape($marker)) { throw 'Baseline config has no </EventFiltering> element.' }
$text = $text.Replace($marker, "$customRules`r`n  $marker")
[xml]$check = $text                                  # validate the merged document
Set-Content -Path $ConfigPath -Value $text -Encoding UTF8
Write-Output "[*] Wrote configuration: $ConfigPath"

Write-Output "[*] Installing Sysmon with config..."
$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output "    Sysmon64.exe -accepteula -c sysmonconfig.xml   (already installed: updating configuration)"
    & $exe -accepteula -c $ConfigPath | Out-Null
} else {
    Write-Output "    Sysmon64.exe -accepteula -i sysmonconfig.xml"
    & $exe -accepteula -i $ConfigPath | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon64.exe failed (exit $LASTEXITCODE)" }

# --------------------------------------------------------------------- Verify
$failed = 0
$svc = Get-Service -Name 'Sysmon64'
$svcOk = ($svc.Status -eq 'Running')
Write-Output ("    {0,-34}{1}" -f "Service: Sysmon64 - $($svc.Status)", $(if ($svcOk) { '[OK]' } else { '[FAILED]' }))
if (-not $svcOk) { $failed++ }

# sc.exe reads the kernel driver service directly (Get-Service and CIM do not list it reliably).
$drvOk = [bool](sc.exe query SysmonDrv | Select-String -Pattern 'STATE\s*:\s*4\s+RUNNING' -Quiet)
Write-Output ("    {0,-34}{1}" -f "Driver: SysmonDrv - $(if ($drvOk) { 'Loaded' } else { 'Not loaded' })", $(if ($drvOk) { '[OK]' } else { '[FAILED]' }))
if (-not $drvOk) { $failed++ }

Write-Output "[*] Verifying event generation..."
$log = 'Microsoft-Windows-Sysmon/Operational'
$null = cmd.exe /c ver                       # spawn a process so there is something to log
Start-Sleep -Seconds 3
$recent = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = (Get-Date).AddSeconds(-60) } -ErrorAction SilentlyContinue)
$evOk = ($recent.Count -gt 0)
Write-Output ("    {0,-34}{1}" -f "Events in last 60 seconds: $($recent.Count)", $(if ($evOk) { '[OK]' } else { '[FAILED]' }))
if (-not $evOk) { $failed++ }

Write-Output "[*] Testing FileCreate detection..."
$test = 'C:\Windows\Temp\sysmon_test.txt'
$start = Get-Date
Set-Content -Path $test -Value "sysmon test $(Get-Date -Format o)"
Write-Output "    Created: $test"
Start-Sleep -Seconds 3
$hit = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 11; StartTime = $start.AddSeconds(-1) } -ErrorAction SilentlyContinue |
       Where-Object { $_.Message -match [regex]::Escape('sysmon_test.txt') } | Select-Object -First 1
Remove-Item -Path $test -Force -ErrorAction SilentlyContinue
if ($hit) {
    Write-Output "    Event ID 11 captured                   [VERIFIED]"
} else {
    Write-Output "    Event ID 11 not captured               [FAILED]"
    $failed++
}
if ($failed -gt 0) { exit 1 }
