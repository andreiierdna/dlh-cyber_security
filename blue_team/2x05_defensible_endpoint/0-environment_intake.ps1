<#
.SYNOPSIS
    0-environment_intake.ps1 - pre-hardening intake for hawthorne-adm-01.
.DESCRIPTION
    Captures the unhardened state as JSON so every later task can be measured
    against it. Read-only. Sibling of 0-environment_intake.sh with the same
    top-level shape (timestamp/hostname/platform/telemetry/firewall).
    Exit: 0 success, 1 a collector failed, 2 environment error.
.NOTES
    Author: Andrei
#>
[CmdletBinding()]
param([string]$OutFile = 'C:\MedDefense_Lab\capstone\intake\windows_intake.json')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    Write-Output 'ERROR: not a Windows host with NetSecurity module'
    exit 2
}

$dir = Split-Path -Parent $OutFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

function Count-If($items) { @($items | Where-Object { $_ }).Count }

# --- identity / patch level ---------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$build = '{0}.{1}' -f $os.BuildNumber, (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
$features = if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    @(Get-WindowsFeature)
} else {
    @(Get-WindowsOptionalFeature -Online)
}

# --- services, users ----------------------------------------------------------
$services = Get-Service | Select-Object Name, Status, StartType
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon
$admins = @()
try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object -ExpandProperty Name) } catch { }

# --- firewall -----------------------------------------------------------------
$fw = @{}
foreach ($p in 'Domain', 'Private', 'Public') {
    $pf = Get-NetFirewallProfile -Profile $p
    $fw[$p] = [pscustomobject]@{
        enabled                = [bool]$pf.Enabled
        default_inbound_action = $pf.DefaultInboundAction.ToString()
        default_outbound       = $pf.DefaultOutboundAction.ToString()
        log_blocked            = [bool]$pf.LogBlocked
    }
}

# --- audit policy -------------------------------------------------------------
$audit = @()
try { $audit = @(auditpol /get /category:* 2>$null) } catch { }

# --- telemetry ----------------------------------------------------------------
$sysmonSvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
$sysmonChannel = 0
try { $sysmonChannel = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1000 -ErrorAction Stop | Measure-Object).Count } catch { }
$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$moduleLog = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging

# --- account policy -----------------------------------------------------------
$netAccounts = (net accounts) -join "`n"

$result = [ordered]@{
    timestamp            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname             = $env:COMPUTERNAME
    platform             = 'windows'
    os                   = $os.Caption
    build                = $build
    install_date         = $os.InstallDate
    feature_count        = @($features).Count
    installed_features   = @($features | Where-Object { $_.InstallState -eq 'Installed' -or $_.State -eq 'Enabled' }).Count
    running_services     = @($services | Where-Object { $_.Status -eq 'Running' })
    service_count        = @($services).Count
    local_users          = @($users)
    administrators       = $admins
    firewall             = $fw
    audit_policy_lines   = @($audit | Select-Object -Skip 2)
    sysmon               = @{
        installed     = ($null -ne $sysmonSvc)
        status        = if ($sysmonSvc) { $sysmonSvc.Status.ToString() } else { 'Absent' }
        channel_events = $sysmonChannel
    }
    powershell_logging   = @{
        script_block = if ($null -ne $sbl) { [int]$sbl } else { 0 }
        module       = if ($null -ne $moduleLog) { [int]$moduleLog } else { 0 }
    }
    account_policy_raw   = $netAccounts
    rdp_nla              = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
}

$result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
Write-Output ("Intake written: {0}" -f $OutFile)
Write-Output ("  host={0} build={1} services={2} users={3} sysmon={4}" -f $result.hostname, $result.build, $result.service_count, @($users).Count, $result.sysmon.status)
Write-Output ("  firewall: " + (($fw.Keys | ForEach-Object { "$_=$($fw[$_].default_inbound_action)" }) -join ' '))
exit 0
