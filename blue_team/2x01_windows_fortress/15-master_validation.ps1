<#
.SYNOPSIS
    15-master_validation.ps1

.DESCRIPTION
    Purpose : Weekly compliance check for the MedDefense Windows domain. Reads
              every hardening setting deployed by tasks 4-14, compares it with
              the expected value and prints PASS / WARN / FAIL per check plus a
              summary. Makes NO changes.
              Exit code 0 when every critical check passes, 1 when any critical
              check fails.
    Author  : Andrei
    Date    : 2026-10-20

.PARAMETER ServiceAccountMaxAgeDays
    Service account passwords older than this produce a WARN. Default 90.
#>

[CmdletBinding()]
param(
    [int]$ServiceAccountMaxAgeDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$script:results = New-Object System.Collections.Generic.List[object]
$script:section = ''

function Start-Section {
    param([string]$Title)
    $script:section = $Title
    Write-Output "--- $Title ---"
}
function Add-Check {
    param([ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status, [string]$Message, [bool]$Critical = $true)
    $script:results.Add([pscustomobject]@{ Section = $script:section; Status = $Status; Message = $Message; Critical = $Critical })
    Write-Output "[$Status] $Message"
}
function Test-Equal {
    param([string]$Label, $Actual, $Expected, [bool]$Critical = $true)
    $shown = if ($null -eq $Actual) { 'not set' } else { "$Actual" }
    if ($shown -eq "$Expected") { Add-Check PASS "${Label}: $shown" $Critical }
    else { Add-Check $(if ($Critical) { 'FAIL' } else { 'WARN' }) "${Label}: $shown (expected $Expected)" $Critical }
}
function Get-RegValue {
    param([string]$Path, [string]$Name)
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return $p.$Name
}

# ----------------------------------------------------------- Password & Lockout
Start-Section 'Password & Lockout'
$pwd = Get-ADDefaultDomainPasswordPolicy
Test-Equal 'Minimum length' $pwd.MinPasswordLength 14
Test-Equal 'Complexity' $(if ($pwd.ComplexityEnabled) { 'Enabled' } else { 'Disabled' }) 'Enabled'
Test-Equal 'History' $pwd.PasswordHistoryCount 24 $false
Test-Equal 'Lockout threshold' $pwd.LockoutThreshold 5
Test-Equal 'Lockout duration (min)' ([int]$pwd.LockoutDuration.TotalMinutes) 15 $false

# ------------------------------------------------------------------ Audit Policy
Start-Section 'Audit Policy'
$audit = auditpol /get /category:* /r | ConvertFrom-Csv
function Get-AuditSetting { param([string]$Sub) ($audit | Where-Object Subcategory -eq $Sub | Select-Object -First 1).'Inclusion Setting' }
$auditExpect = @(
    @('Credential Validation', 'Success and Failure'), @('Kerberos Authentication Service', 'Success and Failure'),
    @('Logon', 'Success and Failure'), @('Special Logon', 'Success'), @('User Account Management', 'Success and Failure'),
    @('Sensitive Privilege Use', 'Success and Failure'), @('Process Creation', 'Success')
)
foreach ($e in $auditExpect) {
    $have = Get-AuditSetting $e[0]
    $ok = ($have -eq $e[1]) -or ($e[1] -eq 'Success' -and $have -eq 'Success and Failure')
    if ($ok) { Add-Check PASS "$($e[0]): $have" } else { Add-Check FAIL "$($e[0]): $have (expected $($e[1]))" }
}
$cmdline = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
Test-Equal 'Command-line logging' $(if ($cmdline -eq 1) { 'Enabled' } else { 'Disabled' }) 'Enabled'
$maxKb = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize'
if ($null -ne $maxKb -and $maxKb -ge 1048576) { Add-Check PASS 'Security log: 1 GB' } else { Add-Check FAIL "Security log: $(if ($null -eq $maxKb) { 'no size policy' } else { "$maxKb KB" }) (expected 1048576 KB)" }

# -------------------------------------------------------------------- PowerShell
Start-Section 'PowerShell'
$psBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Test-Equal 'Script Block Logging' $(if ((Get-RegValue "$psBase\ScriptBlockLogging" 'EnableScriptBlockLogging') -eq 1) { 'Enabled' } else { 'Disabled' }) 'Enabled'
Test-Equal 'Module Logging' $(if ((Get-RegValue "$psBase\ModuleLogging" 'EnableModuleLogging') -eq 1) { 'Enabled' } else { 'Disabled' }) 'Enabled'
Test-Equal 'Transcription' $(if ((Get-RegValue "$psBase\Transcription" 'EnableTranscripting') -eq 1) { 'Enabled' } else { 'Disabled' }) 'Enabled'

# ------------------------------------------------------------------------ Sysmon
Start-Section 'Sysmon'
$sysmon = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmon -and $sysmon.Status -eq 'Running') {
    Add-Check PASS 'Service: Running'
    $exe = Join-Path $env:windir 'Sysmon64.exe'
    if (Test-Path $exe) {
        # Sysmon writes its banner to stderr, which would trip $ErrorActionPreference = "Stop".
        $ErrorActionPreference = 'Continue'
        $dump = (& $exe -c 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $ErrorActionPreference = 'Stop'
        $dump = $dump -replace "`0", ''      # Sysmon prints UTF-16; drop the NULs a non-UTF-16 console leaves behind
        # The dump lists filters but not rule names, so read the config file Sysmon reports.
        $cfgPath = if ($dump -match 'Config file:\s+(.+)') { $Matches[1].Trim() } else { '' }
        if ($cfgPath -and (Test-Path $cfgPath)) {
            $names = [regex]::Matches((Get-Content -Path $cfgPath -Raw), 'name="(MedDefense-[^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
            $custom = @($names).Count
            if ($custom -ge 5) { Add-Check PASS "Custom rules: $custom present" }
            else { Add-Check WARN "Custom rules: $custom present (expected 5)" $false }
        } else {
            Add-Check WARN "Custom rules: config file not readable ($cfgPath)" $false
        }
    } else {
        Add-Check WARN 'Custom rules: Sysmon64.exe not found to read configuration' $false
    }
} else {
    Add-Check FAIL "Service: $(if ($sysmon) { $sysmon.Status } else { 'Not installed' })"
}

# ---------------------------------------------------------------------- Kerberos
Start-Section 'Kerberos'
$enc = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes'
if ($null -eq $enc) { $enc = 31 }
if (($enc -band 3) -eq 0) { Add-Check PASS 'DES: Disabled' } else { Add-Check FAIL 'DES: Enabled' }
if (($enc -band 4) -eq 0) { Add-Check PASS 'RC4: Disabled' } else { Add-Check FAIL 'RC4: Enabled' }
$lm = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
if ($null -ne $lm -and $lm -ge 5) { Add-Check PASS "NTLM: v2 only (LmCompatibilityLevel=$lm)" } else { Add-Check FAIL "NTLM: LmCompatibilityLevel=$(if ($null -eq $lm) { 'not set' } else { $lm }) (expected 5)" }
$desFlag = @(Get-ADUser -Filter 'UseDESKeyOnly -eq $true')
if ($desFlag.Count -eq 0) { Add-Check PASS 'Accounts with DES-only flag: 0' } else { Add-Check FAIL "Accounts with DES-only flag: $($desFlag.Count)" }

# --------------------------------------------------------------------------- SMB
Start-Section 'SMB'
$smb = Get-SmbServerConfiguration
if (-not $smb.EnableSMB1Protocol) { Add-Check PASS 'SMBv1: Disabled' } else { Add-Check FAIL 'SMBv1: Enabled' }
if ($smb.RequireSecuritySignature) { Add-Check PASS 'Signing: Required' } else { Add-Check FAIL 'Signing: Not required' }

# ---------------------------------------------------------------------- Firewall
Start-Section 'Firewall'
$fw = @(Get-NetFirewallProfile)
$fwBad = @($fw | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })
if ($fwBad.Count -eq 0) { Add-Check PASS 'All profiles: ON, DefaultInbound: Block' }
else { Add-Check FAIL "Profiles not compliant: $(($fwBad | ForEach-Object Name) -join ', ')" }
$meddef = @(Get-NetFirewallRule -Group 'MedDefense' -Enabled True -ErrorAction SilentlyContinue)
if ($meddef.Count -ge 6) { Add-Check PASS "MedDefense allow rules: $($meddef.Count) active" }
else { Add-Check WARN "MedDefense allow rules: $($meddef.Count) active (expected at least 6)" $false }

# --------------------------------------------------------------------------- RDP
Start-Section 'RDP'
$ws = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
if ((Get-RegValue $ws 'UserAuthentication') -eq 1) { Add-Check PASS 'NLA: Required' } else { Add-Check FAIL 'NLA: Not required' }
$rdu = @(Get-ADGroupMember -Identity 'Remote Desktop Users' | ForEach-Object SamAccountName)
if ($rdu.Count -eq 1 -and $rdu[0] -eq 'G_IT_Admins') { Add-Check PASS 'G_IT_Admins only' }
else { Add-Check FAIL "Remote Desktop Users: $(if ($rdu.Count) { $rdu -join ', ' } else { 'empty' }) (expected G_IT_Admins only)" }
$ts = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if ((Get-RegValue $ts 'fDisableClip') -eq 1 -and (Get-RegValue $ts 'fDisableCdm') -eq 1) { Add-Check PASS 'Clipboard and drive redirection: Disabled' }
else { Add-Check FAIL 'Clipboard / drive redirection not disabled' }
$idle = Get-RegValue $ts 'MaxIdleTime'
if ($null -ne $idle -and $idle -gt 0 -and $idle -le 900000) { Add-Check PASS 'Idle timeout: 15 min' } else { Add-Check WARN "Idle timeout: $(if ($null -eq $idle) { 'not set' } else { "$idle ms" }) (expected 900000 ms)" $false }

# ------------------------------------------------------------- Service Accounts
Start-Section 'Service Accounts'
$svc = @(Get-ADUser -Filter * -Properties AccountNotDelegated, TrustedForDelegation, PasswordLastSet, DistinguishedName |
         Where-Object { $_.SamAccountName -like '*svc*' -or $_.DistinguishedName -like '*OU=Service Accounts*' })
$restricted = @($svc | Where-Object { $_.AccountNotDelegated -and -not $_.TrustedForDelegation })
if ($svc.Count -gt 0 -and $restricted.Count -eq $svc.Count) { Add-Check PASS "Delegation restricted: $($restricted.Count)/$($svc.Count)" }
else { Add-Check FAIL "Delegation restricted: $($restricted.Count)/$($svc.Count)" }
foreach ($a in $svc) {
    $age = if ($a.PasswordLastSet) { [int]((Get-Date) - $a.PasswordLastSet).TotalDays } else { 99999 }
    if ($age -gt $ServiceAccountMaxAgeDays) { Add-Check WARN "$($a.SamAccountName) password age: $age days" $false }
}

# ----------------------------------------------------------------------- Summary
$pass = @($script:results | Where-Object Status -eq 'PASS').Count
$warn = @($script:results | Where-Object Status -eq 'WARN').Count
$fail = @($script:results | Where-Object Status -eq 'FAIL').Count
$critFail = @($script:results | Where-Object { $_.Status -eq 'FAIL' -and $_.Critical }).Count
Write-Output ""
Write-Output "Summary: PASS $pass, WARN $warn, FAIL $fail (critical failures: $critFail)"
if ($critFail -gt 0) { Write-Output 'Result: NON-COMPLIANT'; exit 1 }
Write-Output 'Result: COMPLIANT'
exit 0
