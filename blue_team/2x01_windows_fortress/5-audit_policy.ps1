<#
.SYNOPSIS
    5-audit_policy.ps1

.DESCRIPTION
    Purpose : Create and link the GPO "MedDefense - Advanced Audit Policy":
              granular audit subcategories, command line in process creation
              events (4688), Security log clearing restricted to Domain Admins,
              Security log size 1 GB. Forces a policy update and verifies with
              auditpol.
              Changes the domain: run as Domain Admin on a domain controller.
    Author  : Andrei
    Date    : 2026-10-20
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = 'MedDefense - Advanced Audit Policy'
$domain  = Get-ADDomain

$securityCse = @('{827D319E-6EAC-11D2-A4EA-00C04F79F83A}', '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')
$auditCse    = @('{F3CCC681-B74C-4060-9F26-CD84525DCA2A}', '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}')

function Add-GpoMachineExtension {
    param([string]$GpoGuid, [string[]]$Pair)
    $dn  = "CN={$GpoGuid},CN=Policies,CN=System,$($domain.DistinguishedName)"
    $obj = Get-ADObject -Identity $dn -Properties gPCMachineExtensionNames, versionNumber
    $current = if ($obj.PSObject.Properties['gPCMachineExtensionNames'] -and $obj.gPCMachineExtensionNames) { [string]$obj.gPCMachineExtensionNames } else { '' }
    $pairs = @([regex]::Matches($current, '\[(\{[^}]+\})(\{[^}]+\})\]') | ForEach-Object { "[$($_.Groups[1].Value)$($_.Groups[2].Value)]" })
    $new = "[$($Pair[0])$($Pair[1])]"
    if ($pairs -notcontains $new) { $pairs += $new }
    $pairs = @($pairs | Sort-Object)
    $oldVer = if ($obj.PSObject.Properties['versionNumber']) { [int]$obj.versionNumber } else { 0 }
    $newVer = $oldVer + 1
    Set-ADObject -Identity $dn -Replace @{ gPCMachineExtensionNames = ($pairs -join ''); versionNumber = $newVer }
    $ini = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$GpoGuid}\GPT.INI"
    Set-Content -Path $ini -Value "[General]`r`nVersion=$newVer" -Encoding ASCII
}

# ---------------------------------------------------------------- Create GPO
Write-Output "[*] Creating GPO: `"$gpoName`"..."
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($gpo) {
    Write-Output "    EXISTS (updating in place)"
} else {
    $gpo = New-GPO -Name $gpoName -Comment 'Advanced audit policy for detection (Task 5)'
    Write-Output "    CREATED"
}
$guid = $gpo.Id.ToString().ToUpper()
$polRoot = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$guid}\Machine\Microsoft\Windows NT"

# ------------------------------------------------- Registry-based policy settings
# Set these first: each Set-GPRegistryValue bumps the GPO version and registers the
# registry CSE, which the SYSVOL file writes below build on.
$null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1
# Security log: 1 GB (value is in KB)
$null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
    -ValueName 'MaxSize' -Type DWord -Value 1048576
# Security log access: only SYSTEM and Domain Admins may clear; Administrators and
# Event Log Readers may read. Mask 0x1 = read, 0x4 = clear.
$daSid = "$($domain.DomainSID.Value)-512"
$sddl  = "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x1;;;BA)(A;;0x5;;;$daSid)(A;;0x1;;;S-1-5-32-573)"
$null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
    -ValueName 'CustomSD' -Type String -Value $sddl

# ------------------------------------------- Advanced audit subcategories (audit.csv)
# Value: 1 = Success, 2 = Failure, 3 = Success and Failure
$audit = @(
    @{ Name = 'Credential Validation';        Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Kerberos Authentication Service'; Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Logon';                        Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Logoff';                       Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Value = 1 }
    @{ Name = 'Special Logon';                Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Value = 1 }
    @{ Name = 'User Account Management';      Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Sensitive Privilege Use';      Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'File System';                  Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Registry';                     Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Process Creation';             Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Value = 1 }
)
$labels = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
$csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
foreach ($a in $audit) {
    $csv += ",System,Audit $($a.Name),$($a.Guid),$($labels[$a.Value]),,$($a.Value)"
}
$auditDir = Join-Path $polRoot 'Audit'
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
Set-Content -Path (Join-Path $auditDir 'audit.csv') -Value $csv -Encoding ASCII
Add-GpoMachineExtension -GpoGuid $guid -Pair $auditCse

# Advanced audit settings must override the legacy basic audit policy.
$inf = @(
    '[Unicode]', 'Unicode=yes',
    '[Registry Values]', 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1',
    '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
)
$secDir = Join-Path $polRoot 'SecEdit'
New-Item -ItemType Directory -Path $secDir -Force | Out-Null
Set-Content -Path (Join-Path $secDir 'GptTmpl.inf') -Value $inf -Encoding Unicode
Add-GpoMachineExtension -GpoGuid $guid -Pair $securityCse

Write-Output "[*] Configuring Audit Categories..."
foreach ($a in $audit) {
    Write-Output ("    {0,-34}{1,-20}[SET]" -f "$($a.Name):", $labels[$a.Value].Replace(' and ', ', '))
}
Write-Output ("[*] {0,-55}[SET]" -f 'Enabling command-line in process creation events...')
Write-Output ("[*] {0,-55}[SET]" -f 'Restricting Security log clearing...')
Write-Output ("[*] {0,-55}[SET]" -f 'Setting Security log max size to 1 GB...')

# ------------------------------------------------------------ Link + force update
$links = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
if (@($links | Where-Object { $_.GpoId -eq $gpo.Id }).Count -eq 0) {
    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
}
gpupdate /force | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed (exit $LASTEXITCODE)" }
Write-Output "[*] Linking GPO and forcing update... COMPLETE"

# ----------------------------------------------------------------------- Verify
Write-Output "[*] Verifying with auditpol /get /category:*"
$effective = auditpol /get /category:* /r | ConvertFrom-Csv
$failed = 0
foreach ($a in $audit) {
    $row = $effective | Where-Object Subcategory -eq $a.Name | Select-Object -First 1
    $have = if ($row) { $row.'Inclusion Setting' } else { 'Unknown' }
    $ok = ($have -eq $labels[$a.Value])
    if (-not $ok) { $failed++ }
    Write-Output ("    {0,-34}{1,-22}{2}" -f $a.Name, $have, $(if ($ok) { '[VERIFIED]' } else { '[MISMATCH]' }))
}
$cmd = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
$cmdOk = ($null -ne $cmd) -and ($cmd.ProcessCreationIncludeCmdLine_Enabled -eq 1)
Write-Output ("    {0,-34}{1,-22}{2}" -f 'Command-line logging', $(if ($cmdOk) { 'Enabled' } else { 'Not applied' }), $(if ($cmdOk) { '[VERIFIED]' } else { '[MISMATCH]' }))
if (-not $cmdOk) { $failed++ }
if ($failed -gt 0) {
    Write-Output "[!] $failed setting(s) not yet effective. Re-run gpupdate /force and check again."
    exit 1
}
