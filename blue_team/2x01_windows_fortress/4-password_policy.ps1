<#
.SYNOPSIS
    4-password_policy.ps1

.DESCRIPTION
    Purpose : Create and link the GPO "MedDefense - Password and Lockout Policy"
              (14 char minimum, complexity, 24 history, no expiry, 1 day minimum
              age, lockout after 5 attempts for 15 minutes), force a policy
              update and verify the effective domain policy.
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

$gpoName = 'MedDefense - Password and Lockout Policy'
$domain  = Get-ADDomain

# CSE pair for "Security Settings" (GptTmpl.inf)
$securityCse = @('{827D319E-6EAC-11D2-A4EA-00C04F79F83A}', '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')

function Add-GpoMachineExtension {
    # Registers a client-side extension pair on the GPO and bumps its machine version so
    # clients re-read SYSVOL. Keeps the extension list sorted as Windows expects.
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
    $gpo = New-GPO -Name $gpoName -Comment 'CIS password and account lockout policy (Task 4)'
    Write-Output "    CREATED"
}
$guid = $gpo.Id.ToString().ToUpper()

# --------------------------------------------------- Password + lockout settings
$settings = [ordered]@{
    MinimumPasswordLength = 14
    PasswordComplexity    = 1
    PasswordHistorySize   = 24
    MaximumPasswordAge    = -1     # -1 = password never expires (Maximum age: 0)
    MinimumPasswordAge    = 1
    LockoutBadCount       = 5
    LockoutDuration       = 15
    ResetLockoutCount     = 15
}
$inf = @("[Unicode]", "Unicode=yes", "[System Access]")
foreach ($k in $settings.Keys) { $inf += "$k = $($settings[$k])" }
$inf += @("[Version]", 'signature="$CHICAGO$"', "Revision=1")

$secDir = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$guid}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -ItemType Directory -Path $secDir -Force | Out-Null
Set-Content -Path (Join-Path $secDir 'GptTmpl.inf') -Value $inf -Encoding Unicode
Add-GpoMachineExtension -GpoGuid $guid -Pair $securityCse

Write-Output "[*] Configuring Password Policy..."
Write-Output ("    {0,-30}[SET]" -f 'Minimum Length: 14')
Write-Output ("    {0,-30}[SET]" -f 'Complexity: Enabled')
Write-Output ("    {0,-30}[SET]" -f 'History: 24')
Write-Output ("    {0,-30}[SET]" -f 'Maximum Age: 0')
Write-Output ("    {0,-30}[SET]" -f 'Minimum Age: 1 day')
Write-Output "[*] Configuring Account Lockout..."
Write-Output ("    {0,-30}[SET]" -f 'Threshold: 5 attempts')
Write-Output ("    {0,-30}[SET]" -f 'Duration: 15 minutes')
Write-Output ("    {0,-30}[SET]" -f 'Reset Counter: 15 minutes')

# ------------------------------------------------------------ Link to domain root
Write-Output "[*] Linking GPO to domain root..."
$links = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
if (@($links | Where-Object { $_.GpoId -eq $gpo.Id }).Count -eq 0) {
    # Order 1 = highest precedence, so it wins over Default Domain Policy.
    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes -Order 1 | Out-Null
    Write-Output "    LINKED"
} else {
    Set-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes -Order 1 | Out-Null
    Write-Output "    ALREADY LINKED (precedence set to 1)"
}

# --------------------------------------------------------- Force update + verify
Write-Output "[*] Forcing Group Policy update..."
gpupdate /force | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed (exit $LASTEXITCODE)" }
Write-Output "    COMPLETE"

Write-Output "[*] Verifying effective domain policy..."
$eff = Get-ADDefaultDomainPasswordPolicy
$checks = @(
    @('Minimum length',    $eff.MinPasswordLength,                 14),
    @('Complexity',        [int][bool]$eff.ComplexityEnabled,      1),
    @('History',           $eff.PasswordHistoryCount,              24),
    @('Maximum age (days)', [int]$eff.MaxPasswordAge.TotalDays,    0),
    @('Minimum age (days)', [int]$eff.MinPasswordAge.TotalDays,    1),
    @('Lockout threshold', $eff.LockoutThreshold,                  5),
    @('Lockout duration (min)', [int]$eff.LockoutDuration.TotalMinutes, 15),
    @('Reset counter (min)', [int]$eff.LockoutObservationWindow.TotalMinutes, 15)
)
$failed = 0
foreach ($c in $checks) {
    $ok = ($c[1] -eq $c[2])
    if (-not $ok) { $failed++ }
    Write-Output ("    {0,-26}{1,-6}{2}" -f $c[0], $c[1], $(if ($ok) { '[VERIFIED]' } else { "[MISMATCH - expected $($c[2])]" }))
}
if ($failed -gt 0) {
    Write-Output "[!] $failed setting(s) not yet effective. Re-run gpupdate /force and check GPO precedence at the domain root."
    exit 1
}
