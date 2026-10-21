<#
.SYNOPSIS
    14-service_accounts.ps1

.DESCRIPTION
    Purpose : Audit every MedDefense service account (group memberships,
              password age, delegation, SPNs, DES flag, last logon), flag the
              weaknesses and remediate: "Account is sensitive and cannot be
              delegated", unconstrained delegation cleared, removal from
              privileged groups, and a GPO ("MedDefense - Service Account
              Restrictions") denying interactive and Remote Desktop logon.
              Use -ReportOnly to audit without changing anything.
              Changes the domain unless -ReportOnly: run as Domain Admin on a DC.
    Author  : Andrei
    Date    : 2026-10-20

.PARAMETER MaxPasswordAgeDays
    Passwords older than this are flagged. Default 90.
#>

[CmdletBinding()]
param(
    [int]$MaxPasswordAgeDays = 90,
    [switch]$ReportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain  = Get-ADDomain
$gpoName = 'MedDefense - Service Account Restrictions'
$privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
                      'Account Operators', 'Server Operators', 'Print Operators')
$securityCse = @('{827D319E-6EAC-11D2-A4EA-00C04F79F83A}', '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')

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

# Exact last logon: lastLogon is not replicated, so ask every DC and keep the newest.
function Get-ExactLastLogon {
    param([string]$Sam)
    $latest = 0L
    foreach ($dc in Get-ADDomainController -Filter *) {
        $u = Get-ADUser -Identity $Sam -Server $dc.HostName -Properties lastLogon
        if ($u.lastLogon -and [int64]$u.lastLogon -gt $latest) { $latest = [int64]$u.lastLogon }
    }
    if ($latest -eq 0) { return $null }
    return [DateTime]::FromFileTime($latest)
}

# ------------------------------------------------------------------------ Audit
$props = 'MemberOf', 'PasswordLastSet', 'TrustedForDelegation', 'TrustedToAuthForDelegation', 'UseDESKeyOnly',
         'AccountNotDelegated', 'ServicePrincipalName', 'DistinguishedName', 'msDS-AllowedToDelegateTo'
$svcAccounts = @(Get-ADUser -Filter * -Properties $props |
    Where-Object { $_.SamAccountName -like '*svc*' -or $_.DistinguishedName -like '*OU=Service Accounts*' } |
    Sort-Object SamAccountName)
if ($svcAccounts.Count -eq 0) { Write-Output 'No service accounts found.'; exit 0 }

$findings = 0
foreach ($a in $svcAccounts) {
    Write-Output "$($a.SamAccountName):"
    $age = if ($a.PasswordLastSet) { [int]((Get-Date) - $a.PasswordLastSet).TotalDays } else { $null }
    if ($null -eq $age) {
        Write-Output ("  {0,-38}[!]" -f 'Password age: never set'); $findings++
    } elseif ($age -gt $MaxPasswordAgeDays) {
        Write-Output ("  {0,-38}[!]" -f "Password age: $age days"); $findings++
    } else {
        Write-Output ("  Password age: {0} days" -f $age)
    }

    if ($a.TrustedForDelegation) {
        Write-Output ("  {0,-38}[!]" -f 'Delegation: Unconstrained'); $findings++
    } elseif (@($a.'msDS-AllowedToDelegateTo').Count -gt 0) {
        Write-Output "  Delegation: Constrained"
    } else {
        Write-Output "  Delegation: None"
    }
    if (-not $a.AccountNotDelegated) {
        Write-Output ("  {0,-38}[!]" -f 'Sensitive (cannot be delegated): No'); $findings++
    }
    if ($a.UseDESKeyOnly) {
        Write-Output ("  {0,-38}[!]" -f 'UseDESKeyOnly: True'); $findings++
    }
    $spns = @($a.ServicePrincipalName)
    if ($spns.Count -gt 0) { Write-Output "  SPN: $($spns -join ', ')" } else { Write-Output '  SPN: none' }

    $last = Get-ExactLastLogon -Sam $a.SamAccountName
    # The Security log also records successful logons (4624) the directory attribute can miss.
    $xpath = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$($a.SamAccountName)']]"
    $logons = @(Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 200 -ErrorAction SilentlyContinue)
    if ($logons.Count -gt 0) {
        $newest = ($logons | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
        if ($null -eq $last -or $newest -gt $last) { $last = $newest }
        $night = @($logons | Where-Object { $_.TimeCreated.Hour -lt 5 })
        if ($night.Count -gt 0) {
            Write-Output ("  {0,-38}[!!!]" -f "Logons between 00:00 and 05:00: $($night.Count) (Security log)")
            $findings++
        }
    }
    if ($null -eq $last) {
        Write-Output '  Last logon: never'
    } else {
        $odd = ($last.Hour -lt 5)       # logons in the small hours are suspicious for a service account
        Write-Output ("  {0,-38}{1}" -f "Last logon: $($last.ToString('yyyy-MM-dd HH:mm'))", $(if ($odd) { '[!!!]' } else { '' }))
        if ($odd) { $findings++ }
    }

    $groups = @($a.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' })
    $priv = @($groups | Where-Object { $privilegedGroups -contains $_ })
    Write-Output "  Groups: $(if ($groups.Count) { $groups -join ', ' } else { 'none' })"
    if ($priv.Count -gt 0) {
        Write-Output ("  {0,-38}[!]" -f "Privileged groups: $($priv -join ', ')"); $findings++
    }
}
Write-Output ""
Write-Output "Findings: $findings across $($svcAccounts.Count) service accounts (password age limit: $MaxPasswordAgeDays days)"
if ($ReportOnly) { Write-Output 'Report only: no changes made.'; exit 0 }

# ------------------------------------------------------------------- Remediation
Write-Output ""
Write-Output "[*] Remediating..."
foreach ($a in $svcAccounts) {
    # One call, by name: passing the cached object would write its stale UserAccountControl back.
    Set-ADAccountControl -Identity $a.SamAccountName -TrustedForDelegation $false -AccountNotDelegated $true
    if ($a.TrustedForDelegation) {
        Write-Output ("    {0,-12}Unconstrained delegation cleared      [DONE]" -f $a.SamAccountName)
    }
    Write-Output ("    {0,-12}Sensitive, cannot be delegated        [DONE]" -f $a.SamAccountName)
    foreach ($g in @($a.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' } | Where-Object { $privilegedGroups -contains $_ })) {
        Remove-ADGroupMember -Identity $g -Members $a -Confirm:$false
        Write-Output ("    {0,-12}Removed from {1,-20}[DONE]" -f $a.SamAccountName, $g)
    }
}

# Deny interactive and Remote Desktop logon with a GPO (user rights are not registry settings).
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $gpoName -Comment 'Deny interactive logon for service accounts (Task 14)' }
$guid = $gpo.Id.ToString().ToUpper()
$sids = ($svcAccounts | ForEach-Object { "*$($_.SID.Value)" }) -join ','
$inf = @('[Unicode]', 'Unicode=yes', '[Privilege Rights]',
         "SeDenyInteractiveLogonRight = $sids",
         "SeDenyRemoteInteractiveLogonRight = $sids",
         '[Version]', 'signature="$CHICAGO$"', 'Revision=1')
$secDir = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$guid}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -ItemType Directory -Path $secDir -Force | Out-Null
Set-Content -Path (Join-Path $secDir 'GptTmpl.inf') -Value $inf -Encoding Unicode
Add-GpoMachineExtension -GpoGuid $guid -Pair $securityCse
$links = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
if (@($links | Where-Object { $_.GpoId -eq $gpo.Id }).Count -eq 0) {
    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
}
gpupdate /force | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed (exit $LASTEXITCODE)" }
Write-Output ("    {0,-44}[DONE]" -f 'Interactive + RDP logon denied (GPO)')

# ----------------------------------------------------------------------- Verify
Write-Output "[*] Verifying..."
$failed = 0
foreach ($a in $svcAccounts) {
    $now = Get-ADUser -Identity $a -Properties TrustedForDelegation, AccountNotDelegated, MemberOf
    $privLeft = @($now.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' } | Where-Object { $privilegedGroups -contains $_ })
    $ok = (-not $now.TrustedForDelegation) -and $now.AccountNotDelegated -and ($privLeft.Count -eq 0)
    if (-not $ok) { $failed++ }
    Write-Output ("    {0,-14}{1}" -f $a.SamAccountName, $(if ($ok) { '[VERIFIED]' } else { '[FAILED]' }))
}
if ($failed -gt 0) { exit 1 }
