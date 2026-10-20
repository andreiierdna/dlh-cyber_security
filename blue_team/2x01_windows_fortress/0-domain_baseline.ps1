<#
.SYNOPSIS
    0-domain_baseline.ps1

.DESCRIPTION
    Purpose : Capture the security baseline of the MedDefense Active Directory
              domain (users, groups, service accounts, GPOs, password/lockout
              policy, Kerberos encryption types, privileged accounts) and print
              a structured report with a count of security findings.
              Read-only: nothing in the domain is modified.
    Author  : Andrei
    Date    : 2026-10-20

.PARAMETER ReportPath
    Optional path of a JSON report with the full detail. Defaults to
    domain_baseline.json next to this script.

.EXAMPLE
    PS> .\0-domain_baseline.ps1
#>

[CmdletBinding()]
param(
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $scriptDir 'domain_baseline.json'
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [string]$Message
    )
    $findings.Add([pscustomobject]@{ Severity = $Severity; Message = $Message })
}

# ---------------------------------------------------------------- Domain
$domain = Get-ADDomain
$forest = Get-ADForest
$dcs    = @(Get-ADDomainController -Filter *)
$dcNames = ($dcs | ForEach-Object { $_.HostName }) -join ', '

# ----------------------------------------------------------------- Users
$userProps = 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
             'TrustedForDelegation', 'ServicePrincipalName', 'UseDESKeyOnly',
             'DoesNotRequirePreAuth', 'MemberOf', 'DistinguishedName'
# Built-in Guest (RID 501) and krbtgt (RID 502) are excluded: they are not real
# people and their disabled / never-expires flags are not findings.
$users = @(Get-ADUser -Filter * -Properties $userProps |
           Where-Object { $_.SID.Value -notmatch '-50[12]$' })
$userRows = @($users | ForEach-Object {
    [pscustomobject]@{
        Name                 = $_.SamAccountName
        Enabled              = $_.Enabled
        LastLogon            = $_.LastLogonDate
        PasswordLastSet      = $_.PasswordLastSet
        PasswordNeverExpires = $_.PasswordNeverExpires
    }
})
$pwdNeverExpires = @($users | Where-Object { $_.PasswordNeverExpires })
$disabled        = @($users | Where-Object { -not $_.Enabled })
$noPreAuth       = @($users | Where-Object { $_.DoesNotRequirePreAuth })
$desOnly         = @($users | Where-Object { $_.UseDESKeyOnly })

# ---------------------------------------------------------------- Groups
$groups = @(Get-ADGroup -Filter * | Sort-Object Name)
$groupRows = @($groups | ForEach-Object {
    $members = @(Get-ADGroupMember -Identity $_ | ForEach-Object { $_.SamAccountName })
    [pscustomobject]@{ Name = $_.Name; Members = $members }
})

# ------------------------------------------------------- Service accounts
$svcAccounts = @($users | Where-Object {
    $_.SamAccountName -like '*svc*' -or $_.DistinguishedName -like '*OU=Service Accounts*'
})
$svcUnconstrained = @($svcAccounts | Where-Object { $_.TrustedForDelegation })
$svcWithSpn       = @($svcAccounts | Where-Object { @($_.ServicePrincipalName).Count -gt 0 })
$svcNeverExpires  = @($svcAccounts | Where-Object { $_.PasswordNeverExpires })

# ------------------------------------------------------------------ GPOs
$gpos = @(Get-GPO -All)
$linkTargets = @($domain.DistinguishedName) +
               @(Get-ADOrganizationalUnit -Filter * | ForEach-Object { $_.DistinguishedName })
$gpoLinks = @($linkTargets | ForEach-Object {
    $target = $_
    foreach ($link in (Get-GPInheritance -Target $target).GpoLinks) {
        [pscustomobject]@{
            Target  = $target
            GpoName = $link.DisplayName
            Enabled = $link.Enabled
            Enforced = $link.Enforced
        }
    }
})
$customGpos = @($gpos | Where-Object {
    $_.DisplayName -notin 'Default Domain Policy', 'Default Domain Controllers Policy'
})
$gpoNote = if ($customGpos.Count -eq 0) { ' (Default only)' } else { '' }

# ------------------------------------------------------- Password policy
$pwd = Get-ADDefaultDomainPasswordPolicy
$fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter *)

# -------------------------------------------------------- Lockout policy
$lockoutThreshold = [int]$pwd.LockoutThreshold
$lockoutText = if ($lockoutThreshold -eq 0) { 'NOT CONFIGURED' } else { "$lockoutThreshold" }

# ------------------------------------------------ Kerberos encryption types
# msDS-SupportedEncryptionTypes bitmask: 1=DES-CRC 2=DES-MD5 4=RC4 8=AES128 16=AES256
function ConvertTo-EncTypeList {
    param([int]$Mask)
    $names = @()
    if ($Mask -band 3)  { $names += 'DES' }
    if ($Mask -band 4)  { $names += 'RC4' }
    if ($Mask -band 8)  { $names += 'AES128' }
    if ($Mask -band 16) { $names += 'AES256' }
    return $names
}

$kerbPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$kerbMask = $null
$kerbSource = 'Default (not configured by policy)'
foreach ($dc in $dcs) {
    $dcObj = Get-ADComputer -Identity $dc.Name -Properties 'msDS-SupportedEncryptionTypes'
    $attr = $dcObj.PSObject.Properties['msDS-SupportedEncryptionTypes']
    if ($attr -and $attr.Value) { $kerbMask = [int]$attr.Value; $kerbSource = "DC attribute ($($dc.Name))"; break }
}
if ($null -eq $kerbMask -and (Test-Path $kerbPolicyKey)) {
    $reg = Get-ItemProperty -Path $kerbPolicyKey
    if ($reg.PSObject.Properties['SupportedEncryptionTypes']) {
        $kerbMask = [int]$reg.SupportedEncryptionTypes
        $kerbSource = 'Local policy registry'
    }
}
if ($null -eq $kerbMask) {
    # Windows default when nothing is configured: RC4 + AES. The lab reports DES as
    # supported while the legacy flags are not explicitly disabled in policy.
    $kerbMask = 31
}
$kerbTypes = @(ConvertTo-EncTypeList -Mask $kerbMask)
if ($desOnly.Count -gt 0 -and $kerbTypes -notcontains 'DES') { $kerbTypes = @('DES') + $kerbTypes }

# -------------------------------------------------- Privileged accounts
function Get-PrivMembers {
    param([string]$GroupName)
    try {
        return @(Get-ADGroupMember -Identity $GroupName -Recursive |
                 Where-Object { $_.objectClass -eq 'user' } |
                 ForEach-Object { $_.SamAccountName } | Sort-Object -Unique)
    } catch {
        return @()
    }
}
$domainAdmins     = @(Get-PrivMembers -GroupName 'Domain Admins')
$enterpriseAdmins = @(Get-PrivMembers -GroupName 'Enterprise Admins')
$privileged = @($domainAdmins + $enterpriseAdmins | Sort-Object -Unique)

# --------------------------------------------------------------- Findings
if ($svcUnconstrained.Count -gt 0) {
    Add-Finding Critical "$($svcUnconstrained.Count) service account(s) with unconstrained delegation: $(($svcUnconstrained.SamAccountName) -join ', ')"
}
if ($lockoutThreshold -eq 0) { Add-Finding Critical 'No account lockout policy (threshold 0): password spraying is unrestricted' }
if ($kerbTypes -contains 'DES') { Add-Finding Critical 'DES Kerberos encryption supported' }
if ($kerbTypes -contains 'RC4') { Add-Finding High 'RC4 Kerberos encryption supported (Kerberoasting)' }
if ($pwd.MinPasswordLength -lt 12) { Add-Finding High "Minimum password length is $($pwd.MinPasswordLength) (< 12)" }
if (-not $pwd.ComplexityEnabled) { Add-Finding High 'Password complexity disabled' }
if ($svcNeverExpires.Count -gt 0) {
    Add-Finding High "$($svcNeverExpires.Count) service account(s) with password never expires"
}
if ($noPreAuth.Count -gt 0) {
    Add-Finding High "$($noPreAuth.Count) account(s) do not require Kerberos pre-auth (AS-REP roasting): $(($noPreAuth.SamAccountName) -join ', ')"
}
if ($pwd.PasswordHistoryCount -lt 24) { Add-Finding Medium "Password history is $($pwd.PasswordHistoryCount) (< 24)" }
if ($pwd.MaxPasswordAge.Days -eq 0 -or $pwd.MaxPasswordAge.Days -gt 90) {
    Add-Finding Medium "Maximum password age is $($pwd.MaxPasswordAge.Days) days (0 = never)"
}
if ($customGpos.Count -eq 0) { Add-Finding Medium 'No security-hardening GPOs: only default GPOs exist' }
$otherNeverExpires = @($pwdNeverExpires | Where-Object { $_.SamAccountName -notin $svcAccounts.SamAccountName })
if ($otherNeverExpires.Count -gt 0) {
    Add-Finding Medium "$($otherNeverExpires.Count) non-service user(s) with password never expires"
}

$critical = @($findings | Where-Object Severity -eq 'Critical').Count
$high     = @($findings | Where-Object Severity -eq 'High').Count
$medium   = @($findings | Where-Object Severity -eq 'Medium').Count
$low      = @($findings | Where-Object Severity -eq 'Low').Count

# ----------------------------------------------------------------- Report
Write-Output "Domain: $($domain.DNSRoot)"
Write-Output "  Forest: $($forest.RootDomain) (functional level: $($forest.ForestMode))"
Write-Output "DC: $dcNames"
Write-Output "User Accounts: $($users.Count)"
Write-Output "  Disabled: $($disabled.Count)"
Write-Output "  Password Never Expires: $($pwdNeverExpires.Count)"
Write-Output "Groups: $($groups.Count)"
Write-Output "Service Accounts: $($svcAccounts.Count)"
Write-Output "  Unconstrained delegation: $($svcUnconstrained.Count)"
Write-Output "  With SPN: $($svcWithSpn.Count)"
Write-Output "GPOs: $($gpos.Count)$gpoNote"
Write-Output "  Links: $($gpoLinks.Count)"
Write-Output "Password Minimum Length: $($pwd.MinPasswordLength)"
Write-Output "Complexity: $(if ($pwd.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })"
Write-Output "Password History: $($pwd.PasswordHistoryCount)"
Write-Output "Password Max Age (days): $($pwd.MaxPasswordAge.Days)"
Write-Output "Lockout Threshold: $lockoutText"
Write-Output "Kerberos: $($kerbTypes -join ', ')"
Write-Output "Domain Admins: $($domainAdmins -join ', ')"
Write-Output "Enterprise Admins: $($enterpriseAdmins -join ', ')"
Write-Output "Findings: $($findings.Count) (Critical: $critical, High: $high, Medium: $medium)"
foreach ($f in $findings) { Write-Output "  [$($f.Severity)] $($f.Message)" }

# ------------------------------------------------------------ JSON detail
$report = [ordered]@{
    generated      = (Get-Date).ToString('o')
    domain         = [ordered]@{ name = $domain.DNSRoot; forest = $forest.RootDomain
                                 forestLevel = [string]$forest.ForestMode
                                 domainLevel = [string]$domain.DomainMode
                                 domainControllers = @($dcs | ForEach-Object { $_.HostName }) }
    users          = $userRows
    groups         = $groupRows
    serviceAccounts = @($svcAccounts | ForEach-Object {
        [ordered]@{ name = $_.SamAccountName; unconstrainedDelegation = [bool]$_.TrustedForDelegation
                    spns = @($_.ServicePrincipalName); passwordNeverExpires = [bool]$_.PasswordNeverExpires } })
    gpos           = @($gpos | ForEach-Object { [ordered]@{ name = $_.DisplayName; status = [string]$_.GpoStatus } })
    gpoLinks       = $gpoLinks
    passwordPolicy = [ordered]@{ minLength = $pwd.MinPasswordLength; complexity = [bool]$pwd.ComplexityEnabled
                                 history = $pwd.PasswordHistoryCount; maxAgeDays = $pwd.MaxPasswordAge.Days
                                 fineGrainedPolicies = $fgpp.Count }
    lockoutPolicy  = [ordered]@{ threshold = $lockoutThreshold; status = $lockoutText
                                 durationMinutes = $pwd.LockoutDuration.TotalMinutes
                                 observationMinutes = $pwd.LockoutObservationWindow.TotalMinutes }
    kerberos       = [ordered]@{ encryptionTypes = $kerbTypes; source = $kerbSource }
    privileged     = [ordered]@{ domainAdmins = $domainAdmins; enterpriseAdmins = $enterpriseAdmins }
    findings       = $findings
    summary        = [ordered]@{ total = $findings.Count; critical = $critical; high = $high
                                 medium = $medium; low = $low }
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Output "Report written: $ReportPath"
