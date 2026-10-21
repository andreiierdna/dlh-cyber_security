<#
.SYNOPSIS
    7-auth_hardening.ps1

.DESCRIPTION
    Purpose : Disable weak Kerberos encryption (DES, RC4) and NTLMv1. Reports the
              current state, the service-account DES flags and SPNs, clears the
              DES flag, enforces AES128/AES256 through the GPO
              "MedDefense - Authentication Hardening" (linked to the domain root)
              and on the service accounts / domain controllers, sets NTLMv2-only
              (LmCompatibilityLevel=5), reports Credential Guard status and
              verifies the result.
              Changes the domain: run as Domain Admin on a domain controller.
              WARNING: anything that still depends on RC4 or NTLMv1 stops
              authenticating. Service accounts need AES keys: reset their
              password once if a service fails after this change.
    Author  : Andrei
    Date    : 2026-10-20
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = 'MedDefense - Authentication Hardening'
$domain  = Get-ADDomain
$aesOnly = 24   # 8 = AES128, 16 = AES256

function ConvertTo-EncTypeList {
    param([int]$Mask)
    $names = @()
    if ($Mask -band 3)  { $names += 'DES' }
    if ($Mask -band 4)  { $names += 'RC4' }
    if ($Mask -band 8)  { $names += 'AES128' }
    if ($Mask -band 16) { $names += 'AES256' }
    return $names
}

function Get-EffectiveKerberosMask {
    # Policy value if present, else the DC computer attribute, else the OS default (RC4 + AES, plus
    # DES flags still honoured per account).
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    if (Test-Path $key) {
        $p = Get-ItemProperty -Path $key
        if ($p.PSObject.Properties['SupportedEncryptionTypes']) { return [int]$p.SupportedEncryptionTypes }
    }
    $dc = Get-ADComputer -Identity $env:COMPUTERNAME -Properties 'msDS-SupportedEncryptionTypes'
    $attr = $dc.PSObject.Properties['msDS-SupportedEncryptionTypes']
    if ($attr -and $attr.Value) { return [int]$attr.Value }
    return 31
}

# ------------------------------------------------------------------ Current state
$before = @(ConvertTo-EncTypeList -Mask (Get-EffectiveKerberosMask))
Write-Output "[*] Current Kerberos types: $($before -join ', ')"
if ($before -contains 'DES') { Write-Output "    [!] DES enabled - trivially breakable" }
if ($before -contains 'RC4') { Write-Output "    [!] RC4 enabled - Kerberoastable" }

$svc = @(Get-ADUser -Filter * -Properties UseDESKeyOnly, ServicePrincipalName, DistinguishedName, 'msDS-SupportedEncryptionTypes' |
         Where-Object { $_.SamAccountName -like '*svc*' -or $_.DistinguishedName -like '*OU=Service Accounts*' })

Write-Output "[*] Accounts with DES flag..."
$desAccounts = @($svc | Where-Object { $_.UseDESKeyOnly })
if ($desAccounts.Count -eq 0) { Write-Output "    none" }
foreach ($a in $desAccounts) { Write-Output ("    {0}: UseDESKeyOnly = True          [!]" -f $a.SamAccountName) }

Write-Output "[*] Service Principal Names..."
$spnCount = 0
foreach ($a in $svc) {
    foreach ($spn in @($a.ServicePrincipalName)) {
        Write-Output ("    {0}: {1}" -f $a.SamAccountName, $spn)
        $spnCount++
    }
}
if ($spnCount -gt 0) { Write-Output "    [!] All $spnCount SPNs are Kerberoastable targets" }

# --------------------------------------------------------------------- Remediate
Write-Output "[*] Remediating..."
foreach ($a in $desAccounts) {
    Set-ADUser -Identity $a -KerberosEncryptionType None
    Set-ADAccountControl -Identity $a -UseDESKeyOnly $false
    Write-Output ("    {0}: Clearing DES flag              [DONE]" -f $a.SamAccountName)
}
foreach ($a in $svc) {
    Set-ADUser -Identity $a -Replace @{ 'msDS-SupportedEncryptionTypes' = $aesOnly }
}
Set-ADComputer -Identity $env:COMPUTERNAME -Replace @{ 'msDS-SupportedEncryptionTypes' = $aesOnly }

$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $gpoName -Comment 'AES-only Kerberos and NTLMv2-only (Task 7)' }
$null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
    -ValueName SupportedEncryptionTypes -Type DWord -Value $aesOnly
$null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' `
    -ValueName LmCompatibilityLevel -Type DWord -Value 5
$links = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
if (@($links | Where-Object { $_.GpoId -eq $gpo.Id }).Count -eq 0) {
    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
}
Write-Output ("    {0,-42}[SET]" -f 'Supported encryption: AES128 + AES256')
Write-Output ("    {0,-42}[SET]" -f 'NTLMv1: Refused (LmCompatibilityLevel=5)')

gpupdate /force | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed (exit $LASTEXITCODE)" }

# ------------------------------------------------------- Credential Guard awareness
Write-Output "[*] Credential Guard..."
$cgRunning = $false
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    $cgRunning = @($dg.SecurityServicesRunning) -contains 1
} catch {
    $cgRunning = $false
}
if ($cgRunning) {
    Write-Output "    Credential Guard: Running                [OK]"
} else {
    Write-Output "    Credential Guard: Not running            [INFO] (not supported on domain controllers; enable on member servers and workstations)"
}

# ----------------------------------------------------------------------- Verify
Write-Output "[*] Verifying..."
$failed = 0
$after = @(ConvertTo-EncTypeList -Mask (Get-EffectiveKerberosMask))
$kerbOk = (($after -join ',') -eq 'AES128,AES256')
if (-not $kerbOk) { $failed++ }
Write-Output ("    Kerberos: {0,-25}{1}" -f ($after -join ', '), $(if ($kerbOk) { '[VERIFIED]' } else { '[MISMATCH]' }))

$lm = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue)
$lmOk = ($null -ne $lm) -and ($lm.LmCompatibilityLevel -eq 5)
if (-not $lmOk) { $failed++ }
Write-Output ("    NTLM: {0,-28}{1}" -f $(if ($lmOk) { 'v2 only' } else { 'not enforced' }), $(if ($lmOk) { '[VERIFIED]' } else { '[MISMATCH]' }))

$desLeft = @(Get-ADUser -Filter 'UseDESKeyOnly -eq $true')
$desOk = ($desLeft.Count -eq 0)
if (-not $desOk) { $failed++ }
Write-Output ("    DES flag accounts: {0,-18}{1}" -f $desLeft.Count, $(if ($desOk) { '[VERIFIED]' } else { '[MISMATCH]' }))
if ($failed -gt 0) { exit 1 }
