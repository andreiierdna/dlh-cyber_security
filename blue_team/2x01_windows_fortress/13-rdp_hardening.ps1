<#
.SYNOPSIS
    13-rdp_hardening.ps1

.DESCRIPTION
    Purpose : Harden Remote Desktop: require NLA, restrict RDP access to the
              G_IT_Admins group, 15 minute idle / 8 hour maximum session,
              highest encryption (TLS), no clipboard or drive redirection, and
              Remote Assistance disabled. Verifies every setting.
              Changes the host: run elevated. On a domain controller the
              "Remote Desktop Users" group is a domain group, so the membership
              change applies to the whole domain.
    Author  : Andrei
    Date    : 2026-10-20
#>

[CmdletBinding()]
param(
    [string]$AllowedGroup = 'G_IT_Admins'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$winStation = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsPolicy   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$raKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'

function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}
function Get-RegDword {
    param([string]$Path, [string]$Name)
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return [int]$p.$Name
}

Import-Module ActiveDirectory
$null = Get-ADGroup -Identity $AllowedGroup    # fail early if the group does not exist

# ------------------------------------------------------------------------- NLA
Write-Output "[*] Enabling NLA..."
Set-RegDword -Path $winStation -Name UserAuthentication -Value 1
Set-RegDword -Path $tsPolicy   -Name UserAuthentication -Value 1
Write-Output ("    {0,-44}[SET]" -f 'UserAuthentication = 1')

# ---------------------------------------------------------- Access restriction
Write-Output "[*] Restricting to $AllowedGroup..."
$rdu = Get-ADGroup -Identity 'Remote Desktop Users'
$members = @(Get-ADGroupMember -Identity $rdu)
foreach ($m in $members) {
    Remove-ADGroupMember -Identity $rdu -Members $m -Confirm:$false
    Write-Output "    Removed: $($m.SamAccountName) from Remote Desktop Users"
}
if ($members.Count -eq 0) { Write-Output "    Remote Desktop Users was already empty" }
Add-ADGroupMember -Identity $rdu -Members $AllowedGroup
Write-Output ("    {0,-44}[SET]" -f "Added: $AllowedGroup")

# ----------------------------------------------------------------- Session limits
Write-Output "[*] Session limits..."
Set-RegDword -Path $tsPolicy -Name MaxIdleTime       -Value (15 * 60 * 1000)
Set-RegDword -Path $tsPolicy -Name MaxConnectionTime -Value (8 * 60 * 60 * 1000)
Set-RegDword -Path $tsPolicy -Name fResetBroken      -Value 1      # end the session when idle/max limit is reached
Write-Output ("    {0,-44}[SET]" -f 'Idle timeout: 15 min')
Write-Output ("    {0,-44}[SET]" -f 'Max session: 8 hours')

# ------------------------------------------------------------------- Encryption
Set-RegDword -Path $winStation -Name MinEncryptionLevel -Value 3     # High
Set-RegDword -Path $winStation -Name SecurityLayer      -Value 2     # TLS
Set-RegDword -Path $tsPolicy   -Name MinEncryptionLevel -Value 3
Set-RegDword -Path $tsPolicy   -Name SecurityLayer      -Value 2
Write-Output ("[*] {0,-47}[SET]" -f 'Encryption: High/SSL')

# ------------------------------------------------------------------ Redirection
Set-RegDword -Path $tsPolicy -Name fDisableClip -Value 1
Write-Output ("[*] {0,-47}[SET]" -f 'Clipboard: Disabled')
Set-RegDword -Path $tsPolicy -Name fDisableCdm -Value 1
Write-Output ("[*] {0,-47}[SET]" -f 'Drive redirection: Disabled')

# ------------------------------------------------------------ Remote Assistance
Set-RegDword -Path $raKey    -Name fAllowToGetHelp -Value 0
Set-RegDword -Path $tsPolicy -Name fAllowToGetHelp -Value 0
Write-Output ("[*] {0,-47}[SET]" -f 'Remote Assistance: Disabled')

# ----------------------------------------------------------------------- Verify
Write-Output "[*] Verification..."
$failed = 0
function Test-Setting {
    param([string]$Label, [bool]$Ok)
    if (-not $Ok) { $script:failed++ }
    Write-Output ("    {0,-44}{1}" -f $Label, $(if ($Ok) { '[VERIFIED]' } else { '[FAILED]' }))
}
Test-Setting 'NLA: Required' ((Get-RegDword $winStation UserAuthentication) -eq 1)
$final = @(Get-ADGroupMember -Identity 'Remote Desktop Users' | ForEach-Object SamAccountName)
Test-Setting "Access: $AllowedGroup only" (($final.Count -eq 1) -and ($final[0] -eq $AllowedGroup))
Test-Setting 'Idle timeout: 15 min'     ((Get-RegDword $tsPolicy MaxIdleTime) -eq 900000)
Test-Setting 'Max session: 8 hours'     ((Get-RegDword $tsPolicy MaxConnectionTime) -eq 28800000)
Test-Setting 'Encryption: High, TLS'    (((Get-RegDword $winStation MinEncryptionLevel) -eq 3) -and ((Get-RegDword $winStation SecurityLayer) -eq 2))
Test-Setting 'Clipboard: Disabled'      ((Get-RegDword $tsPolicy fDisableClip) -eq 1)
Test-Setting 'Drive redirection: Disabled' ((Get-RegDword $tsPolicy fDisableCdm) -eq 1)
Test-Setting 'Remote Assistance: Disabled' ((Get-RegDword $raKey fAllowToGetHelp) -eq 0)
if ($failed -gt 0) { exit 1 }
