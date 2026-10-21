<#
.SYNOPSIS
    11-firewall_hardening.ps1

.DESCRIPTION
    Purpose : Windows Firewall lockdown. Captures the current state, enables the
              Domain, Private and Public profiles with default-deny inbound,
              creates allow rules for RDP / WinRM (management subnet), DNS, LDAP,
              Kerberos and SMB (server subnet), enables dropped-packet logging
              and disables conflicting legacy allow rules.
              Changes the host: run elevated.
              WARNING: with default-deny, anything not listed here is blocked
              inbound, including RPC (135 + dynamic) and other AD traffic used
              for replication and domain join. Review before running on a
              production DC. Use -KeepSshForLab to keep an inbound OpenSSH rule
              (lab management access); without it, SSH to this host stops working.
    Author  : Andrei
    Date    : 2026-10-20
#>

[CmdletBinding()]
param(
    [string]$ManagementSubnet = '10.10.3.0/24',
    [string]$ServerSubnet     = '10.10.1.0/24',
    [switch]$KeepSshForLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Display groups of built-in rules the DC needs; these are never disabled.
$protectedGroups = @(
    'Core Networking', 'Core Networking Diagnostics', 'Active Directory Domain Services',
    'DNS Service', 'Kerberos Key Distribution Center', 'Netlogon Service', 'DFS Replication',
    'Remote Service Management', 'Windows Management Instrumentation (WMI)'
)

# ------------------------------------------------------------- Current state
Write-Output "[*] Current Firewall State..."
$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    $state = if ($p.Enabled -eq 'True') { 'ON' } else { 'OFF' }
    $mark  = if ($p.Enabled -ne 'True' -or $p.DefaultInboundAction -ne 'Block') { '[!]' } else { '' }
    $extra = if ($p.Enabled -eq 'True') { ", DefaultInbound: $($p.DefaultInboundAction)" } else { '' }
    Write-Output ("    {0,-9}{1}{2}  {3}" -f "$($p.Name):", $state, $extra, $mark)
}

# ---------------------------------------------------------- Default deny inbound
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Output "[*] Setting default-deny on all profiles... [SET]"

# ------------------------------------------------------------------- Allow rules
Write-Output "[*] Creating allow rules..."
$rules = @(
    @{ Name = 'MedDef-RDP-Mgmt';  Protocol = 'TCP'; Port = '3389';      Remote = $ManagementSubnet; Label = "TCP 3389 from $ManagementSubnet" }
    @{ Name = 'MedDef-DNS';       Protocol = 'TCP'; Port = '53';        Remote = 'Any';             Label = 'TCP 53' }
    @{ Name = 'MedDef-DNS-UDP';   Protocol = 'UDP'; Port = '53';        Remote = 'Any';             Label = 'UDP 53' }
    @{ Name = 'MedDef-LDAP';      Protocol = 'TCP'; Port = '389';       Remote = 'Any';             Label = 'TCP 389' }
    @{ Name = 'MedDef-Kerberos';  Protocol = 'TCP'; Port = '88';        Remote = 'Any';             Label = 'TCP 88' }
    @{ Name = 'MedDef-Kerberos-UDP'; Protocol = 'UDP'; Port = '88';     Remote = 'Any';             Label = 'UDP 88' }
    @{ Name = 'MedDef-SMB';       Protocol = 'TCP'; Port = '445';       Remote = $ServerSubnet;     Label = "TCP 445 from $ServerSubnet" }
    @{ Name = 'MedDef-WinRM';     Protocol = 'TCP'; Port = '5985-5986'; Remote = $ManagementSubnet; Label = "TCP 5985-5986 from $ManagementSubnet" }
)
if ($KeepSshForLab) {
    $rules += @{ Name = 'MedDef-SSH-Lab'; Protocol = 'TCP'; Port = '22'; Remote = 'Any'; Label = 'TCP 22 (lab management)' }
}
foreach ($r in $rules) {
    $existing = Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
    if ($existing) { Remove-NetFirewallRule -Name $r.Name }
    $null = New-NetFirewallRule -Name $r.Name -DisplayName $r.Name -Group 'MedDefense' -Direction Inbound -Action Allow `
        -Protocol $r.Protocol -LocalPort $r.Port -RemoteAddress $r.Remote -Profile Any -Enabled True
    Write-Output ("    {0,-22}{1,-36}[CREATED]" -f "$($r.Name):", $r.Label)
}

# ----------------------------------------------------------------------- Logging
foreach ($p in 'Domain', 'Private', 'Public') {
    Set-NetFirewallProfile -Profile $p -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 `
        -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall-$($p.ToLower()).log"
}
Write-Output "[*] Enabling dropped packet logging...     [SET]"

# -------------------------------------------------------- Disable legacy allow rules
$legacy = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object {
    $_.Group -ne 'MedDefense' -and
    ($protectedGroups -notcontains $_.DisplayGroup) -and
    -not ($KeepSshForLab -and ($_.Name -in 'sshd', 'OpenSSH-Server-In-TCP'))
})
if ($legacy.Count -gt 0) { $legacy | Disable-NetFirewallRule }
Write-Output "[*] Disabling $($legacy.Count) legacy allow rules...     [DONE]"

# ----------------------------------------------------------------------- Verify
Write-Output "[*] Verification..."
$failed = 0
$bad = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })
$profOk = ($bad.Count -eq 0)
if (-not $profOk) { $failed++ }
Write-Output ("    {0,-44}{1}" -f 'All 3 profiles: ON, DefaultInbound: Block', $(if ($profOk) { '[VERIFIED]' } else { '[FAILED]' }))
# A TCP/UDP service is one logical rule but two firewall rules (suffix -UDP); count them once.
$active = @(Get-NetFirewallRule -Group 'MedDefense' -Enabled True)
$activeFamilies   = @($active | ForEach-Object { $_.Name -replace '-UDP$', '' } | Sort-Object -Unique).Count
$expectedFamilies = @($rules | ForEach-Object { $_.Name -replace '-UDP$', '' } | Sort-Object -Unique).Count
$ruleOk = ($active.Count -eq $rules.Count) -and ($activeFamilies -eq $expectedFamilies)
if (-not $ruleOk) { $failed++ }
Write-Output ("    {0,-44}{1}" -f "Custom rules: $activeFamilies active", $(if ($ruleOk) { '[VERIFIED]' } else { '[FAILED]' }))
if ($failed -gt 0) { exit 1 }
