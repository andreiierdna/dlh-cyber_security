<#
.SYNOPSIS
    MedDefense 2x04 Task 6 - Windows Firewall alignment to segmentation_rules.json.
.DESCRIPTION
    Consumes the same zone/flow contract as 4-nftables_config.sh, sets every
    firewall profile to default-block inbound, recreates the MedDefense-* rule
    set (idempotent), enables blocked-connection logging and exports the
    resulting rules as JSON for cross-platform diffing.
    Author: Andrei
.NOTES
    Requires elevation. Windows host: DC01.
#>
[CmdletBinding()]
param(
    [string]$RulesFile       = (Join-Path $PSScriptRoot 'segmentation_rules.json'),
    [string]$OutputFile      = (Join-Path $PSScriptRoot 'windows_firewall_rules.json'),
    [string]$LogFile         = '%systemroot%\system32\LogFiles\Firewall\meddefense.log'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RulesFile -or -not (Test-Path -LiteralPath $RulesFile)) {
    throw "segmentation_rules.json not found at '$RulesFile'"
}

Write-Output '[*] Reading segmentation_rules.json...'
$seg = Get-Content -LiteralPath $RulesFile -Raw | ConvertFrom-Json
$zoneCidr = @{}
foreach ($z in $seg.zones) {
    $cidrs = @()
    if ($z.PSObject.Properties.Name -contains 'cidrs' -and $z.cidrs) { $cidrs = @($z.cidrs) }
    elseif ($z.cidr) { $cidrs = @($z.cidr) }
    $zoneCidr[$z.name] = $cidrs
}

Write-Output '[*] Setting profile defaults...'
foreach ($fwProfile in 'Domain', 'Private', 'Public') {
    Set-NetFirewallProfile -Profile $fwProfile -DefaultInboundAction Block `
        -DefaultOutboundAction Allow -LogBlocked True -LogFileName $LogFile
    Write-Output ("  {0,-8} DefaultInboundAction=Block  LogBlocked=True   [SET]" -f $fwProfile)
}

Write-Output '[*] Clearing previous MedDefense-* rules...'
$existing = Get-NetFirewallRule -DisplayName 'MedDefense-*' -ErrorAction SilentlyContinue
if ($existing) {
    $removed = @($existing).Count
    $existing | Remove-NetFirewallRule
} else { $removed = 0 }
Write-Output ("  {0} removed" -f $removed)

Write-Output '[*] Creating rules from flow matrix...'
# The task's naming scheme (MedDefense-<src_zone>-<proto>-<dport>) does not carry the
# destination zone, so several contract flows (MGMT->INTERNAL/DMZ/MEDDEV on 22) render
# to the same Windows rule. The Windows rule matches on source address + port, so those
# flows are literally the same rule: emit it once instead of creating duplicates.
$seenRules = @{}
$created = @()
foreach ($f in $seg.flows) {
    if ($f.action -ne 'allow') { continue }
    if ($f.src_zone -eq 'ALL') { continue }          # resolver traffic, not inbound here
    $srcCidrs = $zoneCidr[$f.src_zone]
    if (-not $srcCidrs -or $srcCidrs.Count -eq 0) { continue }
    $proto = $f.proto.ToUpperInvariant()
    $name = 'MedDefense-{0}-{1}-{2}' -f $f.src_zone, $proto, $f.dport
    if ($seenRules.ContainsKey($name)) { continue }
    $seenRules[$name] = $true
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol $proto -LocalPort ([int]$f.dport) -RemoteAddress $srcCidrs -Profile Any `
        -Description $f.justification | Out-Null
    Write-Output ("  {0,-30} Inbound Allow {1,-4} {2,-5} [CREATED]" -f $name, $f.proto, $f.dport)
    $created += $name
}

Write-Output '[*] Exporting applied rules...'
$applied = Get-NetFirewallRule -DisplayName 'MedDefense-*' -ErrorAction SilentlyContinue | ForEach-Object {
    $addr = ($_ | Get-NetFirewallAddressFilter).RemoteAddress
    $port = ($_ | Get-NetFirewallPortFilter).LocalPort
    [pscustomobject]@{
        display_name = $_.DisplayName
        direction    = $_.Direction.ToString()
        action       = $_.Action.ToString()
        enabled      = $_.Enabled.ToString()
        profile      = $_.Profile.ToString()
        protocol     = ($_ | Get-NetFirewallPortFilter).Protocol
        local_port   = @($port)
        remote_address = @($addr)
    }
}
$report = [pscustomobject]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname     = $env:COMPUTERNAME
    platform     = 'windows'
    source       = (Split-Path -Leaf $RulesFile)
    profiles     = @(
        foreach ($p in 'Domain', 'Private', 'Public') {
            $pf = Get-NetFirewallProfile -Profile $p
            [pscustomobject]@{
                profile                 = $p
                default_inbound_action  = $pf.DefaultInboundAction.ToString()
                default_outbound_action = $pf.DefaultOutboundAction.ToString()
                log_blocked             = [bool]$pf.LogBlocked
                log_file_name           = $pf.LogFileName
            }
        }
    )
    rules        = @($applied)
    summary      = [pscustomobject]@{
        removed            = $removed
        created            = @($applied).Count
        flows_in_contract  = @($seg.flows).Count
    }
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
Write-Output ("Report saved to: {0}" -f $OutputFile)
