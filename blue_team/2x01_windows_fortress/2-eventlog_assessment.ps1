<#
.SYNOPSIS
    2-eventlog_assessment.ps1

.DESCRIPTION
    Purpose : Assess which critical Security Event IDs the domain controller is
              able to generate (audit policy) and is actually generating
              (Security log, last 24 hours), and report the visibility gaps.
              Read-only: nothing is modified.
    Author  : Andrei
    Date    : 2026-10-20

.PARAMETER Hours
    Look-back window for the Security log query. Default 24.
#>

[CmdletBinding()]
param(
    [int]$Hours = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Event ID -> description, audit subcategory (auditpol name), setting required.
# Required: Success, Failure, or None (event is always written regardless of policy).
$critical = @(
    [pscustomobject]@{ Id = 4624; Description = 'Successful Logon';      Sub = 'Logon';                    Need = 'Success' }
    [pscustomobject]@{ Id = 4625; Description = 'Failed Logon';          Sub = 'Logon';                    Need = 'Failure' }
    [pscustomobject]@{ Id = 4648; Description = 'Explicit Credentials';  Sub = 'Logon';                    Need = 'Success' }
    [pscustomobject]@{ Id = 4688; Description = 'Process Creation';      Sub = 'Process Creation';         Need = 'Success' }
    [pscustomobject]@{ Id = 4720; Description = 'Account Created';       Sub = 'User Account Management';  Need = 'Success' }
    [pscustomobject]@{ Id = 4726; Description = 'Account Deleted';       Sub = 'User Account Management';  Need = 'Success' }
    [pscustomobject]@{ Id = 4732; Description = 'Member Added to Group'; Sub = 'Security Group Management'; Need = 'Success' }
    [pscustomobject]@{ Id = 4672; Description = 'Special Logon';         Sub = 'Special Logon';            Need = 'Success' }
    [pscustomobject]@{ Id = 1102; Description = 'Audit Log Cleared';     Sub = 'System Integrity';         Need = 'None' }
)

# --- Current audit policy: auditpol /get /category:* in CSV form ---------------
$csv = auditpol /get /category:* /r | ConvertFrom-Csv
if ($LASTEXITCODE -ne 0) { throw "auditpol failed (exit $LASTEXITCODE). Run from an elevated session." }
$policy = @{}
foreach ($row in $csv) {
    $policy[$row.Subcategory] = $row.'Inclusion Setting'
}

# --- Which Event IDs actually appeared in the Security log ---------------------
$since = (Get-Date).AddHours(-$Hours)
$seen = @{}
foreach ($c in $critical) {
    $filter = @{ LogName = 'Security'; Id = $c.Id; StartTime = $since }
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
    $seen[$c.Id] = $events.Count
}

# --- Report ---------------------------------------------------------------------
$rows = foreach ($c in $critical) {
    $setting = if ($policy.ContainsKey($c.Sub)) { $policy[$c.Sub] } else { 'Unknown' }
    $enabled = switch ($c.Need) {
        'Success' { $setting -match 'Success' }
        'Failure' { $setting -match 'Failure' }
        default   { $true }
    }
    $status = if ($seen[$c.Id] -gt 0) { '[GENERATING]' }
              elseif ($enabled)       { '[CONFIGURED - NO EVENTS]' }
              else                    { '[NOT CONFIGURED]' }
    [pscustomobject]@{
        'Event ID'          = $c.Id
        'Description'       = $c.Description
        'Audit Subcategory' = $c.Sub
        'Setting'           = $setting
        'Events'            = $seen[$c.Id]
        'Status'            = $status
    }
}
$rows | Format-Table -AutoSize

$generating = @($rows | Where-Object Status -eq '[GENERATING]').Count
$gaps       = @($rows | Where-Object Status -eq '[NOT CONFIGURED]')
$total      = $rows.Count
Write-Output "Window: last $Hours hours   Generating: $generating/$total   Gaps: $($gaps.Count)"
if ($gaps.Count -gt 0) {
    Write-Output "Visibility gaps (audit subcategory not enabled):"
    foreach ($g in $gaps) {
        Write-Output "  $($g.'Event ID')  $($g.Description)  <- enable '$($g.'Audit Subcategory')' ($($g.Setting))"
    }
}
