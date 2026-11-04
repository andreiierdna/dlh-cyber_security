<#
Name    : 3-windows_telemetry_export.ps1
Purpose : Export Windows Security, Sysmon and PowerShell Operational telemetry
          from a configurable time window into analyst-ready JSON: normalized
          common fields across every event, plus per-event-type enrichment for
          the Event IDs the SOC cares about most.
          Read-only: it only reads event logs and writes the output file.
Author  : Andrei
#>

[CmdletBinding()]
param(
    [int]$HoursBack = 24,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $OutputPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptDir 'windows_events_export.json'
}

$hostname = $env:COMPUTERNAME
$since    = (Get-Date).AddHours(-$HoursBack)

# ------------------------------------------------------------- Per-event enrichment
# Each enricher receives the raw [System.Diagnostics.Eventing.Reader.EventLogRecord]
# and returns a hashtable of extra fields. Values come from named XML fields in the
# event (most reliable) with a regex fallback against the formatted message.
function Get-NamedDataValue {
    param($Event, [string]$Name)
    try {
        $xml = [xml]$Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($node) { return $node.'#text' }
    } catch { }
    return $null
}

function Get-MessageField {
    param([string]$Message, [string]$FieldName)
    if ($Message -match "(?m)^\s*$([regex]::Escape($FieldName)):\s*(.+?)\s*$") { return $Matches[1] }
    return $null
}

$enrichers = @{
    'Security-4624' = {
        param($e)
        [ordered]@{
            target_user   = Get-NamedDataValue $e 'TargetUserName'
            logon_type    = Get-NamedDataValue $e 'LogonType'
            source_ip     = Get-NamedDataValue $e 'IpAddress'
            workstation   = Get-NamedDataValue $e 'WorkstationName'
        }
    }
    'Security-4625' = {
        param($e)
        [ordered]@{
            target_user    = Get-NamedDataValue $e 'TargetUserName'
            failure_reason = Get-NamedDataValue $e 'FailureReason'
            source_ip      = Get-NamedDataValue $e 'IpAddress'
        }
    }
    'Security-4672' = {
        param($e)
        [ordered]@{ privileged_account = Get-NamedDataValue $e 'SubjectUserName' }
    }
    'Security-4688' = {
        param($e)
        [ordered]@{
            process_name   = Get-NamedDataValue $e 'NewProcessName'
            command_line   = Get-NamedDataValue $e 'CommandLine'
            parent_process = Get-NamedDataValue $e 'ParentProcessName'
        }
    }
    'PowerShell-4104' = {
        param($e)
        [ordered]@{ script_block_text = Get-NamedDataValue $e 'ScriptBlockText' }
    }
    'Sysmon-1' = {
        param($e)
        [ordered]@{
            image         = Get-NamedDataValue $e 'Image'
            command_line  = Get-NamedDataValue $e 'CommandLine'
            parent_image  = Get-NamedDataValue $e 'ParentImage'
            hashes        = Get-NamedDataValue $e 'Hashes'
        }
    }
    'Sysmon-3' = {
        param($e)
        [ordered]@{
            destination_ip   = Get-NamedDataValue $e 'DestinationIp'
            destination_port = Get-NamedDataValue $e 'DestinationPort'
            process          = Get-NamedDataValue $e 'Image'
        }
    }
    'Sysmon-11' = {
        param($e)
        [ordered]@{
            target_filename  = Get-NamedDataValue $e 'TargetFilename'
            creating_process = Get-NamedDataValue $e 'Image'
        }
    }
    'Sysmon-13' = {
        param($e)
        [ordered]@{
            registry_key = Get-NamedDataValue $e 'TargetObject'
            value_name   = Get-NamedDataValue $e 'Details'
        }
    }
    'Sysmon-22' = {
        param($e)
        [ordered]@{
            query_name    = Get-NamedDataValue $e 'QueryName'
            query_results = Get-NamedDataValue $e 'QueryResults'
        }
    }
}

# ------------------------------------------------------------------- Channel sources
$channels = @(
    [pscustomobject]@{ Name = 'Security';   LogName = 'Security';                                    SourceType = 'windows_security' }
    [pscustomobject]@{ Name = 'Sysmon';     LogName = 'Microsoft-Windows-Sysmon/Operational';         SourceType = 'sysmon' }
    [pscustomobject]@{ Name = 'PowerShell'; LogName = 'Microsoft-Windows-PowerShell/Operational';     SourceType = 'powershell' }
)

function ConvertTo-NormalizedEvent {
    param($Event, [string]$Channel, [string]$SourceType)
    $key = if ($Channel -eq 'Security' -or $Channel -eq 'PowerShell') { "$Channel-$($Event.Id)" } else { "Sysmon-$($Event.Id)" }
    $record = [ordered]@{
        timestamp       = $Event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        hostname        = $hostname
        platform        = 'windows'
        source_type     = $SourceType
        channel         = $Channel
        event_id        = $Event.Id
        event_category  = $Event.TaskDisplayName
        provider        = $Event.ProviderName
        raw_message     = $Event.Message
    }
    if ($enrichers.ContainsKey($key)) {
        $extra = & $enrichers[$key] $Event
        foreach ($k in $extra.Keys) { $record[$k] = $extra[$k] }
    }
    return [pscustomobject]$record
}

# --------------------------------------------------------------------------- Export
Write-Output "[*] Exporting Windows telemetry from last $HoursBack hours..."
$allRecords = New-Object System.Collections.Generic.List[object]
$counts = [ordered]@{}
foreach ($c in $channels) {
    $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $c.LogName; StartTime = $since } -ErrorAction SilentlyContinue)
    $counts[$c.Name] = $raw.Count
    foreach ($e in $raw) { $allRecords.Add((ConvertTo-NormalizedEvent -Event $e -Channel $c.Name -SourceType $c.SourceType)) }
}

$total = $allRecords.Count
$topIds = $allRecords | Group-Object { if ($_.channel -eq 'Sysmon') { "Sysmon-$($_.event_id)" } else { "$($_.event_id)" } } |
          Sort-Object Count -Descending | Select-Object -First 4 -ExpandProperty Name

Write-Output "Security events: $($counts['Security'])"
Write-Output "Sysmon events: $($counts['Sysmon'])"
Write-Output "PowerShell events: $($counts['PowerShell'])"
Write-Output "Total events: $total"
Write-Output "Top Event IDs: $($topIds -join ', ')"

$export = [ordered]@{
    generated   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    hostname    = $hostname
    window      = [ordered]@{ hours_back = $HoursBack; since = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
    counts      = $counts
    top_event_ids = $topIds
    total_events  = $total
    events      = $allRecords
}
$export | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Output: $OutputPath"
