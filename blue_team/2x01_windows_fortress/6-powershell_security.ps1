<#
.SYNOPSIS
    6-powershell_security.ps1

.DESCRIPTION
    Purpose : Create and link the GPO "MedDefense - PowerShell Security":
              Script Block Logging (4104), Module Logging for all modules (4103)
              and Transcription to C:\PSTranscripts. Verifies AMSI is loaded and
              proves the logging works by running an encoded command and finding
              its decoded text in Event ID 4104.
              Changes the domain: run as Domain Admin on a domain controller.
    Author  : Andrei
    Date    : 2026-10-20
#>

[CmdletBinding()]
param(
    [string]$TranscriptDir = 'C:\PSTranscripts'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = 'MedDefense - PowerShell Security'
$domain  = Get-ADDomain
$base    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

Write-Output "[*] Creating GPO: `"$gpoName`"..."
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($gpo) {
    Write-Output "    EXISTS (updating in place)"
} else {
    $gpo = New-GPO -Name $gpoName -Comment 'PowerShell logging and transcription (Task 6)'
    Write-Output "    CREATED"
}

Write-Output "[*] Configuring Script Block Logging..."
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\ScriptBlockLogging" -ValueName EnableScriptBlockLogging -Type DWord -Value 1
Write-Output ("    {0,-40}[SET]" -f 'EnableScriptBlockLogging = 1')
Write-Output "    -> Event ID 4104 captures decoded scripts"

Write-Output "[*] Configuring Module Logging..."
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\ModuleLogging" -ValueName EnableModuleLogging -Type DWord -Value 1
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\ModuleLogging\ModuleNames" -ValueName '*' -Type String -Value '*'
Write-Output ("    {0,-40}[SET]" -f 'EnableModuleLogging = 1, ModuleNames = *')
Write-Output "    -> Event ID 4103 captures module invocations"

Write-Output "[*] Configuring Transcription..."
if (-not (Test-Path $TranscriptDir)) { New-Item -ItemType Directory -Path $TranscriptDir | Out-Null }
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\Transcription" -ValueName EnableTranscripting -Type DWord -Value 1
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\Transcription" -ValueName OutputDirectory -Type String -Value $TranscriptDir
$null = Set-GPRegistryValue -Guid $gpo.Id -Key "$base\Transcription" -ValueName EnableInvocationHeader -Type DWord -Value 1
Write-Output ("    {0,-40}[SET]" -f "OutputDirectory = $TranscriptDir")

Write-Output "[*] Verifying AMSI..."
$amsi = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -ieq 'amsi.dll' }
if (-not $amsi) {
    # AMSI loads lazily on the first script scan.
    $null = Invoke-Expression '1+1'
    $amsi = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -ieq 'amsi.dll' }
}
Write-Output ("    {0,-40}{1}" -f 'AMSI DLL loaded', $(if ($amsi) { '[OK]' } else { '[NOT LOADED]' }))

$links = (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks
if (@($links | Where-Object { $_.GpoId -eq $gpo.Id }).Count -eq 0) {
    New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
}
gpupdate /force | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed (exit $LASTEXITCODE)" }
Write-Output "[*] Linking GPO and forcing update... COMPLETE"

# ------------------------------------------------------------ End-to-end test
Write-Output "[*] Testing encoded command..."
$plain   = "Write-Host 'Test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($plain))
Write-Output "    Input: powershell -enc $encoded"
$start = Get-Date
$null = powershell.exe -NoProfile -EncodedCommand $encoded 2>&1 | Out-Null
Start-Sleep -Seconds 2
$hit = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $start.AddSeconds(-1) } -ErrorAction SilentlyContinue |
       Where-Object { $_.Message -match [regex]::Escape($plain) } | Select-Object -First 1
if ($hit) {
    Write-Output "    Event ID 4104 found: `"$plain`"  [VERIFIED]"
} else {
    Write-Output "    Event ID 4104 not found for the decoded command  [FAILED]"
    exit 1
}
