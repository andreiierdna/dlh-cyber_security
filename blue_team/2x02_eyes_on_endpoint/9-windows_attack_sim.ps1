<#
Name    : 9-windows_attack_sim.ps1
Purpose : Run a controlled, harmless attacker-playbook sequence against this
          hardened Windows endpoint (local user creation, privilege escalation,
          encoded PowerShell, scheduled-task persistence, outbound connection,
          startup-folder file drop) and record the ground truth of exactly what
          was done and when, for Task 10 to correlate against telemetry.
          Changes the host: creates and then removes a local user, a scheduled
          task and a startup file. Run elevated.
Author  : Andrei
#>

[CmdletBinding()]
param(
    [string]$ReportPath,
    [string]$UserName = 'support_update',
    [string]$TaskName = 'MedDefenseSimPersistence',
    [string]$ProbeIp  = '8.8.8.8'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ReportPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ReportPath = Join-Path $scriptDir 'windows_attack_log.json'
}

$startupDir  = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
$startupFile = Join-Path $startupDir 'meddefense_sim_payload.txt'
$actions = New-Object System.Collections.Generic.List[object]

function Add-Action {
    # Entity: the one literal string that ties a captured event back to THIS specific
    # action (a username, task name, IP, filename...) rather than to any other event of
    # the same type/ID. Task 10 requires it in the event text before calling a match
    # genuine, instead of treating "some event of this ID happened nearby" as proof.
    param([int]$Number, [string]$Description, [datetime]$Timestamp, [string[]]$ExpectedSources, [string]$Mitre, [string]$Entity)
    $actions.Add([ordered]@{
        action_number      = $Number
        description        = $Description
        timestamp           = $Timestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        expected_detection = $ExpectedSources
        mitre_technique    = $Mitre
        entity             = $Entity
    })
}

Write-Output "[*] Running Windows attacker simulation..."

# ----------------------------------------------------------- 1/6 Create local user
$pwd = ConvertTo-SecureString -String ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
$ts1 = Get-Date
New-LocalUser -Name $UserName -Password $pwd -FullName 'Support Update (simulation)' -Description 'MedDefense attack simulation - Task 9' | Out-Null
Write-Output ("    [1/6] Creating local user '$UserName'...      " + $ts1.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 1 "Create local user '$UserName'" $ts1 @('Security EID 4720') 'T1136.001 Create Account: Local Account' $UserName

# ----------------------------------------------------- 2/6 Add to Administrators
$ts2 = Get-Date
# Add-LocalGroupMember does not work on a domain controller (its SAM groups are not
# exposed through Microsoft.PowerShell.LocalAccounts there); the WinNT ADSI provider
# reaches the same local Administrators group and generates the same security events.
$adminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
$adminGroup.Add("WinNT://$env:COMPUTERNAME/$UserName,user")
Write-Output ("    [2/6] Adding to Administrators group...            " + $ts2.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 2 "Add '$UserName' to Administrators group" $ts2 @('Security EID 4732') 'T1098 Account Manipulation' $UserName

# -------------------------------------------------------- 3/6 Encoded PowerShell
$ts3 = Get-Date
$payload = 'Write-Host "C2 beacon"'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$null = powershell.exe -NoProfile -EncodedCommand $encoded 2>&1 | Out-Null
Write-Output ("    [3/6] Running encoded PowerShell...                " + $ts3.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 3 'Run encoded PowerShell command (harmless payload)' $ts3 @('PowerShell EID 4104', 'Sysmon EID 1') 'T1059.001 PowerShell / T1027 Obfuscated Files or Information' $encoded

# ----------------------------------------------------- 4/6 Scheduled task persistence
$ts4 = Get-Date
# schtasks writes a harmless "task may not run, /ST is in the past" warning to stderr;
# PowerShell turns native stderr output into an error record, which $ErrorActionPreference
# = "Stop" then treats as terminating even when redirected to $null. Relax it for just
# this call. The task only needs to exist for persistence, not actually fire, so a past
# start time is fine.
$ErrorActionPreference = 'Continue'
$null = schtasks /create /tn $TaskName /tr 'cmd.exe /c exit' /sc once /st 00:00 /f 2>&1
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -ne 0) { throw "schtasks /create failed (exit $LASTEXITCODE)" }
Write-Output ("    [4/6] Creating scheduled task...                   " + $ts4.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 4 "Create scheduled task '$TaskName' for persistence" $ts4 @('Sysmon EID 1') 'T1053.005 Scheduled Task/Job: Scheduled Task' $TaskName

# --------------------------------------------------------- 5/6 Outbound connection
$ts5 = Get-Date
$null = Test-NetConnection -ComputerName $ProbeIp -Port 443 -WarningAction SilentlyContinue
Write-Output ("    [5/6] Outbound network connection...               " + $ts5.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 5 "Initiate outbound network connection to $ProbeIp" $ts5 @('Sysmon EID 3') 'T1071 Application Layer Protocol / T1041 Exfiltration Over C2 Channel' $ProbeIp

# --------------------------------------------------------------- 6/6 Startup drop
$ts6 = Get-Date
Set-Content -Path $startupFile -Value "MedDefense attack simulation payload $(Get-Date -Format o)"
Write-Output ("    [6/6] Dropping file in Startup...                  " + $ts6.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Action 6 'Drop file in Startup folder for persistence' $ts6 @('Sysmon EID 11') 'T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder' (Split-Path -Leaf $startupFile)

# ----------------------------------------------------------------------- Cleanup
Write-Output "[*] Cleaning up artifacts..."
$cleaned = @()
try { Remove-LocalUser -Name $UserName -ErrorAction Stop; $cleaned += 'user' } catch { Write-Output "    [!] Failed to remove user: $($_.Exception.Message)" }
try { schtasks /delete /tn $TaskName /f 2>&1 | Out-Null; $cleaned += 'task' } catch { Write-Output "    [!] Failed to remove task: $($_.Exception.Message)" }
try { Remove-Item -Path $startupFile -Force -ErrorAction Stop; $cleaned += 'file' } catch { Write-Output "    [!] Failed to remove startup file: $($_.Exception.Message)" }
if ($cleaned.Count -eq 3) {
    Write-Output "    User removed, task deleted, file removed           [CLEAN]"
} else {
    Write-Output "    Partial cleanup: $($cleaned -join ', ') removed            [INCOMPLETE]"
}

# ------------------------------------------------------------------------ Report
Write-Output "Actions executed: $($actions.Count)"
$report = [ordered]@{
    generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname  = $env:COMPUTERNAME
    actions   = $actions
    cleanup   = [ordered]@{ fully_cleaned = ($cleaned.Count -eq 3); items_removed = $cleaned }
}
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Output "Ground truth saved to: $ReportPath"
