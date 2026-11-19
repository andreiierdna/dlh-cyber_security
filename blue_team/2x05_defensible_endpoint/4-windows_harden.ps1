<#
.SYNOPSIS
    4-windows_harden.ps1 - orchestrated hardening pass for hawthorne-adm-01.
.DESCRIPTION
    Applies the Windows control set locally (this lab has no domain controller,
    so the 2x01 GPO-driven scripts cannot be used as-is - the same controls are
    applied with secedit/registry/auditpol/NetSecurity cmdlets instead) and emits
    the same evidence schema as 3-linux_harden.sh:
      timestamp, hostname, steps[], baseline_before, pass_rate_after, target.
    Exit: 0 all steps succeeded and pass rate >= target, 1 a step or the target
    failed, 2 environment error.
.NOTES
    Author: Andrei
#>
[CmdletBinding()]
param(
    [string]$CapRoot    = 'C:\MedDefense_Lab\capstone',
    [int]$TargetRate    = 85,
    [string]$SysmonUrl  = 'https://download.sysinternals.com/files/Sysmon.zip'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$execDir = Join-Path $CapRoot 'exec'
if (-not (Test-Path $execDir)) { New-Item -ItemType Directory -Force -Path $execDir | Out-Null }
$logPath = Join-Path $execDir 'windows_harden.log'
$outPath = Join-Path $execDir 'windows_harden.json'

function Write-Log($msg) { $msg | Tee-Object -FilePath $logPath -Append | Out-Null }

$steps = New-Object System.Collections.Generic.List[object]
function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Log ""
    Write-Log ("===== STEP $Name =====")
    $before = $ErrorActionPreference
    $script:ErrorActionPreference = 'Continue'
    $ok = $true
    try {
        & $Body 2>&1 | ForEach-Object { Write-Log ([string]$_) }
    } catch {
        $ok = $false
        Write-Log ("  error: " + $_.Exception.Message)
    }
    $script:ErrorActionPreference = $before
    $sw.Stop()
    $status = if ($ok) { 0 } else { 1 }
    # console progress must not pollute the function's return value
    [Console]::WriteLine(("  {0,-24} exit={1} {2:N0}s" -f $Name, $status, $sw.Elapsed.TotalSeconds))
    $steps.Add([pscustomobject]@{
        name = $Name; script_path = '4-windows_harden.ps1'; exit_code = $status
        duration_seconds = [int]$sw.Elapsed.TotalSeconds; changed = $true
    })
    return $ok
}

$allOk = $true

# 1. account and lockout policy ------------------------------------------------
if (-not (Invoke-Step 'account_policy' {
    net accounts /minpwlen:14 /maxpwage:90 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 /uniquepw:24 | Out-String
})) { $allOk = $false }

# 2. advanced audit policy -----------------------------------------------------
if (-not (Invoke-Step 'audit_policy' {
    $subs = @('Credential Validation','Logon','Logoff','File System','Sensitive Privilege Use',
              'Special Logon','Other Object Access Events','Security State Change')
    foreach ($s in $subs) {
        auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
    }
    auditpol /get /category:* | Select-String -Pattern 'Credential Validation','Logon','File System','Privilege Use' | Out-String
})) { $allOk = $false }

# 3. firewall ------------------------------------------------------------------
if (-not (Invoke-Step 'firewall' {
    $logFile = '%systemroot%\system32\LogFiles\Firewall\meddefense.log'
    foreach ($p in 'Domain','Private','Public') {
        Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block `
            -DefaultOutboundAction Allow -LogBlocked True -LogFileName $logFile
    }
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, LogBlocked | Out-String
})) { $allOk = $false }

# 4. PowerShell logging --------------------------------------------------------
if (-not (Invoke-Step 'powershell_logging' {
    $sblKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $modKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    New-Item -Path $sblKey -Force | Out-Null
    New-Item -Path $modKey -Force | Out-Null
    Set-ItemProperty -Path $sblKey -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Set-ItemProperty -Path $modKey -Name EnableModuleLogging -Value 1 -Type DWord
    # produce a 4104 record so the channel is provably populated
    & { 'meddefense-sbl-probe' } | Out-Null
    Start-Sleep -Seconds 2
    (Get-ItemProperty $sblKey).EnableScriptBlockLogging
})) { $allOk = $false }

# 5. legacy protocols and credential protections --------------------------------
if (-not (Invoke-Step 'legacy_protocols' {
    $dns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    New-Item -Path $dns -Force | Out-Null
    Set-ItemProperty -Path $dns -Name EnableMulticast -Value 0 -Type DWord

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -Type DWord
    }

    $wd = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if (-not (Test-Path $wd)) { New-Item -Path $wd -Force | Out-Null }
    Set-ItemProperty -Path $wd -Name UseLogonCredential -Value 0 -Type DWord
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0' -Type String
    'legacy protocols configured'
})) { $allOk = $false }

# 6. Sysmon ---------------------------------------------------------------------
if (-not (Invoke-Step 'sysmon' {
    $svc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $svc) {
        $zip = Join-Path $env:TEMP 'Sysmon.zip'
        $dir = Join-Path $CapRoot 'sysmon'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Invoke-WebRequest -UseBasicParsing -Uri $SysmonUrl -OutFile $zip -TimeoutSec 120
        Expand-Archive -Path $zip -DestinationPath $dir -Force
        $cfg = Join-Path $dir 'meddefense-sysmon.xml'
        @'
<Sysmon schemaversion="4.50">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="MedDefense core" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
      <NetworkConnect onmatch="exclude" />
      <FileCreate onmatch="exclude" />
      <RegistryEvent onmatch="exclude" />
      <DnsQuery onmatch="exclude" />
      <ProcessTerminate onmatch="exclude" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content -Path $cfg -Encoding ASCII
        & (Join-Path $dir 'Sysmon64.exe') -accepteula -i $cfg | Out-String
        Start-Sleep -Seconds 3
    } else {
        if ($svc.Status -ne 'Running') { Start-Service $svc.Name }
    }
    (Get-Service -Name 'Sysmon*' | Select-Object Name, Status | Out-String)
})) { $allOk = $false }

# 7. Defender attack surface reduction ------------------------------------------
if (-not (Invoke-Step 'defender_asr' {
    $ids = @(
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',  # block executable content from email/webmail
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # block Office child processes
        '3B576869-A4EC-4529-8536-B80A7769E899',  # block Office executable content
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',  # block Win32 API calls from Office macros
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'   # block execution of potentially obfuscated scripts
    )
    foreach ($id in $ids) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
    }
    (Get-MpPreference).AttackSurfaceReductionRules_Ids.Count
})) { $allOk = $false }

# 8. execution policy ------------------------------------------------------------
if (-not (Invoke-Step 'execution_policy' {
    # A process-scope Bypass (used to launch this script) rejects a LocalMachine
    # change with "Security error", so only set it when it differs.
    $current = Get-ExecutionPolicy -Scope LocalMachine
    if ($current -ne 'RemoteSigned') { Set-ExecutionPolicy -Scope LocalMachine RemoteSigned -Force }
    Get-ExecutionPolicy -List | Out-String
})) { $allOk = $false }

# --- post-hardening audit --------------------------------------------------------
$auditScript = Join-Path $CapRoot 'win_audit.ps1'
Set-ExecutionPolicy -Scope Process Bypass -Force
$lines = & $auditScript
$lines | Set-Content -Path (Join-Path $execDir 'windows_audit_after.log') -Encoding UTF8
$pass = @($lines | Select-String '^PASS ').Count
$fail = @($lines | Select-String '^FAIL ').Count
$na = @($lines | Select-String '^NOT_APPLICABLE ').Count
$total = $pass + $fail + $na
$rate = if ($total -gt 0) { [math]::Round(100.0 * $pass / $total, 1) } else { 0 }

$baselinePath = Join-Path $CapRoot 'baseline\baseline_windows.json'
$before = 0
if (Test-Path $baselinePath) { $before = (Get-Content $baselinePath -Raw | ConvertFrom-Json).pass_rate_percent }

$fwState = (Get-NetFirewallProfile -Profile Domain,Private,Public | Group-Object DefaultInboundAction | ForEach-Object { $_.Name }) -join ','
$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$sysmonSvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
$auditCovered = 0
try {
    foreach ($s in 'Credential Validation','Logon','File System','Sensitive Privilege Use') {
        $line = auditpol /get /subcategory:"$s" 2>$null | Out-String
        if ($line -match 'Success\s+and\s+Failure') { $auditCovered++ }
    }
} catch { }

# Serialisation is built key-by-key: literal hashtable serialisation proved
# unreliable on Windows PowerShell 5.1 in this environment (empty output).
$sblValue = 0
if ($null -ne $sbl) { $sblValue = [int]$sbl }
$sysmonState = 'Absent'
if ($null -ne $sysmonSvc) { $sysmonState = $sysmonSvc.Status.ToString() }

$record = @{}
$record['timestamp']                   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$record['hostname']                    = $env:COMPUTERNAME
$record['platform']                    = 'windows'
$record['steps']                       = @($steps | ForEach-Object { $_ })
$record['pass_rate_before']            = $before
$record['pass_rate_after']             = $rate
$record['pass_count']                  = $pass
$record['fail_count']                  = $fail
$record['na_count']                    = $na
$record['controls_total']              = $total
$record['rate_delta']                  = [math]::Round($rate - $before, 1)
$record['target_rate']                 = $TargetRate
$record['target_met']                  = ($rate -ge $TargetRate)
$record['firewall_default_deny']       = $fwState
$record['sbl_enabled']                 = $sblValue
$record['sysmon_running']              = $sysmonState
$record['audit_subcategories_covered'] = $auditCovered
$record['log_path']                    = $logPath

try {
    $json = ConvertTo-Json -InputObject $record -Depth 6
    Set-Content -Path $outPath -Value $json -Encoding UTF8
    [Console]::WriteLine("  evidence: {0} bytes, written={1}" -f (Get-Item $outPath).Length, (Test-Path $outPath))
} catch {
    [Console]::WriteLine("  EVIDENCE WRITE FAILED: " + $_.Exception.Message)
}

Write-Output ("Windows pass rate: {0}% -> {1}% (target {2}%, delta {3})" -f $before, $rate, $TargetRate, $result.rate_delta)
Write-Output ("Evidence: {0}" -f $outPath)
if ($allOk -and $result.target_met) { exit 0 } else { exit 1 }
