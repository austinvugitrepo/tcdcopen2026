<#
.SYNOPSIS
  TCDC blue team: turn on the Windows logging you need to SEE attacks. Low risk to uptime.

.DESCRIPTION
  Dry run by default: prints what it would do. With -Apply it:
    - enables advanced audit subcategories (logon, account and group changes, process
      creation, services, scheduled tasks, Kerberos, directory changes on a DC)
    - includes the command line in process creation events (4688)
    - turns on PowerShell script block logging (4104)
    - enables the Task Scheduler operational log
    - raises the Security log size to 256 MB so events are not overwritten quickly

  This only changes Windows' own audit settings on THIS box. It does not touch Wazuh
  or any competition agent (rule R7). If Wazuh already reads these logs, you just
  give it more to see.

.EXAMPLE
  .\Enable-WinAuditing.ps1            # dry run
  .\Enable-WinAuditing.ps1 -Apply
#>
[CmdletBinding()]
param([switch]$Apply)

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run from an elevated (Administrator) PowerShell.'
    exit 1
}

$isDC = $false
try { $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { }

# Audit subcategory names are English. On a non-English Windows use "auditpol /list /subcategory:*".
$subs = @(
    'Logon', 'Logoff', 'Special Logon', 'Account Lockout', 'Other Logon/Logoff Events',
    'User Account Management', 'Security Group Management', 'Computer Account Management',
    'Process Creation', 'Credential Validation',
    'Audit Policy Change', 'Authentication Policy Change', 'Security System Extension',
    'Other Object Access Events', 'Sensitive Privilege Use'
)
if ($isDC) {
    $subs += 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations', 'Directory Service Changes', 'Directory Service Access'
}

Write-Host ("Host {0}  isDC={1}  mode={2}" -f $env:COMPUTERNAME, $isDC, $(if ($Apply) { 'APPLY' } else { 'DRY RUN' }))
Write-Host ''

foreach ($s in $subs) {
    $cmd = 'auditpol.exe /set /subcategory:"{0}" /success:enable /failure:enable' -f $s
    if ($Apply) {
        $res = & auditpol.exe /set "/subcategory:$s" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host "ok     $s" -ForegroundColor Green }
        else { Write-Host "FAILED $s : $res" -ForegroundColor Yellow }
    }
    else { Write-Host "would run: $cmd" }
}

$regChanges = @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1; Why = 'advanced audit policy overrides legacy audit settings' },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Why = 'command line in 4688 process events' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Why = 'PowerShell script block logging (4104)' }
)
foreach ($r in $regChanges) {
    if ($Apply) {
        try {
            if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -PropertyType DWord -Force | Out-Null
            Write-Host ("ok     {0}\{1}={2} ({3})" -f $r.Path, $r.Name, $r.Value, $r.Why) -ForegroundColor Green
        }
        catch { Write-Host ("FAILED {0}\{1}: {2}" -f $r.Path, $r.Name, $_.Exception.Message) -ForegroundColor Yellow }
    }
    else { Write-Host ("would set {0}\{1}={2} ({3})" -f $r.Path, $r.Name, $r.Value, $r.Why) }
}

if ($Apply) {
    & wevtutil.exe sl Security /ms:268435456
    if ($LASTEXITCODE -eq 0) { Write-Host 'ok     Security log max size 256 MB' -ForegroundColor Green } else { Write-Host 'FAILED setting Security log size' -ForegroundColor Yellow }
    & wevtutil.exe sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true
    if ($LASTEXITCODE -eq 0) { Write-Host 'ok     Task Scheduler operational log enabled' -ForegroundColor Green } else { Write-Host 'FAILED enabling Task Scheduler log' -ForegroundColor Yellow }
}
else {
    Write-Host 'would run: wevtutil sl Security /ms:268435456'
    Write-Host 'would run: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'
    Write-Host ''
    Write-Host 'DRY RUN. Re-run with -Apply to make these changes.'
}
