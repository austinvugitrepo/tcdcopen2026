<#
.SYNOPSIS
  TCDC blue team: a SHORT list of low-risk Windows hardening changes.

.DESCRIPTION
  Dry run by default. With -Apply it performs each item below and prints what it did.
  Every item is reversible (the undo command is printed), and none of them should
  affect a typical scoring check. Still: change, then check the scoreboard for 2 ticks.

  Items:
    1. Disable SMBv1 server protocol
    2. Require Network Level Authentication for RDP
    3. Disable the built-in Guest account (local, and domain Guest on a DC)
    4. Turn off LLMNR name resolution (a common credential-capture trick)
    5. Turn off WDigest clear-text credential caching

  What it deliberately does NOT do (too risky for uptime without testing):
    - turning the Windows firewall on or changing default inbound action
    - requiring SMB signing, blocking NTLM, changing Kerberos encryption types
    - removing Defender exclusions (it only reports them; see Audit-Windows.ps1)
    - touching blackteam, whiteteam, Wazuh or any competition agent

.EXAMPLE
  .\Harden-Windows-Safe.ps1           # dry run
  .\Harden-Windows-Safe.ps1 -Apply
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

function Invoke-Item2 {
    param([string]$Name, [string]$Undo, [scriptblock]$Do)
    if (-not $Apply) {
        Write-Host "would do: $Name"
        Write-Host "   undo : $Undo"
        return
    }
    try {
        & $Do
        Write-Host "done   : $Name" -ForegroundColor Green
        Write-Host "   undo : $Undo"
    }
    catch { Write-Host "FAILED : $Name : $($_.Exception.Message)" -ForegroundColor Yellow }
}

Write-Host ("Host {0}  isDC={1}  mode={2}" -f $env:COMPUTERNAME, $isDC, $(if ($Apply) { 'APPLY' } else { 'DRY RUN' }))
Write-Host ''

Invoke-Item2 -Name 'Disable SMBv1 server protocol' -Undo 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force' -Do {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Invoke-Item2 -Name 'Require NLA for RDP' -Undo 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp UserAuthentication to 0' -Do {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
}

Invoke-Item2 -Name 'Disable local Guest account' -Undo 'Enable-LocalUser -Name Guest' -Do {
    if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
        $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($g -and $g.Enabled) { Disable-LocalUser -Name 'Guest' }
    }
}

if ($isDC -and (Get-Command Disable-ADAccount -ErrorAction SilentlyContinue)) {
    Invoke-Item2 -Name 'Disable domain Guest account' -Undo 'Enable-ADAccount -Identity Guest' -Do {
        $g = Get-ADUser -Identity 'Guest' -Properties Enabled
        if ($g.Enabled) { Disable-ADAccount -Identity 'Guest' }
    }
}

Invoke-Item2 -Name 'Turn off LLMNR (EnableMulticast=0)' -Undo 'Remove HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient value EnableMulticast' -Do {
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force | Out-Null
}

Invoke-Item2 -Name 'Turn off WDigest clear-text credential caching' -Undo 'Set HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest UseLogonCredential to 1' -Do {
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name 'UseLogonCredential' -Value 0 -PropertyType DWord -Force | Out-Null
}

Write-Host ''
if (-not $Apply) { Write-Host 'DRY RUN. Re-run with -Apply to make these changes.' }
else { Write-Host 'NEXT: check the scoreboard for 2 ticks (60 s). If anything went red, use the undo line above.' }
