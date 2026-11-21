<#
.SYNOPSIS
  TCDC blue team: domain-controller hardening, one named fix at a time. Run on the ad box.

.DESCRIPTION
  Without -Apply it is an audit: it shows the current state of every fix, what
  it would change and the undo line. With -Apply you must name the fixes with
  -Fix, so nothing changes by accident. One fix per run is safest: apply it,
  wait 60 s (2 ticks), check the scoreboard, then do the next.

  Fixes (all reversible; each prints its undo line):
    Zerologon    FullSecureChannelProtection = 1, and remove a planted
                 VulnerableChannelAllowList (lets named machines skip the fix)
    Spooler      stop and disable the Print Spooler (PrintNightmare, printer-bug coercion)
    WebClient    stop and disable WebClient (NTLM relay trigger), if installed
    RunAsPPL     run LSASS as a protected process (blocks most password dumping).
                 Uses value 2 (no UEFI lock, so it can be undone). Needs a REBOOT,
                 which drops AD for a few minutes: plan it for a quiet moment.
    Defender     turn real-time protection back on, and remove policy keys that
                 force it off
    LdapSigning  require LDAP signing and channel binding. NOT part of "All":
                 it rejects simple binds on port 389, which a scorer may use.
                 Only with -Fix LdapSigning, then watch the scoreboard closely.
    AsRep        turn Kerberos pre-authentication back on for every account that
                 has it off (AS-REP roasting). Skips blackteam and whiteteam.
    TimeSync     force a time resync (Kerberos fails beyond 5 minutes of skew)
    DefenderScan run a Defender quick scan now and list detections (takes minutes).
                 NOT part of "All".
    RecycleBin   turn on the AD Recycle Bin, so a deleted user can be restored with
                 its groups and password. NOT part of "All": it can never be turned
                 off again (harmless, but agree as a team first).

  Already done elsewhere (tcdc-blue-toolkit Harden-Windows-Safe.ps1): SMBv1,
  RDP NLA, Guest, LLMNR, WDigest. Not done here on purpose: firewall changes
  (rule R18 and scorer risk), removing Defender exclusions (review them with
  Audit-Windows.ps1 first).

.EXAMPLE
  .\Harden-DC.ps1                              # audit: state of every fix
  .\Harden-DC.ps1 -Apply -Fix Zerologon        # one fix
  .\Harden-DC.ps1 -Apply -Fix Spooler,WebClient
  .\Harden-DC.ps1 -Apply -Fix All              # Zerologon, Spooler, WebClient, RunAsPPL, Defender, AsRep, TimeSync
  .\Harden-DC.ps1 -Apply -Fix LdapSigning      # separate, scorer risk
  .\Harden-DC.ps1 -Apply -Fix DefenderScan     # scan now
  .\Harden-DC.ps1 -Apply -Fix RecycleBin       # one-way switch
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateSet('All', 'Zerologon', 'Spooler', 'WebClient', 'RunAsPPL', 'Defender', 'AsRep', 'TimeSync', 'LdapSigning', 'DefenderScan', 'RecycleBin')]
    [string[]]$Fix = @('All'),
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Continue'
if ($Apply -and -not $PSBoundParameters.ContainsKey('Fix')) {
    Write-Host 'With -Apply, name the fixes: -Fix Zerologon (one at a time is safest), or -Fix All. Run without -Apply first to see the plan.' -ForegroundColor Yellow
    exit 2
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("harden-dc-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function Out-Line([string]$s, [string]$color = 'Gray') { Write-Host $s -ForegroundColor $color; Add-Content -Path $outFile -Value $s }

$safeSet = 'Zerologon', 'Spooler', 'WebClient', 'RunAsPPL', 'Defender', 'AsRep', 'TimeSync'
$optIn = 'LdapSigning', 'DefenderScan', 'RecycleBin'
$selected = @()
foreach ($f in $Fix) { if ($f -eq 'All') { $selected += $safeSet } else { $selected += $f } }
$selected = @($selected | Select-Object -Unique)
if (-not $Apply) { $selected = $safeSet + $optIn }   # audit shows everything
$Never = @('blackteam', 'whiteteam')
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$defPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$defRtp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
function RegVal($path, $name) { (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name }

function Test-ServiceOff($name) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $s) { return @{ Ok = $true; State = 'not installed' } }
    @{ Ok = ($s.Status -ne 'Running' -and $s.StartType -eq 'Disabled'); State = "$($s.Status), start type $($s.StartType)" }
}
function Set-ServiceOff($name) {
    if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) { return }
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $name -StartupType Disabled
}

$fixes = [ordered]@{
    Zerologon   = @{
        Why   = 'Zerologon (CVE-2020-1472) lets anyone on the network take over the DC. The allow-list exempts named machines from the fix.'
        Check = {
            $v = RegVal $nl 'FullSecureChannelProtection'; $al = RegVal $nl 'VulnerableChannelAllowList'
            $script:oldAllow = $al
            @{ Ok = ($v -eq 1 -and -not $al); State = "FullSecureChannelProtection=$v  VulnerableChannelAllowList='$al'" }
        }
        Do    = {
            Set-ItemProperty -Path $nl -Name FullSecureChannelProtection -Value 1 -Type DWord
            if ($script:oldAllow) { Remove-ItemProperty -Path $nl -Name VulnerableChannelAllowList }
        }
        Undo  = { "Set-ItemProperty '$nl' -Name FullSecureChannelProtection -Value 0" + $(if ($script:oldAllow) { "; New-ItemProperty '$nl' -Name VulnerableChannelAllowList -Value '$($script:oldAllow)'" } else { '' }) + '   (a GPO named "Allow vulnerable Netlogon secure channel connections" can put the allow-list back: check GPOs)' }
    }
    Spooler     = @{
        Why   = 'Print Spooler on a DC enables PrintNightmare and lets anyone force the DC to authenticate to them (relay).'
        Check = { Test-ServiceOff 'Spooler' }
        Do    = { Set-ServiceOff 'Spooler' }
        Undo  = { 'Set-Service Spooler -StartupType Automatic; Start-Service Spooler' }
    }
    WebClient   = @{
        Why   = 'WebClient lets attackers coerce NTLM authentication over HTTP for relay attacks.'
        Check = { Test-ServiceOff 'WebClient' }
        Do    = { Set-ServiceOff 'WebClient' }
        Undo  = { 'Set-Service WebClient -StartupType Manual' }
    }
    RunAsPPL    = @{
        Why   = 'A protected LSASS blocks Mimikatz-style password dumping. Takes effect after a reboot.'
        Check = { $v = RegVal $lsa 'RunAsPPL'; $script:oldPpl = $v; @{ Ok = ($v -eq 1 -or $v -eq 2); State = "RunAsPPL=$v" } }
        Do    = { Set-ItemProperty -Path $lsa -Name RunAsPPL -Value 2 -Type DWord }
        Undo  = { "Set-ItemProperty '$lsa' -Name RunAsPPL -Value $(if ($null -ne $script:oldPpl) { $script:oldPpl } else { 0 }); then reboot   (REBOOT NEEDED for the fix itself too; AD drops while it restarts)" }
    }
    Defender    = @{
        Why   = 'Attackers turn real-time protection off first. A policy key can keep it off even after Set-MpPreference.'
        Check = {
            $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $p1 = RegVal $defPol 'DisableAntiSpyware'; $p2 = RegVal $defRtp 'DisableRealtimeMonitoring'
            $exc = Get-MpPreference -ErrorAction SilentlyContinue
            $nExc = @($exc.ExclusionPath) + @($exc.ExclusionProcess) + @($exc.ExclusionExtension) | Where-Object { $_ }
            @{ Ok = ($st -and $st.RealTimeProtectionEnabled -and $p1 -ne 1 -and $p2 -ne 1)
                State = "RealTime=$($st.RealTimeProtectionEnabled) AV=$($st.AntivirusEnabled) policy DisableAntiSpyware=$p1 DisableRealtimeMonitoring=$p2 exclusions=$(@($nExc).Count)" }
        }
        Do    = {
            if ((RegVal $defPol 'DisableAntiSpyware') -eq 1) { Remove-ItemProperty -Path $defPol -Name DisableAntiSpyware }
            if ((RegVal $defRtp 'DisableRealtimeMonitoring') -eq 1) { Remove-ItemProperty -Path $defRtp -Name DisableRealtimeMonitoring }
            Set-MpPreference -DisableRealtimeMonitoring $false
        }
        Undo  = { 'Set-MpPreference -DisableRealtimeMonitoring $true   (not recommended). Exclusions were NOT touched: review them with Audit-Windows.ps1' }
    }
    LdapSigning = @{
        Why   = 'Requiring LDAP signing and channel binding stops NTLM relay to LDAP. RISK: rejects simple binds on 389, which the AD scorer may use.'
        Check = {
            $a = RegVal $ntds 'LDAPServerIntegrity'; $b = RegVal $ntds 'LdapEnforceChannelBinding'
            $script:oldLdap = @($a, $b)
            @{ Ok = ($a -eq 2 -and $b -eq 2); State = "LDAPServerIntegrity=$a LdapEnforceChannelBinding=$b (want 2 and 2)" }
        }
        Do    = {
            Set-ItemProperty -Path $ntds -Name LDAPServerIntegrity -Value 2 -Type DWord
            Set-ItemProperty -Path $ntds -Name LdapEnforceChannelBinding -Value 2 -Type DWord
        }
        Undo  = {
            $a = $(if ($null -ne $script:oldLdap[0]) { $script:oldLdap[0] } else { 1 }); $b = $(if ($null -ne $script:oldLdap[1]) { $script:oldLdap[1] } else { 0 })
            "Set-ItemProperty '$ntds' -Name LDAPServerIntegrity -Value $a; Set-ItemProperty '$ntds' -Name LdapEnforceChannelBinding -Value $b   (run this the moment the AD check goes red)"
        }
    }
    AsRep       = @{
        Why   = 'Accounts without Kerberos pre-authentication hand out crackable password hashes to anyone who asks (AS-REP roasting).'
        Check = {
            $script:asrep = @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -ErrorAction SilentlyContinue |
                    Where-Object { $_.SamAccountName -notin $Never } | ForEach-Object { $_.SamAccountName })
            @{ Ok = ($script:asrep.Count -eq 0); State = "accounts without pre-auth: $(if ($script:asrep.Count) { $script:asrep -join ', ' } else { 'none' })" }
        }
        Do    = { foreach ($u in $script:asrep) { Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $false } }
        Undo  = { ($script:asrep | ForEach-Object { "Set-ADAccountControl $_ -DoesNotRequirePreAuth `$true" }) -join '; ' }
    }
    TimeSync    = @{
        Why   = 'Kerberos logons fail when clocks differ by more than 5 minutes. Red team can break time to break AD.'
        Check = {
            $w = (& w32tm /query /status 2>&1) -join "`n"
            $src = $(if ($w -match 'Source:\s*(.+)') { $Matches[1].Trim() } else { 'unknown' })
            $last = $(if ($w -match 'Last Successful Sync Time:\s*(.+)') { $Matches[1].Trim() } else { 'unknown' })
            $svc = (Get-Service W32Time -ErrorAction SilentlyContinue).Status
            $local = $src -match 'Local CMOS|Free-running'
            @{ Ok = ($svc -eq 'Running' -and -not $local); State = "W32Time=$svc source='$src' lastSync='$last'$(if ($local) { '  (no time server: a resync cannot help; compare the clock with another box by hand)' })" }
        }
        Do    = {
            if ((Get-Service W32Time).Status -ne 'Running') { Start-Service W32Time }
            & w32tm /resync /force | Out-Null
        }
        Undo  = { 'nothing to undo (resync only)' }
    }
    DefenderScan = @{
        Why   = 'A quick scan finds known malware and tools (Mimikatz, Cobalt Strike, common implants) already on the box.'
        Check = {
            $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $recent = $st -and $st.QuickScanEndTime -and $st.QuickScanEndTime -gt (Get-Date).AddHours(-2)
            @{ Ok = [bool]$recent; State = "last quick scan ended: $($st.QuickScanEndTime)" }
        }
        Do    = {
            Start-MpScan -ScanType QuickScan
            $d = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
            if ($d.Count) { foreach ($x in $d) { Out-Line "  DETECTION: $((Get-MpThreat -ThreatID $x.ThreatID -ErrorAction SilentlyContinue).ThreatName) $($x.Resources -join '; ')" 'Red' } }
            else { Out-Line '  no detections' 'Green' }
        }
        Undo  = { 'nothing to undo (scan only)' }
    }
    RecycleBin  = @{
        Why   = 'With the Recycle Bin on, a deleted user comes back with its groups and password: Get-ADObject -Filter "isDeleted -eq `$true" -IncludeDeletedObjects | Restore-ADObject. Without it, a deleted packet user is hard to recover (rule R8).'
        Check = {
            $f = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction SilentlyContinue
            $on = $f -and @($f.EnabledScopes).Count -gt 0
            @{ Ok = [bool]$on; State = "AD Recycle Bin enabled=$([bool]$on)" }
        }
        Do    = {
            $forest = (Get-ADForest).Name
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false
        }
        Undo  = { 'cannot be undone (Microsoft does not allow turning it off). It is harmless.' }
    }
}

Out-Line "TCDC Harden-DC  dc=$env:COMPUTERNAME  apply=$Apply  fixes=$($selected -join ',')  $(Get-Date)" 'White'
foreach ($name in $fixes.Keys) {
    if ($name -notin $selected) { continue }
    $f = $fixes[$name]
    Out-Line ''
    Out-Line "--- $name ---" 'Cyan'
    Out-Line "why:  $($f.Why)"
    $r = & $f.Check
    Out-Line "now:  $($r.State)"
    if ($r.Ok) { Out-Line 'OK:   already done' 'Green'; continue }
    $undo = & $f.Undo
    if (-not $Apply) {
        Out-Line "FLAG: not done. Apply with: .\Harden-DC.ps1 -Apply -Fix $name" 'Red'
        Out-Line "undo: $undo"
        continue
    }
    try {
        & $f.Do
        $after = & $f.Check
        Out-Line "  -> done. now: $($after.State)" 'Magenta'
        Out-Line "undo: $undo" 'Yellow'
    }
    catch { Out-Line "FLAG: $name failed: $($_.Exception.Message)" 'Red' }
}
Out-Line ''
if ($Apply) { Out-Line 'Wait 60 s (2 ticks) and check the scoreboard before the next change. Undo lines are saved in the report.' 'White' }
Out-Line "Saved: $outFile" 'White'
