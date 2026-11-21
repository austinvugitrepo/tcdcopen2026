<#
.SYNOPSIS
  TCDC blue team: hunt for AD backdoors and C2 on the domain controller. Run on the ad box.

.DESCRIPTION
  CHANGES NOTHING. Covers the AD persistence and C2 tricks that tcdc-blue-toolkit's
  Audit-AD.ps1, Audit-Windows.ps1 and Check-CredTheft.ps1 do not:
    - enabled accounts not on the packet list, new computer accounts, MachineAccountQuota
    - resource-based constrained delegation (RBCD) set on any object
    - shadow credentials (msDS-KeyCredentialLink) and SID history
    - AdminSDHolder permissions (a backdoor here is copied to every admin account hourly)
    - SYSVOL: Group Policy Preference passwords (cpassword), scripts and
      scheduled-task files, executables, anything changed recently
    - DSRM admin network logon, DnsAdmins ServerLevelPluginDll (DLL loaded by the DNS service)
    - sticky-keys and IFEO debugger backdoors, SilentProcessExit monitors
    - network connections owned by scripting and LOLBin programs (likely C2)
    - running processes whose program file is not validly signed
    - Defender: detections, recent Defender events (detections, protection
      turned off, settings changed), status
    - who is connected over SMB right now, Credential Guard status

  FLAG: lines are leads, not proof. Before removing anything, check it is not a
  service or checker account (Find-ScorerAccount.ps1) and agree as a team.
  Never touch blackteam, whiteteam, Wazuh or auditd (R7, R8, R15).

.EXAMPLE
  .\Hunt-ADPersistence.ps1
  .\Hunt-ADPersistence.ps1 -Hours 2
#>
[CmdletBinding()]
param(
    [int]$Hours = 6,
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Continue'
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error 'ActiveDirectory module not found. Run this on the domain controller (ad).'
    exit 1
}
Import-Module ActiveDirectory

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("ad-persistence-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$since = (Get-Date).AddHours(-$Hours)
$script:flagCount = 0
function Out-Line([string]$s, [string]$color = 'Gray') { Write-Host $s -ForegroundColor $color; Add-Content -Path $outFile -Value $s }
function Section([string]$t, [string]$why) { Out-Line ''; Out-Line "=== $t ===" 'Cyan'; if ($why) { Out-Line "why: $why" } }
function Flag([string]$s) { $script:flagCount++; Out-Line "FLAG: $s" 'Red' }
function Ok([string]$s) { Out-Line "OK:   $s" 'Green' }
function Note([string]$s) { Out-Line "NOTE: $s" 'Yellow' }
function Invoke-Check([scriptblock]$b) { try { & $b } catch { Note "check failed: $($_.Exception.Message)" } }

$PacketUsers = @('washington', 'kennedy', 'teddy', 'lincoln', 'ross',
    'streep', 'franklin', 'parks', 'armstrong', 'hamilton',
    'mlk', 'tubman', 'manziel', 'deniro', 'bush')
$KnownBuiltin = @('blackteam', 'whiteteam', 'Administrator', 'krbtgt', 'Guest', 'DefaultAccount')

$domain = Get-ADDomain
$dn = $domain.DistinguishedName
Out-Line "TCDC AD persistence hunt  domain=$($domain.DNSRoot)  dc=$env:COMPUTERNAME  window=${Hours}h  $(Get-Date)" 'White'

Section 'Enabled accounts not on the packet list' 'Attackers add their own accounts. Some may be real service or checker accounts: check before acting, and disable rather than delete.'
Invoke-Check {
    $extra = @(Get-ADUser -Filter 'Enabled -eq $true' -Properties whenCreated, Description |
            Where-Object { $_.SamAccountName -notin $PacketUsers -and $_.SamAccountName -notin $KnownBuiltin })
    if ($extra.Count -eq 0) { Ok 'none' }
    foreach ($u in $extra) {
        $new = $(if ($u.whenCreated -ge $since) { ' NEW in this window' } else { '' })
        Flag "$($u.SamAccountName) created=$($u.whenCreated)$new desc='$($u.Description)'"
    }
}

Section 'Computer accounts' 'Any user can add up to MachineAccountQuota computers. A new computer account is the usual first step of an RBCD attack.'
Invoke-Check {
    $q = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    if ($q -gt 0) { Note "ms-DS-MachineAccountQuota=$q. To stop users adding computers: Set-ADDomain -Identity '$($domain.DNSRoot)' -Replace @{'ms-DS-MachineAccountQuota'=0}" }
    else { Ok "ms-DS-MachineAccountQuota=$q" }
    $dcOu = "OU=Domain Controllers,$dn"
    Get-ADComputer -Filter * -Properties whenCreated, OperatingSystem | ForEach-Object {
        $isNew = $_.whenCreated -ge $since
        $line = "$($_.Name) os='$($_.OperatingSystem)' created=$($_.whenCreated)"
        if ($isNew -and $_.DistinguishedName -notlike "*$dcOu") { Flag "new computer account: $line" } else { Out-Line "  $line" }
    }
}

Section 'Resource-based constrained delegation (RBCD)' 'msDS-AllowedToActOnBehalfOfOtherIdentity lets the listed accounts impersonate ANY user to that machine. On the DC it means domain takeover.'
Invoke-Check {
    $r = @(Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity')
    if ($r.Count -eq 0) { Ok 'none' }
    foreach ($o in $r) {
        $who = ($o.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access | ForEach-Object { $_.IdentityReference.ToString() }) -join ', '
        Flag "$($o.Name) trusts: $who   fix: Set-ADObject '$($o.DistinguishedName)' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity"
    }
}

Section 'Shadow credentials and SID history' 'msDS-KeyCredentialLink on a user lets someone log in as that user with a certificate. sIDHistory can silently grant admin rights.'
Invoke-Check {
    $k = @(Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties objectClass)
    if ($k.Count -eq 0) { Ok 'no msDS-KeyCredentialLink set' }
    foreach ($o in $k) {
        if ($o.objectClass -eq 'user') { Flag "user $($o.Name) has msDS-KeyCredentialLink (shadow credentials). fix: Set-ADObject '$($o.DistinguishedName)' -Clear msDS-KeyCredentialLink" }
        else { Note "$($o.objectClass) $($o.Name) has msDS-KeyCredentialLink (can be normal for computers with Windows Hello)" }
    }
    $s = @(Get-ADObject -LDAPFilter '(sIDHistory=*)' -Properties sIDHistory)
    if ($s.Count -eq 0) { Ok 'no sIDHistory set' }
    foreach ($o in $s) { Flag "$($o.Name) has sIDHistory: $($o.sIDHistory -join ', ')" }
}

Section 'AdminSDHolder permissions' 'Every hour AD copies these permissions onto all admin accounts and groups. An extra entry here is a self-healing backdoor.'
Invoke-Check {
    $acl = Get-Acl -Path "AD:\CN=AdminSDHolder,CN=System,$dn"
    $expected = 'NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|\\Domain Admins$|\\Enterprise Admins$|NT AUTHORITY\\SELF|NT AUTHORITY\\Authenticated Users|Everyone|\\Cert Publishers$|Windows Authorization Access Group|Terminal Server License Servers|Pre-Windows 2000 Compatible Access|ENTERPRISE DOMAIN CONTROLLERS|CREATOR OWNER'
    $bad = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.ActiveDirectoryRights.ToString() -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and
            $_.IdentityReference.ToString() -notmatch $expected
        })
    if ($bad.Count -eq 0) { Ok 'only the expected identities have write rights' }
    foreach ($a in $bad) { Flag "$($a.IdentityReference) has $($a.ActiveDirectoryRights) on AdminSDHolder" }
}

Section 'SYSVOL (Group Policy files every machine runs)' 'GPP cpassword values can be decrypted by anyone. New scripts or scheduled-task files in SYSVOL run on every machine the GPO applies to.'
Invoke-Check {
    $share = Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue
    $root = $(if ($share) { $share.Path } else { "$env:windir\SYSVOL\sysvol" })
    $cp = @(Get-ChildItem -Path $root -Recurse -File -Filter *.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword="[^"]+' -List)
    if ($cp.Count -eq 0) { Ok 'no GPP cpassword values' }
    foreach ($m in $cp) { Flag "GPP password in $($m.Path). Anyone can decrypt it: delete that preference item and change that password" }
    $exts = '.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.msi', '.scr'
    $names = 'scripts.ini', 'psscripts.ini', 'ScheduledTasks.xml', 'Registry.pol', 'Groups.xml', 'Services.xml'
    $files = @(Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in $exts -or $_.Name -in $names })
    foreach ($f in $files) {
        $line = "$($f.FullName) modified=$($f.LastWriteTime)"
        if ($f.LastWriteTime -ge $since) { Flag "changed in this window: $line" } else { Out-Line "  $line" }
    }
    if ($files.Count -eq 0) { Ok 'no scripts, executables or task files in SYSVOL' }
}

Section 'DSRM and DNS plugin backdoors' 'DsrmAdminLogonBehavior=2 lets the local DSRM admin log in over the network. ServerLevelPluginDll makes the DNS service load a DLL as SYSTEM.'
Invoke-Check {
    $d = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
    if ($d -eq 2) { Flag "DsrmAdminLogonBehavior=2. fix: Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior" } else { Ok "DsrmAdminLogonBehavior=$d" }
    $p = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll -ErrorAction SilentlyContinue).ServerLevelPluginDll
    if ($p) { Flag "DNS ServerLevelPluginDll='$p'. fix: Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll; Restart-Service DNS" } else { Ok 'no DNS ServerLevelPluginDll' }
    $m = @(Get-ADGroupMember -Identity DnsAdmins -Recursive -ErrorAction SilentlyContinue | ForEach-Object SamAccountName)
    if ($m.Count) { Note "DnsAdmins members (can set that DLL): $($m -join ', ')" } else { Ok 'DnsAdmins is empty' }
}

Section 'Sticky keys, IFEO and SilentProcessExit backdoors' 'Replacing sethc.exe or utilman.exe with cmd.exe, or setting a Debugger for them, gives a SYSTEM shell from the logon screen (RDP included).'
Invoke-Check {
    $shells = 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'pwsh.dll', 'explorer.exe', 'taskmgr.exe'
    $shellHashes = @(foreach ($s in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe', 'explorer.exe') {
            $p = Join-Path "$env:windir\System32" $s
            if (Test-Path $p) { (Get-FileHash $p -Algorithm SHA256).Hash }
        })
    foreach ($f in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:windir\System32" $f
        if (-not (Test-Path $p)) { continue }
        $orig = ((Get-Item $p).VersionInfo.OriginalFilename -replace '\.mui$', '')
        $hash = (Get-FileHash $p -Algorithm SHA256).Hash
        if ($orig -in $shells -or $hash -in $shellHashes) { Flag "$f is really $orig (sticky-keys backdoor). Restore it: sfc /scanfile=$p" }
        elseif ((Get-AuthenticodeSignature $p).Status -ne 'Valid') { Flag "$f signature is not valid" }
        else { Ok "$f looks original" }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $dbg = @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $v = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($v) { "$($_.PSChildName) -> $v" }
        })
    if ($dbg.Count -eq 0) { Ok 'no IFEO Debugger values' }
    foreach ($x in $dbg) { Flag "IFEO Debugger: $x  (runs this instead of the program)" }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    Get-ChildItem $spe -ErrorAction SilentlyContinue | ForEach-Object {
        $mp = (Get-ItemProperty $_.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
        if ($mp) { Flag "SilentProcessExit: when $($_.PSChildName) exits, runs $mp" }
    }
}

Section 'Network connections owned by scripting and LOLBin programs' 'PowerShell, rundll32, mshta and friends rarely need to talk to the network on a DC. A live connection from one is a typical C2 channel.'
Invoke-Check {
    $lol = 'powershell', 'pwsh', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'msbuild', 'installutil', 'wmic', 'curl', 'nc', 'ncat', 'socat', 'python', 'python3'
    $hits = 0
    Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' } | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.Name -in $lol) {
                $hits++
                $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -ErrorAction SilentlyContinue).CommandLine
                Flag "$($proc.Name) pid $($_.OwningProcess) -> $($_.RemoteAddress):$($_.RemotePort) ($($_.State)) cmd: $cmd"
            }
        }
    if ($hits -eq 0) { Ok 'no scripting/LOLBin programs with network connections' }
}

Section 'Running processes with an unsigned or invalid program file' 'Malware and C2 implants are usually unsigned. Do NOT kill Wazuh, auditd, xe-guest or cloud-init processes even if listed (R7, R15).'
Invoke-Check {
    $seen = @{}
    $n = 0
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        if ($seen.ContainsKey($_.Path)) { return }
        $seen[$_.Path] = $true
        $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne 'Valid') {
            $n++
            $protected = $(if ($_.Path -match 'wazuh|ossec|xenserver|xe-guest|citrix|cloudbase|cloud-init') { '  (competition/infra tool: leave it alone)' } else { '' })
            Flag "$($_.Name) pid $($_.Id) $($_.Path) [$($sig.Status)]$protected"
        }
    }
    if ($n -eq 0) { Ok "all $($seen.Count) running program files are validly signed" }
}

Section 'Windows Defender: detections and recent events' 'Attackers turn Defender off or add exclusions first. A detection means something already landed.'
Invoke-Check {
    $st = Get-MpComputerStatus -ErrorAction Stop
    $line = "RealTime=$($st.RealTimeProtectionEnabled) AV=$($st.AntivirusEnabled) Behavior=$($st.BehaviorMonitorEnabled) IOAV=$($st.IoavProtectionEnabled) TamperProtected=$($st.IsTamperProtected) SignatureAgeDays=$($st.AntivirusSignatureAge)"
    if (-not $st.RealTimeProtectionEnabled -or -not $st.AntivirusEnabled) { Flag "Defender is partly OFF: $line. Fix: .\Harden-DC.ps1 -Apply -Fix Defender" } else { Ok $line }
    $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
    if ($det.Count -eq 0) { Ok 'no Defender detections recorded' }
    foreach ($d in $det) {
        $name = (Get-MpThreat -ThreatID $d.ThreatID -ErrorAction SilentlyContinue).ThreatName
        Flag "DETECTION $name at $($d.InitialDetectionTime) action=$($d.ActionSuccess) resources: $($d.Resources -join '; ')"
    }
    $ids = 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $ids; StartTime = $since } -ErrorAction SilentlyContinue)
    if ($ev.Count -eq 0) { Ok "no Defender alerts or setting changes in the last $Hours h" }
    foreach ($e in $ev | Select-Object -First 25) {
        $what = switch ($e.Id) { { $_ -in 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119 } { 'detection/action' } 5001 { 'REAL-TIME PROTECTION TURNED OFF' } 5004 { 'real-time config changed' } 5007 { 'SETTINGS CHANGED (exclusions?)' } { $_ -in 5010, 5012 } { 'SCANNING TURNED OFF' } }
        Flag "$($e.TimeCreated) event $($e.Id) $what : $(($e.Message -split "`n")[0])"
    }
    Note 'To scan now: .\Harden-DC.ps1 -Apply -Fix DefenderScan'
}

Section 'SMB sessions and Credential Guard' 'An SMB session from an address that is not your team or the scorer can be an attacker using stolen credentials (psexec, secretsdump).'
Invoke-Check {
    $sess = @(Get-SmbSession -ErrorAction SilentlyContinue)
    if ($sess.Count -eq 0) { Ok 'no SMB sessions right now' }
    foreach ($s in $sess) { Note "SMB session from $($s.ClientComputerName) as $($s.ClientUserName) open files=$($s.NumOpens) seconds=$($s.SecondsExists)" }
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        $cg = $(if (@($dg.SecurityServicesRunning) -contains 1) { 'running' } else { 'not running' })
        Note "Credential Guard is $cg (information only; turning it on needs a reboot and supported hardware)"
    }
}

Out-Line ''
Out-Line "Done. $($script:flagCount) FLAG line(s). Saved: $outFile" 'White'
Out-Line 'Also run from tcdc-blue-toolkit: Audit-AD.ps1 (DCSync, delegation, roastable accounts), Check-CredTheft.ps1 (LSA and password theft), Audit-Windows.ps1 -Mode Diff.' 'White'
