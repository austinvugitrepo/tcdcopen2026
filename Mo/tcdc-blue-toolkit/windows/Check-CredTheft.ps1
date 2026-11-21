<#
.SYNOPSIS
  TCDC blue team: read-only hunt for password theft on the ad (Server 2025) and mqtt (Windows 11) boxes.

.DESCRIPTION
  CHANGES NOTHING. It only reads settings, files and event logs. It makes no network connections.

  It looks for the usual ways red team captures Windows passwords:
    - extra LSA packages and password filter DLLs (code that sees every password change)
    - odd credential providers (code on the sign-in screen) and network providers
    - Winlogon and AppInit hooks
    - recently written, unsigned DLLs and EXEs in the system folders
    - credential dumping tools or commands running right now
    - dump files and copied registry hives or ntds.dit
    - password resets, failed and remote logons, new services, DCSync activity (from event logs)
    - connections from this box to addresses outside 10.0.0.0/8
    - Mosquitto password file exposure (mqtt box)

  Every suspicious item is printed as a line starting with FLAG:. A flag is a lead,
  not proof. Windows updates and your own changes can trigger some of them.

  Run from an elevated (Administrator) PowerShell. Works on Windows PowerShell 5.1.
  Event log checks need auditing turned on (see Enable-WinAuditing.ps1). If a log
  has no matching events the script says so. That can also mean auditing was off.

.EXAMPLE
  .\Check-CredTheft.ps1
  .\Check-CredTheft.ps1 -Hours 2
#>
[CmdletBinding()]
param(
    [int]$Hours = 6,
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Continue'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Not running as Administrator. Some checks will be incomplete.'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = Join-Path $OutDir ("credtheft-{0}-{1}.txt" -f $env:COMPUTERNAME, $stamp)
$cut = (Get-Date).AddHours(-$Hours)

$script:Lines = New-Object System.Collections.Generic.List[string]
$script:FlagCount = 0

function Say {
    param([string]$Text, [string]$Color)
    $script:Lines.Add($Text)
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Section {
    param([string]$Title)
    Say ''
    Say ("=== {0} ===" -f $Title)
}

function Add-Flag {
    param([string]$Text)
    $script:FlagCount++
    Say ("FLAG: {0}" -f $Text) 'Yellow'
}

function Get-SigInfo {
    param([string]$Path)
    try {
        $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signer = ''
        if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
        return [pscustomobject]@{ Status = "$($s.Status)"; Signer = $signer }
    }
    catch {
        return [pscustomobject]@{ Status = 'Error'; Signer = '' }
    }
}

function Get-EventData {
    param($Event)
    $h = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    }
    catch { }
    return $h
}

function Split-Values {
    param($Value)
    $out = @()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($p in ("$v" -split '[\s,]+')) {
            $p = $p.Trim().Trim('"')
            if ($p) { $out += $p }
        }
    }
    return $out
}

function Test-Private {
    param([string]$Addr)
    if (-not $Addr) { return $true }
    if ($Addr -match '^(::ffff:)?(10\.|127\.|169\.254\.)') { return $true }
    if ($Addr -in @('::1', '::', '0.0.0.0', '-')) { return $true }
    if ($Addr -match '^(fe80:|fc|fd)') { return $true }
    return $false
}

$isDC = $false
try { $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { }

Say ("TCDC credential theft check on {0} at {1}" -f $env:COMPUTERNAME, (Get-Date))
Say ("Read-only. Looking back {0} hours. Domain controller: {1}" -f $Hours, $isDC)

# ---------------------------------------------------------------- LSA
Section 'LSA packages (code that sees passwords)'
$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsa = $null
try { $lsa = Get-ItemProperty -Path $lsaKey -ErrorAction Stop } catch { Say '(could not read the LSA key)' }
if ($lsa) {
    $knownAuth = @('msv1_0')
    $knownSec = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts')
    $knownNotify = @('scecli', 'rassfm')

    $auth = Split-Values $lsa.'Authentication Packages'
    $sec = Split-Values $lsa.'Security Packages'
    $notify = Split-Values $lsa.'Notification Packages'

    Say ("Authentication Packages : {0}" -f ($auth -join ', '))
    Say ("Security Packages       : {0}" -f ($sec -join ', '))
    Say ("Notification Packages   : {0}" -f ($notify -join ', '))

    foreach ($p in $auth) {
        if ($knownAuth -notcontains $p.ToLower()) { Add-Flag "Unusual LSA Authentication Package: $p" }
    }
    foreach ($p in $sec) {
        if ($knownSec -notcontains $p.ToLower()) { Add-Flag "Unusual LSA Security Package: $p" }
    }
    foreach ($p in $notify) {
        if ($knownNotify -notcontains $p.ToLower()) { Add-Flag "Unusual password filter (Notification Package): $p. A password filter sees every password change" }
    }

    # Check the DLL for anything that is not a known default.
    $all = @()
    foreach ($p in $auth) { if ($knownAuth -notcontains $p.ToLower()) { $all += $p } }
    foreach ($p in $sec) { if ($knownSec -notcontains $p.ToLower()) { $all += $p } }
    foreach ($p in $notify) { if ($knownNotify -notcontains $p.ToLower()) { $all += $p } }
    foreach ($name in ($all | Sort-Object -Unique)) {
        $dll = Join-Path $env:SystemRoot ("System32\{0}.dll" -f $name)
        if (Test-Path $dll) {
            $si = Get-SigInfo $dll
            Say ("  {0}: signature {1} {2}" -f $dll, $si.Status, $si.Signer)
            if ($si.Status -ne 'Valid') { Add-Flag "$dll is not validly signed" }
        }
        else {
            Say ("  {0}: file not found in System32" -f $name)
        }
    }

    $ppl = $lsa.RunAsPPL
    Say ("RunAsPPL (LSA protection): {0}" -f $(if ($null -eq $ppl) { 'not set' } else { $ppl }))
    if ($null -ne $ppl -and $ppl -eq 0) { Add-Flag 'LSA protection (RunAsPPL) is explicitly set to 0' }
}

$osc = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'
if (Test-Path $osc) {
    try {
        $o = Get-ItemProperty -Path $osc -ErrorAction Stop
        $osec = Split-Values $o.'Security Packages'
        Say ("OSConfig Security Packages: {0}" -f ($osec -join ', '))
    }
    catch { }
}

Section 'WDigest clear-text password caching'
$wd = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$ulc = $null
try { $ulc = (Get-ItemProperty -Path $wd -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential } catch { }
if ($null -eq $ulc) { Say 'UseLogonCredential not set (modern Windows default is off)' }
else {
    Say ("UseLogonCredential = {0}" -f $ulc)
    if ($ulc -eq 1) { Add-Flag 'WDigest UseLogonCredential is 1: clear-text passwords are kept in memory. Run Harden-Windows-Safe.ps1' }
}

# ---------------------------------------------------- sign-in screen
Section 'Credential providers (code on the sign-in screen)'
$cpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
if (Test-Path $cpKey) {
    foreach ($k in Get-ChildItem $cpKey -ErrorAction SilentlyContinue) {
        $guid = $k.PSChildName
        $label = ''
        try { $label = (Get-ItemProperty -Path $k.PSPath -ErrorAction Stop).'(default)' } catch { }
        $clsid = "HKLM:\SOFTWARE\Classes\CLSID\$guid\InprocServer32"
        $dllPath = ''
        try { $dllPath = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -Path $clsid -ErrorAction Stop).'(default)') } catch { }
        if ($dllPath -and (Test-Path $dllPath)) {
            $si = Get-SigInfo $dllPath
            Say ("{0} {1} -> {2} [{3}]" -f $guid, $label, $dllPath, $si.Status)
            if ($si.Status -ne 'Valid' -or ($si.Signer -and $si.Signer -notmatch 'Microsoft')) {
                Add-Flag "Credential provider $guid uses $dllPath (signature: $($si.Status) $($si.Signer))"
            }
        }
        else {
            Say ("{0} {1} -> {2} (file not found or no path)" -f $guid, $label, $dllPath)
        }
    }
}
else { Say '(credential provider key not found)' }

Section 'Network providers'
$npKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
try {
    $order = Split-Values (Get-ItemProperty -Path $npKey -ErrorAction Stop).ProviderOrder
    Say ("ProviderOrder: {0}" -f ($order -join ', '))
    $knownNP = @('rdpnp', 'lanmanworkstation', 'webclient', 'vmhgfs', 'vboxsf')
    foreach ($p in $order) {
        if ($knownNP -notcontains $p.ToLower()) { Add-Flag "Unusual network provider in the order list: $p" }
    }
}
catch { Say '(could not read network provider order)' }

Section 'Winlogon and AppInit hooks'
$wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
try {
    $wl = Get-ItemProperty -Path $wlKey -ErrorAction Stop
    Say ("Userinit: {0}" -f $wl.Userinit)
    Say ("Shell   : {0}" -f $wl.Shell)
    $ui = ("$($wl.Userinit)").Trim().ToLower()
    $expect1 = (Join-Path $env:SystemRoot 'system32\userinit.exe').ToLower() + ','
    if ($ui -ne $expect1 -and $ui -ne ($expect1.TrimEnd(','))) { Add-Flag "Winlogon Userinit is not the default: $($wl.Userinit)" }
    if (("$($wl.Shell)").Trim().ToLower() -ne 'explorer.exe') { Add-Flag "Winlogon Shell is not explorer.exe: $($wl.Shell)" }
    if ($wl.GinaDLL) { Add-Flag "Winlogon GinaDLL is set: $($wl.GinaDLL)" }
}
catch { Say '(could not read Winlogon key)' }
if (Test-Path "$wlKey\Notify") { Add-Flag 'Winlogon Notify key exists' }

foreach ($ak in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
    try {
        $ai = Get-ItemProperty -Path $ak -ErrorAction Stop
        if ($ai.AppInit_DLLs -and ("$($ai.AppInit_DLLs)").Trim()) {
            Add-Flag "AppInit_DLLs is set in $ak : $($ai.AppInit_DLLs)"
        }
    }
    catch { }
}

# ------------------------------------------------------------ files
Section ("DLL and EXE files written in the last {0} hours in the system folders" -f $Hours)
$anyRecent = $false
foreach ($dir in @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'))) {
    if (-not (Test-Path $dir)) { continue }
    $recent = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
        Where-Object { ($_.Extension -eq '.dll' -or $_.Extension -eq '.exe') -and $_.LastWriteTime -gt $cut } |
        Select-Object -First 40
    foreach ($f in $recent) {
        $anyRecent = $true
        $si = Get-SigInfo $f.FullName
        Say ("{0}  {1}  [{2}]" -f $f.LastWriteTime, $f.FullName, $si.Status)
        if ($si.Status -ne 'Valid') { Add-Flag "Recently written and not validly signed: $($f.FullName)" }
    }
}
if (-not $anyRecent) { Say 'none' }

Section 'Dump files and copied credential stores'
$scanDirs = @('C:\Windows\Temp', 'C:\ProgramData', 'C:\Temp', 'C:\Users', 'C:\PerfLogs')
$dumpHits = @()
foreach ($d in $scanDirs) {
    if (-not (Test-Path $d)) { continue }
    $dumpHits += Get-ChildItem -Path $d -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -gt $cut -and (
                $_.Extension -eq '.dmp' -or $_.Name -ieq 'ntds.dit' -or
                $_.Name -imatch '^(sam|system|security)(\.(hiv|bak|save))?$' -or
                $_.Name -imatch 'lsass|mimikatz|sekurlsa|procdump|ntds')
        }
}
if ($dumpHits.Count -gt 0) {
    $dumpHits | Select-Object -First 30 | ForEach-Object { Say ("{0}  {1}" -f $_.LastWriteTime, $_.FullName) }
    Add-Flag 'Possible credential dump or copied hive files found'
}
else { Say 'none' }

# -------------------------------------------------------- processes
Section 'Processes running credential dumping tools or commands'
$pattern = 'mimikatz|sekurlsa|procdump|comsvcs(\.dll)?.*minidump|minidump|lsass.*\.dmp|rubeus|nanodump|lazagne|keylog|invoke-mimikatz|ntdsutil|secretsdump|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|vssadmin.*create\s+shadow|wmic.*shadowcopy'
$procHits = @()
try {
    $procHits = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ProcessId -ne $PID -and (
            ("$($_.CommandLine)" -imatch $pattern) -or ("$($_.Name)" -imatch 'mimikatz|procdump|rubeus|nanodump|lazagne|keylog'))
    }
}
catch { Say '(could not list processes)' }
if (@($procHits).Count -gt 0) {
    foreach ($p in $procHits) { Say ("pid {0} {1}: {2}" -f $p.ProcessId, $p.Name, $p.CommandLine) }
    Add-Flag 'A running process matches a credential dumping tool or command'
}
else { Say 'none' }

Section 'WSL and OpenSSH server (places red team hides tools)'
$wslHit = $false
foreach ($n in @('wsl', 'wslhost', 'wslservice', 'bash')) {
    if (Get-Process -Name $n -ErrorAction SilentlyContinue) { $wslHit = $true; Say "process running: $n" }
}
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    $wl2 = & wsl.exe -l -v 2>&1
    $wl2 = @($wl2 | ForEach-Object { ("$_" -replace "`0", '').Trim() } | Where-Object { $_ })
    if ($wl2.Count -gt 0) { $wl2 | ForEach-Object { Say "wsl: $_" } }
}
if ($wslHit) { Add-Flag 'WSL related processes are running' }
$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshd) {
    Say ("sshd service: {0} (startup {1})" -f $sshd.Status, $sshd.StartType)
    Add-Flag 'An OpenSSH server (sshd) service exists on this box'
}
else { Say 'no sshd service' }

# ----------------------------------------------------- event logs
Section ("Password resets and changes in the last {0} hours (4723 / 4724)" -f $Hours)
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4723, 4724; StartTime = $cut } -ErrorAction SilentlyContinue
if ($ev) {
    foreach ($e in ($ev | Select-Object -First 40)) {
        $d = Get-EventData $e
        Say ("{0}  id {1}  target {2}  by {3}" -f $e.TimeCreated, $e.Id, $d['TargetUserName'], $d['SubjectUserName'])
    }
    Say ("(total: {0}. Compare with the resets your team did. Anything else is a lead)" -f @($ev).Count)
}
else { Say 'none found (or Security auditing for account management is off)' }

Section ("Failed logons in the last {0} hours (4625), top sources" -f $Hours)
$fails = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $cut } -ErrorAction SilentlyContinue
if ($fails) {
    $rows = foreach ($e in $fails) { $d = Get-EventData $e; [pscustomobject]@{ Ip = $d['IpAddress']; User = $d['TargetUserName'] } }
    $rows | Group-Object Ip | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { Say ("{0,5} failed from {1}" -f $_.Count, $_.Name) }
    $rows | Group-Object User | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { Say ("{0,5} failed for user {1}" -f $_.Count, $_.Name) }
    $big = $rows | Group-Object Ip | Where-Object { $_.Count -ge 50 }
    if ($big) { Add-Flag 'One or more sources have 50 or more failed logons (password guessing)' }
}
else { Say 'none found (or logon failure auditing is off)' }

Section ("Successful network or remote logons from outside 10.0.0.0/8 (4624 types 3 and 10)")
$oks = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $cut } -ErrorAction SilentlyContinue
$outside = @()
if ($oks) {
    foreach ($e in $oks) {
        $d = Get-EventData $e
        if (($d['LogonType'] -eq '3' -or $d['LogonType'] -eq '10') -and -not (Test-Private $d['IpAddress'])) {
            $outside += [pscustomobject]@{ Time = $e.TimeCreated; User = $d['TargetUserName']; Ip = $d['IpAddress']; Type = $d['LogonType'] }
        }
    }
}
if ($outside.Count -gt 0) {
    $outside | Select-Object -First 20 | ForEach-Object { Say ("{0}  {1} from {2} (type {3})" -f $_.Time, $_.User, $_.Ip, $_.Type) }
    Add-Flag 'Successful logons came from addresses outside 10.0.0.0/8'
}
else { Say 'none found' }

Section ("Services installed in the last {0} hours (7045 / 4697)" -f $Hours)
$svc = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $cut } -ErrorAction SilentlyContinue
$svc2 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4697; StartTime = $cut } -ErrorAction SilentlyContinue
$svcCount = 0
foreach ($e in @($svc) + @($svc2)) {
    if (-not $e) { continue }
    $svcCount++
    $d = Get-EventData $e
    Say ("{0}  {1}  {2}" -f $e.TimeCreated, $d['ServiceName'], $d['ImagePath'])
    if (-not $d['ImagePath']) { Say ("   " + (("$($e.Message)" -split "`n")[0])) }
}
if ($svcCount -gt 0) { Add-Flag 'New services were installed. Check each one is yours' }
else { Say 'none found' }

Section ("Suspicious process command lines in the last {0} hours (4688, needs command line auditing)" -f $Hours)
$p4688 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $cut } -ErrorAction SilentlyContinue
$sus = @()
if ($p4688) {
    foreach ($e in $p4688) {
        $d = Get-EventData $e
        if ("$($d['CommandLine'])" -imatch $pattern) { $sus += $e }
    }
}
if ($sus.Count -gt 0) {
    $sus | Select-Object -First 15 | ForEach-Object { $d = Get-EventData $_; Say ("{0}  {1}  {2}" -f $_.TimeCreated, $d['NewProcessName'], $d['CommandLine']) }
    Add-Flag 'Process creation events match credential dumping commands'
}
else { Say 'none found (or process auditing is off)' }

if ($isDC) {
    Section ("Possible DCSync (4662 with replication rights) in the last {0} hours" -f $Hours)
    $rep = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662; StartTime = $cut } -ErrorAction SilentlyContinue
    $dc = @()
    if ($rep) {
        foreach ($e in $rep) {
            $m = "$($e.Message)"
            if ($m -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c') {
                $d = Get-EventData $e
                if ("$($d['SubjectUserName'])" -notmatch '\$$') { $dc += $e }
            }
        }
    }
    if ($dc.Count -gt 0) {
        $dc | Select-Object -First 10 | ForEach-Object { $d = Get-EventData $_; Say ("{0}  by {1}" -f $_.TimeCreated, $d['SubjectUserName']) }
        Add-Flag 'Directory replication rights were used by a non-computer account (DCSync pattern)'
    }
    else { Say 'none found (needs Directory Service Access auditing)' }
}

# ---------------------------------------------------------- network
Section 'Established connections to addresses outside 10.0.0.0/8 and loopback'
$outConns = @()
try {
    $outConns = Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { -not (Test-Private $_.RemoteAddress) }
}
catch { Say '(could not read TCP connections)' }
if (@($outConns).Count -gt 0) {
    foreach ($c in $outConns) {
        $pn = ''
        try { $pn = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { }
        Say ("{0}:{1} -> {2}:{3}  pid {4} {5}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.OwningProcess, $pn)
    }
    Add-Flag 'This box has established connections to outside addresses. Check each one'
}
else { Say 'none' }

# ----------------------------------------------------------- mqtt
Section 'Mosquitto password file (mqtt box)'
$conf = @('C:\Program Files\mosquitto\mosquitto.conf', 'C:\Program Files (x86)\mosquitto\mosquitto.conf') | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($conf) {
    Say ("config: {0}" -f $conf)
    $lines = Get-Content $conf -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
    $lines | Where-Object { $_ -match 'password_file|allow_anonymous|acl_file|listener|per_listener_settings' } | ForEach-Object { Say ("  {0}" -f $_) }
    foreach ($l in $lines) {
        if ($l -match '^\s*password_file\s+(.+)$') {
            $pf = $Matches[1].Trim().Trim('"')
            if (Test-Path $pf) {
                $acl = Get-Acl $pf
                foreach ($a in $acl.Access) {
                    Say ("  {0} {1} {2}" -f $pf, $a.IdentityReference, $a.FileSystemRights)
                    if ("$($a.IdentityReference)" -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and "$($a.FileSystemRights)" -match 'Read|FullControl|Modify') {
                        Add-Flag "Mosquitto password file $pf is readable by $($a.IdentityReference)"
                    }
                }
            }
        }
    }
}
else { Say 'Mosquitto not found on this box' }

# ---------------------------------------------------------- summary
Section 'SUMMARY'
Say ("FLAGS raised: {0}" -f $script:FlagCount)
Say ("Report saved to: {0}" -f $report)
Say 'A flag is a lead, not proof. Nothing was changed on this machine.'

try { Set-Content -Path $report -Value $script:Lines -Encoding UTF8 } catch { Write-Warning "Could not save the report: $($_.Exception.Message)" }
