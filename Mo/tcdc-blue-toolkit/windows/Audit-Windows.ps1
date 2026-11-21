<#
.SYNOPSIS
  TCDC blue team: read-only Windows audit for the mqtt (Windows 11) and ad (Server 2025) boxes.

.DESCRIPTION
  CHANGES NOTHING. It only reads settings and lists things. It makes no network connections.

  Modes:
    Report    Print findings and save a copy (default)
    Snapshot  Save a baseline of persistence related state
    Diff      Compare current state to the saved baseline (+ new, - gone)

  Suggested use: run Snapshot in the first minutes, then Diff every 15 to 30 minutes.
  Run from an elevated (Administrator) PowerShell. Works on Windows PowerShell 5.1.

.EXAMPLE
  .\Audit-Windows.ps1 -Mode Snapshot
  .\Audit-Windows.ps1 -Mode Diff
  .\Audit-Windows.ps1 -Mode Report -Hours 2
#>
[CmdletBinding()]
param(
    [ValidateSet('Report', 'Snapshot', 'Diff')]
    [string]$Mode = 'Report',
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
$baseFile = Join-Path $OutDir 'baseline.state'

# Run a block, return its output as an array of strings, never throw.
function Invoke-Safe {
    param([scriptblock]$Block)
    try {
        $r = & $Block
        if ($null -eq $r) { return @() }
        return @($r | ForEach-Object { "$_" })
    }
    catch {
        return @("(error: $($_.Exception.Message))")
    }
}

$isDC = $false
try { $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { }
$hasAD = [bool](Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue)

# Stable, comparable state (used by Snapshot, Diff and Report).
function Get-State {
    $s = [ordered]@{}

    $s['Local users'] = Invoke-Safe {
        Get-LocalUser | Sort-Object Name | ForEach-Object { '{0} enabled={1}' -f $_.Name, $_.Enabled }
    }

    $s['Local privileged groups (Administrators, Remote Desktop Users, Backup Operators)'] = Invoke-Safe {
        $map = [ordered]@{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-555' = 'RemoteDesktopUsers'; 'S-1-5-32-551' = 'BackupOperators' }
        foreach ($sid in $map.Keys) {
            Get-LocalGroupMember -SID $sid -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { '{0}: {1}' -f $map[$sid], $_.Name }
        }
    }

    if ($isDC -and $hasAD) {
        $s['Domain privileged groups (recursive)'] = Invoke-Safe {
            $groups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
                      'Server Operators', 'Backup Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Print Operators'
            foreach ($g in $groups) {
                try {
                    Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Sort-Object SamAccountName | ForEach-Object { '{0}: {1}' -f $g, $_.SamAccountName }
                }
                catch { }
            }
        }
        $s['Domain users (name, enabled)'] = Invoke-Safe {
            Get-ADUser -Filter * | Sort-Object SamAccountName | ForEach-Object { '{0} enabled={1}' -f $_.SamAccountName, $_.Enabled }
        }
    }

    $s['Scheduled tasks outside \Microsoft\'] = Invoke-Safe {
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Sort-Object TaskPath, TaskName | ForEach-Object {
            $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
            '{0}{1} user={2} action={3}' -f $_.TaskPath, $_.TaskName, $_.Principal.UserId, $a
        }
    }

    $s['Scheduled tasks (any path) that launch script interpreters'] = Invoke-Safe {
        foreach ($t in (Get-ScheduledTask | Sort-Object TaskPath, TaskName)) {
            $cmd = (@($t.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
            if ($cmd -match '(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)') {
                '{0}{1}  action={2}' -f $t.TaskPath, $t.TaskName, $cmd
            }
        }
    }

    $s['Services outside C:\Windows (name, start mode, account, path)'] = Invoke-Safe {
        Get-CimInstance Win32_Service | Where-Object { $_.PathName -and ($_.PathName -notmatch '^"?[A-Za-z]:\\Windows\\') } |
            Sort-Object Name | ForEach-Object { '{0} start={1} acct={2} path={3}' -f $_.Name, $_.StartMode, $_.StartName, $_.PathName }
    }

    $s['Autorun registry values (Run, RunOnce)'] = Invoke-Safe {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $item = Get-ItemProperty -Path $p
                $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { '{0}\{1} = {2}' -f $p, $_.Name, $_.Value }
            }
        }
    }

    $s['Winlogon Shell/Userinit and Image File Execution Options debuggers'] = Invoke-Safe {
        $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        "Shell = $($w.Shell)"
        "Userinit = $($w.Userinit)"
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
            $d = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { 'IFEO {0} debugger = {1}' -f $_.PSChildName, $d }
        }
    }

    $s['Startup folders'] = Invoke-Safe {
        $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
        foreach ($d in $dirs) {
            if (Test-Path $d) { Get-ChildItem -Path $d -Force -File | ForEach-Object { $_.FullName } }
        }
    }

    $s['WMI event subscriptions (filters, consumers, bindings)'] = Invoke-Safe {
        foreach ($c in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
            Get-CimInstance -Namespace 'root\subscription' -ClassName $c -ErrorAction SilentlyContinue | ForEach-Object {
                '{0}: {1}' -f $c, (($_.PSObject.Properties | Where-Object { $_.Name -in 'Name', 'Query', 'CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'Filter', 'Consumer' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | ')
            }
        }
    }

    $s['Listening TCP ports (address:port process)'] = Invoke-Safe {
        $procs = @{}
        Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
            'tcp {0}:{1} {2}' -f $_.LocalAddress, $_.LocalPort, $procs[[int]$_.OwningProcess]
        } | Sort-Object -Unique
    }

    $s['Enabled inbound ALLOW firewall rules'] = Invoke-Safe {
        Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Sort-Object DisplayName | ForEach-Object { $_.DisplayName }
    }

    $s['Firewall profiles'] = Invoke-Safe {
        Get-NetFirewallProfile | ForEach-Object { '{0} enabled={1} inbound-default={2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction }
    }

    $s['SMB shares and SMB1'] = Invoke-Safe {
        Get-SmbShare | Sort-Object Name | ForEach-Object { 'share {0} -> {1}' -f $_.Name, $_.Path }
        'SMB1 enabled = ' + (Get-SmbServerConfiguration).EnableSMB1Protocol
    }

    $s['RDP settings'] = Invoke-Safe {
        $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        'fDenyTSConnections = ' + $ts.fDenyTSConnections + '   (0 means RDP is ON)'
        $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        'UserAuthentication (NLA) = ' + $rdp.UserAuthentication
    }

    $s['Defender status and exclusions'] = Invoke-Safe {
        $st = Get-MpComputerStatus
        'RealTimeProtection = ' + $st.RealTimeProtectionEnabled
        'AntivirusEnabled = ' + $st.AntivirusEnabled
        $p = Get-MpPreference
        foreach ($x in $p.ExclusionPath) { 'exclude path: ' + $x }
        foreach ($x in $p.ExclusionProcess) { 'exclude process: ' + $x }
        foreach ($x in $p.ExclusionExtension) { 'exclude extension: ' + $x }
    }

    $s['hosts file (hash)'] = Invoke-Safe {
        (Get-FileHash "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash
    }

    $s['Mosquitto config (non-comment lines and file hashes)'] = Invoke-Safe {
        $conf = @('C:\Program Files\mosquitto\mosquitto.conf', 'C:\Program Files (x86)\mosquitto\mosquitto.conf') | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($conf) {
            "conf: $conf"
            Get-Content $conf | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object { "  $_" }
            Get-ChildItem (Split-Path $conf) -File | Where-Object { $_.Extension -in '.conf', '.txt', '.acl', '' } | ForEach-Object {
                '{0} {1}' -f $_.Name, (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            }
        }
        else { '(mosquitto.conf not found in the default locations)' }
    }

    return $s
}

function ConvertTo-StateLines {
    param($State)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $State.Keys) {
        $out.Add("=== $k ===")
        foreach ($l in $State[$k]) { $out.Add($l) }
        $out.Add('')
    }
    return $out
}

function Read-StateFile {
    param([string]$Path)
    $h = [ordered]@{}
    $cur = $null
    foreach ($line in (Get-Content -Path $Path)) {
        if ($line -match '^=== (.+) ===$') { $cur = $Matches[1]; $h[$cur] = New-Object System.Collections.Generic.List[string] }
        elseif ($cur -and $line -ne '') { $h[$cur].Add($line) }
    }
    return $h
}

# Extra volatile checks that are useful in a report but too noisy to diff.
function Get-ReportExtras {
    $out = New-Object System.Collections.Generic.List[string]
    $start = (Get-Date).AddHours(-$Hours)

    $out.Add("=== Interactive sessions now ===")
    foreach ($l in (Invoke-Safe { quser 2>&1 })) { $out.Add($l) }

    $out.Add('')
    $out.Add("=== Established TCP connections (remote, process) ===")
    foreach ($l in (Invoke-Safe {
        $procs = @{}
        Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
        Get-NetTCPConnection -State Established | Sort-Object RemoteAddress | ForEach-Object {
            '{0}:{1} -> {2}:{3} {4}' -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $procs[[int]$_.OwningProcess]
        }
    })) { $out.Add($l) }

    $out.Add('')
    $out.Add("=== Processes running from outside Windows and Program Files ===")
    foreach ($l in (Invoke-Safe {
        Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -notmatch '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\))\\') } |
            ForEach-Object { 'pid={0} {1}' -f $_.ProcessId, $_.ExecutablePath }
    })) { $out.Add($l) }

    $sets = @(
        @{ Log = 'Security'; Ids = @(4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4719, 4697, 4698, 4702, 1102); Label = 'account, group, service, task and audit changes' },
        @{ Log = 'System'; Ids = @(7045, 104); Label = 'new services and cleared logs' },
        @{ Log = 'Microsoft-Windows-WMI-Activity/Operational'; Ids = @(5861); Label = 'WMI event subscriptions' },
        @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141); Label = 'task registered, updated, deleted' }
    )
    foreach ($set in $sets) {
        $out.Add('')
        $out.Add("=== Events in the last $Hours h: $($set.Label) [$($set.Log)] ===")
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $set.Log; Id = $set.Ids; StartTime = $start } -ErrorAction Stop | Select-Object -First 100
            foreach ($e in $ev) { $out.Add(('{0} id={1} {2}' -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $e.Id, ($e.Message -split "`n")[0].Trim())) }
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') { $out.Add('(none)') }
            else { $out.Add("(could not read: $($_.Exception.Message))") }
        }
    }

    $out.Add('')
    $out.Add("=== RDP logons (4624 type 10) in the last $Hours h: time, user, source ===")
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $start } -ErrorAction Stop -MaxEvents 2000 |
            Where-Object { $_.Properties[8].Value -eq 10 } | Select-Object -First 50 | ForEach-Object {
                $out.Add(('{0} {1} from {2}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $_.Properties[5].Value, $_.Properties[18].Value))
            }
    }
    catch { $out.Add('(none or could not read)') }

    $out.Add('')
    $out.Add("=== Failed logons (4625) in the last $Hours h: top 10 account and source ===")
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction Stop -MaxEvents 5000 |
            ForEach-Object { '{0} from {1}' -f $_.Properties[5].Value, $_.Properties[19].Value } |
            Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { $out.Add(('{0,5} x {1}' -f $_.Count, $_.Name)) }
    }
    catch { $out.Add('(none or could not read)') }

    return $out
}

switch ($Mode) {
    'Snapshot' {
        $state = Get-State
        ConvertTo-StateLines -State $state | Out-File -FilePath $baseFile -Encoding utf8
        Write-Host "Baseline saved: $baseFile at $(Get-Date)"
    }
    'Diff' {
        if (-not (Test-Path $baseFile)) {
            Write-Error "No baseline yet. Run: .\Audit-Windows.ps1 -Mode Snapshot"
            exit 1
        }
        $base = Read-StateFile -Path $baseFile
        $now = Get-State
        Write-Host ("Comparing baseline ({0}) to now ({1})" -f (Get-Item $baseFile).LastWriteTime, (Get-Date))
        $changes = 0
        foreach ($k in $now.Keys) {
            $b = @(); if ($base.Contains($k)) { $b = @($base[$k]) }
            $n = @($now[$k] | Where-Object { $_ -ne '' })
            $bset = @{}; foreach ($l in $b) { $bset[$l] = $true }
            $nset = @{}; foreach ($l in $n) { $nset[$l] = $true }
            $lines = New-Object System.Collections.Generic.List[string]
            foreach ($l in $n) { if (-not $bset.ContainsKey($l)) { $lines.Add("+ $l") } }
            foreach ($l in $b) { if (-not $nset.ContainsKey($l)) { $lines.Add("- $l") } }
            if ($lines.Count -gt 0) {
                $changes += $lines.Count
                Write-Host ''
                Write-Host "--- $k" -ForegroundColor Yellow
                foreach ($l in $lines) {
                    if ($l.StartsWith('+')) { Write-Host $l -ForegroundColor Red } else { Write-Host $l -ForegroundColor DarkGray }
                }
            }
        }
        if ($changes -eq 0) { Write-Host 'NO CHANGES since baseline.' -ForegroundColor Green }
        else { Write-Host "`n$changes changed line(s). + is new since baseline, - is gone. Investigate each one." }
    }
    default {
        $outFile = Join-Path $OutDir "report-$stamp.txt"
        $all = New-Object System.Collections.Generic.List[string]
        $all.Add("TCDC Windows audit  host=$env:COMPUTERNAME  time=$(Get-Date)  user=$env:USERNAME  isDC=$isDC")
        $all.Add('')
        foreach ($l in (ConvertTo-StateLines -State (Get-State))) { $all.Add($l) }
        foreach ($l in (Get-ReportExtras)) { $all.Add($l) }
        $all | Tee-Object -FilePath $outFile
        Write-Host "`nSaved: $outFile"
    }
}
