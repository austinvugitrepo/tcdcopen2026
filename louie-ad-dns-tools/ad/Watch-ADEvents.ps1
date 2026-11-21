<#
.SYNOPSIS
  TCDC blue team: live alerts for attacks on the domain controller. Leave it running on the ad box.

.DESCRIPTION
  Read-only. Every few seconds it reads new events from the Security, System and
  Defender logs and prints one line per event that matters, with who did it:

    accounts   4720 created, 4722 enabled, 4725 disabled, 4726 deleted,
               4724 password reset by someone else, 4738 changed, 4740 locked out,
               4781 renamed
    groups     4728/4732/4756 member added, 4729/4733/4757 member removed
               (privileged groups are shown in red)
    directory  5136 object changed (GPOs, ACLs, delegation), 4662 replication
               rights used by a non-DC account (DCSync)
    host       4698/4702 scheduled task created/changed, 7045 service installed,
               4719 audit policy changed, 1102/104 log CLEARED
    Defender   1116/1117 detection, 5001 real-time protection off, 5007 settings changed
    sprays     5 or more failed logons (4625/4771) for one account inside one
               minute, and 10 or more accounts failing from one address

  It also prints a heartbeat line every 5 minutes so you know it is alive.

  Many of these events only exist if auditing is on. Run Enable-WinAuditing.ps1
  -Apply from tcdc-blue-toolkit first. Directory changes (5136) and DCSync (4662)
  need "Directory Service Changes" and "Directory Service Access" auditing.

  Stop it (Ctrl+C) before hands-off periods (rule R10).

.EXAMPLE
  .\Watch-ADEvents.ps1
  .\Watch-ADEvents.ps1 -Interval 10 -IgnoreUser svc_backup
#>
[CmdletBinding()]
param(
    [int]$Interval = 15,
    [string[]]$IgnoreUser = @(),
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logFile = Join-Path $OutDir ("ad-events-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

$privGroups = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators|DnsAdmins|Group Policy Creator Owners|Print Operators|Remote Desktop Users|Remote Management Users'
$replGuids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'

function Alert([datetime]$t, [string]$sev, [string]$msg) {
    $color = switch ($sev) { 'HIGH' { 'Red' } 'MED' { 'Yellow' } default { 'Gray' } }
    $line = '{0:HH:mm:ss} {1,-4} {2}' -f $t, $sev, $msg
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line
}
function Get-Data($e) {
    $d = @{}
    foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
    $d
}

$secIds = 4720, 4722, 4724, 4725, 4726, 4738, 4740, 4781, 4728, 4729, 4732, 4733, 4756, 4757, 5136, 4662, 4698, 4702, 4719, 1102, 4625, 4771
$sysIds = 7045, 104
$defIds = 1116, 1117, 5001, 5007
$since = Get-Date
$lastBeat = Get-Date
$fails = New-Object System.Collections.Generic.List[object]
$alerted = @{}

Write-Host "Watching the ad box every $Interval s. Log: $logFile. Ctrl+C to stop. Stop before hands-off periods (R10)." -ForegroundColor White
if (-not (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue)) { Write-Host 'Cannot read the Security log. Run PowerShell as Administrator.' -ForegroundColor Red; exit 1 }

while ($true) {
    $now = Get-Date
    $events = @()
    $events += @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $secIds; StartTime = $since } -ErrorAction SilentlyContinue)
    $events += @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $sysIds; StartTime = $since } -ErrorAction SilentlyContinue)
    $events += @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $defIds; StartTime = $since } -ErrorAction SilentlyContinue)
    $since = $now

    foreach ($e in ($events | Sort-Object TimeCreated)) {
        $d = Get-Data $e
        $by = $d['SubjectUserName']
        $target = $d['TargetUserName']
        if ($by -and $IgnoreUser -contains $by) { continue }
        $t = $e.TimeCreated
        switch ($e.Id) {
            4720 { Alert $t 'HIGH' "USER CREATED: $target by $by" }
            4722 { Alert $t 'MED' "user enabled: $target by $by" }
            4725 { Alert $t 'HIGH' "USER DISABLED: $target by $by (packet users must stay; Check-ADHealth.ps1 -Apply re-enables)" }
            4726 { Alert $t 'HIGH' "USER DELETED: $target by $by (rule R8: tell Black Team; restore from the Recycle Bin if it is on)" }
            4724 { if ($by -ne $target) { Alert $t 'MED' "password reset: $target by $by (mirror it on the dashboard if it was you)" } }
            4738 { if ($d['UserAccountControl'] -and $d['UserAccountControl'] -ne '-') { Alert $t 'MED' "account flags changed: $target by $by -> $($d['UserAccountControl'])" } }
            4740 { Alert $t 'HIGH' "LOCKED OUT: $target (from $($d['TargetDomainName'])). Unlock: Unlock-ADAccount $target" }
            4781 { Alert $t 'HIGH' "ACCOUNT RENAMED: $($d['OldTargetUserName']) -> $($d['NewTargetUserName']) by $by" }
            { $_ -in 4728, 4732, 4756 } {
                $sev = $(if ($target -match $privGroups) { 'HIGH' } else { 'MED' })
                Alert $t $sev "added to group '$target': $($d['MemberName']) by $by"
            }
            { $_ -in 4729, 4733, 4757 } { Alert $t 'MED' "removed from group '$target': $($d['MemberName']) by $by" }
            5136 {
                $obj = $d['ObjectDN']; $attr = $d['AttributeLDAPDisplayName']
                $sev = $(if ($attr -match 'nTSecurityDescriptor|msDS-AllowedToActOnBehalfOfOtherIdentity|msDS-KeyCredentialLink|servicePrincipalName|gPCFileSysPath|gPLink|scriptPath|sIDHistory|member|userAccountControl') { 'HIGH' } else { 'MED' })
                Alert $t $sev "directory change: $attr on $obj by $by ($($d['OperationType']))"
            }
            4662 {
                if ($d['Properties'] -match $replGuids -and $by -notmatch '\$$') { Alert $t 'HIGH' "DCSYNC: replication rights used by $by (a user, not a DC). Likely password-hash theft" }
            }
            4698 { Alert $t 'HIGH' "SCHEDULED TASK CREATED: $($d['TaskName']) by $by" }
            4702 { Alert $t 'MED' "scheduled task changed: $($d['TaskName']) by $by" }
            4719 { Alert $t 'HIGH' "AUDIT POLICY CHANGED by $by (someone may be hiding their tracks)" }
            1102 { Alert $t 'HIGH' "SECURITY LOG CLEARED by $($d['SubjectUserName'])" }
            104 { Alert $t 'HIGH' "an event log was CLEARED (System log event 104)" }
            7045 { Alert $t 'HIGH' "SERVICE INSTALLED: $($d['ServiceName']) -> $($d['ImagePath']) as $($d['AccountName'])" }
            1116 { Alert $t 'HIGH' "DEFENDER DETECTION: $($d['Threat Name']) $($d['Path'])" }
            1117 { Alert $t 'MED' "Defender acted on: $($d['Threat Name']) action=$($d['Action Name'])" }
            5001 { Alert $t 'HIGH' 'DEFENDER REAL-TIME PROTECTION TURNED OFF. Fix: .\Harden-DC.ps1 -Apply -Fix Defender' }
            5007 { Alert $t 'MED' "Defender settings changed: $((($e.Message -split "`n") | Select-String 'New value' | Select-Object -First 1).Line)" }
            { $_ -in 4625, 4771 } {
                $src = $d['IpAddress'] -replace '^::ffff:', ''
                $fails.Add([pscustomobject]@{ Time = $t; User = $target; Src = $src })
            }
        }
    }

    # Password spray and brute force: rolling 60-second window, one alert per
    # account or source per minute.
    $cut = $now.AddSeconds(-60)
    $recent = @($fails | Where-Object { $_.Time -ge $cut })
    $fails = New-Object System.Collections.Generic.List[object]
    foreach ($r in $recent) { $fails.Add($r) }
    foreach ($k in @($alerted.Keys)) { if ($alerted[$k] -lt $cut) { $alerted.Remove($k) } }
    foreach ($g in ($recent | Group-Object User | Where-Object { $_.Count -ge 5 })) {
        if ($alerted.ContainsKey("u:$($g.Name)")) { continue }
        $alerted["u:$($g.Name)"] = $now
        Alert $now 'HIGH' "BRUTE FORCE: $($g.Count) failed logons for '$($g.Name)' in 60 s from $((($g.Group | ForEach-Object Src) | Select-Object -Unique) -join ', '). Lockout risk for the scored account"
    }
    foreach ($g in ($recent | Group-Object Src | Where-Object { $_.Name -and (@($_.Group | ForEach-Object User | Select-Object -Unique).Count -ge 10) })) {
        if ($alerted.ContainsKey("s:$($g.Name)")) { continue }
        $alerted["s:$($g.Name)"] = $now
        Alert $now 'HIGH' "PASSWORD SPRAY from $($g.Name): $(@($g.Group | ForEach-Object User | Select-Object -Unique).Count) accounts failing in 60 s"
    }

    if (($now - $lastBeat).TotalMinutes -ge 5) { Write-Host ('{0:HH:mm:ss} .... still watching' -f $now) -ForegroundColor DarkGray; $lastBeat = $now }
    Start-Sleep -Seconds $Interval
}
