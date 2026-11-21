<#
.SYNOPSIS
  TCDC blue team: work out which account the scorer logs in with. Run on the domain controller.

.DESCRIPTION
  Read-only. The packet says checks may use credentials and you are not told
  which user. The scorer logs in on a fixed rhythm (a tick every 30 s), so it
  stands out in the DC's Security log: the same user, from the same address,
  again and again.

  This reads recent logon events (4624 success, 4625 failure, 4768 Kerberos
  ticket, 4771 Kerberos pre-auth failure, 4776 NTLM check), groups them by user,
  source, kind and result, and marks the regular ones as LIKELY CHECKER.
  A likely checker that is FAILING means the password on the dashboard does not
  match: fix it at dash.playtcdc.org/team/passwords now.

  Fields are read by name from the event XML, so they are right for every event ID.
  Machine accounts (ending in $) and local logons are left out.

  If nothing shows up, logon auditing may be off. Run Enable-WinAuditing.ps1 -Apply
  from tcdc-blue-toolkit first. A check that only does an anonymous LDAP query
  may not log a user at all.

.EXAMPLE
  .\Find-ScorerAccount.ps1
  .\Find-ScorerAccount.ps1 -Minutes 10
#>
[CmdletBinding()]
param(
    [int]$Minutes = 30,
    [int]$MaxEvents = 20000,
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("scorer-account-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function Out-Line([string]$s, [string]$color = 'Gray') { Write-Host $s -ForegroundColor $color; Add-Content -Path $outFile -Value $s }

$start = (Get-Date).AddMinutes(-$Minutes)
Out-Line "TCDC scorer-account finder  dc=$env:COMPUTERNAME  last $Minutes min  $(Get-Date)" 'White'

try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625, 4768, 4771, 4776; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction Stop)
}
catch {
    Out-Line "No matching logon events in the last $Minutes min ($($_.Exception.Message))." 'Yellow'
    Out-Line 'Logon auditing may be off: run Enable-WinAuditing.ps1 -Apply (tcdc-blue-toolkit), wait a few minutes, then run this again.' 'Yellow'
    exit 0
}
if ($events.Count -ge $MaxEvents) { Out-Line "NOTE: hit the $MaxEvents event cap; use a shorter -Minutes for a complete picture." 'Yellow' }

$rows = foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
    $user = $d['TargetUserName']
    $src = $d['IpAddress']
    if (-not $src -or $src -eq '-') { $src = $d['Workstation'] }
    if ($src) { $src = $src -replace '^::ffff:', '' }
    $status = $d['Status']
    switch ($e.Id) {
        4624 { $kind = "logon type $($d['LogonType'])"; $result = 'success' }
        4625 { $kind = "logon type $($d['LogonType'])"; $result = 'FAILED' }
        4768 { $kind = 'Kerberos ticket'; $result = $(if ($status -eq '0x0') { 'success' } else { 'FAILED' }) }
        4771 { $kind = 'Kerberos pre-auth'; $result = 'FAILED' }
        4776 { $kind = 'NTLM'; $result = $(if ($status -eq '0x0') { 'success' } else { 'FAILED' }) }
    }
    [pscustomobject]@{ Time = $e.TimeCreated; User = $user; Source = $src; Kind = $kind; Result = $result }
}

$rows = @($rows | Where-Object {
        $_.User -and $_.User -notmatch '\$$' -and
        $_.Source -and $_.Source -notin @('127.0.0.1', '::1', '-', 'localhost', $env:COMPUTERNAME)
    })
if ($rows.Count -eq 0) {
    Out-Line 'Only machine-account or local logons found. The scorer may not have logged in to AD in this window, or auditing is off.' 'Yellow'
    exit 0
}

$summary = $rows | Group-Object User, Source, Kind, Result | ForEach-Object {
    $t = @($_.Group | Sort-Object Time | ForEach-Object { $_.Time })
    $gap = $null
    if ($t.Count -gt 1) { $gap = [math]::Round(($t[-1] - $t[0]).TotalSeconds / ($t.Count - 1)) }
    $f = $_.Group[0]
    $likely = ($t.Count -ge 4 -and $gap -ge 15 -and $gap -le 75)
    [pscustomobject]@{
        Hint      = $(if ($likely) { 'LIKELY CHECKER' } else { '' })
        Count     = $t.Count
        AvgGapSec = $gap
        User      = $f.User
        Source    = $f.Source
        Kind      = $f.Kind
        Result    = $f.Result
        Last      = $t[-1].ToString('HH:mm:ss')
    }
} | Sort-Object @{ Expression = { $_.Hint -ne '' }; Descending = $true }, @{ Expression = 'Count'; Descending = $true }

Out-Line ''
Out-Line ($summary | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()

Out-Line ''
foreach ($s in $summary | Where-Object { $_.Hint }) {
    if ($s.Result -eq 'FAILED') {
        Out-Line "FLAG: likely checker $($s.User) from $($s.Source) is FAILING ($($s.Kind)). Make the dashboard password match the real one NOW." 'Red'
    }
    else {
        Out-Line "LIKELY CHECKER: $($s.User) from $($s.Source) ($($s.Kind)) about every $($s.AvgGapSec) s. Mirror every password change for this user." 'Green'
    }
}
if (-not ($summary | Where-Object { $_.Hint })) {
    Out-Line 'No regular pattern yet. Run again after a few more ticks, or use a longer -Minutes.' 'Yellow'
}
Out-Line 'Never change or disable blackteam or whiteteam (R8), even if they show up here.' 'Yellow'
Out-Line "Saved: $outFile" 'White'
