<#
.SYNOPSIS
  TCDC blue team: reset the krbtgt password to kill golden tickets. Run on the ad box.

.DESCRIPTION
  If red team ever had Domain Admin or DCSync, they may hold the krbtgt hash and
  can forge "golden tickets" that log in as anyone, even after you change every
  other password. Resetting krbtgt TWICE makes those tickets useless (AD keeps the
  current and the previous key, so one reset is not enough).

  Without -Apply it only shows the krbtgt state. With -Apply it resets the password
  ONCE to a long random value (nobody needs to know it; it is not a login account)
  and confirms the key version went up. Run it again for the second reset.

  Side effect: after the second reset every existing Kerberos ticket stops working,
  so users and services have to log in again. Services that log in fresh each time
  (like a scorer) recover by themselves. Do it when the scoreboard is green, then
  watch it for 2 ticks after each reset.

  A second reset within 10 minutes of the first needs -Force, so it is never done
  by accident. With more than one DC, wait for replication between resets
  (repadmin /syncall /AdeP); the TCDC topology has one DC.

  This changes no other account and never touches blackteam or whiteteam (R8).
  krbtgt is not used by the scorer and is not on the password dashboard.

.EXAMPLE
  .\Reset-Krbtgt.ps1            # show state only
  .\Reset-Krbtgt.ps1 -Apply     # first reset
  .\Reset-Krbtgt.ps1 -Apply     # second reset (add -Force if under 10 minutes later)
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Force,
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logFile = Join-Path $OutDir 'krbtgt-resets.log'
function Out-Line([string]$s, [string]$color = 'Gray') { Write-Host $s -ForegroundColor $color; Add-Content -Path $logFile -Value ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $s) }

$k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber'
$dcs = @(Get-ADDomainController -Filter *)
$age = (Get-Date) - $k.PasswordLastSet
Out-Line ("krbtgt PasswordLastSet={0}  ({1:N0} min ago)  keyVersion={2}  domain controllers={3}" -f $k.PasswordLastSet, $age.TotalMinutes, $k.'msDS-KeyVersionNumber', $dcs.Count) 'White'
if ($age.TotalDays -gt 1) { Out-Line 'Not reset during this event. If red team may have had Domain Admin or DCSync, reset it twice.' 'Yellow' }

if (-not $Apply) {
    Out-Line 'Read-only run. Add -Apply to reset once.' 'White'
    exit 0
}
if ($age.TotalMinutes -lt 10 -and -not $Force) {
    Out-Line ("The last reset was {0:N0} minutes ago. A second reset now ends every existing Kerberos ticket right away. Check the scoreboard is green, then run again with -Apply -Force." -f $age.TotalMinutes) 'Yellow'
    exit 2
}
if ($dcs.Count -gt 1) { Out-Line "There are $($dcs.Count) DCs: wait for replication between the two resets (repadmin /syncall /AdeP)." 'Yellow' }

# 64 random characters from a cryptographic generator.
$chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%^*-_=+'
$bytes = New-Object byte[] 64
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$pw = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
$secure = ConvertTo-SecureString $pw -AsPlainText -Force
$pw = $null

$before = $k.'msDS-KeyVersionNumber'
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $secure
$after = (Get-ADUser -Identity krbtgt -Properties 'msDS-KeyVersionNumber').'msDS-KeyVersionNumber'
if ($after -gt $before) {
    Out-Line "krbtgt reset done. keyVersion $before -> $after." 'Green'
}
else {
    Out-Line "Reset ran but keyVersion did not change ($before -> $after). Check the domain controller." 'Red'
    exit 1
}
Out-Line 'Wait 60 s (2 ticks) and check the scoreboard. Run again with -Apply for the second reset (add -Force within 10 minutes).' 'White'
