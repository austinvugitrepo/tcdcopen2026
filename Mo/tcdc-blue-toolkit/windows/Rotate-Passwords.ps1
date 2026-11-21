<#
.SYNOPSIS
  TCDC blue team: rotate OS user passwords one at a time, safely.

.DESCRIPTION
  Dry run by default (lists who would change). With -Apply it changes ONE user,
  prints the new password, then WAITS for you to update the TCDC dashboard
  (https://dash.playtcdc.org/team/passwords) and confirm the scoreboard is
  still green before it moves to the next user.

  Scope:
    -Scope Local    local accounts (use this on the mqtt box)
    -Scope Domain   Active Directory accounts (use this on the ad box)

  Never touches: blackteam, whiteteam (rule R8), krbtgt. Never deletes, disables or locks anyone.
  Only users in the packet list (or the ones you pass with -Users) are considered,
  and only if they exist.

  New passwords are saved to a file readable only by Administrators and SYSTEM, so the
  captain can record them. Keep that file out of any git repo.

.EXAMPLE
  .\Rotate-Passwords.ps1 -Scope Domain                       # dry run on ad
  .\Rotate-Passwords.ps1 -Scope Domain -Apply                # rotate one at a time
  .\Rotate-Passwords.ps1 -Scope Local -Apply -Users washington,kennedy
  .\Rotate-Passwords.ps1 -Scope Local -Apply -NoWait
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Local', 'Domain')]
    [string]$Scope,
    [switch]$Apply,
    [switch]$NoWait,
    [string[]]$Users = @('washington', 'kennedy', 'teddy', 'lincoln', 'ross', 'streep', 'franklin', 'parks', 'armstrong', 'hamilton', 'mlk', 'tubman', 'manziel', 'deniro', 'bush'),
    [int]$Length = 20,
    [string]$OutDir = 'C:\ProgramData\tcdc-pw'
)

$never = @('blackteam', 'whiteteam', 'krbtgt')

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function Get-RandomIndex {
    param([int]$Max)
    $bytes = New-Object byte[] 4
    $rng.GetBytes($bytes)
    $v = [BitConverter]::ToUInt32($bytes, 0)
    return [int]($v % $Max)
}

# Random password with upper, lower, digit and a few safe symbols (no quotes, spaces or colons).
function New-RandomPassword {
    param([int]$Len = 20)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '@%+=_-')
    $all = ($sets -join '')
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $chars.Add($s[(Get-RandomIndex -Max $s.Length)]) }
    while ($chars.Count -lt $Len) { $chars.Add($all[(Get-RandomIndex -Max $all.Length)]) }
    # Fisher-Yates shuffle so the guaranteed characters are not always first.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomIndex -Max ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return (-join $chars)
}

function Test-UserExists {
    param([string]$Name)
    try {
        if ($Scope -eq 'Domain') { $null = Get-ADUser -Identity $Name -ErrorAction Stop }
        else { $null = Get-LocalUser -Name $Name -ErrorAction Stop }
        return $true
    }
    catch { return $false }
}

if ($Scope -eq 'Domain') {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'ActiveDirectory module not found. Use -Scope Domain only on the domain controller.'
        exit 1
    }
    Import-Module ActiveDirectory
}

$plan = New-Object System.Collections.Generic.List[string]
foreach ($u in $Users) {
    if ($never -contains $u.ToLower()) { Write-Host "SKIP $u (protected)"; continue }
    if (-not (Test-UserExists -Name $u)) { Write-Host "skip $u (not found in $Scope scope)"; continue }
    $plan.Add($u)
}

Write-Host ''
Write-Host ("Users to rotate on {0} ({1}): {2}" -f $env:COMPUTERNAME, $Scope, ($plan -join ', '))
if (-not $Apply) {
    Write-Host 'DRY RUN. Re-run with -Apply. Nothing was changed.'
    return
}
if ($plan.Count -eq 0) { return }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("passwords-{0}-{1}.txt" -f $env:COMPUTERNAME, $Scope)
if (-not (Test-Path $outFile)) { New-Item -ItemType File -Path $outFile | Out-Null }
# Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18) only.
& icacls.exe $outFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
Write-Host "Passwords will be appended to: $outFile"
Write-Host 'Keep a second admin session or console open. Do not lock yourself out.'
Write-Host ''

foreach ($u in $plan) {
    $pw = New-RandomPassword -Len $Length
    $secure = ConvertTo-SecureString -String $pw -AsPlainText -Force
    try {
        if ($Scope -eq 'Domain') { Set-ADAccountPassword -Identity $u -Reset -NewPassword $secure -ErrorAction Stop }
        else { Set-LocalUser -Name $u -Password $secure -ErrorAction Stop }
        Add-Content -Path $outFile -Value ("{0} {1} {2} {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $u, $pw)
        Write-Host "CHANGED  $u  ->  $pw" -ForegroundColor Green
        if (-not $NoWait) {
            Write-Host '  1) Update the dashboard password page if this user could be used by a check.'
            Write-Host '  2) Confirm the scoreboard is green for 2 ticks (60 s).'
            $ans = Read-Host '  Press Enter for the next user, or type q to stop'
            if ($ans -eq 'q') { Write-Host 'Stopped by user.'; break }
        }
    }
    catch {
        Write-Host "FAILED to change $u : $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host "Done. Record passwords from $outFile somewhere your team controls, then protect or remove the file."
