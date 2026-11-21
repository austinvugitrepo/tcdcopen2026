<#
.SYNOPSIS
  TCDC blue team: is the ad box healthy the way the scorer needs it? Run on the domain controller.

.DESCRIPTION
  Read-only unless you add -Apply. Run it first whenever the AD check goes red.

  It checks:
    - core DC services (NTDS, Netlogon, KDC, DNS, W32Time, ADWS, DFSR, Server)
    - the ports an AD check is likely to use (53, 88, 135, 389, 445, 464, 3268)
    - an LDAP query, DNS lookups for the domain and its DC SRV record
    - SYSVOL and NETLOGON shares, dcdiag (advertising, services, sysvol)
    - time sync, free disk space, account lockout policy
    - the 15 packet users: missing, disabled, locked out, password expired,
      account expired, logon hours restricted. Red team uses these as cheap
      denial-of-service tricks against the scored account.

  With -Apply it fixes ONLY these, printing each action and its undo:
    - starts a stopped core DC service (sets a Disabled one back to Automatic first)
    - enables a disabled packet user, unlocks a locked one
    - clears an account expiry date or logon-hours limit on a packet user
  It never changes passwords and never touches blackteam, whiteteam or krbtgt (R8).

  -Users adds more accounts to the user checks (and -Apply fixes), such as the
  service account Find-ScorerAccount.ps1 identifies. blackteam, whiteteam and
  krbtgt are always skipped.

.EXAMPLE
  .\Check-ADHealth.ps1
  .\Check-ADHealth.ps1 -Apply
  .\Check-ADHealth.ps1 -Users svc_scorer -Apply
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string[]]$Users = @(),
    [string]$OutDir = 'C:\ProgramData\tcdc-audit'
)

$ErrorActionPreference = 'Continue'
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error 'ActiveDirectory module not found. Run this on the domain controller (ad).'
    exit 1
}
Import-Module ActiveDirectory

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("ad-health-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:flagCount = 0

function Out-Line([string]$s, [string]$color = 'Gray') { Write-Host $s -ForegroundColor $color; Add-Content -Path $outFile -Value $s }
function Section([string]$t) { Out-Line ''; Out-Line "=== $t ===" 'Cyan' }
function Flag([string]$s) { $script:flagCount++; Out-Line "FLAG: $s" 'Red' }
function Ok([string]$s) { Out-Line "OK:   $s" 'Green' }
function Note([string]$s) { Out-Line "NOTE: $s" 'Yellow' }
function Act([string]$s) { Out-Line "  -> $s" 'Magenta' }

$PacketUsers = @('washington', 'kennedy', 'teddy', 'lincoln', 'ross',
    'streep', 'franklin', 'parks', 'armstrong', 'hamilton',
    'mlk', 'tubman', 'manziel', 'deniro', 'bush')
# Extra accounts to check, e.g. the service account Find-ScorerAccount.ps1 found.
$Never = @('blackteam', 'whiteteam', 'krbtgt')
$CheckUsers = @(@($PacketUsers) + @($Users) | Where-Object { $_ -and $_ -notin $Never } | Select-Object -Unique)

$domain = $null
try { $domain = Get-ADDomain -ErrorAction Stop } catch { }
Out-Line "TCDC AD health  dc=$env:COMPUTERNAME  domain=$($domain.DNSRoot)  apply=$Apply  $(Get-Date)" 'White'

Section 'Core DC services'
$core = 'NTDS', 'Netlogon', 'Kdc', 'DNS', 'W32Time', 'ADWS', 'DFSR', 'LanmanServer'
foreach ($name in $core) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { Note "$name not installed"; continue }
    if ($svc.Status -eq 'Running') { Ok "$name running"; continue }
    Flag "$name is $($svc.Status) (start type $($svc.StartType))"
    if ($Apply) {
        if ($svc.StartType -eq 'Disabled') {
            Set-Service -Name $name -StartupType Automatic
            Act "set $name start type to Automatic   (undo: Set-Service $name -StartupType Disabled)"
        }
        try { Start-Service -Name $name -ErrorAction Stop; Act "started $name" }
        catch { Flag "could not start ${name}: $($_.Exception.Message)" }
    }
}

Section 'Listening ports'
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique)
foreach ($p in 53, 88, 135, 389, 445, 464, 3268) {
    if ($listen -contains $p) { Ok "port $p listening" } else { Flag "port $p is NOT listening" }
}
if ($listen -contains 636) { Ok 'port 636 (LDAPS) listening' } else { Note 'port 636 (LDAPS) not listening (normal without a certificate)' }

Section 'LDAP and DNS answers'
try {
    $root = [ADSI]'LDAP://localhost/RootDSE'
    $nc = $root.Properties['defaultNamingContext'][0]
    if ($nc) { Ok "LDAP RootDSE answers: $nc" } else { Flag 'LDAP RootDSE returned nothing' }
}
catch { Flag "LDAP query to localhost failed: $($_.Exception.Message)" }
if ($domain) {
    Ok "Get-ADDomain works (AD Web Services up): $($domain.DNSRoot)"
    foreach ($q in @(@{N = $domain.DNSRoot; T = 'A' }, @{N = "_ldap._tcp.dc._msdcs.$($domain.DNSRoot)"; T = 'SRV' })) {
        try {
            $r = Resolve-DnsName -Name $q.N -Type $q.T -Server 127.0.0.1 -DnsOnly -ErrorAction Stop
            Ok "$($q.T) $($q.N) resolves ($(@($r).Count) answers)"
        }
        catch { Flag "$($q.T) $($q.N) does NOT resolve on this DC: $($_.Exception.Message)" }
    }
}
else { Flag 'Get-ADDomain failed. AD Web Services (ADWS) or NTDS may be down' }
$dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } |
    ForEach-Object { $_.ServerAddresses }) -join ', '
Note "this DC asks these DNS servers: $dnsServers. If ns1 is one of them, an ns1 outage can break AD too"

Section 'Shares and dcdiag'
foreach ($s in 'SYSVOL', 'NETLOGON') {
    if (Get-SmbShare -Name $s -ErrorAction SilentlyContinue) { Ok "$s share present" } else { Flag "$s share missing (logons and Group Policy break)" }
}
$dc = & dcdiag /test:advertising /test:services /test:sysvolcheck /q 2>&1
if (-not $dc) { Ok 'dcdiag advertising/services/sysvolcheck passed' }
else { Flag 'dcdiag reported problems:'; $dc | ForEach-Object { Out-Line "  $_" } }

Section 'Time and disk'
$w = & w32tm /query /status 2>&1
($w | Select-String -Pattern 'Source:|Last Successful Sync Time:|Stratum:') | ForEach-Object { Out-Line "  $($_.Line.Trim())" }
Note 'Kerberos fails when clocks differ by more than 5 minutes. Compare with the time on another box if logons fail.'
$c = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($c) {
    $freeGb = [math]::Round($c.Free / 1GB, 1)
    if ($freeGb -lt 2) { Flag "only $freeGb GB free on C: (log flooding can fill the disk and stop AD)" } else { Ok "$freeGb GB free on C:" }
}

Section 'Lockout policy'
$pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
if ($pol) {
    Out-Line "  threshold=$($pol.LockoutThreshold) duration=$($pol.LockoutDuration) window=$($pol.LockoutObservationWindow)"
    if ($pol.LockoutThreshold -gt 0) {
        Note 'lockout is on: anyone can lock out the scored account by guessing wrong passwords. Decide as a team; unlock with -Apply if it happens.'
    }
}
$fg = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue)
if ($fg.Count -gt 0) { Note "fine-grained password policies exist: $(($fg | ForEach-Object Name) -join ', '). Check who they apply to." }

Section 'Packet users and -Users accounts (rule R8: never delete them)'
foreach ($u in $CheckUsers) {
    $a = Get-ADUser -Filter "SamAccountName -eq '$u'" -Properties Enabled, LockedOut, PasswordExpired, AccountExpirationDate, logonHours -ErrorAction SilentlyContinue
    if (-not $a) { Flag "$u is MISSING. Tell Black Team if it was deleted; do not recreate it blindly"; continue }
    $issues = @()
    if (-not $a.Enabled) { $issues += 'disabled' }
    if ($a.LockedOut) { $issues += 'locked out' }
    if ($a.PasswordExpired) { $issues += 'password expired' }
    $expired = $a.AccountExpirationDate -and $a.AccountExpirationDate -lt (Get-Date)
    if ($expired) { $issues += "account expired $($a.AccountExpirationDate)" }
    $hoursLimited = $a.logonHours -and (@($a.logonHours | Where-Object { $_ -ne 255 }).Count -gt 0)
    if ($hoursLimited) { $issues += 'logon hours restricted' }
    if ($issues.Count -eq 0) { Ok "$u fine"; continue }
    Flag "$u : $($issues -join ', ')"
    if ($a.PasswordExpired) {
        Out-Line "  fix by hand (no password change): Set-ADUser $u -Replace @{pwdLastSet=0}; Set-ADUser $u -Replace @{pwdLastSet=-1}"
    }
    if ($Apply) {
        if (-not $a.Enabled) { Enable-ADAccount -Identity $u; Act "enabled $u   (undo: Disable-ADAccount $u)" }
        if ($a.LockedOut) { Unlock-ADAccount -Identity $u; Act "unlocked $u" }
        if ($expired) { Clear-ADAccountExpiration -Identity $u; Act "cleared account expiry on $u" }
        if ($hoursLimited) { Set-ADUser -Identity $u -Clear logonHours; Act "cleared logon-hours limit on $u" }
    }
}

Out-Line ''
Out-Line "Done. $($script:flagCount) FLAG line(s). Saved: $outFile" 'White'
if ($Apply) { Out-Line 'After any fix: wait 60 s (2 ticks) and check the scoreboard.' 'White' }
