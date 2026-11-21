<#
.SYNOPSIS
  TCDC blue team: back up the settings and data you may need to restore, before you change anything.

.DESCRIPTION
  Read-only on the system; it only copies and exports into a local folder, then zips it.
  Nothing leaves the box (rule R23).

  Collects:
    - Mosquitto folder (config, password and ACL files) if present
    - Windows firewall policy export, local security policy export
    - Run keys, services and scheduled tasks (list and XML export of non-Microsoft tasks)
    - On a domain controller: GPO backup, user and group lists, DNS zone records (if DNS role installed)

.EXAMPLE
  .\Backup-Windows.ps1
#>
[CmdletBinding()]
param([string]$BackupRoot = 'C:\ProgramData\tcdc-backup')

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run from an elevated (Administrator) PowerShell.'
    exit 1
}

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir = Join-Path $BackupRoot ("{0}-{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Backing up to $dir"

$isDC = $false
try { $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { }

# Mosquitto
foreach ($m in 'C:\Program Files\mosquitto', 'C:\Program Files (x86)\mosquitto') {
    if (Test-Path $m) {
        $dest = Join-Path $dir 'mosquitto'
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Get-ChildItem -Path $m -File | Where-Object { $_.Extension -in '.conf', '.txt', '.acl', '' } | Copy-Item -Destination $dest -Force
        Write-Host "  mosquitto files copied from $m"
    }
}

# Firewall and local security policy
& netsh.exe advfirewall export (Join-Path $dir 'firewall.wfw') | Out-Null
& secedit.exe /export /cfg (Join-Path $dir 'secpol.inf') | Out-Null
Write-Host '  firewall policy and local security policy exported'

# Run keys
$regDir = Join-Path $dir 'registry'
New-Item -ItemType Directory -Force -Path $regDir | Out-Null
& reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' (Join-Path $regDir 'HKLM-Run.reg') /y | Out-Null
& reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' (Join-Path $regDir 'HKLM-RunOnce.reg') /y | Out-Null
& reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services' (Join-Path $regDir 'Services.reg') /y | Out-Null

# Services and scheduled tasks
Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName | Export-Csv -Path (Join-Path $dir 'services.csv') -NoTypeInformation
$taskDir = Join-Path $dir 'tasks'
New-Item -ItemType Directory -Force -Path $taskDir | Out-Null
foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
    try {
        $safe = ($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>| ]', '_'
        Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File -FilePath (Join-Path $taskDir "$safe.xml") -Encoding utf8
    }
    catch { }
}
Write-Host '  run keys, services and scheduled tasks exported'

# Domain controller extras
if ($isDC) {
    if (Get-Command Backup-GPO -ErrorAction SilentlyContinue) {
        $gpoDir = Join-Path $dir 'gpo'
        New-Item -ItemType Directory -Force -Path $gpoDir | Out-Null
        Backup-GPO -All -Path $gpoDir | Out-Null
        Write-Host '  GPOs backed up'
    }
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Get-ADUser -Filter * -Properties Enabled, MemberOf, PasswordLastSet, whenCreated, ServicePrincipalName |
            Select-Object SamAccountName, Enabled, PasswordLastSet, whenCreated, @{ n = 'MemberOf'; e = { $_.MemberOf -join ';' } }, @{ n = 'SPN'; e = { $_.ServicePrincipalName -join ';' } } |
            Export-Csv -Path (Join-Path $dir 'ad-users.csv') -NoTypeInformation
        Get-ADGroup -Filter * | Select-Object Name, GroupScope, DistinguishedName | Export-Csv -Path (Join-Path $dir 'ad-groups.csv') -NoTypeInformation
        Write-Host '  AD user and group lists exported'
    }
    if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
        $dnsDir = Join-Path $dir 'dns'
        New-Item -ItemType Directory -Force -Path $dnsDir | Out-Null
        foreach ($z in (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated })) {
            Get-DnsServerResourceRecord -ZoneName $z.ZoneName |
                Select-Object HostName, RecordType, TimeToLive, @{ n = 'Data'; e = { ($_.RecordData | Out-String).Trim() } } |
                Export-Csv -Path (Join-Path $dnsDir ("{0}.csv" -f $z.ZoneName)) -NoTypeInformation
        }
        Write-Host '  DNS zone records exported'
    }
}

$zip = "$dir.zip"
Compress-Archive -Path "$dir\*" -DestinationPath $zip -Force
$hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
"$hash  $zip" | Out-File -FilePath "$zip.sha256" -Encoding ascii
Write-Host ''
Write-Host "Backup written: $zip"
Write-Host "SHA256: $hash"
