<#
.SYNOPSIS
  TCDC blue team: read-only Active Directory audit. Run on the ad box (domain controller).

.DESCRIPTION
  CHANGES NOTHING. It only queries AD and prints findings with a short "why it matters" note.
  Needs the ActiveDirectory module (present on a domain controller). Run as a domain admin.

  What it looks for:
    - Kerberoastable accounts (user accounts with SPNs)
    - AS-REP roastable accounts (no Kerberos pre-authentication)
    - Delegation set up on accounts or computers
    - Weak account flags (password not required, reversible encryption)
    - Members of privileged groups, including nested members
    - Who holds DCSync style replication rights on the domain
    - Dangerous permissions on the domain root object
    - Accounts created or changed recently
    - GPOs changed recently, krbtgt age, Guest account state
  Fixes are NOT applied. Decide with your team, change one thing at a time, and
  watch the scoreboard (see the playbook).

.EXAMPLE
  .\Audit-AD.ps1
  .\Audit-AD.ps1 -Hours 2
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
$outFile = Join-Path $OutDir ("ad-audit-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$since = (Get-Date).AddHours(-$Hours)
$lines = New-Object System.Collections.Generic.List[string]

function Add-Section {
    param([string]$Title, [string]$Why, [scriptblock]$Block)
    $lines.Add('')
    $lines.Add("=== $Title ===")
    $lines.Add("why: $Why")
    try {
        $r = @(& $Block)
        if ($r.Count -eq 0) { $lines.Add('(none)') }
        else { foreach ($x in $r) { $lines.Add("$x") } }
    }
    catch { $lines.Add("(error: $($_.Exception.Message))") }
}

$domain = Get-ADDomain
$lines.Add("TCDC AD audit  domain=$($domain.DNSRoot)  dc=$env:COMPUTERNAME  time=$(Get-Date)")

Add-Section 'Accounts with SPNs (Kerberoastable)' 'Any domain user can request tickets for these and crack the password offline. Needs long random passwords, or remove unused SPNs.' {
    Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName, PasswordLastSet, Enabled |
        Where-Object { $_.SamAccountName -ne 'krbtgt' } |
        ForEach-Object { '{0} enabled={1} pwdLastSet={2} spn={3}' -f $_.SamAccountName, $_.Enabled, $_.PasswordLastSet, ($_.ServicePrincipalName -join ',') }
}

Add-Section 'Accounts with Kerberos pre-authentication disabled (AS-REP roastable)' 'Attackers can get crackable data for these without any password. There is almost never a good reason for this flag.' {
    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, Enabled |
        ForEach-Object { '{0} enabled={1}' -f $_.SamAccountName, $_.Enabled }
}

Add-Section 'Unconstrained or constrained delegation' 'Delegation lets an account impersonate users to other services. Unexpected delegation is a common takeover path.' {
    Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation | ForEach-Object { 'USER unconstrained: ' + $_.SamAccountName }
    Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation | Where-Object { $_.DistinguishedName -notlike "*OU=Domain Controllers*" } | ForEach-Object { 'COMPUTER unconstrained: ' + $_.Name }
    Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties 'msDS-AllowedToDelegateTo' | ForEach-Object { 'constrained: {0} -> {1}' -f $_.Name, ($_.'msDS-AllowedToDelegateTo' -join ',') }
}

Add-Section 'Weak account flags (password not required, reversible encryption, never expires)' 'Password-not-required accounts can have empty passwords. Reversible encryption stores recoverable passwords.' {
    Get-ADUser -Filter 'PasswordNotRequired -eq $true' | ForEach-Object { 'PasswordNotRequired: ' + $_.SamAccountName }
    Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' | ForEach-Object { 'ReversibleEncryption: ' + $_.SamAccountName }
}

Add-Section 'Privileged group members (recursive)' 'Anyone here can control the domain or a DC. Every name should be explainable. Do NOT delete the competition users listed in the packet (rule R8).' {
    $groups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Backup Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Print Operators'
    foreach ($g in $groups) {
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Sort-Object SamAccountName | ForEach-Object { '{0}: {1}' -f $g, $_.SamAccountName }
        }
        catch { }
    }
}

Add-Section 'Accounts with adminCount=1' 'Accounts that are, or once were, in protected groups. Old leftovers can keep odd permissions.' {
    Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount | Sort-Object SamAccountName | ForEach-Object { $_.SamAccountName }
}

Add-Section 'Replication rights on the domain root (DCSync)' 'Anyone with Get-Changes and Get-Changes-All can pull every password hash. Only Domain Controllers, Enterprise DCs and Domain/Enterprise Admins normally have this.' {
    $acl = Get-Acl -Path ('AD:\' + $domain.DistinguishedName)
    $g = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    }
    $acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $g.ContainsKey($_.ObjectType.ToString()) } |
        ForEach-Object { '{0} : {1}' -f $_.IdentityReference, $g[$_.ObjectType.ToString()] }
}

Add-Section 'Powerful rights on the domain root for unexpected identities' 'GenericAll, WriteDacl or WriteOwner on the domain object lets someone grant themselves anything.' {
    $acl = Get-Acl -Path ('AD:\' + $domain.DistinguishedName)
    $expected = 'NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|\\Domain Admins|\\Enterprise Admins|\\Administrators$|CREATOR OWNER'
    $acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        ($_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|WriteOwner') -and
        ($_.IdentityReference.ToString() -notmatch $expected)
    } | ForEach-Object { '{0} : {1}' -f $_.IdentityReference, $_.ActiveDirectoryRights }
}

Add-Section "Users and groups created or changed in the last $Hours h" 'New or modified accounts and group changes are the first sign of persistence. Compare with what your team did.' {
    Get-ADUser -Filter * -Properties whenCreated, whenChanged | Where-Object { $_.whenChanged -ge $since } |
        Sort-Object whenChanged -Descending | ForEach-Object { 'user {0} created={1} changed={2}' -f $_.SamAccountName, $_.whenCreated, $_.whenChanged }
    Get-ADGroup -Filter * -Properties whenChanged | Where-Object { $_.whenChanged -ge $since } |
        Sort-Object whenChanged -Descending | ForEach-Object { 'group {0} changed={1}' -f $_.Name, $_.whenChanged }
}

Add-Section "GPOs modified in the last $Hours h" 'A changed GPO can push scheduled tasks, scripts or settings to every machine.' {
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        Get-GPO -All | Where-Object { $_.ModificationTime -ge $since } | Sort-Object ModificationTime -Descending |
            ForEach-Object { '{0} modified={1}' -f $_.DisplayName, $_.ModificationTime }
    }
    else { '(GroupPolicy module not available)' }
}

Add-Section 'krbtgt, Guest and default domain password policy' 'Old krbtgt password means old forged tickets can still work. Guest should be disabled.' {
    $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
    'krbtgt pwdLastSet = ' + $k.PasswordLastSet
    $gst = Get-ADUser -Identity Guest -Properties Enabled
    'Guest enabled = ' + $gst.Enabled
    $p = Get-ADDefaultDomainPasswordPolicy
    'minLen={0} complexity={1} lockoutThreshold={2} reversible={3}' -f $p.MinPasswordLength, $p.ComplexityEnabled, $p.LockoutThreshold, $p.ReversibleEncryptionEnabled
}

$lines | Tee-Object -FilePath $outFile
Write-Host "`nSaved: $outFile"
