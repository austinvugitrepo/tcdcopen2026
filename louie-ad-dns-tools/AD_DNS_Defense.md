# AD + DNS Defense — Master Reference (TCDC Open 2026)

Single source of truth for defending `ad` and `ns1`. Pairs with the scripts `defend-ad.ps1` (audit by default, `-Apply` to change) and `defend-dns.sh`. Team scope, rules, offense, store, and roles live in `TCDC_Open_26_Gameplan.md`.

**Boxes:** `ad` (Win Server 2025, 10.(100+X).20.88) · `ns1` (Ubuntu 26.04, 10.(100+X).10.53). Swap `X` for your team ID.

### The rules that bite
- **Mirror every password change** at `dash.playtcdc.org/team/passwords` or the service reads as down.
- **Never delete/disable** the 15 required users or `blackteam`/`whiteteam` (R7/R8).
- **One change, one verify** — check the scoreboard / functional test after every change. A broken scored service costs the same as a breach.
- Required admins: washington, kennedy, teddy, lincoln, ross. Employees: streep, franklin, parks, armstrong, hamilton, mlk, tubman, manziel, deniro, bush.

### Order of operations
1. **Audit first** (run scripts with no `-Apply`) — capture baseline, list findings, change nothing.
2. **Snapshot** both boxes (store) — your rollback point.
3. **Identify the scorer's account** (see "Scorer discovery" below) — before rotating passwords blindly.
4. **AD, highest value first:** Zerologon → priv-group drift → delegation → Kerberoasting/AS-REP → persistence → host hardening → credential protection.
5. **DNS:** close AXFR → restrict recursion → hide version → lock perms.
6. **Verify scorer green after each change.** Re-sweep every 20–45 min — Red Team returns.

### Scorer discovery (do this early — biggest uptime lever)
The checker authenticates every ~30s and you won't be told which account. Read it off the DC's Security log instead of rotating all 15 and praying:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 100 |
  Select TimeCreated, Id, @{N='User';E={$_.Properties[5].Value}}, @{N='Src';E={$_.Properties[18].Value}}
```
The account logging in repeatedly from the scoring server's IP is the one you must keep working and mirror religiously.

---

# AD (`ad`) — PowerShell as Domain Admin

Format per item: **audit command · what to look for · fix command**. `<user>`/`<obj>` you fill in from audit output.

### Zerologon (CVE-2020-1472)
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name FullSecureChannelProtection
```
Want `1`. Missing/`0` = unauthenticated DC takeover possible — fix first.
```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name FullSecureChannelProtection -Value 1 -Type DWord
```
Verify: re-read = 1; `nltest /sc_verify:$env:USERDNSDOMAIN` still succeeds.

### Privileged-group membership
```powershell
Get-ADGroupMember "Domain Admins"; Get-ADGroupMember "Enterprise Admins"; Get-ADGroupMember "Schema Admins"
```
Want only your 5 admins. Any extra name = attacker persistence.
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members <baduser> -Confirm:$false
```
Then check `AdminSDHolder` ACL — SDProp re-adds members every ~60 min if the backdoor ACL remains. Fix the ACL, not just the membership.

### Delegation (unconstrained + RBCD backdoor)
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | ? {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'}
```
Anything beyond the DC's expected delegation is suspect; RBCD results are a common stealth backdoor.
```powershell
Set-ADAccountControl <obj> -TrustedForDelegation $false
Set-ADComputer <obj> -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
```

### Kerberoasting (SPNs) + AS-REP roasting
```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | ft Name,ServicePrincipalName
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```
SPN accounts are offline-crackable; AS-REP accounts give a hash with no creds. Both want remediation.
```powershell
# SPN not needed -> remove; needed -> rotate to long random pw (mirror if scored):
Set-ADUser <user> -ServicePrincipalNames @{Remove="<spn>"}
$pw = -join ((33..126)|Get-Random -Count 28|%{[char]$_}); Set-ADAccountPassword <user> -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force); $pw
# AS-REP:
Set-ADAccountControl <user> -DoesNotRequirePreAuth $false
```

### Account hygiene + lockout
```powershell
Get-ADDefaultDomainPasswordPolicy | select LockoutThreshold,LockoutDuration,LockoutObservationWindow
Search-ADAccount -LockedOut
'washington','kennedy','teddy','lincoln','ross','streep','franklin','parks','armstrong','hamilton','mlk','tubman','manziel','deniro','bush' | % { Get-ADUser -Filter "SamAccountName -eq '$_'" -Properties Enabled | select SamAccountName,Enabled }
```
Low `LockoutThreshold` = a rival can lock out your required users / the scored account as a cheap DoS. Any required user missing, disabled, or locked = fix (`Enable-ADAccount` / `Unlock-ADAccount <user>`). Rotate the 5 admin passwords early (mirror on dashboard).

### Persistence (GPOs + tasks)
```powershell
Get-GPO -All | sort ModificationTime -Desc | select DisplayName,ModificationTime
Get-ScheduledTask | ? State -ne Disabled | select TaskPath,TaskName
```
Recently-changed GPO you didn't touch, or an unrecognized task = investigate/revert. `Unregister-ScheduledTask -TaskName <name> -Confirm:$false`. If a task reappears, hunt what re-creates it.

### Host hardening (service/coercion surface)
```powershell
Get-Service Spooler, WebClient
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | select State
Get-NetTCPConnection -State Listen | select -Unique LocalPort,OwningProcess | sort LocalPort
quser
```
Spooler = PrintNightmare/coercion; WebClient = NTLM relay trigger; SMB1 = legacy; unknown listener/session = investigate.
```powershell
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
Stop-Service WebClient -Force; Set-Service WebClient -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LDAPServerIntegrity -Value 2 -Type DWord   # VERIFY AD check after — scorer may bind over LDAP
```
Windows Firewall: a DC needs `53,88,135,139,389,445,464,636,3268,3269,9389` + RPC dynamic range (49152-65535) inbound from your subnets. Scope those to team subnets, block the rest — or do it at OPNsense (R18) if unsure, where a mistake is easier to undo.

### Credential-theft protection (needs reboot — do in a lull)
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL                                   # want 1
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential    # want 0
```
```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 1 -Type DWord
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0 -Type DWord
```
Rebooting the DC drops the scored service during restart — plan it.

### Defender + time
```powershell
Get-MpComputerStatus | select RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureAge   # want True/True, age <2
Get-MpThreatDetection
w32tm /query /status                                                                              # Kerberos breaks >5 min skew
```
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false; Start-MpScan -ScanType QuickScan; Update-MpSignature
w32tm /config /syncfromflags:domhier /update; Restart-Service w32time
```
(Sysinternals **Autoruns** and **Sigcheck** — download + test before the event — are the fastest way to eyeball persistence and unsigned binaries; leave Process Explorer's VirusTotal upload off per R23.)

---

# DNS (`ns1`) — bash with sudo

### Identify resolver + validate config
```bash
sudo ss -ulpn | grep :53; ps aux | grep -E 'named|unbound' | grep -v grep
sudo named-checkconf        # BIND
sudo unbound-checkconf      # Unbound
```
Tells you which daemon you have (changes the config path) and whether config is valid. Run the checkconf before every reload.

### Open zone transfer / recursion / version
```bash
dig @127.0.0.1 <zone> AXFR           # returns records = AXFR open = leak
dig @127.0.0.1 google.com +short     # answers for outside = recursion open = abusable
dig @127.0.0.1 version.bind CH TXT   # version string = info leak
dig @127.0.0.1 <scored-record> +short # THE functional check — confirm the real record early
```
**Fix (BIND)** — `sudo vim /etc/bind/named.conf.options`, set `allow-transfer { none; };`, an ACL of your subnets, `allow-recursion { team_nets; };`, `version "none";`, then `sudo named-checkconf && sudo rndc reload`.
**Fix (Unbound)** — `sudo vim /etc/unbound/unbound.conf.d/tcdc.conf`, under `server:` add `access-control:` allow lines for your subnets + `access-control: 0.0.0.0/0 refuse`, `hide-identity: yes`, `hide-version: yes`, then `sudo unbound-checkconf && sudo systemctl reload unbound`.
Verify after either: `dig @127.0.0.1 <scored-record> +short` still resolves.

### Perms / persistence / time
```bash
sudo find /etc/bind /etc/unbound -perm -0002 -o -name '*.key' 2>/dev/null   # world-writable / exposed keys
sudo find /etc/bind /etc/unbound -mtime -14 -type f -ls                     # recent changes you didn't make
sudo crontab -l                                                             # cron rewriting zones
timedatectl                                                                 # want synchronized: yes
```
Fix: `sudo chmod 640 <keyfile>; sudo chown root:bind <keyfile>` (group varies by distro); remove rogue cron/units and restore the zone from baseline; `sudo timedatectl set-ntp true`.

---

# Dependencies, rollback, reporting

### Know your dependencies (map before the game)
- **Does AD rely on `ns1`?** `Get-DnsClientServerAddress` on `ad`; `resolvectl status` on the Linux boxes. If AD resolves via ns1 and it drops, the AD check can fail too — know this so you don't debug blind.
- **Time:** both clocks synced, or Kerberos (and the AD check) fails — check the clock first when AD auth breaks mysteriously.
- **ADCS (conditional):** no CA box in your topology, so ESC1–ESC8 cert abuse is almost certainly absent. 30-sec confirm: `Get-CATemplate` errors if no CA → forget it.

### Rollback & incident response
- Can't fix a broken scored service in ~2 min → revert to snapshot (store) rather than troubleshoot live.
- Keep a known-good copy of every file you edit (paste into the team sheet) for granular restore.
- Confirmed breach: (1) screenshot + time, (2) kill the process/session, (3) remove the *persistence* not just the process, (4) rotate creds + mirror, (5) re-baseline, (6) log it.
- Don't delete things you can't identify on a hunch — disable/quarantine first. A wrong delete on a DC/resolver is worse than the vuln.

### Finding/inject report row (team sheet or Discord)
```
TIME | BOX | FINDING | SEVERITY | EVIDENCE | ACTION TAKEN | VERIFIED(Y/N)
```
White Team grades injects on documented, verified remediation — writing it down as you go is worth points.

### Prep-week (before Nov 21)
- Run `defend-ad.ps1` in your homelab AD so it parses and behaves (couldn't be linted on Linux).
- Dry-run `defend-dns.sh` against a test BIND/Unbound.
- Fill real subnets/records/IPs into both scripts' config blocks; pre-save known-good configs + the required-user list offline.
- Confirm snapshot/store status so a revert point exists from minute one.
- R21: these are **prep** — understand them now; no AI tooling live during the event.
