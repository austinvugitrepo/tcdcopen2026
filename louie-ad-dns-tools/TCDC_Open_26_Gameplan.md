# TCDC Open 2026 — Team Gameplan

**Event:** Sat, Nov 21, 2026 · Online · Attack & Defense
**Hands-on blocks:** 9:00 AM–12:00 PM and 1:00 PM–5:00 PM CT (lunch hands-off 12–1, results 5:00–5:45)
**Scoring:** Uptime 80% (checks every 30s) / Injects 20%
**Team size:** 5 + 1 alternate (alternate cannot coach or guide during competition — R5)

---

## 1. Your Network (team ID = X)

| Host | OS | Service (scored?) | IP | Notes |
|---|---|---|---|---|
| jumpbox | — | No | 10.99.X.2 | Your access point only. 6 browser clients on :3001–3006, 2 Remmina RDP on :3007–3008. Attack tooling can live here (R16) |
| opnsense | OPNsense 26.7 | No | 10.(100+X).40.1 | Firewall. You control rules here (see §5) |
| ns1 | Ubuntu 26.04 | **DNS — Yes** | 10.(100+X).10.53 | |
| ipcam | Ubuntu 26.04 | **HTTP (IP Cam SaaS, cloud) — Yes** | 10.150.0.X | Shared cloud range, not your team subnet |
| ftp-archive | Ubuntu 26.04 | **FTP — Yes** | 10.(100+X).10.21 | |
| artifactorium | Ubuntu 26.04 | **HTTP (on-prem) — Yes** | 10.(100+X).10.80 | |
| ssh-workstation | Ubuntu 26.04 | **SSH — Yes** | 10.(100+X).10.22 | |
| ad | Windows Server 2025 | **Active Directory — Yes** | 10.(100+X).20.88 | Keep this alive — everything may depend on it |
| mqtt | Windows 11 Pro | **MQTT telemetry — Yes** | 10.(100+X).30.49 | |

9 boxes in scope for your defense (the 8 above + jumpbox), per R6. Those same boxes on **other** teams are in scope for purple teaming.

### OS users on every box (do not delete any of these — R8)
Admins: `washington`, `kennedy`, `teddy`, `lincoln`, `ross`
Employees: `streep`, `franklin`, `parks`, `armstrong`, `hamilton`, `mlk`, `tubman`, `manziel`, `deniro`, `bush`

Out of scope entirely, for everyone's boxes, every team's: `blackteam`/`whiteteam` users, Wazuh, auditd, Xen Orchestra, cloud-init/guest tools, scoreboard/dashboard, Discord (R7). Never disable, modify, or impersonate any of these (R8, R14, R15).

---

## 2. Pre-Game Checklist (before Nov 21)

- [ ] All 5 members + alternate confirm VPN access works (per TxCR instructions)
- [ ] All 5 members can reach the jumpbox (Xen Orchestra console AND VPN+browser-client paths, as a fallback)
- [ ] Pull OS/service user credentials from Discord and store in your team's shared vault/sheet
- [ ] Assign one owner per scored service (see §4) — don't have 5 people touching the same box
- [ ] Assign one person as **scoreboard/dashboard watcher** for the whole event
- [ ] Assign one person as **injects lead** to own https://dash.playtcdc.org/team/injects
- [ ] Register any custom purple-teaming tool in a public repo and submit via the Tool Links form (R20) — do this now, not mid-game
- [ ] Test every tool you plan to use, outside competition infra, before the event (R24)
- [ ] Confirm all tools are free-tier — **no AI usage** of any kind is allowed (R21)
- [ ] Walk through https://dash.playtcdc.org/team/passwords once as a dry run so nobody fumbles it live
- [ ] Decide store strategy as a team now (see §7) — currency is fixed, no way to earn more

---

## 3. Phase-by-Phase

### Phase 0 — Before "go" / any hands-off window
- No changes on your boxes (R10). Use this time only to read configs, review the network diagram, and plan.

### First 30–45 minutes of each hands-on block
1. **Baseline every box**: current users, listening services, cron/scheduled tasks, firewall rules, installed packages.
2. **Confirm each scored service actually passes a real check**, not just "port is open" — the checker validates functional responses and may use credentials (see §4 per-box).
3. **Change default passwords** for OS and service users on all 8 boxes, but only after confirming which users the uptime checks might be using — stagger this if unsure, and immediately mirror every change at https://dash.playtcdc.org/team/passwords. **A password change that isn't mirrored there reads as the service being down, even if it's healthy.**
4. Snapshot your boxes early if you can afford the store cost (see §7) — cheaper to revert later than to rebuild from scratch.
5. Lock down OPNsense egress/ingress rules per §5 once services are confirmed working.

### Steady state (rest of each block)
- Rotate: harden → verify checker still passes → log the change → move to next box.
- One person stays glued to the scoreboard; any dip gets triaged within 2 minutes.
- Watch Discord continuously for White/Black Team announcements — they carry rule authority equal to the packet itself.
- Start purple-teaming other teams once your own boxes are stable (see §6) — don't neglect your own uptime to do this.
- Submit injects as soon as they're assigned; don't batch them for later.

### Lunch (12–1) and any other hands-off window
- Hands off means hands off (R10). Use it to plan the afternoon block, not to sneak in changes.

### Last 30 minutes (4:30–5:00 PM)
- Stop any risky purple-teaming — a broken box you can't fix before 5:00 only hurts you if it's yours, and reversibility still applies to what you did to others (R11–R13).
- Final sweep: confirm all 8 scored services green, all password-dashboard entries match reality, all injects submitted.

---

## 4. Per-Box Hardening (owner-assigned)

**ns1 — DNS**
- Confirm zone files/records match what the checker expects before changing anything.
- Check for unauthorized zone transfers, open recursion, and extra records.
- Lock down `named`/`bind`/`unbound` config permissions; rotate any TSIG/service creds and mirror on the dashboard.

**ftp-archive — FTP**
- Disable anonymous login unless the checker depends on it (verify first).
- Check chroot config, writable directories, and for planted files in the FTP root.
- Rotate FTP user password and mirror on the dashboard.

**artifactorium — HTTP (on-prem)**
- Check webroot for shells/backdoors (`eval`, `base64_decode`, `system(`, `shell_exec`).
- Review file ownership/permissions — the web user shouldn't own the code.
- Pull DB/app credentials out of configs if hardcoded; rotate and mirror.

**ipcam — HTTP (cloud SaaS)**
- Same checks as artifactorium, but note this one sits on the shared `10.150.0.X` cloud range, not your private subnet — your OPNsense subnet rules (§5) may not fully protect it the same way.

**ssh-workstation — SSH**
- Audit `authorized_keys` across all users, `sshd_config` (`PermitRootLogin`, `PasswordAuthentication`, `AllowUsers`).
- Check cron/systemd persistence.
- Don't lock out any admin/employee user listed in §1 — R8 covers deletion, but a check-breaking lockout also costs you uptime points.

**ad — Active Directory (Windows Server 2025)**
- Audit Domain Admins / privileged groups for unexpected members.
- Check GPOs for backdoored logon scripts or scheduled tasks.
- Review trust relationships and LDAP bind accounts.
- **Do not disable Netlogon or anything that would lock your own team out** — and remember R12 means you can't do this to opponents either.

**mqtt — Windows 11 / MQTT telemetry**
- Identify the broker (Mosquitto, HiveMQ, etc.) and check ACLs/auth config.
- Confirm topic permissions aren't wide open; check for unauthorized subscribers/publishers.
- Rotate broker creds if applicable and mirror on the dashboard.

**opnsense — Firewall** (not scored directly, but gates everything)
- See §5 for the specific rule constraints.
- Double-check you haven't accidentally blocked a path the checker itself needs.

---

## 5. Firewall Rules You're Allowed to Write (R18, R19)

- **Between your own 4 subnets:** write anything you want.
- **Traffic to/from outside your subnets:**
  - *Incoming block rules* must apply to **all source IPs** (`*`) — you can block a port/service entirely for everyone, but you **cannot** block a specific outside IP or range.
  - *Outgoing block rules* must name **exactly one destination IP and one port** — no default-deny outbound, no blocking whole subnets/ranges.
- **No network-level attacks** — no DoS, no ARP spoofing (R19), against anyone.
- Practical read: you can harden your perimeter against *everyone equally* on a given port, but you cannot selectively block the Red Team or a specific rival team's IP while leaving others open, and you cannot wholesale-firewall your outbound traffic.

---

## 6. Purple Teaming — What's In Bounds

- Same 9-box set on **other teams** is fair game.
- Every malicious action must be **reasonably reversible** — nobody should have to rebuild from scratch because of you (R11–R13). No deleting root dirs, no irrecoverable file deletion without a backup, no permanent lockouts (e.g., disabling Netlogon).
- Never impersonate or attack Wazuh, auditd, cloud-init, or Xen Orchestra guest tools (R14, R15).
- Any custom tool must be in a public repo, linked via the Tool Links form, tested beforehand, free-tier, and **has to contain zero AI usage** (R20, R21, R24).
- No exfiltrating data/artifacts from competition infra — screenshots and passwords are the only exceptions (R23).
- Never log into personal accounts on the infra (R25).
- **When in doubt, ask Black Team before acting (R17)** — cheaper than a DQ.
- Be respectful, especially while purple teaming (R1); never impersonate White/Black Team (R3); follow any White/Black/Gold directive immediately, verbal or written (R4).

Good targets to prioritize against rivals (same reversible-damage standard applies): default/starting credentials, planted web shells they haven't found, unpatched service configs you already identified on your own matching box (since the topology is identical, a weakness you find on your own `ad` box likely exists on theirs too).

---

## 7. Store Strategy (https://dash.playtcdc.org/team/store)

Fixed currency, no way to earn more — spend deliberately as a team, not reactively:
- **Snapshots/reverts** — take one early once your boxes are hardened and stable; this is your insurance against a Red Team or rival hit you can't clean up fast.
- **Targeted Red Team request** — situational; mostly useful if you want to stress-test a specific box you're unsure about, or bait Red away from a weak point mid-fix.
- **Lockout of a rival's Xen Orchestra console** — offensive tempo play; coordinate timing with your purple-teaming push rather than using it standalone.
- **Extra console access** — worth buying early if you're short on hands-on access paths, since it removes a bottleneck for the whole event.

Decide the order of priority as a team *before* the event — don't deliberate live while the clock is running.

---

## 8. Roles (suggested 5-person split)

1. **Linux lead** — ns1, ftp-archive, artifactorium, ssh-workstation
2. **Windows lead** — ad, mqtt
3. **Cloud/network lead** — ipcam, opnsense, firewall rules, dashboard password mirroring
4. **Scoreboard + injects watcher** — owns uptime triage and inject submissions end-to-end
5. **Purple team / floater** — attacks rival boxes once home turf is stable, backs up whichever lead needs help

---

## 9. Things That Have Cost Teams Points Before (don't repeat)

- Changing a password without mirroring it on the dashboard → service reads as down even though it's fine.
- Deleting or disabling a listed OS user, or the `blackteam`/`whiteteam` users.
- Touching anything on the out-of-scope list (R7) while "just checking."
- An irreversible purple-team action against a rival (no backup, no snapshot).
- Working through a hands-off period.
- Using any AI tool for competition tasks — explicitly banned (R21).

---

## 10. Quick Reference — Commands & Scripts

Memorize/print this section — R21 bans AI tools live, so there's no copilot on game day. Replace `X` with your team ID throughout.

### 10.1 General Linux recon (run on every Ubuntu box first)

```bash
# Users, UID 0, recently added accounts
getent passwd | awk -F: '$3==0 || $3>=1000 {print}'
lastlog | grep -v Never
sudo cat /etc/shadow | awk -F: '$2!~/^[!*]/ {print $1}'   # accounts with a usable password hash

# sudoers / privilege
sudo grep -rv '^#\|^$' /etc/sudoers /etc/sudoers.d/

# SSH persistence
sudo find / -xdev -name authorized_keys -exec ls -l {} \; 2>/dev/null
sudo sshd -T 2>/dev/null | grep -Ei 'permitroot|passwordauth|allowusers|authorizedkeys'

# Persistence: cron/systemd
sudo crontab -l; for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -u "$u" -l 2>/dev/null; done
ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
systemctl list-unit-files --state=enabled
systemctl list-timers --all

# Listening services / established connections
sudo ss -tulpn
sudo ss -tnp state established

# Recently modified files, SUID binaries
sudo find / -xdev -mtime -14 -type f 2>/dev/null | grep -v '^/proc\|^/sys' | head -50
sudo find / -xdev -perm -4000 -type f 2>/dev/null

# Package/service integrity sanity check
dpkg -V 2>/dev/null | grep -v '^??'   # files changed since package install
```

### 10.2 Password rotation (every box, OS + service users)

```bash
sudo passwd <username>
```
Then **immediately** mirror the change at `https://dash.playtcdc.org/team/passwords` — a rotation that isn't mirrored there reads as the service being down. Keep a running log (time, box, user, who changed it) in your team sheet.

### 10.3 ns1 — DNS (BIND/Unbound)

```bash
# Config + zone sanity
sudo named-checkconf /etc/bind/named.conf 2>/dev/null || sudo unbound-checkconf 2>/dev/null
sudo named-checkzone <zone> /etc/bind/zones/<zonefile> 2>/dev/null

# Look for unauthorized zone transfer / recursion exposure
sudo grep -Ei 'allow-transfer|allow-recursion|allow-query' /etc/bind/named.conf* 2>/dev/null

# Confirm the service answers correctly (what the checker is doing)
dig @127.0.0.1 <expected-record> +short
dig @10.(100+X).10.53 <expected-record> +short

# Restart safely after edits
sudo systemctl reload bind9 2>/dev/null || sudo systemctl reload unbound 2>/dev/null
```

### 10.4 ftp-archive — FTP (vsftpd)

```bash
grep -Ei 'anonymous_enable|local_enable|write_enable|chroot_local_user' /etc/vsftpd.conf
cat /etc/ftpusers /etc/vsftpd.userlist 2>/dev/null

# Find planted/writable content
sudo find /srv/ftp /var/ftp -type d -perm -o+w 2>/dev/null
sudo find /srv/ftp /var/ftp -mtime -14 -type f -ls 2>/dev/null

# Functional check (mirrors what the scorer likely does)
curl -sS --user '<user>:<pass>' 'ftp://10.(100+X).10.21/' 

sudo systemctl restart vsftpd
```

### 10.5 artifactorium / ipcam — HTTP

```bash
# Hunt for webshells / suspicious code
sudo grep -rlE 'eval\(|base64_decode|system\(|shell_exec|passthru' /var/www 2>/dev/null
sudo find /var/www -mtime -14 -type f -ls 2>/dev/null

# Ownership sanity (web user should not own the app code)
find /var/www -not -user root -not -user www-data -ls 2>/dev/null

# Config test + reload
sudo nginx -t && sudo systemctl reload nginx     # or:
sudo apache2ctl configtest && sudo systemctl reload apache2

# Functional check
curl -skI https://10.(100+X).10.80/
curl -skI https://10.150.0.X/        # ipcam, shared cloud range
```

### 10.6 ssh-workstation — SSH hardening (verify before you lock anything)

```bash
sudo sshd -t                           # validate config BEFORE reloading
sudo sshd -T | grep -Ei 'permitroot|passwordauth|allowusers'
sudo systemctl reload sshd

# Confirm every required user still logs in from another box
for u in washington kennedy teddy lincoln ross; do
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$u@10.(100+X).10.22" true && echo "$u OK" || echo "$u FAIL"
done
```

### 10.7 ad — Active Directory (PowerShell, run as admin on `ad`)

```powershell
# Privileged group membership audit
Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select Name,SamAccountName

# All users + last logon, flag anything unexpected
Get-ADUser -Filter * -Properties LastLogonDate,Enabled | Select Name,SamAccountName,Enabled,LastLogonDate

# GPOs — look for odd logon scripts/scheduled tasks
Get-GPO -All | Select DisplayName, GpoStatus, ModificationTime

# Reset a password the required way (updates AD; still mirror on the TCDC dashboard)
Set-ADAccountPassword -Identity <user> -Reset -NewPassword (ConvertTo-SecureString "<newpw>" -AsPlainText -Force)

# Service health check equivalent to what the scorer sees
nltest /sc_verify:<domain>
Test-NetConnection -ComputerName 10.(100+X).20.88 -Port 389
```

### 10.8 mqtt — Windows 11 / MQTT broker (Mosquitto-style)

```powershell
# Confirm broker config / ACL file location
Get-Content "C:\Program Files\mosquitto\mosquitto.conf" | Select-String -Pattern "acl_file|allow_anonymous|password_file"

# Functional check
Test-NetConnection -ComputerName 10.(100+X).30.49 -Port 1883
```
```bash
# From a Linux box with mosquitto-clients installed, to sanity-check pub/sub auth
mosquitto_sub -h 10.(100+X).30.49 -t '#' -u <user> -P '<pass>' -C 1
```

### 10.9 opnsense — Firewall (web UI is primary; CLI fallback via console)

- Prefer the web UI for rule changes — safer than hand-editing `/conf/config.xml` under time pressure.
- Rule shape reminders (R18): incoming blocks must use source `*` (can't target a specific outside IP); outgoing blocks must name exactly one destination IP + one port (no default-deny outbound, no range blocks).
- Quick CLI sanity check from the console if the UI is unreachable:
  ```bash
  pfctl -sr          # show current ruleset
  pfctl -t <table> -T show   # show a named table's contents
  ```

### 10.10 Monitoring loop (run continuously from the jumpbox or your own box)

```bash
watch -n 25 'for h in 10.(100+X).10.53 10.(100+X).10.21 10.(100+X).10.80 10.(100+X).10.22 10.(100+X).20.88 10.(100+X).30.49; do
  nc -z -w2 "$h" 22 2>/dev/null && echo "$h: host reachable" || echo "$h: UNREACHABLE";
done'
```
This is a cheap reachability check, not a substitute for the real scorer — a host can answer on the port and still fail the functional check (wrong creds, broken app logic). Use it only to catch a box going fully dark between scoreboard refreshes.

### 10.11 Initial Vulnerability / Compromise Triage (run on your own boxes the moment you get hands-on)

Every team starts from the same identical build, so a weakness here is almost certainly present on rival teams' matching boxes too — and anything Red Team or a rival finds on yours, they'll try first. Run this before you harden anything else.

**Patch level and known CVEs (Linux)**
```bash
cat /etc/os-release
apt list --upgradable 2>/dev/null
dpkg -l | grep -Ei 'openssh|vsftpd|bind9|unbound|nginx|apache2|mosquitto'  # version-match against public CVE lists
uname -r
```
Cross-check versions against the NVD or vendor advisories from your own laptop (not through the box) — don't pull external tools onto the scored boxes themselves unless you've vetted them (R22, R24).

**Default / leftover credentials**
```bash
# Any account with a password hash that still matches a known-default or blank pattern
sudo awk -F: '($2!="*"&&$2!="!"){print $1}' /etc/shadow
# Config files that often hardcode creds
sudo grep -rEi 'password\s*=|passwd\s*=|secret\s*=' /etc /opt /var/www /srv 2>/dev/null | grep -v Binary
```

**Already-compromised indicators (previous team's box, possible prior breach)**
```bash
# Unexpected SUID/SGID binaries beyond the standard set
sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

# World-writable files/dirs outside expected spots
sudo find / -xdev -perm -0002 -type f 2>/dev/null | grep -v '^/proc\|^/tmp\|^/var/tmp'

# Unexpected outbound connections / beaconing
sudo ss -tnp state established
sudo lsof -i 2>/dev/null | grep -v 'sshd\|systemd'

# Kernel modules not part of the base image
lsmod | sort

# Hidden/odd files in common persistence spots
sudo find /etc /usr/lib/systemd /lib/systemd /var/spool/cron -newer /etc/hostname -type f 2>/dev/null
```

**Web app specific (artifactorium, ipcam)**
```bash
# Identify stack/version via headers and files
curl -skI https://10.(100+X).10.80/ | grep -Ei 'server|x-powered-by'
sudo find /var/www -iname '*.config' -o -iname 'wp-config.php' -o -iname 'settings.py' 2>/dev/null

# Exposed admin/debug endpoints
curl -sk https://10.(100+X).10.80/admin https://10.(100+X).10.80/debug https://10.(100+X).10.80/.git/config -o /dev/null -w '%{http_code} %{url_effective}\n'
```

**Windows / AD-specific checks (run as admin on `ad`)**
```powershell
# Patch level
Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10
Get-ComputerInfo | Select WindowsVersion, OsBuildNumber

# Zerologon exposure check (unpatched DCs are vulnerable — verify RPC signing is enforced)
# Review: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -> FullSecureChannelProtection should be 1
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name FullSecureChannelProtection -ErrorAction SilentlyContinue

# Kerberoasting exposure — accounts with SPNs set
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | Select Name,ServicePrincipalName

# Unconstrained delegation (high-value misconfig to fix immediately)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# AdminSDHolder / privileged group membership drift
Get-ADGroupMember -Identity "Domain Admins","Enterprise Admins","Schema Admins" | Select Name,SamAccountName

# Scheduled tasks / logon scripts planted as persistence
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName, TaskPath
```

**MQTT broker (Windows 11 `mqtt` box)**
```powershell
# Confirm anonymous access isn't allowed and ACLs are actually enforced
Get-Content "C:\Program Files\mosquitto\mosquitto.conf" | Select-String "allow_anonymous"
```
If `allow_anonymous true` or there's no `password_file`/`acl_file` set, that's an immediate open door — fix it, then verify the checker still passes before moving on.

**After every fix found above:** re-run the §4 functional check for that service, confirm the scoreboard still shows it green, and log the finding (what, where, how you fixed it) for injects/reporting purposes — White Team may ask for exactly this kind of writeup.

---

## 11. Common Defenses — Hardening Playbook

For each class of weakness in §10.11, here's the standard fix. Rule of thumb for all of these: **harden, then immediately re-run the functional check from §4 before moving to the next box** — a "secure" service that fails the checker costs you the same points as a breached one.

### 11.1 Patch level / known CVEs
- `sudo apt update && sudo apt upgrade -y` on each Linux box, but do it service-by-service and re-check functionality after each — a blind full upgrade can break the exact config the checker depends on.
- Windows: apply available updates via `Get-WindowsUpdate`/`Install-WindowsUpdate` (PSWindowsUpdate module) or Settings, but snapshot first (store purchase) — a bad patch on `ad` can be worse than the vulnerability.
- If you can't patch safely mid-competition, mitigate instead: disable the vulnerable feature/endpoint, restrict access to it via firewall, or add compensating auth.

### 11.2 Default / leftover credentials
- Rotate every OS and service user password as early as possible (§10.2) — then **always mirror on the TCDC password dashboard**.
- Remove or disable any account that isn't in the §1 required list and isn't `blackteam`/`whiteteam` (don't touch those — R8).
- Check for credentials hardcoded in configs/scripts/env files and rotate the underlying account, not just the file.

### 11.3 Already-compromised indicators
- **Unexpected SUID/SGID binaries:** remove the bit (`sudo chmod u-s,g-s <file>`) unless you can confirm it's legitimately required; if unsure, don't delete the binary outright — a wrong guess can break the OS.
- **World-writable files/dirs:** tighten permissions (`chmod o-w`), and audit who/what put them there.
- **Unexpected outbound connections:** kill the owning process (`sudo kill <pid>`), then find and remove its persistence (service unit, cron entry, or `authorized_keys`), not just the running process — otherwise it respawns.
- **Unexpected kernel modules:** `sudo rmmod <module>` if non-essential and unrecognized; blacklist it in `/etc/modprobe.d/` so it doesn't reload on reboot.
- **Planted persistence (cron/systemd/authorized_keys):** remove the entry, but preserve Zeta-equivalent/required admin access — don't strip an SSH key or cron job that a required user or the checker itself depends on without verifying first.

### 11.4 Web apps (artifactorium, ipcam)
- Delete identified webshells, then check for *how* they got there (upload form, exposed admin panel, outdated plugin) and close that path, not just the shell file.
- Set correct ownership/permissions on the webroot so the web server user can't write to its own code (`chown -R root:www-data /var/www/app; chmod -R 755 /var/www/app`).
- Remove or auth-protect exposed debug/admin endpoints; block `.git`, `.env`, and backup-file exposure at the web server config level (nginx `location ~ /\.git { deny all; }` or Apache equivalent).
- Rotate any DB/API credentials found hardcoded in app configs, and move them to environment variables or a restricted-permission config file if time allows.

### 11.5 SSH
- Disable root login (`PermitRootLogin no`), but confirm password or key auth still works for every required user before you reload.
- Remove unauthorized `authorized_keys` entries; keep required ones (anything acting as the Zeta-equivalent "staff check" account in this event, plus the five admin users).
- Consider `AllowUsers <list>` only once you're certain of the full required-user list — getting this wrong locks out your own uptime score.
- Rate-limit or fail2ban brute-force attempts if you have slack to configure it, without blocking the legitimate checker's source.

### 11.6 Active Directory
- **Zerologon:** confirm `FullSecureChannelProtection=1` (should be default on Server 2025, but verify) and that patches are current; this is the single highest-value fix on `ad`.
- **Kerberoasting exposure:** for accounts with SPNs that don't need them, remove the SPN; for accounts that must keep one, make sure the password is long/random and rotate it.
- **Unconstrained delegation:** switch affected computer/user objects to constrained delegation or remove delegation entirely unless a specific service genuinely requires it — unconstrained delegation is one of the fastest domain-compromise paths for Red Team.
- **Privileged group drift:** remove any account from Domain/Enterprise/Schema Admins that isn't supposed to be there; document who's supposed to be in each group so you can spot drift fast on a re-check.
- **GPO/logon-script persistence:** revert or delete unauthorized GPOs and scheduled tasks; re-link only the GPOs you recognize as legitimate.
- Enable/verify auditing on privileged group changes and account lockouts so you catch the *next* attempt faster (native Windows auditing, not Wazuh/auditd — those are out of scope to touch, R7).

### 11.7 MQTT broker
- Set `allow_anonymous false` and configure a `password_file` and `acl_file` so only authenticated, authorized clients can publish/subscribe.
- Scope ACLs per-user/per-topic rather than granting blanket access.
- Restart the broker and re-verify both the functional check *and* that your legitimate publisher/subscriber clients (whatever the inject/scenario requires) still work.

### 11.8 DNS
- Restrict `allow-transfer`/`allow-recursion` to only what's needed (your own subnets, not `any`).
- Confirm zone files haven't been tampered with (compare against your baseline from §10.11) before and after any change.
- Keep TSIG/service keys rotated and mirrored on the dashboard if the checker authenticates.

### 11.9 FTP
- Disable anonymous access unless the checker specifically requires it (verify first — don't break your own score).
- Enforce chroot per user so an FTP account can't traverse outside its home directory.
- Remove write access to directories that don't need it, and periodically re-scan for planted files.

### 11.10 Firewall (OPNsense)
- Once every scored service is confirmed passing, tighten inbound rules to only the ports each service actually needs — remember incoming blocks must apply to all sources (`*`), so you're closing a port for everyone, not just attackers (R18).
- Log dropped/blocked traffic so you have evidence for injects or disputes.
- Re-test every scored service from outside your subnet after each rule change — a firewall tightened too far silently kills your own uptime score, which looks identical to a Red Team win.

### 11.11 General hygiene across all boxes
- Baseline-diff regularly: re-run your §10.11 triage commands periodically through the day, not just once at the start — Red Team and rivals will plant new things after your first sweep.
- Keep one shared doc/channel logging every change (who, what, when, why) so teammates don't fight each other's fixes or re-break something already patched.
- Snapshot (store purchase) after each major hardening pass so a bad config or a Red Team hit has a clean revert point.

---

## 12. Monitoring — What You Can Run Given the Rules

Wazuh and auditd are already running and are explicitly out of scope — don't touch, disable, or impersonate them (R7, R15), and don't assume you'll have visibility into their alerts unless Black Team gives you a dashboard/read path. That means your own visibility has to come from native OS logging plus lightweight scripts you control. Anything custom you build should be free, tested beforehand outside competition infra, and — to be safe given R20's "any custom tool" wording — submitted through the Tool Links form even if it's purely defensive monitoring, not an attack tool.

### 12.1 Synthetic uptime checks (beat the scoreboard to the bad news)
The scorer ticks every 30 seconds and may use credentials you don't know — so you can't perfectly replicate it, but you can catch a service going dark before the scoreboard shows red.

```bash
# Run from your own box or jumpbox, loop every ~20s (faster than the 30s tick)
watch -n 20 '
for svc in "10.(100+X).10.53:53" "10.(100+X).10.21:21" "10.(100+X).10.80:443" \
           "10.(100+X).10.22:22" "10.(100+X).20.88:389" "10.(100+X).30.49:1883" \
           "10.150.0.X:443"; do
  host=${svc%%:*}; port=${svc##*:};
  nc -z -w2 "$host" "$port" 2>/dev/null && echo "$svc OK" || echo "$svc DOWN";
done'
```
Pair this with a quick functional probe per service (the `dig`/`curl`/`mosquitto_sub` one-liners from §10.3–10.8) on a slower cadence (every 2–3 min) since those actually validate the response, not just the port.

### 12.2 Centralize alerts to your team (not competition infra)
Posting your own synthetic-check output to a private channel in the *existing* competition Discord (where you already coordinate) is fine — you're not touching competition infrastructure, just using your own team's coordination channel. A simple webhook post on state change avoids someone having to stare at a terminal all day:

```bash
# only fires on a state change, not every loop iteration
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"content":"⚠️ '"$svc"' just went DOWN"}' \
  "$YOUR_TEAM_DISCORD_WEBHOOK_URL"
```

### 12.3 Auth/account monitoring (native logs only — leave Wazuh/auditd alone)

**Linux:**
```bash
sudo tail -f /var/log/auth.log           # Ubuntu — live logon/sudo activity
sudo lastb | head -20                    # recent failed logins
sudo journalctl -u sshd -f               # live SSH daemon log
# Periodic diff against your baseline user list from §10.11
getent passwd | awk -F: '$3>=1000{print $1}' > /tmp/users.now
diff /tmp/users.baseline /tmp/users.now
```

**Windows / AD** (native Event Viewer / PowerShell, no agent install needed):
```powershell
# New account created (4720), group membership change (4728/4732/4756), logon (4624), explicit creds (4648)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4756} -MaxEvents 50 |
  Select TimeCreated, Id, Message

# Privileged logons specifically
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 20 | Select TimeCreated, Message
```
Run this on a loop (`while ($true) {...; Start-Sleep 30}`) or schedule it, and pipe new hits to your Discord webhook the same way as §12.2.

### 12.4 File/config integrity baseline
Cheap, doesn't install anything new, and directly supports the §10.11 "already-compromised" checks — take a hash manifest right after your first hardening pass, then diff periodically through the day.

```bash
# Baseline (right after hardening)
sudo find /etc /var/www /srv -type f -exec sha256sum {} \; > /root/baseline-$(hostname).sha256

# Re-check later
sudo find /etc /var/www /srv -type f -exec sha256sum {} \; > /tmp/now.sha256
diff /root/baseline-$(hostname).sha256 /tmp/now.sha256
```
Windows equivalent: `Get-FileHash` over `C:\Windows\System32\GroupPolicy`, your webroot, and mosquitto's config directory, same baseline/diff pattern.

### 12.5 Network connection watch
```bash
# Flag new established connections not seen on your baseline sweep
sudo ss -tnp state established
```
```powershell
Get-NetTCPConnection -State Established | Select RemoteAddress, RemotePort, OwningProcess
```
Run this every few minutes on `ad` and `ssh-workstation` especially — those are your two highest-value pivot points (§9 from the targeting discussion), so unexpected outbound traffic there is the earliest signal something landed.

### 12.6 Division of labor
Don't let monitoring become its own full-time job that competes with hardening time. The scoreboard watcher (§8 role split) owns 12.1/12.2 continuously; whoever's assigned AD/DNS/SSH/web runs 12.3–12.5 against their own boxes on a periodic sweep (every 20–30 min) rather than constantly — the goal is catching drift between hardening passes, not real-time SOC-style monitoring you don't have the headcount for.
