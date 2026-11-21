# TCDC Blue Team Toolkit: what each tool does

Team: Mo, Josh, Austin, Sai, Louis. This file explains every script in the toolkit in plain words. `README.md` has the run order, the safety habits and the testing table.

Two rules that apply to every script:
- Anything that changes a system is a dry run until you add `--apply` (Linux) or `-Apply` (Windows). Run the dry run first and read it.
- After any change that touches a service or account, wait 60 seconds (2 scoreboard ticks) and check the scoreboard before the next change.

## Quick map

| Script | Boxes | Changes anything? | Tested? |
|---|---|---|---|
| `linux/audit.sh` | ns1, ftp-archive, artifactorium, ssh-workstation, ipcam | No | Run for real |
| `linux/backup.sh` | same five | Writes one archive | Run for real |
| `linux/rotate-passwords.sh` | same five | Only with `--apply` | Run for real on test users |
| `linux/harden-ssh.sh` | ssh-workstation (others if needed) | Only with `--apply` | Stub sshd only |
| `linux/credcheck.sh` | same five | No | Run for real with planted fakes |
| `linux/svc-check.sh` | jumpbox | No | Helper parts only |
| `windows/Audit-Windows.ps1` | ad, mqtt | No | Never run |
| `windows/Audit-AD.ps1` | ad | No | Never run |
| `windows/Backup-Windows.ps1` | ad, mqtt | Writes one zip | Never run |
| `windows/Rotate-Passwords.ps1` | ad (Domain), mqtt (Local) | Only with `-Apply` | Never run |
| `windows/Enable-WinAuditing.ps1` | ad, mqtt | Only with `-Apply` | Never run |
| `windows/Harden-Windows-Safe.ps1` | ad, mqtt | Only with `-Apply` | Never run |
| `windows/Check-CredTheft.ps1` | ad, mqtt | No | Never run |

Never run means the syntax was checked with a parser and nothing more. Louis: run each one on a Windows practice VM before Saturday.

---

## Linux scripts (run with sudo on the Ubuntu boxes)

### `linux/audit.sh`
**What it does:** Looks at the places red team hides things and prints what it finds. It covers users, UID 0 accounts, empty passwords, sudoers, SSH keys, sshd settings, cron, systemd services, shell startup files, PAM files, `ld.so.preload`, setuid files, kernel modules, listening ports, established connections, deleted-but-running programs, shell processes started by web servers, recently changed files and web-root files.

**Modes:**
- `sudo ./audit.sh report` prints everything and saves a copy (default).
- `sudo ./audit.sh snapshot` saves a baseline. Run it in the first minutes, before you harden anything.
- `sudo ./audit.sh diff` compares now against the baseline. Anything listed is new since the snapshot and needs an explanation.

**Env vars:** `OUT_DIR` (default `/var/tmp/tcdc-audit`), `RECENT_MIN` (default 60, for the recent-files check).

**How to read it:** Lines starting with `FLAG:` are leads. A new user, a new SSH key or a new cron job that nobody on the team made is the kind of thing to chase.

### `linux/backup.sh`
**What it does:** Makes a tar.gz of /etc, web roots, DNS data, cron, SSH keys and Mosquitto data (whichever exist) plus a sha256 file and a notes file. It skips any directory larger than `MAX_MB` (default 300) unless you pass that directory as an argument.

**Run:** `sudo ./backup.sh` (extra paths: `sudo ./backup.sh /some/path`).
**Saved to:** `/root/tcdc-backup` (change with `BACKUP_DIR`). Backups stay on the box (rule R23).
**Restore one file:** `sudo tar -xzpf <archive> -C / <path-without-leading-slash>`

### `linux/rotate-passwords.sh`
**What it does:** Changes the passwords of the 15 packet users (washington, kennedy, teddy, lincoln, ross, streep, franklin, parks, armstrong, hamilton, mlk, tubman, manziel, deniro, bush), one at a time, and only those that exist on the box.

**Run:**
- `sudo ./rotate-passwords.sh` is a dry run that lists who would change.
- `sudo ./rotate-passwords.sh --apply` changes one user, prints the new password, then waits. You update `dash.playtcdc.org/team/passwords`, check the scoreboard, and press Enter for the next user.
- Options: `--users a,b` for specific users, `--no-wait` to skip the pause. `PW_LENGTH` sets the length (default 20).

**Saved to:** a root-only file, `/root/tcdc-passwords-<host>.txt`. Give it to your captain. Never commit it to a repo.
**It never touches** blackteam or whiteteam (R8), and it never deletes or locks anyone.
**Why the pause matters:** the checker uses accounts you are not told about. If you change a password and forget the dashboard, the service shows down.

### `linux/harden-ssh.sh`
**What it does:** Writes a small sshd drop-in at `/etc/ssh/sshd_config.d/00-tcdc-hardening.conf` with PermitRootLogin no, PermitEmptyPasswords no, MaxAuthTries 3, LoginGraceTime 30, X11Forwarding no and PermitUserEnvironment no. It checks the result with `sshd -t` before reloading and restores the old file if the check fails.

**Run:** `sudo ./harden-ssh.sh` (dry run), then `sudo ./harden-ssh.sh --apply`. Optional: `--allow-users a,b,c`. A typo there can lock people out, so keep one SSH session open and test a second login first.
**It deliberately does not touch `PasswordAuthentication`.** The checker may log in with a password. Only change that if Black Team confirms the checker uses keys.
**Tested only against a stub sshd.** Try it on a practice VM first.

### `linux/credcheck.sh`
**What it does:** Hunts for password theft. It checks:
- PAM modules that no package owns, and any `pam_exec` or `pam_script` line
- changed files in sshd, sudo, su, login and passwd packages (`dpkg -V`)
- fake `sudo`, `su` or `ssh` programs in other folders or earlier in PATH
- shell aliases or functions that wrap sudo, ssh or su
- `LD_PRELOAD` hooks
- strace, gdb or sniffer processes, and processes being traced
- connections to addresses outside 10.0.0.0/8
- Python or PAM errors flooding the journal

**Run:** `sudo ./credcheck.sh`. Run it after the first password rotation and again before the second. It saves a report under `/var/tmp/tcdc-audit`.
**How to read it:** `FLAG:` lines are leads, not proof. `NOTE:` lines are usually harmless. A package update or your own change can trigger some flags.
**It cannot see** kernel-level keyloggers, sniffing done from another box, or anything that lives only in memory.

### `linux/svc-check.sh`
**What it does:** Runs on the jumpbox and checks your 7 scored services every 30 seconds from your side: DNS on ns1, FTP banner, HTTP on artifactorium and ipcam, SSH banner, AD ports 88/389/445, MQTT port 1883. It logs UP or DOWN and does not log in.

**Run:** `./svc-check.sh <team-id>` (options: `--once`, `--interval 30`). Needs bash and curl, and uses `dig` if installed.
**Limit:** the real checker may log in with credentials. An UP here is necessary but not always enough. The scoreboard is the source of truth. This tells you quickly that something broke right after your change.

---

## Windows scripts (Louis; run in an elevated PowerShell on ad and mqtt)

If PowerShell blocks scripts, allow them for this window only: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

### `windows/Audit-Windows.ps1`
**What it does:** The Windows version of `audit.sh`. It lists users and admins, scheduled tasks, services, run keys and autoruns, WMI subscriptions, listening ports, firewall allow rules, Defender exclusions, the Mosquitto config, established connections and recent security events.
**Modes:** `-Mode Report` (default), `-Mode Snapshot` (baseline, run first), `-Mode Diff` (what changed since). `-Hours` sets the look-back window (default 6).
**Saved to:** `C:\ProgramData\tcdc-audit`.

### `windows/Audit-AD.ps1`
**What it does:** Read-only Active Directory review on the domain controller (ad). It finds Kerberoastable and AS-REP roastable accounts, delegation, weak account flags, privileged group members, who holds DCSync-style replication rights, dangerous permissions on the domain root, recent account and GPO changes, krbtgt age and the Guest account. Each finding comes with a short why-it-matters note. It fixes nothing; decide as a team and change one thing at a time.
**Run:** `.\Audit-AD.ps1` (option `-Hours 2`). Run as a domain admin.

### `windows/Backup-Windows.ps1`
**What it does:** Collects and zips what you may need to restore: the Mosquitto folder, firewall and security policy exports, run keys, services and scheduled tasks (XML for non-Microsoft tasks), and on the DC the GPO backup, user and group lists and DNS records. Nothing leaves the box.
**Run:** `.\Backup-Windows.ps1`

### `windows/Rotate-Passwords.ps1`
**What it does:** Same one-at-a-time rotation as the Linux script, with the same pause for the dashboard and scoreboard. Never touches blackteam, whiteteam or krbtgt, and never deletes, disables or locks anyone.
**Run:**
- ad: `.\Rotate-Passwords.ps1 -Scope Domain` (dry run), then add `-Apply`
- mqtt: `.\Rotate-Passwords.ps1 -Scope Local`, then add `-Apply`
- Options: `-Users a,b`, `-NoWait`.
**Saved to:** a file readable only by Administrators and SYSTEM. Keep it out of any repo.

### `windows/Enable-WinAuditing.ps1`
**What it does:** Turns on the Windows logging you need to see attacks: advanced audit subcategories, command lines in process-creation events (4688), PowerShell script block logging (4104), the Task Scheduler log and a 256 MB Security log. It changes only this box's own audit settings and does not touch Wazuh (R7).
**Run:** `.\Enable-WinAuditing.ps1` (dry run), then `-Apply`. Run it before `Check-CredTheft.ps1` so the event log checks have data.

### `windows/Harden-Windows-Safe.ps1`
**What it does:** Five low-risk fixes, each with a printed undo line: disable SMBv1, require NLA for RDP, disable the Guest account, turn off LLMNR, turn off WDigest clear-text caching.
**What it deliberately does not do:** turn the Windows firewall on or change inbound defaults, require SMB signing, block NTLM, change Kerberos encryption, or remove Defender exclusions.
**Run:** `.\Harden-Windows-Safe.ps1` (dry run), then `-Apply`.

### `windows/Check-CredTheft.ps1`
**What it does:** The Windows password-theft hunt. It checks:
- extra LSA packages and password filter DLLs
- unusual credential providers and network providers
- Winlogon and AppInit hooks
- recently written system DLLs and EXEs that are not validly signed
- running credential-dumping tools and commands, plus dump files and copied registry hives
- a WSL process or an sshd service
- password resets, failed logons, remote logons from outside 10.0.0.0/8, new services and DCSync patterns (from event logs)
- outbound connections and Mosquitto password file permissions

**Run:** `.\Check-CredTheft.ps1` (option `-Hours 2`). Run it after the first rotation and again before the second.
**How to read it:** `FLAG:` lines are leads. A "none found" on an event log check can also mean auditing is off, so run `Enable-WinAuditing.ps1 -Apply` first.

---

## Not built yet

- **OPNsense:** no script. Use the web interface: change the admin password, download a config backup, review the rules and NAT port forwards, check users and access settings, add inbound port blocks, then segment between subnets.
- **Host firewall scripts** (Linux and Windows): not built. A bad firewall rule can take every service down, and they cannot be tested properly outside real VMs.
- **ipcam** has no firewall in front of it. It needs host-level hardening only.

## Third-party tools to download ahead of time (not in the zip)

All free. Download to the jumpbox now, because it is unknown whether the boxes can reach the internet. Ask Black Team if a tool you didn't write needs review.
- Sysinternals Autoruns, Process Explorer, TCPView and Sysmon (Windows)
- Wireshark (check whether passwords are leaving the box)
- nmap on the jumpbox (confirm what is really listening on your own boxes)

Do not use fail2ban: it blocks specific source IPs, which rule R18 does not allow.

## Rules to remember (TCDC packet)

- R8: never change, disable or remove the blackteam or whiteteam users. Never delete a listed OS user.
- R10: do nothing on the boxes during hands-off periods.
- R18: inbound blocks must apply to all sources. Outbound blocks must name exactly one IP and one port. No default-deny outbound.
- R20: custom tools go in a public repo and onto the Tool Links form before Saturday. Submit by Friday, Nov 20.
- R21: free tools only, and no AI connected to the competition platform.
- R23: nothing leaves the boxes except screenshots and passwords. Never commit passwords.
