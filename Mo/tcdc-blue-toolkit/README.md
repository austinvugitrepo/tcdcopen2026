# TCDC Blue Team Toolkit

Small, readable scripts for defending the TCDC Open 26 museum network. Every script is plain text, makes no outbound network connections (except `svc-check.sh`, which only talks to your own team's boxes), and anything that changes a system is a dry run until you add `--apply` / `-Apply`.

Rules this toolkit is built around (TCDC packet):
- R20: custom tools must be in a public repo and submitted through the Tool Links form before the event.
- R21: free tools only, and no AI connected to the competition platform.
- R8: never touch the `blackteam` or `whiteteam` users and never delete listed OS users. The scripts refuse to.
- R7 / R15: nothing here touches Wazuh, auditd, Xen Orchestra or cloud-init tools.
- R23: backups stay on the box. Passwords may leave, but never commit them.
- R10: do not run anything on the boxes during hands-off periods.

## What is in here

| Script | Where | Changes anything? | What it does |
|---|---|---|---|
| `linux/audit.sh` | all Ubuntu boxes | No | `snapshot` a baseline, `diff` against it later, or full `report`: users, sudoers, SSH keys, cron, systemd, PAM, SUID, listeners, web shell hints, recent file changes |
| `linux/backup.sh` | all Ubuntu boxes | No (writes a tar.gz) | Backs up /etc, web roots, DNS data, cron, SSH keys to a local archive with a checksum. Skips huge directories |
| `linux/rotate-passwords.sh` | all Ubuntu boxes | Only with `--apply` | Rotates the packet users one at a time and pauses so you can update the dashboard and check the scoreboard |
| `linux/harden-ssh.sh` | ssh-workstation (and others) | Only with `--apply` | Safe sshd drop-in. Does NOT touch `PasswordAuthentication`. Validates with `sshd -t` and restores on failure |
| `linux/credcheck.sh` | all Ubuntu boxes | No | Hunts for password theft: PAM modules and `pam_exec` hooks, replaced sshd/sudo/su/login (package verify), strace or sniffers, shell aliases wrapping sudo/ssh, fake sudo in other folders, LD_PRELOAD, outbound connections, noisy journal. Prints `FLAG:` lines |
| `linux/svc-check.sh` | jumpbox | No | Checks all 7 scored services every 30 s from your side and logs UP/DOWN |
| `windows/Audit-Windows.ps1` | ad, mqtt | No | Snapshot / Diff / Report: users, admins, tasks, services, autoruns, WMI, ports, firewall allow rules, Defender exclusions, Mosquitto config, recent security events |
| `windows/Audit-AD.ps1` | ad | No | Kerberoastable and AS-REP roastable accounts, delegation, DCSync rights, privileged groups, recent changes, GPOs, krbtgt age |
| `windows/Check-CredTheft.ps1` | ad, mqtt | No | Hunts for password theft: extra LSA packages and password filter DLLs, credential and network providers, Winlogon/AppInit hooks, unsigned recent system DLLs, dump tools and dump files, WSL and sshd, password resets, failed and remote logons, new services, DCSync, outbound connections, Mosquitto password file. Prints `FLAG:` lines |
| `windows/Backup-Windows.ps1` | ad, mqtt | No (writes a zip) | Mosquitto files, firewall and security policy, tasks, services, GPOs, AD lists, DNS records |
| `windows/Rotate-Passwords.ps1` | ad (`-Scope Domain`), mqtt (`-Scope Local`) | Only with `-Apply` | Same one-at-a-time rotation, never touches blackteam, whiteteam, krbtgt |
| `windows/Enable-WinAuditing.ps1` | ad, mqtt | Only with `-Apply` | Turns on the audit settings you need to see attacks (4688 with command line, 4104, tasks, services, account changes) |
| `windows/Harden-Windows-Safe.ps1` | ad, mqtt | Only with `-Apply` | 5 low-risk fixes with a printed undo line each (SMBv1, RDP NLA, Guest, LLMNR, WDigest) |

## Suggested run order

Linux boxes (ns1, ftp-archive, artifactorium, ssh-workstation, ipcam):
1. `sudo ./audit.sh report` to see what you have, then `sudo ./backup.sh`
2. `sudo ./audit.sh snapshot` (baseline BEFORE you change anything)
3. `sudo ./rotate-passwords.sh` (dry run), then `--apply`, one user at a time
4. ssh-workstation: `sudo ./harden-ssh.sh`, then `--apply`
5. `sudo ./credcheck.sh` right after the first rotation and again before the second one (see below)
6. Every 15 to 30 minutes: `sudo ./audit.sh diff`. Anything new is yours to explain

Windows boxes (ad, mqtt):
1. `.\Backup-Windows.ps1`, then `.\Audit-Windows.ps1 -Mode Snapshot`
2. ad only: `.\Audit-AD.ps1`
3. `.\Enable-WinAuditing.ps1 -Apply` (low risk, gives you visibility)
4. `.\Rotate-Passwords.ps1 -Scope Domain` on ad or `-Scope Local` on mqtt (dry run first, then `-Apply`)
5. `.\Harden-Windows-Safe.ps1`, review, then `-Apply`
6. `.\Check-CredTheft.ps1` after the first rotation and again before the second one
7. Every 15 to 30 minutes: `.\Audit-Windows.ps1 -Mode Diff`

Jumpbox: `./svc-check.sh <your team id>` in a spare terminal all day.

## Checking for password theft (rotate, hunt, rotate again)

Red team can have a foothold before you start, so a password you set in minute 3 may be captured. The order that deals with that:

1. Rotate passwords (first pass).
2. Run `credcheck.sh` (Linux) or `Check-CredTheft.ps1` (Windows) on each box. Read every `FLAG:` line.
3. Remove what you find (a rogue PAM line, a fake `sudo`, an extra LSA package), then rotate again. Update the dashboard after each rotation.
4. Repeat the check every hour or so. Saved reports are in `/var/tmp/tcdc-audit` and `C:\ProgramData\tcdc-audit`.

A flag is a lead, not proof. Package updates and your own changes can trigger some of them. Things these scripts cannot see: a kernel-level keylogger, a tool that sniffs the network from another box, and anything red team runs only in memory. Use the Wireshark and process checks by hand for those.

## Safety habits (these are what cost teams points)

- Scoreboard first. After every change that touches a service or account, wait for 2 ticks (60 s).
- One change at a time. The scripts pause between users on purpose.
- The checker uses accounts you are not told about. Update `dash.playtcdc.org/team/passwords` right after each rotation.
- Keep a second session open before changing SSH, RDP or passwords.
- Run `audit.sh snapshot` and `Audit-Windows.ps1 -Mode Snapshot` BEFORE hardening, or the diff will include your own changes.

## Getting this into a public repo (needed for rule R20)

```bash
cd tcdc-blue-toolkit
git init
git add .
git commit -m "TCDC blue team toolkit"
# create an empty PUBLIC repo on GitHub first, then:
git branch -M main
git remote add origin https://github.com/<your-user>/<repo-name>.git
git push -u origin main
```

Then submit the repo link through the Tool Links form (the link is in the competition packet). Do it by Friday Nov 20 so Black Team has time to review. Unreviewed custom tools can mean point deductions or disqualification. If you change a script after submitting, tell Black Team.

Never commit passwords. `.gitignore` excludes the usual output files, but double check with `git status` before pushing.

## Getting scripts onto the boxes

Clone the repo on your jumpbox, then copy to each box with `scp` (Linux) over the VPN or jumpbox. For Windows boxes, use the Remmina RDP clients on the jumpbox and copy files over the RDP session, or serve the folder from the jumpbox with `python3 -m http.server` and download from the Windows box. Confirm that path works on practice day. Whether boxes can reach GitHub directly is unknown.

PowerShell may block unsigned scripts. If so, for the current session only: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

## What has and has not been tested

Be honest with Black Team and your teammates about this:

| Script | Testing so far |
|---|---|
| `audit.sh` | Run for real on Ubuntu: snapshot, diff (it caught a new user), report. shellcheck clean |
| `backup.sh` | Run for real, archive and checksum verified. shellcheck clean |
| `rotate-passwords.sh` | Run for real on test users: password hashes changed, file is mode 600, blackteam skipped. shellcheck clean |
| `harden-ssh.sh` | Run against a STUB sshd only (dry run, apply, failure and restore paths). Not tested against a real sshd. shellcheck clean |
| `credcheck.sh` | Run for real on Ubuntu with planted fakes: a PAM module not owned by a package, a `pam_exec` line, a modified setuid binary, a fake `sudo`, a `sudo` alias in .bashrc, and an `strace` attached to a process. All were flagged and then removed. The outbound-connection filter was tested against a fake `ss` only (the sandbox has no `ss`). Not run on real Ubuntu 26.04, which uses Rust sudo and coreutils. shellcheck clean |
| `svc-check.sh` | Its helper functions (port check, banner read, HTTP code) tested against local fake FTP, SSH and HTTP servers. The full loop was not run against a real TCDC network |
| All `.ps1` | Syntax checked with a parser only. NEVER RUN. They must be run on a Windows practice VM first (rule R24 asks for good-faith testing before the event) |

Test everything on practice VMs that look like your boxes (Ubuntu 26.04, Windows Server 2025 with AD, Windows 11 with Mosquitto). Ubuntu 26.04 replaces some core utilities and sudo with Rust versions, so test the Linux scripts there specifically.

## Known limits

- The Linux audit cannot see inside encrypted traffic or kernel rootkits. It finds the common, cheap persistence red teams use.
- `Audit-Windows.ps1` reads current-user autorun keys for whoever runs it, not every user.
- `Audit-AD.ps1` checks the domain root ACL for replication rights, not every object.
- Audit subcategory names in `Enable-WinAuditing.ps1` are English.
- None of this replaces a person watching the scoreboard.
