# TCDC tool downloads

Download everything on this page before Saturday, to the jumpbox or a laptop, and keep a second copy on a USB or shared folder. Assume the competition boxes cannot reach the internet.

Rules (TCDC packet):
- R21: all tools must be free. Everything below is free.
- R20: ask Black Team in your team channel whether they want this list on the Tool Links form. Submit by Friday, Nov 20.
- R24: test every tool on a practice VM first.
- R23: never use an option that uploads files or hashes to a website.

## Windows (ad, mqtt)

| Tool | Where to get it | Use |
|---|---|---|
| Sysinternals Suite | https://download.sysinternals.com/files/SysinternalsSuite.zip | Autoruns, Process Explorer, TCPView, Process Monitor, Sigcheck, strings, Sysmon in one zip |
| Autoruns command line (`autorunsc64.exe`) | Inside the Sysinternals zip | Baseline: `autorunsc64.exe -accepteula -a * -s -h -c > autoruns-baseline.csv`. Run it again later and compare. Do not use `-vt` (it uploads hashes) |
| Sysmon (`Sysmon64.exe`) | Inside the Sysinternals zip | Detailed process, network and file logging. It adds a driver and service, so test on a practice VM before deciding |
| Sysmon config | https://github.com/SwiftOnSecurity/sysmon-config (file `sysmonconfig-export.xml`) | Install: `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Wireshark | https://www.wireshark.org/download.html | Check whether passwords leave a box. The installer includes Npcap |
| Npcap (only if installed separately) | https://npcap.com/ | Free for up to 5 systems |
| 7-Zip (optional) | https://www.7-zip.org/ | Unpacking. PowerShell `Expand-Archive` also works |

The toolkit's `.ps1` scripts need nothing extra. PowerShell is built in.

## Ubuntu (ns1, ftp-archive, artifactorium, ssh-workstation, ipcam)

Check first that `sudo apt update` works on the box. If it does:

```
sudo apt install -y nmap tcpdump strace debsums lsof dnsutils curl git unzip
```

If `apt` cannot reach the internet, download the packages on a machine that can and copy them over:

```
apt download nmap tcpdump strace debsums lsof
```

| Tool | Use |
|---|---|
| `debsums` | Verify installed files against their packages |
| `strace`, `tcpdump` | Look at what a suspicious process or connection is doing |
| `lsof` | See which processes hold which files and ports |
| `dnsutils` (`dig`) | DNS checks, used by `svc-check.sh` |
| `nmap` | Confirm what is really listening |
| `curl`, `git`, `unzip` | Move files and pull the repo |

Optional, if you have time to test:
- **Lynis**: `git clone https://github.com/CISOfy/lynis`, then `cd lynis && ./lynis audit system`. No installation. It prints hardening suggestions. Treat them as ideas, because some would break scored services.
- **rkhunter** or **chkrootkit** (`apt install`): rootkit scanners. They throw false positives on a fresh box, so use them to look for something specific.

## Jumpbox

| Tool | Where to get it | Use |
|---|---|---|
| nmap | https://nmap.org/download.html or `apt install nmap` | Check what is listening on your own boxes. Your own subnets only, and no DoS (R19) |
| Wireshark or `tcpdump` | https://www.wireshark.org/download.html | Look at traffic from the jumpbox side |
| `python3 -m http.server 8000` | Built in | Serve the toolkit folder so the other boxes can download it |
| `scp`, `git` | Built in | Move files and pull the repo |

The jumpbox's Remmina RDP clients (ports 3007 to 3008) can also copy files to the Windows boxes.

## Before you trust a download

- Windows: `Get-AuthenticodeSignature .\Autoruns64.exe` should say `Valid` with a Microsoft signer.
- Wireshark's installer is signed by the Wireshark Foundation.
- Download only from the official pages above, never from a download-aggregator site.
- Write the version and date of each download in the team log.
