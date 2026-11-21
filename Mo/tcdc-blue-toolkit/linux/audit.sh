#!/usr/bin/env bash
# TCDC blue team: read-only host audit for Ubuntu boxes.
#
# This script CHANGES NOTHING on the system. It only reads files and runs
# listing commands. It makes no network connections.
#
# Usage (run as root so it can read /etc/shadow and every home directory):
#   sudo ./audit.sh report      Print findings and save a copy (default)
#   sudo ./audit.sh snapshot    Save a baseline of persistence related state
#   sudo ./audit.sh diff        Compare current state to the saved baseline
#
# Env vars:
#   OUT_DIR      where reports and the baseline are kept (default /var/tmp/tcdc-audit)
#   RECENT_MIN   minutes for the "recently modified files" check (default 60)
#
# Suggested use: run "snapshot" in the first minutes, then "diff" every
# 15 to 30 minutes. Anything that shows up in the diff is new since baseline.

set -u
export LC_ALL=C

OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
RECENT_MIN="${RECENT_MIN:-60}"
MODE="${1:-report}"
BASELINE="$OUT_DIR/baseline.state"
STAMP="$(date +%Y%m%d-%H%M%S)"

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root. Some checks will be incomplete." >&2
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

section() { printf '\n=== %s ===\n' "$1"; }

# Home directories to inspect (root plus every real user home).
homes() {
  { echo /root; awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $6}' /etc/passwd; } | sort -u
}

# Stable, comparable state. Used by snapshot, diff and report.
collect_state() {
  section "passwd (name:uid:gid:shell)"
  awk -F: '{print $1":"$3":"$4":"$7}' /etc/passwd | sort

  section "accounts with UID 0"
  awk -F: '$3==0 {print $1}' /etc/passwd

  section "accounts with EMPTY password field"
  if [ -r /etc/shadow ]; then awk -F: '$2=="" {print $1}' /etc/shadow; else echo "(cannot read /etc/shadow)"; fi

  section "privileged groups"
  getent group sudo admin wheel root adm 2>/dev/null | sort

  section "sudoers (non-comment lines)"
  { cat /etc/sudoers 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null; } | grep -Ev '^\s*(#|$)'

  section "authorized_keys (path, line count, key fingerprints)"
  for h in $(homes); do
    f="$h/.ssh/authorized_keys"
    if [ -f "$f" ]; then
      echo "$f lines=$(grep -Evc '^\s*(#|$)' "$f") sha256=$(sha256sum "$f" | cut -d' ' -f1)"
      if have ssh-keygen; then
        ssh-keygen -lf "$f" 2>/dev/null | sed "s|^|    |"
      fi
    fi
  done
  for f in /etc/ssh/authorized_keys /etc/ssh/authorized_keys.d/*; do
    [ -f "$f" ] && echo "$f sha256=$(sha256sum "$f" | cut -d' ' -f1)"
  done

  section "sshd effective settings (key items)"
  if have sshd; then
    sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|allowusers|allowgroups|maxauthtries|usepam|permituserenvironment|port|listenaddress) '
  else
    echo "(sshd not installed)"
  fi

  section "cron files (hash)"
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done
  echo "-- at jobs"
  if have atq; then atq 2>/dev/null; else echo "(atq not installed)"; fi

  section "systemd: enabled unit files"
  if have systemctl; then systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort; fi

  section "systemd: timers"
  if have systemctl; then systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{print $(NF-1)}' | sort -u; fi

  section "systemd: custom unit files in /etc and user dirs (hash)"
  find /etc/systemd /run/systemd/system /etc/xdg/systemd -type f 2>/dev/null | sort | while read -r f; do
    echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done
  for h in $(homes); do
    find "$h/.config/systemd" -type f 2>/dev/null | sort | while read -r f; do
      echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
    done
  done

  section "shell startup files (hash)"
  for f in /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/* /etc/update-motd.d/*; do
    [ -f "$f" ] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done
  for h in $(homes); do
    for n in .bashrc .profile .bash_profile .bash_login .bash_logout .zshrc; do
      [ -f "$h/$n" ] && echo "$h/$n $(sha256sum "$h/$n" | cut -d' ' -f1)"
    done
  done

  section "PAM config (hash)"
  for f in /etc/pam.d/*; do
    [ -f "$f" ] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done

  section "LD_PRELOAD style hooks"
  if [ -e /etc/ld.so.preload ]; then echo "/etc/ld.so.preload EXISTS:"; cat /etc/ld.so.preload; else echo "/etc/ld.so.preload not present"; fi
  for f in /etc/ld.so.conf /etc/ld.so.conf.d/*; do
    [ -f "$f" ] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done

  section "SUID/SGID binaries"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort

  section "loaded kernel modules"
  if have lsmod; then lsmod | awk 'NR>1 {print $1}' | sort; fi

  section "listening sockets (no PIDs, for stable diffs)"
  if have ss; then ss -tuln 2>/dev/null | awk 'NR>1 {print $1, $5}' | sort -u; elif have netstat; then netstat -tuln | awk 'NR>2 {print $1, $4}' | sort -u; fi

  section "hosts and resolver files (hash)"
  for f in /etc/hosts /etc/resolv.conf /etc/nsswitch.conf; do
    [ -f "$f" ] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done
}

# Extra, volatile checks that are useful in a report but too noisy to diff.
report_extras() {
  section "logged in now"
  who 2>/dev/null
  echo "-- last 15 logins"
  last -n 15 2>/dev/null

  section "listening sockets with owning process"
  if have ss; then ss -tulnp 2>/dev/null; fi

  section "established connections"
  if have ss; then ss -tnp state established 2>/dev/null; fi

  section "processes whose binary was deleted from disk"
  found=0
  for e in /proc/[0-9]*/exe; do
    t="$(readlink "$e" 2>/dev/null)"
    case "$t" in *"(deleted)") echo "$e -> $t"; found=1 ;; esac
  done
  [ "$found" -eq 0 ] && echo "none found"

  section "processes started from /tmp, /var/tmp, /dev/shm"
  found=0
  for e in /proc/[0-9]*/exe; do
    t="$(readlink "$e" 2>/dev/null)"
    case "$t" in /tmp/*|/var/tmp/*|/dev/shm/*) echo "$e -> $t"; found=1 ;; esac
  done
  [ "$found" -eq 0 ] && echo "none found"

  section "web or service daemons with shell children (possible web shell)"
  ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null | awk '
    { pid=$1; ppid=$2; comm[pid]=$4; parent[pid]=ppid; line[pid]=$0 }
    END {
      for (p in comm) {
        if (comm[p] ~ /^(sh|bash|dash|python3?|perl|nc|ncat|socat)$/ && comm[parent[p]] ~ /^(apache2|httpd|nginx|php-fpm|php-fpm[0-9.]*|vsftpd|proftpd|named|tomcat|java)$/)
          print line[p]
      }
    }' | grep . || echo "none found"

  section "files modified in the last ${RECENT_MIN} minutes (key dirs)"
  find /etc /usr/local /opt /srv /var/www /root /home -xdev -type f -mmin "-$RECENT_MIN" \
    -not -path '/var/tmp/tcdc-audit/*' -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort | tail -n 200

  section "world-writable files in web roots"
  for d in /var/www /srv; do
    [ -d "$d" ] && find "$d" -xdev -type f -perm -0002 -printf '%m %u %p\n' 2>/dev/null | head -n 100
  done

  section "script files inside likely upload dirs"
  for d in /var/www /srv; do
    [ -d "$d" ] && find "$d" -xdev -type f \( -ipath '*upload*' -o -ipath '*files*' -o -ipath '*media*' \) \
      \( -name '*.php' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.py' -o -name '*.pl' -o -name '*.cgi' \) 2>/dev/null | head -n 100
  done

  section "hidden files in web roots and /tmp"
  find /var/www /srv /tmp /var/tmp /dev/shm -xdev -name '.*' -type f 2>/dev/null | head -n 100

  section "FLAGS (things worth a human look)"
  flags=0
  extra0="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)"
  if [ -n "$extra0" ]; then echo "FLAG: extra UID 0 account(s): $extra0"; flags=$((flags+1)); fi
  if [ -r /etc/shadow ]; then
    empty="$(awk -F: '$2=="" {print $1}' /etc/shadow)"
    if [ -n "$empty" ]; then echo "FLAG: empty password field: $empty"; flags=$((flags+1)); fi
  fi
  if [ -e /etc/ld.so.preload ]; then echo "FLAG: /etc/ld.so.preload exists"; flags=$((flags+1)); fi
  for h in $(homes); do
    if [ -f "$h/.ssh/authorized_keys" ]; then echo "NOTE: $h/.ssh/authorized_keys exists (verify every key is yours)"; fi
  done
  if have sshd; then
    sshd -T 2>/dev/null | grep -Ei '^(authorizedkeyscommand|permitemptypasswords yes|permituserenvironment yes)' | sed 's/^/FLAG: sshd setting: /' && true
  fi
  echo "flag count (not counting NOTE lines): $flags"
}

case "$MODE" in
  report)
    OUTFILE="$OUT_DIR/report-$STAMP.txt"
    {
      echo "TCDC audit report  host=$(hostname)  time=$(date)  user=$(id -un)"
      collect_state
      report_extras
    } | tee "$OUTFILE"
    echo
    echo "Saved: $OUTFILE"
    ;;
  snapshot)
    collect_state > "$BASELINE"
    chmod 600 "$BASELINE"
    echo "Baseline saved: $BASELINE ($(wc -l < "$BASELINE") lines) at $(date)"
    ;;
  diff)
    if [ ! -f "$BASELINE" ]; then
      echo "No baseline yet. Run: sudo $0 snapshot" >&2
      exit 1
    fi
    NOW="$OUT_DIR/now-$STAMP.state"
    collect_state > "$NOW"
    echo "Comparing baseline ($(stat -c %y "$BASELINE" | cut -d. -f1)) to now ($(date '+%F %T'))"
    if diff -u "$BASELINE" "$NOW"; then
      echo "NO CHANGES since baseline."
    else
      echo
      echo "CHANGES FOUND. Lines starting with + are new, - are gone. Investigate each one."
    fi
    ;;
  *)
    echo "Usage: $0 [report|snapshot|diff]" >&2
    exit 2
    ;;
esac
