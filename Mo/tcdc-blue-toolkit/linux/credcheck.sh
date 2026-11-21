#!/usr/bin/env bash
# TCDC blue team: read-only hunt for password theft on Ubuntu boxes.
#
# This script CHANGES NOTHING. It only reads files and runs listing commands.
# It makes no network connections.
#
# It looks for the usual ways red team captures passwords on Linux:
#   - a PAM module or pam_exec hook that logs what users type
#   - a replaced sshd, sudo, su, login or passwd binary
#   - a process tracing sshd or sudo (strace, gdb), or a sniffer or keylogger
#   - shell startup files that wrap sudo, ssh or su
#   - fake sudo/ssh/su programs placed earlier in PATH
#   - LD_PRELOAD hooks
#   - established connections from this box to outside addresses
#   - a service flooding the journal with errors (a broken stealer is noisy)
#
# Usage (run as root):
#   sudo ./credcheck.sh
#
# Env vars:
#   RECENT_MIN   minutes for "recently modified" checks (default 120)
#   OUT_DIR      where a copy of the report is saved (default /var/tmp/tcdc-audit)
#
# Every suspicious item is printed as a line starting with "FLAG:".
# A FLAG is a lead to look at, not proof. Package updates and your own
# changes can trigger some of them.

set -u
export LC_ALL=C

RECENT_MIN="${RECENT_MIN:-120}"
OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
STAMP="$(date +%Y%m%d-%H%M%S)"
FLAGS=0

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root. Some checks will be incomplete." >&2
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
REPORT="$OUT_DIR/credcheck-$(hostname)-$STAMP.txt"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n=== %s ===\n' "$1"; }
flag() { echo "FLAG: $*"; FLAGS=$((FLAGS + 1)); }

# Home directories to inspect (root plus every real user home).
homes() {
  echo /root
  for d in /home/*; do [ -d "$d" ] && echo "$d"; done
}

run() {
  echo "TCDC credcheck on $(hostname) at $(date)"
  echo "Read-only. RECENT_MIN=$RECENT_MIN"

  # ---------------------------------------------------------------- PAM
  section "PAM: modules referenced that are not owned by a package"
  # Collect every module named in /etc/pam.d, then check where it lives.
  mods="$(grep -hEv '^\s*#|^\s*$|^@include' /etc/pam.d/* 2>/dev/null \
    | grep -oE '[A-Za-z0-9_.-]+\.so' | sort -u)"
  for m in $mods; do
    path=""
    for dir in /lib/security /lib/*/security /usr/lib/security /usr/lib/*/security; do
      [ -e "$dir/$m" ] && { path="$dir/$m"; break; }
    done
    if [ -z "$path" ]; then
      echo "NOTE: PAM module $m is referenced but was not found in the usual directories (often harmless: an optional module that was removed)"
      continue
    fi
    if have dpkg; then
      if ! dpkg -S "$path" >/dev/null 2>&1; then
        real="$(readlink -f "$path" 2>/dev/null)"
        if [ -n "$real" ] && dpkg -S "$real" >/dev/null 2>&1; then :; else
          flag "PAM module $path is not owned by any package"
        fi
      fi
    fi
  done
  echo "(checked $(echo "$mods" | wc -w) modules)"

  section "PAM: lines that run programs or scripts"
  hits="$(grep -nE 'pam_exec|pam_script|pam_python|pam_unix_hook|\bexpose_authtok\b' /etc/pam.d/* 2>/dev/null | grep -v ':\s*#')"
  if [ -n "$hits" ]; then
    echo "$hits"
    flag "PAM config runs an external program (pam_exec, pam_script or similar)"
  else
    echo "none found"
  fi

  section "PAM: files changed in the last $RECENT_MIN minutes"
  recent="$(find /etc/pam.d /etc/security /lib/security /lib/*/security /usr/lib/*/security \
    -type f -mmin "-$RECENT_MIN" 2>/dev/null)"
  if [ -n "$recent" ]; then
    echo "$recent"
    flag "PAM related files changed recently"
  else
    echo "none"
  fi

  # --------------------------------------------------------- binaries
  section "Package verification of login related programs"
  if have dpkg; then
    pkgs="openssh-server openssh-client sudo sudo-rs login passwd libpam-modules libpam-runtime libpam0g util-linux shadow"
    for p in $pkgs; do
      dpkg -s "$p" >/dev/null 2>&1 || continue
      # Only report changed contents (checksum mismatch) and missing program or
      # library files. Missing docs and man pages are normal on minimal images.
      out="$(dpkg -V "$p" 2>/dev/null | awk '{ f=$1; q=$NF; if (f ~ /^..5/ && $2 != "c") print; else if (f=="missing" && q ~ /^\/(usr\/)?(bin|sbin|lib)/) print }')"
      if [ -n "$out" ]; then
        echo "package $p:"
        echo "$out"
        flag "files of package $p differ from the installed package"
      fi
    done
    echo "(dpkg -V finished. No output above means files match the packages)"
  else
    echo "dpkg not available"
  fi

  section "Where sudo, su, ssh, sshd, login and passwd resolve to"
  for c in sudo su ssh sshd login passwd; do
    p="$(command -v "$c" 2>/dev/null)"
    [ -z "$p" ] && continue
    echo "$c -> $p"
    case "$p" in
      /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*) : ;;
      *) flag "$c resolves outside the system directories: $p" ;;
    esac
  done

  section "Fake sudo/su/ssh programs in other locations"
  found=0
  for d in /usr/local/bin /usr/local/sbin /tmp /var/tmp /dev/shm /opt $(homes); do
    [ -d "$d" ] || continue
    r="$(find "$d" -maxdepth 3 -type f \( -name sudo -o -name su -o -name ssh -o -name sshd -o -name login -o -name passwd \) 2>/dev/null)"
    if [ -n "$r" ]; then echo "$r"; found=1; fi
  done
  [ "$found" -eq 1 ] && flag "programs named like login tools exist outside system directories" || echo "none found"

  section "Programs with the setuid bit changed recently"
  r="$(find / -xdev -type f -perm -4000 -mmin "-$RECENT_MIN" 2>/dev/null)"
  if [ -n "$r" ]; then echo "$r"; flag "setuid files changed recently"; else echo "none"; fi

  # ---------------------------------------------------------- hooks
  section "LD_PRELOAD style hooks"
  if [ -s /etc/ld.so.preload ]; then
    cat /etc/ld.so.preload
    flag "/etc/ld.so.preload is not empty"
  else
    echo "none"
  fi
  r=""
  for pid in /proc/[0-9]*; do
    [ -r "$pid/environ" ] || continue
    if cat "$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -q '^LD_PRELOAD='; then
      r="$r ${pid#/proc/}"
    fi
  done
  if [ -n "$r" ]; then
    echo "processes with LD_PRELOAD in their environment:$r"
    flag "some processes run with LD_PRELOAD set (pids:$r)"
  fi

  section "Shell startup files that wrap sudo, ssh or su"
  files="/etc/profile /etc/bash.bashrc /etc/environment /etc/bash_completion"
  for f in /etc/profile.d/*; do [ -f "$f" ] && files="$files $f"; done
  for h in $(homes); do
    for f in .bashrc .bash_profile .profile .bash_login .zshrc .bash_logout; do
      [ -f "$h/$f" ] && files="$files $h/$f"
    done
  done
  any=0
  for f in $files; do
    [ -f "$f" ] || continue
    r="$(grep -nE "^\s*(alias\s+(sudo|su|ssh|passwd)=|function\s+(sudo|su|ssh|passwd)\b|(sudo|su|ssh|passwd)\s*\(\)|trap\s+.*DEBUG|PROMPT_COMMAND=|export\s+LD_PRELOAD|exec\s+script\b|script\s+-)" "$f" 2>/dev/null)"
    if [ -n "$r" ]; then echo "$f:"; echo "$r"; any=1; fi
  done
  [ "$any" -eq 1 ] && flag "shell startup files wrap login commands or set hooks" || echo "none found"

  # ------------------------------------------------------- processes
  section "Processes that trace or sniff"
  # shellcheck disable=SC2009
  r="$(ps -eo pid,user,comm,args 2>/dev/null | grep -E '\b(strace|ltrace|gdb|tcpdump|tshark|dumpcap|logkeys|ttyrec|auditd-keylog|bpftrace)\b' | grep -v grep)"
  if [ -n "$r" ]; then echo "$r"; flag "tracing, sniffing or keylogging tools are running"; else echo "none"; fi

  section "Processes being traced by another process"
  any=0
  for s in /proc/[0-9]*/status; do
    tp="$(awk '/^TracerPid:/ {print $2}' "$s" 2>/dev/null)"
    if [ -n "$tp" ] && [ "$tp" != "0" ]; then
      pid="${s#/proc/}"; pid="${pid%/status}"
      echo "pid $pid ($(cat /proc/"$pid"/comm 2>/dev/null)) is traced by pid $tp ($(cat /proc/"$tp"/comm 2>/dev/null))"
      any=1
    fi
  done
  [ "$any" -eq 1 ] && flag "a process is being traced (strace style password capture)" || echo "none"

  section "Running programs whose file was deleted"
  any=0
  for e in /proc/[0-9]*/exe; do
    t="$(readlink "$e" 2>/dev/null)"
    case "$t" in *"(deleted)") echo "$e -> $t"; any=1 ;; esac
  done
  [ "$any" -eq 1 ] && flag "a running program has no file on disk" || echo "none found"

  section "Python, perl or shell scripts running as services or from odd places"
  # shellcheck disable=SC2009
  r="$(ps -eo pid,user,args 2>/dev/null | grep -E '(python|perl|ruby|node)[0-9.]* +[^ ]*(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/|/opt/|\.py|\.pl)' | grep -v grep)"
  if [ -n "$r" ]; then echo "$r"; flag "scripting interpreters are running files from odd locations"; else echo "none"; fi

  # --------------------------------------------------------- network
  section "Established connections to addresses outside 10.0.0.0/8 and loopback"
  if have ss; then
    # Output columns: Recv-Q Send-Q Local Peer [Process]. Keep lines whose peer is outside.
    r="$(ss -tnpH state established 2>/dev/null | awk '{ peer=$4; if (peer !~ /^(10\.|127\.|\[::1\]|::1)/) print $0 }')"
    if [ -n "$r" ]; then
      echo "$r"
      flag "this box has established connections to outside addresses. Check each one"
    else
      echo "none"
    fi
  else
    echo "ss not available"
  fi

  # --------------------------------------------------------- logging
  section "Noisy log sources in the last 60 minutes (a broken stealer is loud)"
  if have journalctl; then
    journalctl --no-pager --since "-60min" -p warning -o short 2>/dev/null \
      | grep -v '^--' | awk '{ id=$5; sub(/\[[0-9]+\]:?$/, "", id); sub(/:$/, "", id); c[id]++ } END { for (i in c) print c[i], i }' \
      | sort -rn | head -10
    big="$(journalctl --no-pager --since "-60min" -p warning -o short 2>/dev/null | wc -l)"
    echo "(total warning or worse lines in the last hour: $big)"
    r="$(journalctl --no-pager --since "-60min" -o short 2>/dev/null | grep -iE 'pam|python|traceback|permission denied.*(shadow|pam)' | grep -iE 'traceback|python|module' | head -5)"
    if [ -n "$r" ]; then echo "$r"; flag "journal shows python or PAM module errors. Check which program is behind them"; fi
  else
    echo "journalctl not available"
  fi

  section "Hidden or recently created files in temp locations"
  r="$(find /tmp /var/tmp /dev/shm -xdev -mmin "-$RECENT_MIN" -type f \( -name '.*' -o -name '*.py' -o -name '*.sh' -o -name '*.so' -o -name '*.pl' \) 2>/dev/null | head -30)"
  if [ -n "$r" ]; then echo "$r"; flag "hidden or script-like files appeared in temp directories"; else echo "none"; fi

  section "SUMMARY"
  echo "FLAGS raised: $FLAGS"
  echo "Report saved to: $REPORT"
}

# Run once, print to the screen and keep a copy. FLAGS is counted inside a
# subshell by the pipe, so recount from the saved text for the final number.
run 2>&1 | tee "$REPORT"
chmod 600 "$REPORT"
total="$(grep -c '^FLAG:' "$REPORT")"
echo
echo "Total FLAG lines: $total (see above). A flag is a lead, not proof."
