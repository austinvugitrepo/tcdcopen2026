#!/usr/bin/env bash
# TCDC blue team: hunt for malware, C2 and DNS hijacking on ns1.
#
# CHANGES NOTHING. Looks for the things that turn a DNS server into an attacker's tool:
#   - something other than BIND/Unbound answering on port 53 (rogue resolver, DNS tunnel)
#   - a second or replaced DNS server process, LD_PRELOAD, libraries no package owns
#   - modified BIND/Unbound package files (dpkg -V)
#   - DNS tunnel and C2 tools, reverse shells, programs run from /tmp or /dev/shm
#   - outbound connections to addresses outside 10.0.0.0/8
#   - forwarders sending your queries somewhere else
#   - records pointing outside your network (hijacked names)
#   - cron jobs and admin-made systemd units that touch DNS
#   - query-log signs of DNS tunnelling (very long names), if query logging is on
#
# Prints FLAG: (look now) and NOTE: lines, and saves a copy. A FLAG is a lead,
# not proof. Never kill Wazuh, auditd or cloud-init/xe-guest processes (R7, R15).
# Pairs with linux/credcheck.sh and linux/audit.sh in tcdc-blue-toolkit, which
# cover PAM, sudo, SSH keys and general persistence.
#
# Usage: sudo ./dns-hunt.sh
# Env:   OUT_DIR (default /var/tmp/tcdc-audit), LOG_MIN (default 60, query-log window)
set -uo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 2; fi

OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
LOG_MIN="${LOG_MIN:-60}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/dns-hunt-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

FLAGS=0
flag() { FLAGS=$((FLAGS + 1)); printf 'FLAG: %s\n' "$*"; }
note() { printf 'NOTE: %s\n' "$*"; }
ok()   { printf 'OK:   %s\n' "$*"; }
sec()  { printf '\n=== %s ===\n' "$*"; }
# True if the address is inside 10/8 or loopback (IPv4, IPv6, IPv4-mapped).
internal() { [[ "$1" =~ ^(10\.|127\.|::1$|::ffff:10\.|::ffff:127\.|\[::1\]|\*|0\.0\.0\.0) ]]; }

bind_stmts() {
  named-checkconf -p 2>/dev/null | awk '
    { text = text $0 " " }
    END {
      n = length(text); depth = 0; buf = ""; top = ""
      for (i = 1; i <= n; i++) {
        c = substr(text, i, 1)
        if (c == "{") { if (depth == 0) { top = buf; buf = "" } else buf = buf c; depth++; continue }
        if (c == "}") { depth--; if (depth > 0) buf = buf c; continue }
        if (c == ";") {
          if (depth == 1) {
            s = buf; gsub(/[ \t]+/, " ", s); gsub(/^ | $/, "", s)
            t = top; gsub(/[ \t]+/, " ", t); gsub(/^ | $/, "", t)
            if (s != "") print t "\t" s
            buf = ""
          } else if (depth == 0) buf = ""
          else buf = buf c
          continue
        }
        buf = buf c
      }
    }'
}

bind_zone_files() {
  local dir
  dir="$(printf '%s\n' "$STMTS" | awk -F'\t' '$1 == "options" && $2 ~ /^directory / { s = $2; sub(/^directory "/, "", s); sub(/"$/, "", s); print s }')"
  printf '%s\n' "$STMTS" | awk -F'\t' -v dir="${dir:-/var/cache/bind}" '
    $1 ~ /^zone "/ && $2 ~ /^file "/ {
      z = $1; sub(/^zone "/, "", z); sub(/".*/, "", z)
      f = $2; sub(/^file "/, "", f); sub(/"$/, "", f)
      if (f !~ /^\//) f = dir "/" f
      if (z ~ /^(localhost|127\.in-addr\.arpa|0\.in-addr\.arpa|255\.in-addr\.arpa|\.)$/) next
      print z "\t" f
    }'
}

STMTS=""
command -v named-checkconf >/dev/null 2>&1 && STMTS="$(bind_stmts)"
echo "TCDC DNS hunt  host=$(hostname)  $(date '+%F %T')"

sec "Who answers on port 53"
if command -v ss >/dev/null 2>&1; then
  while read -r line; do
    echo "  $line"
    procs="$(printf '%s' "$line" | grep -o '(("[^"]*"' | tr -d '("' | sort -u)"
    for p in $procs; do
      case "$p" in
        named|unbound|systemd-resolve) ;;
        dnsmasq) note "dnsmasq on port 53. Expected on this box?" ;;
        *) flag "$p is listening on port 53. A rogue resolver or DNS tunnel endpoint? ($line)" ;;
      esac
    done
    [ -n "$procs" ] || note "could not read which process owns this listener (run with sudo): $line"
  done < <(ss -lntupH '( sport = :53 )' 2>/dev/null | awk '{ print $1, $5, $7 }' | sed 's/,fd=[0-9]*//g' | sort -u)
else
  note "ss not installed. Use: sudo netstat -lntup | grep ':53 '"
fi

sec "DNS server processes"
# Live (non-zombie) DNS server processes.
pids="$(ps -eo pid=,stat=,comm= | awk '($3 == "named" || $3 == "unbound") && $2 !~ /^Z/ { print $1 }')"
[ -n "$pids" ] || flag "no named or unbound process is running"
n_named="$(ps -eo stat=,comm= | awk '$2 == "named" && $1 !~ /^Z/' | wc -l)"
if [ "${n_named:-0}" -gt 1 ]; then flag "$n_named named processes. Normal is one. A second instance can answer instead of yours"; fi
for pid in $pids; do
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
  user="$(ps -o user= -p "$pid" 2>/dev/null)"
  echo "  pid $pid user=$user exe=$exe"
  case "$exe" in
    '') note "could not read /proc/$pid/exe (run with sudo on the real box)" ;;
    *'(deleted)'*) flag "pid $pid runs a DELETED binary ($exe): replaced while running" ;;
    /usr/sbin/named|/usr/sbin/unbound) ;;
    *) flag "pid $pid runs from an unexpected path: $exe" ;;
  esac
  if [ -r "/proc/$pid/environ" ] && tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q '^LD_PRELOAD='; then
    flag "pid $pid has LD_PRELOAD set: $(tr '\0' '\n' < "/proc/$pid/environ" | grep '^LD_PRELOAD=')"
  fi
  while read -r lib; do
    if ! dpkg -S "$lib" >/dev/null 2>&1 && ! dpkg -S "${lib#/usr}" >/dev/null 2>&1 && ! dpkg -S "/usr$lib" >/dev/null 2>&1; then
      flag "pid $pid has a library loaded that no package owns: $lib"
    fi
  done < <(awk '$6 ~ /\.so/ { print $6 }' "/proc/$pid/maps" 2>/dev/null | sort -u)
done

sec "BIND / Unbound package files (dpkg -V)"
pkgs="$(dpkg-query -W -f='${Package}\n' 'bind9*' 'libbind*' 'unbound*' 'libunbound*' 2>/dev/null | sort -u | tr '\n' ' ')"
if [ -n "${pkgs// /}" ]; then
  # shellcheck disable=SC2086
  vout="$(dpkg -V $pkgs 2>/dev/null)"
  if [ -z "$(printf '%s\n' "$vout" | grep -Ev '^missing[[:space:]]+/usr/share/(doc|man|info|locale|lintian)/' | grep .)" ]; then ok "no package files changed ($pkgs)"; fi
  while read -r line; do
    [ -n "$line" ] || continue
    # Minimized Ubuntu images strip docs and man pages; "missing" there is normal.
    if printf '%s' "$line" | grep -Eq '^missing[[:space:]]+/usr/share/(doc|man|info|locale|lintian)/'; then continue; fi
    if printf '%s' "$line" | awk '{ exit !($2 == "c") }'; then
      note "config file edited (expected if you or the image changed it): $line"
    else
      flag "package file changed (binary or library replaced?): $line"
    fi
  done <<< "$vout"
fi

sec "Preload hooks"
if [ -s /etc/ld.so.preload ]; then flag "/etc/ld.so.preload is set: $(tr '\n' ' ' < /etc/ld.so.preload)"; else ok "no /etc/ld.so.preload"; fi

sec "Tunnel, C2 and reverse-shell processes"
found=0
while read -r pid user args; do
  [ "$pid" = "$$" ] && continue
  flag "pid $pid ($user): $args"
  found=1
done < <(ps -eo pid=,user=,args= | grep -Ei '(^|[ /])(iodined?|dnscat2?|dns2tcpd?|dnstt-(server|client)|chisel|ligolo|sliver|frpc|ngrok|gost|ncat|socat)( |$)|/dev/tcp/|bash -i|nc .*-e |python[0-9.]* .*socket|perl .*socket' | grep -v -e 'grep -Ei' -e 'dns-hunt.sh')
[ "$found" -eq 0 ] && ok "none seen"
while read -r f; do
  flag "executable file in a temp folder: $f ($(stat -c '%U %y' "$f" | cut -d. -f1))"
done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | grep -v "^$OUT_DIR")

sec "Outbound connections"
if command -v ss >/dev/null 2>&1; then
  outside=0
  while read -r _ _ _ local peer procinfo; do
    addr="${peer%:*}"; port="${peer##*:}"
    internal "$addr" && continue
    outside=1
    pname="$(printf '%s' "$procinfo" | grep -o '(("[^"]*"' | tr -d '("' | head -n1)"
    if [ "$port" = 53 ] && [[ "$pname" =~ ^(named|unbound)$ ]]; then
      note "$pname asks $peer (recursion or forwarding; expected if ns1 resolves outside names)"
    else
      flag "connection to $peer from ${pname:-unknown} (local $local)"
    fi
  done < <(ss -tnpH state established 2>/dev/null | awk '{ print "x", "x", "x", $3, $4, $5 }')
  [ "$outside" -eq 0 ] && ok "no established connections outside 10.0.0.0/8"
fi

sec "Where your queries are forwarded"
fw=""
if [ -n "$STMTS" ]; then
  fw="$(printf '%s\n' "$STMTS" | awk -F'\t' '$2 ~ /^forwarders / || $2 == "type forward" { print $1 ": " $2 }')"
fi
if [ -d /etc/unbound ]; then
  fw="$fw$(grep -rhE '^[[:space:]]*(forward-addr|forward-host|stub-addr):' /etc/unbound 2>/dev/null | sed 's/^[[:space:]]*/unbound: /')"
fi
if [ -z "$fw" ]; then ok "no forwarders configured"; fi
while read -r line; do
  [ -n "$line" ] || continue
  outside="$(printf '%s' "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '^(10|127)\.' | tr '\n' ' ')"
  if [ -n "$outside" ]; then flag "queries forwarded outside 10.0.0.0/8 ($outside): $line. Expected?"; else note "$line"; fi
done <<< "$fw"

sec "Records pointing outside your network"
if [ -n "$STMTS" ]; then
  while IFS=$'\t' read -r z f; do
    [ -n "$z" ] && [ -f "$f" ] || continue
    [ -e "$f.jnl" ] && rndc sync "$z" >/dev/null 2>&1   # include recent dynamic updates
    while read -r name _ _ type data; do
      case "$type" in
        A) [[ "$data" =~ ^(10|127)\. ]] || flag "$z: $name A $data is outside 10.0.0.0/8. Hijacked?" ;;
        AAAA) note "$z: $name AAAA $data (check it is yours)" ;;
      esac
    done < <(named-checkzone -D -o - "$z" "$f" 2>/dev/null | awk '$3 == "IN" && ($4 == "A" || $4 == "AAAA")')
  done < <(bind_zone_files)
fi
if command -v unbound-control >/dev/null 2>&1 && pgrep -x unbound >/dev/null 2>&1; then
  while read -r name _ _ type data; do
    [ "$type" = A ] || continue
    [[ "$data" =~ ^(10|127)\. ]] || flag "unbound local-data: $name A $data is outside 10.0.0.0/8"
  done < <(unbound-control list_local_data 2>/dev/null)
fi

sec "Cron jobs and admin-made systemd units that touch DNS"
hits=0
while read -r f; do
  flag "$f mentions DNS tools or files. Read it: $(grep -hEm1 'rndc|nsupdate|named|/etc/bind|unbound' "$f")"
  hits=1
done < <(grep -rlE 'rndc|nsupdate|named|/etc/bind|unbound' /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron/crontabs /etc/systemd/system /run/systemd/system 2>/dev/null | grep -vE '/etc/systemd/system/(multi-user|sockets|timers)\.target\.wants/' )
[ "$hits" -eq 0 ] && ok "none"

sec "Query log: signs of DNS tunnelling (last $LOG_MIN min)"
qlog=""
if command -v journalctl >/dev/null 2>&1; then
  qlog="$(journalctl -u named -u bind9 -u unbound --since "-${LOG_MIN} min" --no-pager 2>/dev/null | grep -E 'query: |info: [0-9.]+ ' )"
fi
if [ -z "$qlog" ] && [ -d /var/log/named ]; then qlog="$(grep -h 'query: ' /var/log/named/* 2>/dev/null | tail -n 20000)"; fi
if [ -z "$qlog" ]; then
  note "no query log lines found. Query logging is probably off. Turn it on for a while with 'sudo rndc querylog on' (it is verbose; turn it off with 'rndc querylog off')"
else
  total="$(printf '%s\n' "$qlog" | wc -l)"
  long="$(printf '%s\n' "$qlog" | grep -oE 'query: [^ ]+' | awk '{ n = $2; m = 0; c = split(n, a, "."); for (i = 1; i <= c; i++) if (length(a[i]) > m) m = length(a[i]); if (m >= 40 || length(n) >= 100) print n }')"
  txt="$(printf '%s\n' "$qlog" | grep -cE ' IN (TXT|NULL) ')"
  echo "  $total query lines, $txt TXT/NULL queries"
  if [ -n "$long" ]; then
    flag "$(printf '%s\n' "$long" | wc -l) queries with very long labels (typical of DNS tunnels). Examples:"
    printf '%s\n' "$long" | sort | uniq -c | sort -rn | head -n 5 | sed 's/^/    /'
  else
    ok "no very long query names"
  fi
fi

echo
echo "Done. $FLAGS FLAG line(s). Saved: $REPORT"
