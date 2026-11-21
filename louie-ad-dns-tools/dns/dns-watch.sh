#!/usr/bin/env bash
# TCDC blue team: live watch on ns1. Leave it running in a spare terminal.
#
# Read-only. Every INTERVAL seconds it checks ns1 and prints a line ONLY when
# something changes, so a quiet screen means a quiet box:
#   - DNS stops (or starts) answering for the scored record, on 127.0.0.1 or ns1's IP
#   - the DNS server process restarts, dies, or a second one appears
#   - a new program starts listening on port 53, or a listener disappears
#   - records change compared with the dns-baseline.sh snapshot (only NEW differences
#     are printed, not the same ones every round)
#   - a DNS config or zone file changes
#   - a new connection to an address outside 10.0.0.0/8 appears
#   - a DNS tunnel / C2 / reverse-shell process appears
# A heartbeat line every 5 minutes shows it is still running.
#
# Take a snapshot first (sudo ./dns-baseline.sh snapshot) so record changes can be
# seen. Stop it (Ctrl+C) before hands-off periods (rule R10).
#
# Usage:   sudo ./dns-watch.sh <team-id> [--name NAME] [--interval SECONDS]
# Example: sudo ./dns-watch.sh 5 --name artifactorium.team5.playtcdc.org
# Env:     OUT_DIR (default /var/tmp/tcdc-audit), NS_EXT (default 10.(100+id).10.53)
set -uo pipefail
umask 077

TEAM="${1:-}"
if ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
  echo "Usage: sudo $0 <team-id> [--name NAME] [--interval SECONDS]" >&2
  exit 2
fi
shift
NAME="ns1.team$TEAM.playtcdc.org"
INTERVAL=30
while [ $# -gt 0 ]; do
  case "$1" in
    --name) shift; NAME="${1:?--name needs a value}" ;;
    --interval) shift; INTERVAL="${1:?--interval needs a value}" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 2; fi
command -v dig >/dev/null 2>&1 || { echo "dig not found. Install it: sudo apt install dnsutils" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
NS_EXT="${NS_EXT:-10.$((100 + TEAM)).10.53}"
OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/dns-watch-$(date +%Y%m%d-%H%M%S).log"
STATE="$(mktemp -d "$OUT_DIR/.dns-watch.XXXXXX")"
trap 'rm -rf "$STATE"' EXIT
if [ -t 1 ]; then RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; RST=$'\e[0m'; else RED=""; YEL=""; GRN=""; RST=""; fi

alert() { # level message
  local color="$YEL"
  case "$1" in HIGH) color="$RED" ;; OK) color="$GRN" ;; esac
  printf '%s%s %-4s %s%s\n' "$color" "$(date +%H:%M:%S)" "$1" "$2" "$RST"
  printf '%s %s %s\n' "$(date '+%F %T')" "$1" "$2" >> "$LOG"
}

resolves() {
  local out
  out="$(dig @"$1" "$NAME" A +time=2 +tries=1 +noall +comments +answer 2>/dev/null)" || return 1
  printf '%s\n' "$out" | grep -q 'status: NOERROR' || return 1
  printf '%s\n' "$out" | grep -v '^;' | grep -q '[^[:space:]]'
}

# Each probe writes its current view to a file; the loop compares with last round.
probe_health()    { local s; for s in 127.0.0.1 "$NS_EXT"; do if resolves "$s"; then echo "$s up"; else echo "$s DOWN"; fi; done; }
probe_procs()     { ps -eo pid=,stat=,comm= | awk '($3 == "named" || $3 == "unbound") && $2 !~ /^Z/ { print $3 " pid " $1 }'; }
probe_listeners() { ss -lntupH '( sport = :53 )' 2>/dev/null | awk '{ p = $7; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); print $1, $5, (p == "" ? "?" : p) }'; }
probe_files()     { find /etc/bind /var/lib/bind /var/cache/bind /etc/unbound -type f ! -name '*.jnl' ! -name 'managed-keys.bind*' ! -name '*.mkeys*' -printf '%p %T@\n' 2>/dev/null | sort; }
probe_conns()     { ss -tnpH state established 2>/dev/null | awk '{ print $4, $5 }' | grep -Ev '^(10\.|127\.|\[::1\]|\[::ffff:10\.|\[::ffff:127\.)' | sed -E 's/,fd=[0-9]+//g' | sort -u; }
probe_badprocs()  { ps -eo pid=,args= | grep -Ei '(^|[ /])(iodined?|dnscat2?|dns2tcpd?|dnstt-(server|client)|chisel|ligolo|sliver|frpc|ngrok|gost|ncat|socat)( |$)|/dev/tcp/|bash -i|nc .*-e ' | grep -v -e 'grep -Ei' -e 'dns-watch.sh' | sort; }
probe_records()   { if [ -d "$OUT_DIR/dns-baseline" ]; then "$HERE/dns-baseline.sh" diff 2>/dev/null | grep '^FLAG:' | sort; fi; }

# compare NAME: prints lines that appeared (+) and disappeared (-) since last round
changes() {
  local name="$1" new="$STATE/$1.new" old="$STATE/$1.old"
  "probe_$name" | LC_ALL=C sort -u > "$new"
  if [ -f "$old" ]; then
    LC_ALL=C comm -13 "$old" "$new" | sed 's/^/+ /'
    LC_ALL=C comm -23 "$old" "$new" | sed 's/^/- /'
  fi
  mv "$new" "$old"
}

echo "Watching ns1 (record $NAME, ns1 IP $NS_EXT) every ${INTERVAL}s. Log: $LOG"
echo "Quiet screen = no changes. Ctrl+C to stop. Stop before hands-off periods (R10)."
[ -d "$OUT_DIR/dns-baseline" ] || echo "${YEL}No dns-baseline.sh snapshot yet: record changes will not be watched. Run: sudo $HERE/dns-baseline.sh snapshot${RST}"

first=1
beat=$(date +%s)
while :; do
  for p in health procs listeners files conns badprocs records; do
    while IFS= read -r line; do
      [ "$first" -eq 1 ] && continue
      sign="${line:0:1}"; text="${line:2}"
      case "$p:$sign" in
        health:+) case "$text" in *DOWN) alert HIGH "DNS NOT ANSWERING via ${text% DOWN} for $NAME" ;; *) alert OK "DNS answering again via ${text% up}" ;; esac ;;
        health:-) ;;
        procs:+) alert HIGH "DNS server process started/restarted: $text" ;;
        procs:-) alert HIGH "DNS server process gone: $text" ;;
        listeners:+) case "${text##* }" in
                       named|unbound|systemd-resolve) alert MED "port 53 listener (re)opened: $text" ;;
                       *) alert HIGH "NEW PROGRAM ON PORT 53: $text (rogue resolver or tunnel?)" ;;
                     esac ;;
        listeners:-) alert MED "port 53 listener gone: $text" ;;
        files:+) alert MED "DNS file changed or added: ${text% *}" ;;
        files:-) ;;
        conns:+) alert HIGH "new connection outside 10.0.0.0/8: $text" ;;
        conns:-) ;;
        badprocs:+) alert HIGH "tunnel/C2/reverse-shell process: $text" ;;
        badprocs:-) alert MED "suspicious process ended: $text" ;;
        records:+) alert HIGH "record change vs snapshot: ${text#FLAG: }" ;;
        records:-) alert OK "no longer different from snapshot: ${text#FLAG: }" ;;
      esac
    done < <(changes "$p")
  done
  if [ "$first" -eq 1 ]; then
    first=0
    alert OK "started. Current state: $(tr '\n' ' ' < "$STATE/health.old")| $(wc -l < "$STATE/records.old") record differences vs snapshot"
    if [ -s "$STATE/records.old" ]; then sed 's/^/   already different: /' "$STATE/records.old"; fi
  fi
  if [ $(( $(date +%s) - beat )) -ge 300 ]; then echo "$(date +%H:%M:%S) .... still watching"; beat=$(date +%s); fi
  sleep "$INTERVAL"
done
