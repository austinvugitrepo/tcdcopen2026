#!/usr/bin/env bash
# TCDC blue team: safe DNS hardening for ns1 (BIND9 or Unbound).
#
# Dry run by default: prints the plan and the exact diff. With --apply it makes
# the change, and undoes it by itself if anything fails.
#
# BIND, in the file that holds the options block:
#   acl tcdc_team_nets { <your 4 subnets>; localhost; };
#   allow-transfer { none; };              no more zone copies for anyone
#   allow-recursion { tcdc_team_nets; };   recursion only for your boxes
#   version "none";                        hide the version
#   hostname none;                         hide the server's hostname
# It never touches allow-query: the scorer asks from outside your subnets.
# A directive that is already right is left alone. One that exists on a single
# line is replaced. Anything more complex is printed for you to do by hand.
#
# Unbound: writes /etc/unbound/unbound.conf.d/zz-tcdc-hardening.conf (zz- so it
#   loads last: for the same netblock the last access-control line wins) with
#   access-control for your subnets, refuse_non_local for everyone else (your
#   own local-data still answers, recursion is refused), hide-identity, hide-version.
#
# --apply steps: check DNS works now -> back up -> write -> validate config
# (named-checkconf / unbound-checkconf) -> reload -> check DNS again. If any step
# fails it restores the backup and reloads.
#
# IMPORTANT: the check after the change runs FROM ns1, which sits in your own
# subnet and is always allowed. It cannot see the scorer's side. After --apply,
# watch the scoreboard for 2 ticks (60 s). If DNS goes red, run the undo line
# the script prints.
#
# Usage:   sudo ./dns-harden.sh <team-id> [--apply] [--name NAME]
# Example: sudo ./dns-harden.sh 5             (dry run)
#          sudo ./dns-harden.sh 5 --apply
#   --name  record used for the before/after check (default ns1.team<id>.playtcdc.org)
# Env:     OUT_DIR (default /var/tmp/tcdc-audit), NS_EXT (default 10.(100+id).10.53)
set -uo pipefail
umask 077

TEAM="${1:-}"
if ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
  echo "Usage: sudo $0 <team-id> [--apply] [--name NAME]" >&2
  exit 2
fi
shift
APPLY=0
NAME="ns1.team$TEAM.playtcdc.org"
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --name) shift; NAME="${1:?--name needs a value}" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 2; fi
command -v dig >/dev/null 2>&1 || { echo "dig not found. Install it: sudo apt install dnsutils" >&2; exit 2; }

NET="10.$((100 + TEAM))"
SUBNETS=("$NET.10.0/24" "$NET.20.0/24" "$NET.30.0/24" "$NET.40.0/24")
NS_EXT="${NS_EXT:-$NET.10.53}"
OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$OUT_DIR/dns-harden-$STAMP"
mkdir -p "$WORK"

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
die()  { printf 'STOP: %s\n' "$*" >&2; exit 1; }

# DNS works if NAME resolves via loopback and via ns1's own address.
resolves() {
  local out
  out="$(dig @"$1" "$NAME" A +time=2 +tries=1 +noall +comments +answer 2>/dev/null)" || return 1
  printf '%s\n' "$out" | grep -q 'status: NOERROR' || return 1
  printf '%s\n' "$out" | grep -v '^;' | grep -q '[^[:space:]]'
}
health() { resolves 127.0.0.1 && resolves "$NS_EXT"; }
wait_health() { local i; for i in 1 2 3 4 5 6 7 8 9 10; do health && return 0; sleep 1; done; return 1; }

detect_engine() {
  if pgrep -x named >/dev/null 2>&1; then echo bind
  elif pgrep -x unbound >/dev/null 2>&1; then echo unbound
  else echo none; fi
}

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

reload_bind() {
  rndc reload >/dev/null 2>&1 && return 0
  systemctl reload named >/dev/null 2>&1 && return 0
  systemctl reload bind9 >/dev/null 2>&1 && return 0
  pkill -HUP -x named
}
reload_unbound() {
  unbound-control reload >/dev/null 2>&1 && return 0
  systemctl reload unbound >/dev/null 2>&1 && return 0
  systemctl restart unbound >/dev/null 2>&1 && return 0
  pkill -HUP -x unbound
}

# Strip spaces and quotes so 'allow-transfer { "none"; }' == 'allow-transfer{none;}'.
norm() { printf '%s' "$1" | tr -d ' "\t'; }

harden_bind() {
  local main=/etc/bind/named.conf files=() f optfile="" n
  [ -f "$main" ] || die "$main not found"
  files=("$main")
  while read -r f; do [ -f "$f" ] && files+=("$f"); done < <(grep -hoE '^[[:space:]]*include[[:space:]]+"[^"]+"' "$main" | sed -E 's/.*"([^"]+)"/\1/')
  n=0
  for f in "${files[@]}"; do
    if grep -qE '^[[:space:]]*options[[:space:]]*\{' "$f"; then optfile="$f"; n=$((n + 1)); fi
  done
  [ "$n" -eq 1 ] || die "found $n files with an options block (expected 1). Edit by hand."
  say "options block is in: $optfile"

  # Line range of the options block (comments stripped for brace counting).
  local range start end
  range="$(awk '
    { line = $0; sub(/\/\/.*/, "", line); sub(/#.*/, "", line) }
    !inopt && line ~ /^[[:space:]]*options[[:space:]]*\{/ { inopt = 1; start = NR; depth = 0 }
    inopt { o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c; if (depth <= 0) { print start, NR; exit } }
  ' "$optfile")"
  start="${range% *}"; end="${range#* }"
  [ -n "$range" ] && [ "$start" -lt "$end" ] || die "could not find where the options block ends in $optfile. Edit by hand."

  local stmts acl_line recursion_off=0
  stmts="$(bind_stmts)"
  [ -n "$stmts" ] || die "named-checkconf -p could not read the current config. Fix it first."
  printf '%s\n' "$stmts" | awk -F'\t' '$1 == "options" && $2 == "recursion no" { found = 1 } END { exit !found }' && recursion_off=1

  local acl_members
  acl_members="$(printf '%s; ' "${SUBNETS[@]}")localhost;"
  acl_line="acl tcdc_team_nets { $acl_members };"

  local edits="$WORK/edits.tsv" manual=0
  : > "$edits"
  if grep -qE '^[[:space:]]*acl[[:space:]]+"?tcdc_team_nets"?' "${files[@]}" 2>/dev/null; then
    say "  acl tcdc_team_nets: already present, left alone"
  else
    printf 'A\t%s\n' "$acl_line" >> "$edits"
    say "  acl tcdc_team_nets: will add above the options block"
  fi

  # plan KEY "desired statement"
  plan() {
    local key="$1" want="$2" cur lines ln text clean opens closes
    cur="$(printf '%s\n' "$stmts" | awk -F'\t' -v k="$key" '$1 == "options" && index($2, k " ") == 1 { print $2 }')"
    if [ -n "$cur" ] && [ "$(norm "$cur")" = "$(norm "${want%;}")" ]; then
      say "  $key: already '$cur', left alone"; return
    fi
    lines="$(awk -v s="$start" -v e="$end" -v k="$key" 'NR > s && NR < e && $0 ~ "^[[:space:]]*" k "([[:space:]]|\\{|;|$)" { print NR }' "$optfile")"
    if [ -z "$lines" ] && [ -z "$cur" ]; then
      printf 'I\t%s\n' "$want" >> "$edits"
      say "  $key: not set, will add: $want"
      return
    fi
    if [ "$(printf '%s\n' "$lines" | grep -c .)" -eq 1 ]; then
      ln="$lines"; text="$(sed -n "${ln}p" "$optfile")"
      clean="${text%%//*}"; clean="${clean%%#*}"
      opens="$(printf '%s' "$clean" | tr -cd '{' | wc -c)"; closes="$(printf '%s' "$clean" | tr -cd '}' | wc -c)"
      if [ "$opens" -eq "$closes" ] && printf '%s' "$clean" | grep -qE ';[[:space:]]*$'; then
        printf 'R\t%s\t%s\n' "$ln" "$want" >> "$edits"
        say "  $key: will replace line $ln ('$(printf '%s' "$text" | sed -E 's/^[[:space:]]+//')') with: $want"
        return
      fi
    fi
    warn "$key is set as '$cur' over several lines or in an include. Change it by hand to: $want"
    manual=1
  }

  plan allow-transfer 'allow-transfer { none; };'
  if [ "$recursion_off" -eq 1 ]; then
    say "  allow-recursion: recursion is off, nothing to do"
  else
    plan allow-recursion 'allow-recursion { tcdc_team_nets; };'
  fi
  plan version 'version "none";'
  plan hostname 'hostname none;'

  # Zone-level settings override the options block.
  printf '%s\n' "$stmts" | awk -F'\t' '$1 ~ /^zone / && $2 ~ /^(allow-transfer|allow-update|update-policy) / { print $1 ": " $2 }' |
    while read -r line; do warn "zone-level override, fix by hand if it allows too much: $line"; done

  if [ ! -s "$edits" ]; then
    say "Nothing to change."
    [ "$manual" -eq 1 ] && say "(see the WARN lines for changes to make by hand)"
    return 0
  fi

  # Build the candidate file: ACL above the options line, inserts right after
  # the options line, replacements in place.
  local cand="$WORK/$(basename "$optfile").new" orig="$WORK/$(basename "$optfile").orig"
  cp -a "$optfile" "$orig"
  awk -F'\t' -v start="$start" '
    NR == FNR { if ($1 == "R") rep[$2] = $3; else if ($1 == "I") ins[++ni] = $2; else if ($1 == "A") acl[++na] = $2; next }
    FNR == start { for (i = 1; i <= na; i++) print acl[i] }
    (FNR in rep) { match($0, /^[ \t]*/); print substr($0, 1, RLENGTH) rep[FNR]; next }
    { print }
    FNR == start { for (i = 1; i <= ni; i++) print "\t" ins[i] "\t// tcdc dns-harden.sh" }
  ' "$edits" "$optfile" > "$cand"

  say ""
  say "Planned change to $optfile:"
  diff -u "$orig" "$cand" | sed 's/^/  /'

  if [ "$APPLY" -eq 0 ]; then
    say ""
    say "Dry run. Nothing changed. Re-run with --apply to make this change."
    return 0
  fi

  say ""
  health || die "DNS does not answer for $NAME right now (127.0.0.1 and $NS_EXT). Fix that first, or pick a working record with --name; a change can't be verified otherwise."
  cat "$cand" > "$optfile"     # keeps the file's owner and mode
  if ! named-checkconf >"$WORK/checkconf.txt" 2>&1; then
    cat "$orig" > "$optfile"
    sed 's/^/  /' "$WORK/checkconf.txt"
    die "named-checkconf rejected the new config. Restored the original. Nothing was reloaded."
  fi
  say "named-checkconf: OK. Reloading..."
  reload_bind
  if ! wait_health; then
    warn "DNS stopped answering after the reload. Restoring the original."
    cat "$orig" > "$optfile"; reload_bind
    if wait_health; then die "restored and DNS answers again. Check the scoreboard."
    else die "restored, but DNS still does not answer. Check 'journalctl -u named' and the scoreboard NOW."; fi
  fi
  say "DONE. DNS still answers from ns1 for $NAME."
  say "Backup: $orig"
  say "UNDO:   sudo cp '$orig' '$optfile' && sudo rndc reload"
  say "Now watch the scoreboard for 2 ticks (60 s). This check ran from inside your subnet and cannot see the scorer's side."
}

harden_unbound() {
  local main=/etc/unbound/unbound.conf dropin=/etc/unbound/unbound.conf.d/zz-tcdc-hardening.conf s
  [ -f "$main" ] || die "$main not found"
  if ! grep -qE '^[[:space:]]*include(-toplevel)?:[[:space:]]*"?/etc/unbound/unbound\.conf\.d/\*\.conf' "$main"; then
    die "$main does not include unbound.conf.d/*.conf, so a drop-in file would be ignored. Add the lines below to the server: section by hand."
  fi
  {
    echo "# Written by tcdc dns-harden.sh $STAMP. Undo: delete this file and reload unbound."
    echo "server:"
    echo "    access-control: 127.0.0.0/8 allow"
    echo "    access-control: ::1/128 allow"
    for s in "${SUBNETS[@]}"; do echo "    access-control: $s allow"; done
    echo "    # Everyone else: your own local-data/local-zone still answers, recursion is refused."
    echo "    access-control: 0.0.0.0/0 refuse_non_local"
    echo "    access-control: ::0/0 refuse_non_local"
    echo "    hide-identity: yes"
    echo "    hide-version: yes"
  } > "$WORK/zz-tcdc-hardening.conf"
  say "Planned new file $dropin:"
  sed 's/^/  /' "$WORK/zz-tcdc-hardening.conf"
  if grep -rqE '^[[:space:]]*access-control:[[:space:]]+(0\.0\.0\.0/0|::0?/0)' /etc/unbound --exclude="$(basename "$dropin")" 2>/dev/null; then
    warn "another file also sets access-control for 0.0.0.0/0 or ::0/0. Files in unbound.conf.d load in name order and the LAST one wins, which is why this file is named zz-...; a setting in unbound.conf itself after the include line would still win. Re-test from the jumpbox with dns-exposure.sh."
  fi
  warn "If the scored records come from an auth-zone, stub-zone or forward-zone (not local-data), refuse_non_local will refuse them. Test from the jumpbox with dns-health.sh after applying."
  if [ "$APPLY" -eq 0 ]; then
    say ""
    say "Dry run. Nothing changed. Re-run with --apply to make this change."
    return 0
  fi
  health || die "DNS does not answer for $NAME right now. Fix that first, or pick a working record with --name."
  [ -e "$dropin" ] && cp -a "$dropin" "$WORK/zz-tcdc-hardening.conf.orig"
  install -m 644 "$WORK/zz-tcdc-hardening.conf" "$dropin"
  if ! unbound-checkconf >"$WORK/checkconf.txt" 2>&1; then
    rm -f "$dropin"; [ -e "$WORK/zz-tcdc-hardening.conf.orig" ] && cp -a "$WORK/zz-tcdc-hardening.conf.orig" "$dropin"
    sed 's/^/  /' "$WORK/checkconf.txt"
    die "unbound-checkconf rejected it. Removed the file. Nothing was reloaded."
  fi
  reload_unbound
  if ! wait_health; then
    warn "DNS stopped answering after the reload. Removing the file."
    rm -f "$dropin"; [ -e "$WORK/zz-tcdc-hardening.conf.orig" ] && cp -a "$WORK/zz-tcdc-hardening.conf.orig" "$dropin"
    reload_unbound
    if wait_health; then die "restored and DNS answers again."; else die "restored, but DNS still does not answer. Check 'journalctl -u unbound' NOW."; fi
  fi
  say "DONE. DNS still answers from ns1 for $NAME."
  say "UNDO: sudo rm '$dropin' && sudo systemctl reload unbound"
  say "Now watch the scoreboard for 2 ticks (60 s). This check ran from inside your subnet and cannot see the scorer's side."
}

ENGINE="$(detect_engine)"
say "TCDC DNS harden  team=$TEAM  engine=$ENGINE  apply=$APPLY  check record=$NAME"
say "team subnets: ${SUBNETS[*]}"
say "If ipcam (10.150.0.$TEAM) or other boxes outside these subnets resolve through ns1, recursion for them will stop. Check with 'resolvectl status' on those boxes first."
say ""
case "$ENGINE" in
  bind) harden_bind ;;
  unbound) harden_unbound ;;
  *) die "no running named or unbound found" ;;
esac
