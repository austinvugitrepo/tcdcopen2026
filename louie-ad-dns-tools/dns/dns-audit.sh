#!/usr/bin/env bash
# TCDC blue team: read-only audit of the DNS server on ns1 (BIND9 or Unbound).
#
# CHANGES NOTHING. It reads the effective config (BIND: named-checkconf -p, which
# follows every include) and reports the settings that matter for defence:
#   - config and zone files load cleanly
#   - zone transfers, recursion, dynamic updates, version hiding, forwarders
#   - per-zone overrides (a zone-level allow-transfer beats the options block)
#   - rndc / unbound-control listening beyond localhost
#   - zone file and key file permissions, files changed recently
#   - which process owns port 53, the user the server runs as, time sync
#
# Prints FLAG: (fix this), NOTE: (look at this) and OK: lines, and saves a copy.
#
# Usage: sudo ./dns-audit.sh
# Env:   OUT_DIR (default /var/tmp/tcdc-audit), RECENT_MIN (default 60)
set -uo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 2; fi

OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
RECENT_MIN="${RECENT_MIN:-60}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/dns-audit-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

FLAGS=0
flag() { FLAGS=$((FLAGS + 1)); printf 'FLAG: %s\n' "$*"; }
note() { printf 'NOTE: %s\n' "$*"; }
ok()   { printf 'OK:   %s\n' "$*"; }
sec()  { printf '\n=== %s ===\n' "$*"; }

# Print "<block><TAB><statement>" for every statement one level inside each
# top-level block of the effective BIND config, e.g.
#   options<TAB>allow-transfer { "none"; }
#   zone "team5.playtcdc.org"<TAB>file "/etc/bind/db.team5"
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

# Print "<zone><TAB><file>" for each non-default zone that has a file.
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

# Value of an options statement, empty if not set.
opt() { printf '%s\n' "$STMTS" | awk -F'\t' -v k="$1" '$1 == "options" && (index($2, k " ") == 1 || $2 == k) { print $2 }'; }

detect_engine() {
  if pgrep -x named >/dev/null 2>&1; then echo bind
  elif pgrep -x unbound >/dev/null 2>&1; then echo unbound
  elif command -v named-checkconf >/dev/null 2>&1 && [ -d /etc/bind ]; then echo bind
  elif [ -d /etc/unbound ]; then echo unbound
  else echo none; fi
}

ENGINE="$(detect_engine)"
echo "TCDC DNS audit  host=$(hostname)  engine=$ENGINE  $(date '+%F %T')"

sec "Server process and version"
while read -r pid user args; do
  echo "pid $pid user=$user $args"
  if [ "$user" = root ]; then flag "DNS server pid $pid runs as root. Normal is user bind (BIND) or unbound"; fi
done < <(ps -o pid=,user=,args= -C named,unbound 2>/dev/null)
dpkg-query -W -f='${Package} ${Version}\n' bind9 unbound 2>/dev/null | grep -v '^$' || true
note "Look the version up against vendor advisories from your own laptop, not from the box"

audit_bind() {
  sec "Config and zones load cleanly (named-checkconf -z)"
  if named-checkconf -z >/tmp/.tcdc-ckz.$$ 2>&1; then
    ok "named-checkconf -z passed"
  else
    flag "named-checkconf -z failed. A reload would fail too:"
  fi
  sed 's/^/  /' /tmp/.tcdc-ckz.$$; rm -f /tmp/.tcdc-ckz.$$

  STMTS="$(bind_stmts)"
  if [ -z "$STMTS" ]; then flag "could not read the config with named-checkconf -p"; return; fi

  sec "Options that matter"
  local k v
  for k in allow-query allow-query-cache allow-recursion recursion allow-transfer allow-update update-policy version forwarders forward listen-on listen-on-v6 also-notify dnssec-validation; do
    v="$(opt "$k")"
    echo "  ${v:-$k (not set)}"
  done

  v="$(opt allow-transfer)"
  if [ -z "$v" ]; then
    flag "allow-transfer is not set in options. The default depends on the BIND version; set allow-transfer { none; } explicitly"
  elif printf '%s' "$v" | grep -q '"any"\|[{ ]any;'; then
    flag "allow-transfer allows ANY host to copy every zone: $v"
  else ok "allow-transfer: $v"; fi

  v="$(opt recursion)"
  if [ "$v" = "recursion no" ]; then
    ok "recursion is off"
  else
    v="$(opt allow-recursion)"
    if [ -z "$v" ]; then
      note "recursion on, allow-recursion not set: BIND then limits it to localhost and localnets via allow-query-cache. Set it explicitly"
    elif printf '%s' "$v" | grep -q '"any"\|[{ ]any;'; then
      flag "open resolver: $v. Limit it to your team subnets (dns-harden.sh)"
    else ok "$v"; fi
  fi

  v="$(opt allow-update)"
  if [ -n "$v" ] && ! printf '%s' "$v" | grep -q '"none"'; then
    flag "allow-update in options lets matching hosts rewrite records with nsupdate: $v"
  fi
  if [ -z "$(opt version)" ]; then note "version not hidden. Add version \"none\"; (dns-harden.sh)"; fi

  sec "Per-zone overrides (these beat the options block)"
  while IFS=$'\t' read -r z s; do
    case "$s" in
      allow-transfer*any*|allow-update*any*) flag "$z: $s" ;;
      allow-update*none*) echo "  $z: $s" ;;
      allow-update*|update-policy*) flag "$z: $s (dynamic updates allowed; anyone matching can change records)" ;;
      *) echo "  $z: $s" ;;
    esac
  done < <(printf '%s\n' "$STMTS" | awk -F'\t' '$1 ~ /^zone / && $2 ~ /^(allow-transfer|allow-update|update-policy|also-notify|allow-query|type forward|forwarders) */ { print $1 "\t" $2 }')

  sec "rndc control channel"
  local ctl
  ctl="$(printf '%s\n' "$STMTS" | awk -F'\t' '$1 == "controls" { print $2 }')"
  if [ -n "$ctl" ]; then
    echo "  $ctl"
    if printf '%s' "$ctl" | grep -q 'inet' && ! printf '%s' "$ctl" | grep -Eq 'inet (127\.0\.0\.1|::1)'; then
      flag "rndc listens beyond localhost. Anyone with the key can reload, freeze or dump zones"
    fi
  else
    note "no controls statement: rndc uses 127.0.0.1:953 with /etc/bind/rndc.key by default"
  fi
  while read -r p; do
    case "$p" in *filter-aaaa*|*filter-a*) note "plugin loaded: $p" ;; *) flag "unexpected BIND plugin: $p" ;; esac
  done < <(printf '%s\n' "$STMTS" | awk -F'\t' '$1 ~ /^plugin / { print $1 }')

  sec "Zones"
  local zf z f perm owner serial count
  zf="$(bind_zone_files)"
  if [ -z "$zf" ]; then note "no zones with files found (zones inside view blocks are not listed)"; fi
  while IFS=$'\t' read -r z f; do
    [ -n "$z" ] || continue
    if [ ! -f "$f" ]; then flag "zone $z: file $f missing"; continue; fi
    perm="$(stat -c '%a' "$f")"; owner="$(stat -c '%U:%G' "$f")"
    serial="$(named-checkzone "$z" "$f" 2>/dev/null | grep -o 'loaded serial [0-9]*' | awk '{print $3}')"
    count="$(named-checkzone -D -o - "$z" "$f" 2>/dev/null | awk '$3 == "IN"' | wc -l)"
    echo "  $z  file=$f  owner=$owner  mode=$perm  serial=${serial:-?}  records=$count"
    if [ -z "$serial" ]; then flag "zone $z does not load (named-checkzone $z $f)"; fi
    if [ $((8#$perm & 2)) -ne 0 ]; then flag "zone file $f is world-writable"; fi
    if named-checkzone -D -o - "$z" "$f" 2>/dev/null | awk '$3 == "IN"' | grep -q '^\*\.'; then
      note "zone $z has wildcard records (answers for ANY name). Expected?"
    fi
  done <<< "$zf"

  sec "Key and config file permissions"
  while read -r f; do
    perm="$(stat -c '%a' "$f")"
    echo "  $f $(stat -c '%U:%G' "$f") $perm"
    if [ $((8#$perm & 4)) -ne 0 ]; then flag "$f is readable by every user. Fix: chmod 640 $f; chown root:bind $f"; fi
  done < <(find /etc/bind -type f \( -name '*.key' -o -name 'rndc.conf' \) 2>/dev/null)
  while read -r f; do
    perm="$(stat -c '%a' "$f")"
    if [ $((8#$perm & 4)) -ne 0 ]; then flag "$f holds a TSIG/rndc secret and is world-readable"; fi
  done < <(grep -rlE 'secret[[:space:]]+"' /etc/bind 2>/dev/null)
  while read -r f; do
    flag "world-writable: $f"
  done < <(find /etc/bind /var/lib/bind /var/cache/bind -perm -0002 \( -type f -o -type d \) ! -type l 2>/dev/null)
  while read -r f; do
    note "$f is owned by bind, so the DNS process could rewrite its own config"
  done < <(find /etc/bind -type f -user bind ! -name rndc.key 2>/dev/null)
}

audit_unbound() {
  sec "Config loads cleanly (unbound-checkconf)"
  if unbound-checkconf >/tmp/.tcdc-ckz.$$ 2>&1; then ok "unbound-checkconf passed"; else flag "unbound-checkconf failed:"; fi
  sed 's/^/  /' /tmp/.tcdc-ckz.$$; rm -f /tmp/.tcdc-ckz.$$

  sec "Settings that matter"
  local lines
  lines="$(grep -rhE '^[[:space:]]*(include|interface|access-control|hide-identity|hide-version|forward-addr|stub-addr|auth-zone|control-enable|control-interface|local-zone):' /etc/unbound 2>/dev/null | sed 's/^[[:space:]]*//')"
  printf '%s\n' "$lines" | sed 's/^/  /'
  if printf '%s\n' "$lines" | grep -Eq '^access-control:[[:space:]]+(0\.0\.0\.0/0|::0?/0)[[:space:]]+allow([[:space:]]|$)'; then
    flag "access-control allows the whole internet to recurse (open resolver)"
  fi
  printf '%s\n' "$lines" | grep -q '^hide-version:[[:space:]]*yes' || note "hide-version not set. Add hide-version: yes"
  printf '%s\n' "$lines" | grep -q '^hide-identity:[[:space:]]*yes' || note "hide-identity not set. Add hide-identity: yes"
  if printf '%s\n' "$lines" | grep -E '^control-interface:' | grep -Evq '127\.0\.0\.1|::1|/'; then
    flag "unbound-control listens beyond localhost"
  fi
  echo "  local-data records: $(grep -rhcE '^[[:space:]]*local-data:' /etc/unbound 2>/dev/null | awk '{s += $1} END {print s + 0}')"
}

case "$ENGINE" in
  bind) audit_bind ;;
  unbound) audit_unbound ;;
  *) flag "no BIND or Unbound found. Find the DNS server with: sudo ss -lntup 'sport = :53'" ;;
esac

sec "Who listens on port 53 and the control ports"
if command -v ss >/dev/null 2>&1; then
  ss -lntupH '( sport = :53 or sport = :953 or sport = :8953 )' 2>/dev/null | awk '{ print $1, $5, $7 }' | sed 's/,fd=[0-9]*//g' | sort -u | sed 's/^/  /'
  if ss -lntH '( sport = :953 or sport = :8953 )' 2>/dev/null | awk '{print $4}' | grep -Evq '^(127\.0\.0\.1|\[::1\]):'; then
    flag "a DNS control port (953/8953) listens beyond localhost"
  fi
else
  note "ss not installed. Use: sudo netstat -lntup | grep -E ':(53|953|8953) '"
fi

sec "Files changed in the last $RECENT_MIN minutes"
changed="$(find /etc/bind /var/lib/bind /var/cache/bind /etc/unbound -type f -mmin "-$RECENT_MIN" ! -name '*.jnl' ! -name 'managed-keys.bind*' ! -name '*.mkeys*' 2>/dev/null)"
if [ -n "$changed" ]; then
  printf '%s\n' "$changed" | while read -r f; do note "changed $(stat -c '%y' "$f" | cut -d. -f1): $f"; done
else
  ok "nothing changed"
fi

sec "Time sync"
if command -v timedatectl >/dev/null 2>&1; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then ok "clock synchronized"
  else flag "clock not synchronized (DNSSEC, TSIG and Kerberos break with skew). Fix: sudo timedatectl set-ntp true"; fi
else
  note "timedatectl not available. Check chrony or ntpd by hand"
fi

echo
echo "Done. $FLAGS FLAG line(s). Saved: $REPORT"
