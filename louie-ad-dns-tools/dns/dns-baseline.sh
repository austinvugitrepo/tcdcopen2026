#!/usr/bin/env bash
# TCDC blue team: baseline the DNS records and config on ns1, then spot changes.
#
# Red team's favourite DNS trick is quiet: change one A record so a scored name
# points somewhere else, or add a record. This catches it at the RECORD level,
# not just "a file changed".
#
#   snapshot  save a baseline: sha256 of every DNS config/zone file, plus every
#             record of every zone (BIND: named-checkzone dump; Unbound:
#             unbound-control list_local_data). Run it in the first minutes,
#             and again after each change YOUR team makes on purpose.
#   diff      compare now against the baseline. Prints FLAG: lines for
#             added/removed/changed records and files. Exit code 1 if anything changed.
#   restore ZONE
#             put a BIND zone back exactly as it was at the snapshot (the snapshot
#             keeps a copy of every zone file). Dry run unless --apply. With
#             --apply it validates the saved copy, backs up the current file,
#             writes the saved records with a NEW higher serial, reloads the zone
#             and checks the new serial is live. Dynamic zones (with a .jnl
#             journal) are frozen first and thawed after.
#
# snapshot/diff only read, except "rndc sync" on dynamic zones (writes pending
# journal changes into the zone file, which BIND does by itself every few minutes). Writes only to OUT_DIR (root-only, stays on the
# box, rule R23). Journals (*.jnl) and managed-keys files are skipped because
# BIND changes them by itself.
#
# Usage: sudo ./dns-baseline.sh snapshot | diff | restore <zone> [--apply]
# Env:   OUT_DIR (default /var/tmp/tcdc-audit)
set -uo pipefail
umask 077
MODE="${1:-}"
case "$MODE" in snapshot|diff|restore) ;; *) echo "Usage: sudo $0 snapshot | diff | restore <zone> [--apply]" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 2; fi

OUT_DIR="${OUT_DIR:-/var/tmp/tcdc-audit}"
BASE="$OUT_DIR/dns-baseline"
NOW="$OUT_DIR/dns-now"
mkdir -p "$OUT_DIR"

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
  local stmts dir
  stmts="$(bind_stmts)"
  dir="$(printf '%s\n' "$stmts" | awk -F'\t' '$1 == "options" && $2 ~ /^directory / { s = $2; sub(/^directory "/, "", s); sub(/"$/, "", s); print s }')"
  printf '%s\n' "$stmts" | awk -F'\t' -v dir="${dir:-/var/cache/bind}" '
    $1 ~ /^zone "/ && $2 ~ /^file "/ {
      z = $1; sub(/^zone "/, "", z); sub(/".*/, "", z)
      f = $2; sub(/^file "/, "", f); sub(/"$/, "", f)
      if (f !~ /^\//) f = dir "/" f
      if (z ~ /^(localhost|127\.in-addr\.arpa|0\.in-addr\.arpa|255\.in-addr\.arpa|\.)$/) next
      print z "\t" f
    }'
}

# collect DEST: write files.sha256 and records/<zone>.txt into DEST
collect() {
  local dest="$1" paths=() p z f
  rm -rf "$dest"; mkdir -p "$dest/records" "$dest/zonefiles"; : > "$dest/zones.tsv"
  for p in /etc/bind /var/lib/bind /var/cache/bind /etc/unbound; do [ -d "$p" ] && paths+=("$p"); done
  if [ ${#paths[@]} -gt 0 ]; then
    find "${paths[@]}" -type f ! -name '*.jnl' ! -name 'managed-keys.bind*' ! -name '*.mkeys*' \
      -exec sha256sum {} + 2>/dev/null | sort -k2 > "$dest/files.sha256"
  else
    : > "$dest/files.sha256"
  fi
  if command -v named-checkconf >/dev/null 2>&1 && [ -d /etc/bind ]; then
    while IFS=$'\t' read -r z f; do
      [ -n "$z" ] && [ -f "$f" ] || continue
      # Dynamic zones keep recent changes (e.g. from nsupdate) in a .jnl journal
      # for a few minutes. Write them into the file first so we see live records.
      [ -e "$f.jnl" ] && rndc sync "$z" >/dev/null 2>&1
      # Canonical dump: one record per line, names fully qualified, comments removed.
      named-checkzone -D -o - "$z" "$f" 2>/dev/null | awk '$3 == "IN" { $1 = $1; print }' | sort > "$dest/records/${z//\//_}.txt"
      # Keep a copy of the zone file itself, for "restore".
      cp -p "$f" "$dest/zonefiles/${z//\//_}.zone"
      printf '%s\t%s\n' "$z" "$f" >> "$dest/zones.tsv"
    done < <(bind_zone_files)
  fi
  if command -v unbound-control >/dev/null 2>&1 && pgrep -x unbound >/dev/null 2>&1; then
    unbound-control list_local_data 2>/dev/null | sort > "$dest/records/unbound-local-data.txt"
    unbound-control list_local_zones 2>/dev/null | sort > "$dest/records/unbound-local-zones.txt"
  fi
}

if [ "$MODE" = restore ]; then
  ZONE="${2:-}"; APPLY=0
  [ "${3:-}" = "--apply" ] && APPLY=1
  [ -n "$ZONE" ] || { echo "Usage: sudo $0 restore <zone> [--apply]" >&2; exit 2; }
  [ -d "$BASE" ] || { echo "No baseline yet. Run: sudo $0 snapshot" >&2; exit 2; }
  ZONE="${ZONE%.}"
  saved="$BASE/zonefiles/${ZONE//\//_}.zone"
  target="$(awk -F'\t' -v z="$ZONE" '$1 == z { print $2 }' "$BASE/zones.tsv" 2>/dev/null)"
  if [ ! -f "$saved" ] || [ -z "$target" ]; then
    echo "No saved copy of zone '$ZONE' in the baseline. Zones saved:" >&2
    cut -f1 "$BASE/zones.tsv" 2>/dev/null | sed 's/^/  /' >&2
    echo "(Unbound local-data is restored from the config backup instead: backup.sh in tcdc-blue-toolkit.)" >&2
    exit 2
  fi
  named-checkzone -q "$ZONE" "$saved" || { echo "STOP: the saved copy does not validate (named-checkzone $ZONE $saved)." >&2; exit 1; }
  cur_serial="$(dig @127.0.0.1 "$ZONE" SOA +short +time=2 +tries=1 2>/dev/null | grep -v '^;' | awk 'NF >= 7 { print $3; exit }')"
  old_serial="$(named-checkzone "$ZONE" "$saved" 2>/dev/null | grep -o 'loaded serial [0-9]*' | awk '{ print $3 }')"
  new_serial=$(( ${cur_serial:-0} > ${old_serial:-0} ? ${cur_serial:-0} + 1 : ${old_serial:-0} + 1 ))
  echo "zone $ZONE  file=$target  live serial=${cur_serial:-?}  snapshot serial=${old_serial:-?}  new serial=$new_serial"
  echo "Changes this restore will undo (snapshot vs current file):"
  diff <(named-checkzone -D -o - "$ZONE" "$saved" 2>/dev/null | awk '$3 == "IN" && $4 != "SOA" { $1 = $1; print }' | sort) \
       <(named-checkzone -D -o - "$ZONE" "$target" 2>/dev/null | awk '$3 == "IN" && $4 != "SOA" { $1 = $1; print }' | sort) |
    sed -n 's/^< /  put back: /p; s/^> /  remove:   /p'
  if [ "$APPLY" -ne 1 ]; then echo "Dry run. Add --apply to restore."; exit 0; fi

  work="$OUT_DIR/dns-restore-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$work"
  cp -p "$target" "$work/$(basename "$target").current"
  # Canonical copy of the snapshot records with the new serial (SOA field 7).
  named-checkzone -D -o - "$ZONE" "$saved" 2>/dev/null |
    awk -v s="$new_serial" '$4 == "SOA" && !done { $7 = s; done = 1 } { print }' > "$work/restored.zone"
  named-checkzone -q "$ZONE" "$work/restored.zone" || { echo "STOP: the rebuilt zone does not validate. Nothing changed." >&2; exit 1; }
  dynamic=0
  if [ -e "$target.jnl" ]; then
    dynamic=1
    rndc freeze "$ZONE" || { echo "STOP: rndc freeze $ZONE failed. Nothing changed." >&2; exit 1; }
    mv "$target.jnl" "$work/"
  fi
  cat "$work/restored.zone" > "$target"     # keeps the file's owner and mode
  if [ "$dynamic" -eq 1 ]; then rndc thaw "$ZONE"; else rndc reload "$ZONE" >/dev/null 2>&1 || pkill -HUP -x named; fi
  sleep 2
  live="$(dig @127.0.0.1 "$ZONE" SOA +short +time=2 +tries=1 2>/dev/null | grep -v '^;' | awk 'NF >= 7 { print $3; exit }')"
  if [ "$live" = "$new_serial" ]; then
    echo "DONE. $ZONE restored, live serial $live."
  else
    echo "WARN: live serial is '${live:-none}', expected $new_serial. Check 'journalctl -u named' and dns-health.sh."
  fi
  echo "Previous file kept: $work/$(basename "$target").current"
  echo "UNDO: sudo cp '$work/$(basename "$target").current' '$target' && sudo rndc reload $ZONE"
  echo "Then find HOW it was changed (dns-audit.sh: allow-update, rndc access; dns-hunt.sh) or it will happen again."
  echo "Take a new snapshot now (the serial is higher than the old one): sudo $0 snapshot"
  exit 0
fi

if [ "$MODE" = snapshot ]; then
  if [ -d "$BASE" ]; then rm -rf "$BASE.prev"; mv "$BASE" "$BASE.prev"; echo "previous baseline kept at $BASE.prev"; fi
  collect "$BASE"
  echo "Baseline saved: $BASE"
  echo "  files:   $(wc -l < "$BASE/files.sha256")"
  for f in "$BASE"/records/*.txt; do [ -e "$f" ] && echo "  records: $(basename "$f" .txt) $(wc -l < "$f")"; done
  exit 0
fi

# diff
if [ ! -d "$BASE" ]; then echo "No baseline yet. Run: sudo $0 snapshot" >&2; exit 2; fi
collect "$NOW"
CHANGES=0
flag() { CHANGES=$((CHANGES + 1)); printf 'FLAG: %s\n' "$*"; }

echo "=== Files (baseline $(stat -c '%y' "$BASE/files.sha256" | cut -d. -f1)) ==="
while read -r kind path; do
  case "$kind" in
    NEW) flag "new file: $path" ;;
    GONE) flag "file removed: $path" ;;
    CHANGED) flag "file changed: $path (diff it against your backup)" ;;
  esac
done < <(awk 'NR == FNR { old[$2] = $1; next } { now[$2] = $1 }
  END {
    for (p in now) if (!(p in old)) print "NEW", p; else if (old[p] != now[p]) print "CHANGED", p
    for (p in old) if (!(p in now)) print "GONE", p
  }' "$BASE/files.sha256" "$NOW/files.sha256" | sort -k2)

echo
echo "=== Records ==="
for f in "$BASE"/records/*.txt "$NOW"/records/*.txt; do
  [ -e "$f" ] && basename "$f"
done | sort -u | while read -r name; do printf '%s\n' "$name"; done > "$NOW/.zones"
while read -r name; do
  b="$BASE/records/$name"; n="$NOW/records/$name"
  if [ ! -e "$b" ]; then flag "new zone/list: ${name%.txt} ($(wc -l < "$n") records)"; continue; fi
  if [ ! -e "$n" ]; then flag "zone/list gone: ${name%.txt}"; continue; fi
  while IFS= read -r line; do
    case "$line" in
      '> '*) flag "${name%.txt}: record ADDED   ${line#> }" ;;
      '< '*) flag "${name%.txt}: record REMOVED ${line#< }" ;;
    esac
  done < <(diff "$b" "$n")
done < "$NOW/.zones"
rm -f "$NOW/.zones"

echo
if [ "$CHANGES" -eq 0 ]; then
  echo "No changes since the baseline."
  exit 0
fi
echo "$CHANGES change(s). A change your team made on purpose is fine: re-run 'snapshot' after it."
echo "A SOA line that only differs in the serial means the zone was edited. Look for the other lines."
exit 1
