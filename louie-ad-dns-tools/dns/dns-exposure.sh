#!/usr/bin/env bash
# TCDC blue team: what does ns1 give away to someone who is NOT on ns1?
#
# Run this on the JUMPBOX, not on ns1. Tests run from ns1 itself come from an
# address your own config usually trusts, so they can say "refused" while the
# rest of the world gets everything.
#
# It checks, against ns1:
#   - zone transfer (AXFR): should be refused
#   - recursion: the "ra" flag means ns1 will resolve other names for this host
#   - version.bind / hostname.bind / id.server: information leaks
#   - TCP 53: the scorer may query over TCP, so it should answer
# It does NOT test dynamic updates, because that test would change your zone.
# dns-audit.sh on ns1 reports allow-update / update-policy instead.
#
# Read-only. Prints FLAG: (fix this), NOTE: (look at this) and OK: lines.
#
# Usage:   ./dns-exposure.sh <team-id> [zone ...]
# Example: ./dns-exposure.sh 5
#          ./dns-exposure.sh 5 team5.playtcdc.org 10.105.in-addr.arpa
# Env:     SERVER=<ip> to test another address than 10.(100+id).10.53
# Needs:   dig
set -uo pipefail

TEAM="${1:-}"
if ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <team-id> [zone ...]" >&2
  exit 2
fi
shift
command -v dig >/dev/null 2>&1 || { echo "dig not found. Install it: sudo apt install dnsutils" >&2; exit 2; }
SERVER="${SERVER:-10.$((100 + TEAM)).10.53}"
if [ $# -gt 0 ]; then ZONES=("$@"); else ZONES=("team$TEAM.playtcdc.org"); fi

FLAGS=0
flag() { FLAGS=$((FLAGS + 1)); printf 'FLAG: %s\n' "$*"; }
note() { printf 'NOTE: %s\n' "$*"; }
ok()   { printf 'OK:   %s\n' "$*"; }
sec()  { printf '\n=== %s ===\n' "$*"; }

echo "TCDC DNS exposure test  server=$SERVER  from=$(hostname) ($(hostname -I 2>/dev/null | awk '{print $1}'))  $(date '+%F %T')"

sec "Server answers"
out="$(dig @"$SERVER" "${ZONES[0]}" SOA +time=3 +tries=1 +noall +comments +answer 2>/dev/null)"
rc=$?
status="$(printf '%s\n' "$out" | grep -o 'status: [A-Z]*' | head -n1 | cut -d' ' -f2)"
if [ $rc -eq 0 ] && [ "$status" = NOERROR ]; then
  ok "SOA for ${ZONES[0]} answered over UDP"
elif [ $rc -ne 0 ]; then
  flag "ns1 at $SERVER does not answer at all (dig rc=$rc). Nothing else can be tested; the results would be meaningless."
  echo
  echo "Done. $FLAGS FLAG line(s)."
  exit 1
else
  flag "no good SOA answer for ${ZONES[0]} (status=${status:-none}). Wrong zone name, or the zone failed to load?"
fi
out="$(dig @"$SERVER" "${ZONES[0]}" SOA +tcp +time=3 +tries=1 +noall +comments 2>/dev/null)"
if [ $? -eq 0 ] && printf '%s\n' "$out" | grep -q 'status: NOERROR'; then
  ok "TCP 53 answers"
else
  note "no answer over TCP 53. A scorer that uses TCP would mark DNS down. Check listen-on and the firewall"
fi

sec "Zone transfer (AXFR)"
for z in "${ZONES[@]}"; do
  out="$(dig @"$SERVER" "$z" AXFR +time=3 +tries=1 2>/dev/null)"
  n="$(printf '%s\n' "$out" | grep -v '^;' | grep -c '[^[:space:]]')"
  if printf '%s\n' "$out" | grep -v '^;' | grep -q '[[:space:]]SOA[[:space:]]' && [ "$n" -gt 1 ]; then
    flag "AXFR of $z is ALLOWED ($n records handed out). Set allow-transfer { none; } (dns-harden.sh)"
  else
    ok "AXFR of $z refused"
  fi
done

sec "Recursion"
out="$(dig @"$SERVER" example.com A +time=3 +tries=1 +noall +comments 2>/dev/null)"
flags_line="$(printf '%s\n' "$out" | grep -m1 ';; flags:')"
if printf '%s\n' "$flags_line" | grep -q ' ra[ ;]'; then
  flag "recursion is available to this host ($flags_line). If this host is outside your team subnets, ns1 is an open resolver"
else
  ok "recursion not offered to this host"
fi

sec "Information leaks"
for q in version.bind hostname.bind id.server; do
  ans="$(dig @"$SERVER" "$q" TXT CH +short +time=3 +tries=1 2>/dev/null | grep -v '^;' | head -n1)"
  if [ -n "$ans" ] && [ "$ans" != '"none"' ]; then
    note "$q reveals $ans. Hide it (BIND: version \"none\"; Unbound: hide-version / hide-identity)"
  else
    ok "$q hidden"
  fi
done

echo
echo "Done. $FLAGS FLAG line(s)."
