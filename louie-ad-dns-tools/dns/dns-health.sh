#!/usr/bin/env bash
# TCDC blue team: DNS functional check for ns1 (roughly what the scorer does).
#
# Asks ns1 a real question over UDP and over TCP and checks for a real answer,
# not just an open port. A check passes only when dig exits 0, the status is
# NOERROR and the answer is not empty. (On a timeout dig still prints text, so
# "got some output" is NOT a pass. That mistake makes a dead server look UP.)
#
# Run it on the jumpbox (outside view) or on ns1 itself (it then also checks
# 127.0.0.1, because a listen-on change can break one address and not the other).
# Read-only. It does not log in or change anything.
#
# Usage:   ./dns-health.sh <team-id> [--name NAME] [--server IP] [--watch [SECONDS]]
# Example: ./dns-health.sh 5
#          ./dns-health.sh 5 --name artifactorium.team5.playtcdc.org --watch 30
#
#   --name    record to ask for (default ns1.team<id>.playtcdc.org). Switch to the
#             record the scorer really asks for once you know it.
#   --server  ask this IP instead of 10.(100+id).10.53
#   --watch   repeat every N seconds (default 30) and flag zone serial changes.
#             Stop it before hands-off periods (rule R10).
#
# Exit code (without --watch): 0 = all checks passed, 1 = something failed.
# Needs: dig (package dnsutils / bind9-dnsutils).
set -uo pipefail

TEAM="${1:-}"
if ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <team-id> [--name NAME] [--server IP] [--watch [SECONDS]]" >&2
  exit 2
fi
shift
DOMAIN="team$TEAM.playtcdc.org"
NAME="ns1.$DOMAIN"
SERVERS=("10.$((100 + TEAM)).10.53")
WATCH=0
INTERVAL=30
while [ $# -gt 0 ]; do
  case "$1" in
    --name)   shift; NAME="${1:?--name needs a value}" ;;
    --server) shift; SERVERS=("${1:?--server needs a value}") ;;
    --watch)  WATCH=1; if [[ "${2:-}" =~ ^[0-9]+$ ]]; then INTERVAL="$2"; shift; fi ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
command -v dig >/dev/null 2>&1 || { echo "dig not found. Install it: sudo apt install dnsutils" >&2; exit 2; }

# On ns1 itself, also check loopback.
if pgrep -x named >/dev/null 2>&1 || pgrep -x unbound >/dev/null 2>&1; then
  SERVERS+=("127.0.0.1")
fi
LOG="${LOG:-./dns-health-team$TEAM.log}"
if [ -t 1 ]; then GREEN=$'\e[32m'; RED=$'\e[31m'; RST=$'\e[0m'; else GREEN=""; RED=""; RST=""; fi

# query SERVER NAME TYPE [extra dig options]  ->  sets Q_RC, Q_STATUS, Q_ANSWER
query() {
  local out
  out="$(dig @"$1" "$2" "$3" +time=2 +tries=1 +noall +comments +answer "${@:4}" 2>/dev/null)"
  Q_RC=$?
  Q_STATUS="$(printf '%s\n' "$out" | grep -o 'status: [A-Z]*' | head -n1 | cut -d' ' -f2)"
  Q_ANSWER="$(printf '%s\n' "$out" | grep -v '^;' | grep '[^[:space:]]' | awk '{print $NF}' | tr '\n' ' ')"
}

result() { # name ok(0/1) detail
  local name="$1" ok="$2" detail="$3"
  if [ "$ok" -eq 0 ]; then
    printf '  %s%-22s UP%s   %s\n' "$GREEN" "$name" "$RST" "$detail"
  else
    printf '  %s%-22s DOWN%s %s\n' "$RED" "$name" "$RST" "$detail"
  fi
  printf '%s %s %s %s\n' "$(date '+%F %T')" "$name" "$([ "$ok" -eq 0 ] && echo UP || echo DOWN)" "$detail" >> "$LOG"
}

LAST_SERIAL=""
check_once() {
  local s proto status=0 serial
  echo "[$(date '+%F %T')] team $TEAM  record $NAME"
  for s in "${SERVERS[@]}"; do
    for proto in udp tcp; do
      if [ "$proto" = tcp ]; then query "$s" "$NAME" A +tcp; else query "$s" "$NAME" A; fi
      if [ "$Q_RC" -eq 0 ] && [ "$Q_STATUS" = NOERROR ] && [ -n "${Q_ANSWER// /}" ]; then
        result "$s $proto" 0 "-> $Q_ANSWER"
      else
        result "$s $proto" 1 "dig rc=$Q_RC status=${Q_STATUS:-none} answer='${Q_ANSWER}'"
        status=1
      fi
    done
  done
  # Zone serial: a change you did not make means someone edited the zone.
  serial="$(dig @"${SERVERS[0]}" "$DOMAIN" SOA +short +time=2 +tries=1 2>/dev/null | grep -v '^;' | awk 'NF >= 7 { print $3; exit }')"
  if [ -n "$serial" ]; then
    echo "  zone $DOMAIN serial $serial"
    if [ -n "$LAST_SERIAL" ] && [ "$serial" != "$LAST_SERIAL" ]; then
      echo "  ${RED}FLAG: zone serial changed $LAST_SERIAL -> $serial. Was that your team?${RST}"
      printf '%s FLAG serial %s -> %s\n' "$(date '+%F %T')" "$LAST_SERIAL" "$serial" >> "$LOG"
    fi
    LAST_SERIAL="$serial"
  fi
  echo
  return $status
}

if [ "$WATCH" -eq 0 ]; then
  check_once
  exit $?
fi
echo "Logging to $LOG. Every ${INTERVAL}s. Ctrl+C to stop. Stop it before hands-off periods (R10)."
while :; do
  check_once
  sleep "$INTERVAL"
done
