#!/usr/bin/env bash
# TCDC blue team: independent service health check, run from your jumpbox.
#
# The scoreboard is the source of truth, but it is slow to react and does not
# tell you WHY something is down. This checks each exhibit yourself every N seconds
# so you notice a problem right after you make a change.
#
# It only connects to YOUR team's own boxes. It does not log in, send
# credentials, or change anything. It checks that something answers correctly
# on the service port, which is necessary but not always sufficient for the
# real checker (which may log in).
#
# Usage:  ./svc-check.sh <team-id> [--once] [--interval 30]
# Example: ./svc-check.sh 5
#
# Needs: bash, curl. Uses dig if installed for the DNS check.

TEAM="${1:-}"
if ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <team-id> [--once] [--interval SECONDS]" >&2
  exit 2
fi
shift
ONCE=0
INTERVAL=30
while [ $# -gt 0 ]; do
  case "$1" in
    --once) ONCE=1 ;;
    --interval) shift; INTERVAL="${1:-30}" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

NET=$((100 + TEAM))
IP_NS1="10.$NET.10.53"
IP_FTP="10.$NET.10.21"
IP_WEB="10.$NET.10.80"
IP_SSH="10.$NET.10.22"
IP_AD="10.$NET.20.88"
IP_MQTT="10.$NET.30.49"
IP_CAM="10.150.0.$TEAM"
DOMAIN="team$TEAM.playtcdc.org"
LOG="${LOG:-./svc-check-team$TEAM.log}"

if [ -t 1 ]; then GREEN=$'\e[32m'; RED=$'\e[31m'; RST=$'\e[0m'; else GREEN=""; RED=""; RST=""; fi

# TCP connect test with a timeout, using bash's /dev/tcp (no nc needed).
tcp_open() { timeout 3 bash -c ">/dev/tcp/$1/$2" 2>/dev/null; }

# Read the first line a server sends after connecting (FTP and SSH banners).
banner() {
  timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2 && IFS= read -r -t 3 line <&3 && printf '%s' \"\$line\"" 2>/dev/null | tr -d '\r'
}

http_code() { curl -s -o /dev/null -m 4 -w '%{http_code}' "http://$1/" 2>/dev/null; }

result() { # name status detail
  local name="$1" ok="$2" detail="$3"
  if [ "$ok" -eq 0 ]; then
    printf '  %s%-18s UP%s   %s\n' "$GREEN" "$name" "$RST" "$detail"
  else
    printf '  %s%-18s DOWN%s %s\n' "$RED" "$name" "$RST" "$detail"
  fi
  printf '%s %s %s %s\n' "$(date '+%F %T')" "$name" "$([ "$ok" -eq 0 ] && echo UP || echo DOWN)" "$detail" >> "$LOG"
}

check_all() {
  echo "[$(date '+%F %T')] team $TEAM"

  # DNS: ask ns1 for its own A record, if dig is available. Otherwise just TCP 53.
  if command -v dig >/dev/null 2>&1; then
    ans="$(dig +time=2 +tries=1 +short @"$IP_NS1" "ns1.$DOMAIN" A 2>/dev/null | head -n1)"
    if [ -n "$ans" ]; then result "DNS ns1" 0 "ns1.$DOMAIN -> $ans"; else result "DNS ns1" 1 "no answer for ns1.$DOMAIN from $IP_NS1"; fi
  else
    if tcp_open "$IP_NS1" 53; then result "DNS ns1 (tcp53)" 0 "port open (install dig for a real query)"; else result "DNS ns1 (tcp53)" 1 "port closed"; fi
  fi

  # FTP: expect a 220 banner.
  b="$(banner "$IP_FTP" 21)"
  case "$b" in 220*) result "FTP ftp-archive" 0 "$b" ;; *) result "FTP ftp-archive" 1 "banner: '${b:-none}'" ;; esac

  # HTTP on-prem and cloud.
  code="$(http_code "$IP_WEB")"
  case "$code" in 2*|3*|401|403) result "HTTP artifactorium" 0 "HTTP $code" ;; *) result "HTTP artifactorium" 1 "HTTP ${code:-none}" ;; esac
  code="$(http_code "$IP_CAM")"
  case "$code" in 2*|3*|401|403) result "HTTP ipcam" 0 "HTTP $code" ;; *) result "HTTP ipcam" 1 "HTTP ${code:-none}" ;; esac

  # SSH: expect SSH- banner.
  b="$(banner "$IP_SSH" 22)"
  case "$b" in SSH-*) result "SSH ssh-workstation" 0 "$b" ;; *) result "SSH ssh-workstation" 1 "banner: '${b:-none}'" ;; esac

  # Active Directory: Kerberos, LDAP, SMB should all answer.
  missing=""
  for p in 88 389 445; do tcp_open "$IP_AD" "$p" || missing="$missing $p"; done
  if [ -z "$missing" ]; then result "AD ad (88,389,445)" 0 "all ports open"; else result "AD ad" 1 "closed:$missing"; fi

  # MQTT: TCP 1883 reachable. Credentials are not tested here.
  if tcp_open "$IP_MQTT" 1883; then result "MQTT mqtt (1883)" 0 "port open"; else result "MQTT mqtt (1883)" 1 "port closed"; fi
  echo
}

echo "Logging to $LOG. Ctrl+C to stop."
while :; do
  check_all
  [ "$ONCE" -eq 1 ] && break
  sleep "$INTERVAL"
done
