#!/usr/bin/env bash
# TCDC blue team: rotate OS user passwords one at a time, safely.
#
# Dry run by default (lists who would change). With --apply it changes ONE user,
# prints the new password, then WAITS for you to update the TCDC dashboard
# (https://dash.playtcdc.org/team/passwords) and confirm the scoreboard is
# still green before it moves to the next user.
#
# Never touches: blackteam, whiteteam (rule R8). Never deletes or locks anyone.
# Never changes a password you did not ask for: the default list is the OS
# users from the competition packet, and only those that exist on this box.
#
# New passwords are saved to a root-only file so your captain can record them.
# (Passwords are allowed to leave the box by rule R23; keep them off the repo.)
#
# Usage:
#   sudo ./rotate-passwords.sh                       dry run, default packet users
#   sudo ./rotate-passwords.sh --apply               rotate each user interactively
#   sudo ./rotate-passwords.sh --apply --users washington,kennedy
#   sudo ./rotate-passwords.sh --apply --users root  rotate root explicitly
#   sudo ./rotate-passwords.sh --apply --no-wait     do not pause between users
#
# Env: PW_LENGTH (default 20), OUT_FILE (default /root/tcdc-passwords-<host>.txt)

set -u
umask 077

DEFAULT_USERS="washington kennedy teddy lincoln ross streep franklin parks armstrong hamilton mlk tubman manziel deniro bush"
NEVER="blackteam whiteteam"
APPLY=0
WAIT=1
USERS="$DEFAULT_USERS"
PW_LENGTH="${PW_LENGTH:-20}"
OUT_FILE="${OUT_FILE:-/root/tcdc-passwords-$(hostname -s).txt}"

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --no-wait) WAIT=0 ;;
    --users) shift; USERS="$(echo "${1:-}" | tr ',' ' ')" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then echo "Run as root (sudo)." >&2; exit 1; fi

# Random password with upper, lower, digit and a few safe symbols.
# No characters that confuse shells or chpasswd (no colon, quote, backslash, space).
gen_pw() {
  local pw
  while :; do
    pw="$(LC_ALL=C tr -dc 'A-Za-z0-9@%+=_-' < /dev/urandom | head -c "$PW_LENGTH")"
    case "$pw" in
      *[A-Z]*) ;; *) continue ;;
    esac
    case "$pw" in
      *[a-z]*) ;; *) continue ;;
    esac
    case "$pw" in
      *[0-9]*) ;; *) continue ;;
    esac
    printf '%s' "$pw"
    return
  done
}

is_never() {
  for n in $NEVER; do [ "$1" = "$n" ] && return 0; done
  return 1
}

PLAN=()
for u in $USERS; do
  if is_never "$u"; then echo "SKIP $u (protected by rule R8)"; continue; fi
  if ! id "$u" >/dev/null 2>&1; then echo "skip $u (not on this box)"; continue; fi
  PLAN+=("$u")
done

echo
echo "Users to rotate on $(hostname): ${PLAN[*]:-none}"
if [ "$APPLY" -ne 1 ]; then
  echo "DRY RUN. Re-run with --apply. Nothing was changed."
  exit 0
fi
[ "${#PLAN[@]}" -eq 0 ] && exit 0

touch "$OUT_FILE"; chmod 600 "$OUT_FILE"
echo "Passwords will be appended to: $OUT_FILE"
echo "Keep a root shell or console open. Do not log out of your only session."
echo

for u in "${PLAN[@]}"; do
  pw="$(gen_pw)"
  if printf '%s:%s\n' "$u" "$pw" | chpasswd; then
    printf '%s %s %s %s\n' "$(date '+%F %T')" "$(hostname -s)" "$u" "$pw" >> "$OUT_FILE"
    echo "CHANGED  $u  ->  $pw"
    if [ "$WAIT" -eq 1 ]; then
      echo "  1) Update the dashboard password page if this user could be used by a check."
      echo "  2) Confirm the scoreboard is green for 2 ticks (60 s)."
      read -r -p "  Press Enter for the next user, or type q to stop: " ans
      [ "$ans" = "q" ] && { echo "Stopped by user."; break; }
    fi
  else
    echo "FAILED to change $u" >&2
  fi
done
echo "Done. Record passwords from $OUT_FILE somewhere your team controls, then protect or remove the file."
