#!/usr/bin/env bash
# TCDC blue team: apply SAFE sshd hardening through a drop-in file.
#
# Dry run by default. Nothing changes unless you pass --apply.
#
# What it sets (all low risk for a password-checked SSH service):
#   PermitRootLogin no, PermitEmptyPasswords no, MaxAuthTries 3,
#   LoginGraceTime 30, X11Forwarding no, PermitUserEnvironment no
# Optional (only if you pass them):
#   --allow-users a,b,c   adds an AllowUsers line. A typo locks people out, so
#                         double check the names, and keep a session open.
#
# What it deliberately does NOT touch:
#   PasswordAuthentication. The scoring checker may log in with a password.
#   Turning it off could take your SSH service down. Only change it if Black
#   Team confirms the checker uses keys.
#
# Safety: it validates with "sshd -t" before reloading, keeps a backup, and
# removes its own drop-in if validation fails. KEEP YOUR CURRENT SSH SESSION
# OPEN and test a second login before closing it.
#
# Usage: sudo ./harden-ssh.sh [--apply] [--allow-users alice,bob]

set -u
APPLY=0
ALLOW=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --allow-users) shift; ALLOW="${1:-}" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

DROPIN_DIR=/etc/ssh/sshd_config.d
DROPIN="$DROPIN_DIR/00-tcdc-hardening.conf"

if [ "$(id -u)" -ne 0 ]; then echo "Run as root (sudo)." >&2; exit 1; fi
command -v sshd >/dev/null 2>&1 || { echo "sshd not found." >&2; exit 1; }

CONTENT="# Managed by TCDC blue team toolkit. Remove this file to revert.
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
PermitUserEnvironment no"
if [ -n "$ALLOW" ]; then
  CONTENT="$CONTENT
AllowUsers $(echo "$ALLOW" | tr ',' ' ')"
fi

echo "Drop-in file: $DROPIN"
echo "----"
echo "$CONTENT"
echo "----"

if ! grep -Eqs '^\s*Include\s+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then
  echo "WARNING: /etc/ssh/sshd_config has no Include for sshd_config.d. The drop-in would be ignored." >&2
  echo "Add this as the first line of /etc/ssh/sshd_config yourself: Include /etc/ssh/sshd_config.d/*.conf" >&2
fi

if [ "$APPLY" -ne 1 ]; then
  echo "DRY RUN. Re-run with --apply to write the file and reload sshd."
  exit 0
fi

mkdir -p "$DROPIN_DIR"
# Keep the previous version outside sshd_config.d so sshd never reads the copy.
PREV=""
if [ -f "$DROPIN" ]; then
  PREV="/root/00-tcdc-hardening.conf.prev.$(date +%s)"
  cp -p "$DROPIN" "$PREV"
fi
printf '%s\n' "$CONTENT" > "$DROPIN"
chmod 644 "$DROPIN"

if sshd -t 2>/tmp/tcdc-sshd-test.err; then
  echo "sshd -t passed."
else
  echo "sshd -t FAILED:" >&2
  cat /tmp/tcdc-sshd-test.err >&2
  if [ -n "$PREV" ]; then
    cp -p "$PREV" "$DROPIN"
    echo "Restored the previous drop-in from $PREV" >&2
  else
    rm -f "$DROPIN"
    echo "Removed the new drop-in. sshd config is unchanged." >&2
  fi
  exit 1
fi

# Ubuntu names the unit "ssh"; some systems use "sshd".
if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
  echo "sshd reloaded. Existing sessions stay connected."
else
  echo "Could not reload via systemctl. Reload sshd manually." >&2
  exit 1
fi

echo "Effective values now:"
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries|logingracetime|x11forwarding|permituserenvironment|allowusers|passwordauthentication) '
echo
echo "NEXT: open a SECOND SSH session to confirm login still works, then check the scoreboard."
