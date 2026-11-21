#!/usr/bin/env bash
# TCDC blue team: back up service configs and data on a box, before you change anything.
#
# Creates a local tar.gz plus a sha256 file in BACKUP_DIR. Nothing leaves the box
# (rule R23: do not exfiltrate data from competition infrastructure). Existing
# files are only read, never modified.
#
# Usage:  sudo ./backup.sh [extra_path ...]
# Env:    BACKUP_DIR (default /root/tcdc-backup)
#
# To restore a single file:  sudo tar -xzpf <archive> -C / <path-without-leading-slash>

set -u
BACKUP_DIR="${BACKUP_DIR:-/root/tcdc-backup}"
STAMP="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -s)"
ARCHIVE="$BACKUP_DIR/$HOST-$STAMP.tar.gz"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Candidate paths. Only ones that exist are included.
CANDIDATES=(
  /etc
  /var/www
  /srv
  /opt
  /usr/local/etc
  /var/lib/bind
  /var/cache/bind
  /var/spool/cron
  /root/.ssh
  /var/lib/mosquitto
)
for h in /home/*; do
  [ -d "$h/.ssh" ] && CANDIDATES+=("$h/.ssh")
done
for extra in "$@"; do
  CANDIDATES+=("$extra")
done

# Directories bigger than MAX_MB are skipped (a huge /opt can make a backup
# take minutes and fill the disk). Paths you pass on the command line are
# always included.
MAX_MB="${MAX_MB:-300}"
PATHS=()
for p in "${CANDIDATES[@]}"; do
  [ -e "$p" ] || continue
  explicit=0
  for extra in "$@"; do [ "$p" = "$extra" ] && explicit=1; done
  if [ "$explicit" -eq 0 ]; then
    size_mb="$(timeout 20 du -sm "$p" 2>/dev/null | cut -f1)"
    if [ -z "$size_mb" ] || [ "$size_mb" -gt "$MAX_MB" ]; then
      echo "SKIPPING $p (over ${MAX_MB} MB or too slow to measure). Pass it as an argument to force it."
      continue
    fi
  fi
  PATHS+=("$p")
done

echo "Backing up ${#PATHS[@]} paths:"
printf '  %s\n' "${PATHS[@]}"

# Keep the backup dir itself out of the archive. tar warns about files that
# change while reading; that is fine for a live system.
tar --warning=no-file-changed --exclude="$BACKUP_DIR" -czpf "$ARCHIVE" "${PATHS[@]}" 2>/dev/null
rc=$?
if [ "$rc" -gt 1 ]; then
  echo "tar failed with code $rc" >&2
  exit "$rc"
fi

chmod 600 "$ARCHIVE"
sha256sum "$ARCHIVE" | tee "$ARCHIVE.sha256"
echo "Backup written: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# Also keep a plain copy of key package and service state for reference.
{
  echo "# $(date)"
  echo "## dpkg selections"
  dpkg --get-selections 2>/dev/null
  echo "## enabled services"
  systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null
  echo "## listening sockets"
  ss -tulnp 2>/dev/null
} > "$BACKUP_DIR/$HOST-$STAMP-state.txt"
chmod 600 "$BACKUP_DIR/$HOST-$STAMP-state.txt"
echo "State notes: $BACKUP_DIR/$HOST-$STAMP-state.txt"
