#!/usr/bin/env bash
set -Eeuo pipefail

TS="$(date -u +%Y%m%dT%H-%M-%SZ)"
BACKUP_DIR="/opt/tu1nz_repos/backups/encrypted-system"
LOG_FILE="/var/log/tausendunde1nz/rclone_backup.log"
ARCHIVE="$BACKUP_DIR/tu1nz_system_backup_${TS}.tar.gz"
DUMP_DIR=""
DB_DUMP=""

notify() {
  /usr/local/bin/notify_telegram.sh "$1" || true
}

on_err() {
  rc=$?
  notify "🔴 Backup/Upload fehlgeschlagen auf $(hostname) - $(date -Is). Siehe Log: $LOG_FILE"
  exit "$rc"
}
trap on_err ERR

cleanup() {
  if [[ -n "$DUMP_DIR" && "$DUMP_DIR" == "$BACKUP_DIR"/.s1-dump.* ]]; then
    [[ -z "$DB_DUMP" ]] || /usr/bin/rm -f -- "$DB_DUMP"
    /usr/bin/rmdir -- "$DUMP_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

for required in \
  /opt/telegram_chatbot \
  /opt/spicymila_bot \
  /etc/nginx \
  /opt/tu1nz_repos/control \
  /opt/tu1nz_repos/adult-publishing-core \
  /opt/tu1nz_repos/releases/adult-publishing/staging-s1/application \
  /opt/tu1nz_repos/releases/adult-publishing/staging-s1/control \
  /opt/tu1nz_repos/releases/adult-publishing/staging-s1/venv \
  /etc/tu1nz/adult-publishing/staging-s1 \
  /var/lib/tausendunde1nz/adult-publishing/staging-s1
do
  [[ -e "$required" ]] || {
    echo "Required backup path is absent: $required" >&2
    exit 1
  }
done

DUMP_DIR="$(/usr/bin/mktemp -d "$BACKUP_DIR/.s1-dump.XXXXXX")"
DB_DUMP="$DUMP_DIR/staging-s1-database.dump"
/usr/sbin/runuser -u tu1nz-adult-s1 -- \
  /usr/bin/pg_dump --format=custom --file="$DB_DUMP" --dbname=tu1nz_adult_s1
[[ -s "$DB_DUMP" ]] || {
  echo "STAGING-S1 PostgreSQL dump is empty" >&2
  exit 1
}

/usr/bin/tar -czf "$ARCHIVE" \
  --exclude='*/.git/FETCH_HEAD' \
  --exclude='*/.git/index.lock' \
  -C /opt telegram_chatbot spicymila_bot \
  -C /etc nginx \
  -C /opt/tu1nz_repos control adult-publishing-core \
  -C /opt/tu1nz_repos \
    releases/adult-publishing/staging-s1/application \
    releases/adult-publishing/staging-s1/control \
    releases/adult-publishing/staging-s1/venv \
  -C /etc tu1nz/adult-publishing/staging-s1 \
  -C /var/lib tausendunde1nz/adult-publishing/staging-s1 \
  -C "$DUMP_DIR" staging-s1-database.dump

/usr/bin/rclone copyto "$ARCHIVE" "gcrypt01:backups/$(basename "$ARCHIVE")" \
  --transfers=2 --checkers=4 --bwlimit=2M \
  --log-file="$LOG_FILE" --log-level INFO

/usr/bin/find "$BACKUP_DIR" -type f -name '*.tar.gz' -mtime +7 -delete

COUNT=$(/usr/bin/find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | /usr/bin/wc -l)
TOTAL=$(/usr/bin/du -ch "$BACKUP_DIR"/*.tar.gz 2>/dev/null | /usr/bin/tail -1 | /usr/bin/awk '{print $1}')
notify "🟢 Backup fertig auf $(hostname) - $(date -Is). Dateien: $COUNT, lokal belegt: ${TOTAL:-0}, Ziel: gcrypt01:backups, enthält: control + adult-publishing-core + STAGING-S1 release/config/state/PostgreSQL, Log: $LOG_FILE"
