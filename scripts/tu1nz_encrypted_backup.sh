#!/usr/bin/env bash
set -Eeuo pipefail

TS="$(date -u +%Y%m%dT%H-%M-%SZ)"
BACKUP_DIR="/opt/tu1nz_repos/backups/encrypted-system"
LOG_FILE="/var/log/tausendunde1nz/rclone_backup.log"
ARCHIVE="$BACKUP_DIR/tu1nz_system_backup_${TS}.tar.gz"

notify() {
  /usr/local/bin/notify_telegram.sh "$1" || true
}

on_err() {
  rc=$?
  notify "🔴 Backup/Upload fehlgeschlagen auf $(hostname) - $(date -Is). Siehe Log: $LOG_FILE"
  exit "$rc"
}
trap on_err ERR

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

for required in \
  /opt/telegram_chatbot \
  /opt/spicymila_bot \
  /etc/nginx \
  /opt/tu1nz_repos/control \
  /opt/tu1nz_repos/adult-publishing-core
do
  [[ -e "$required" ]] || {
    echo "Required backup path is absent: $required" >&2
    exit 1
  }
done

/usr/bin/tar -czf "$ARCHIVE" \
  --exclude='*/.git/FETCH_HEAD' \
  --exclude='*/.git/index.lock' \
  -C /opt telegram_chatbot spicymila_bot \
  -C /etc nginx \
  -C /opt/tu1nz_repos control adult-publishing-core

/usr/bin/rclone copyto "$ARCHIVE" "gcrypt01:backups/$(basename "$ARCHIVE")" \
  --transfers=2 --checkers=4 --bwlimit=2M \
  --log-file="$LOG_FILE" --log-level INFO

/usr/bin/find "$BACKUP_DIR" -type f -name '*.tar.gz' -mtime +7 -delete

COUNT=$(/usr/bin/find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | /usr/bin/wc -l)
TOTAL=$(/usr/bin/du -ch "$BACKUP_DIR"/*.tar.gz 2>/dev/null | /usr/bin/tail -1 | /usr/bin/awk '{print $1}')
notify "🟢 Backup fertig auf $(hostname) - $(date -Is). Dateien: $COUNT, lokal belegt: ${TOTAL:-0}, Ziel: gcrypt01:backups, enthält: control + adult-publishing-core, Log: $LOG_FILE"
