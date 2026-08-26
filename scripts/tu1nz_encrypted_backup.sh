#!/usr/bin/env bash
set -Eeuo pipefail

TS="$(date +%F_%H-%M)"
BACKUP_DIR="/root/bot_backups"
LOG_FILE="/var/log/rclone_backup.log"
ARCHIVE="$BACKUP_DIR/bot_system_backup_${TS}.tar.gz"

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

/usr/bin/tar -czf "$ARCHIVE" \
  -C /opt telegram_chatbot spicymila_bot \
  -C /etc nginx \
  -C /opt/tu1nz_repos control

/usr/bin/rclone copyto "$ARCHIVE" "gcrypt01:backups/$(basename "$ARCHIVE")" \
  --transfers=2 --checkers=4 --bwlimit=2M \
  --log-file="$LOG_FILE" --log-level INFO

/usr/bin/find "$BACKUP_DIR" -type f -name '*.tar.gz' -mtime +7 -delete

COUNT=$(/usr/bin/find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | /usr/bin/wc -l)
TOTAL=$(/usr/bin/du -ch "$BACKUP_DIR"/*.tar.gz 2>/dev/null | /usr/bin/tail -1 | /usr/bin/awk '{print $1}')
notify "🟢 Backup fertig auf $(hostname) - $(date -Is). Dateien: $COUNT, lokal belegt: ${TOTAL:-0}, Ziel: gcrypt01:backups, Log: $LOG_FILE"
