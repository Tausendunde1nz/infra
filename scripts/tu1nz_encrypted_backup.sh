#!/usr/bin/env bash
set -Eeuo pipefail

TS="$(date -u +%Y%m%dT%H-%M-%SZ)"
BACKUP_DIR="/opt/tu1nz_repos/backups/encrypted-system"
LOG_FILE="/var/log/tausendunde1nz/rclone_backup.log"
ARCHIVE="$BACKUP_DIR/tu1nz_system_backup_${TS}.tar.gz"
S1_DUMP_DIR=""
S1_DB_DUMP=""
S1_RUNTIME_USER="tu1nz-adult-s1"
COMMERCIAL_DUMP_DIR=""
COMMERCIAL_DB_DUMP=""
COMMERCIAL_INCLUDED=0
COMMERCIAL_RUNTIME_USER="postgres"
COMMERCIAL_RELEASE_ROOT="/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial"
COMMERCIAL_CONFIG_ROOT="/etc/tu1nz/adult-publishing/staging-s0-commercial"
COMMERCIAL_STATE_ROOT="/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial"
COMMERCIAL_TAR_ARGS=()

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
  if [[ -n "$S1_DUMP_DIR" && "$S1_DUMP_DIR" == "$BACKUP_DIR"/.s1-dump.* ]]; then
    [[ -z "$S1_DB_DUMP" ]] || /usr/bin/rm -f -- "$S1_DB_DUMP"
    /usr/bin/rmdir -- "$S1_DUMP_DIR" 2>/dev/null || true
  fi
  if [[ -n "$COMMERCIAL_DUMP_DIR" && "$COMMERCIAL_DUMP_DIR" == "$BACKUP_DIR"/.commercial-s0-dump.* ]]; then
    [[ -z "$COMMERCIAL_DB_DUMP" ]] || /usr/bin/rm -f -- "$COMMERCIAL_DB_DUMP"
    /usr/bin/rmdir -- "$COMMERCIAL_DUMP_DIR" 2>/dev/null || true
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

S1_DUMP_DIR="$(/usr/bin/mktemp -d "$BACKUP_DIR/.s1-dump.XXXXXX")"
chown "$S1_RUNTIME_USER:$S1_RUNTIME_USER" "$S1_DUMP_DIR"
chmod 0700 "$S1_DUMP_DIR"
S1_DB_DUMP="$S1_DUMP_DIR/staging-s1-database.dump"
/usr/sbin/runuser -u "$S1_RUNTIME_USER" -- \
  /usr/bin/pg_dump --format=custom --file="$S1_DB_DUMP" --dbname=tu1nz_adult_s1
[[ -s "$S1_DB_DUMP" ]] || {
  echo "STAGING-S1 PostgreSQL dump is empty" >&2
  exit 1
}

commercial_paths=(
  "$COMMERCIAL_RELEASE_ROOT/application"
  "$COMMERCIAL_RELEASE_ROOT/control"
  "$COMMERCIAL_RELEASE_ROOT/venv"
  "$COMMERCIAL_CONFIG_ROOT"
  "$COMMERCIAL_STATE_ROOT"
)
commercial_present=0
for candidate in "${commercial_paths[@]}"; do
  [[ ! -e "$candidate" ]] || commercial_present=$((commercial_present + 1))
done
if (( commercial_present != 0 && commercial_present != ${#commercial_paths[@]} )); then
  echo "Commercial S0 backup paths are only partially provisioned" >&2
  exit 1
fi
if (( commercial_present == ${#commercial_paths[@]} )); then
  COMMERCIAL_INCLUDED=1
  COMMERCIAL_DUMP_DIR="$(/usr/bin/mktemp -d "$BACKUP_DIR/.commercial-s0-dump.XXXXXX")"
  chown root:root "$COMMERCIAL_DUMP_DIR"
  chmod 0700 "$COMMERCIAL_DUMP_DIR"
  COMMERCIAL_DB_DUMP="$COMMERCIAL_DUMP_DIR/commercial-s0-database.dump"
  /usr/sbin/runuser -u "$COMMERCIAL_RUNTIME_USER" -- \
    /usr/bin/pg_dump --format=custom \
      --dbname=tu1nz_adult_commercial_s0 >"$COMMERCIAL_DB_DUMP"
  chown root:root "$COMMERCIAL_DB_DUMP"
  chmod 0600 "$COMMERCIAL_DB_DUMP"
  [[ -s "$COMMERCIAL_DB_DUMP" ]] || {
    echo "Commercial S0 PostgreSQL dump is empty" >&2
    exit 1
  }
  COMMERCIAL_TAR_ARGS=(
    -C /opt/tu1nz_repos
      releases/adult-publishing/staging-s0-commercial/application
      releases/adult-publishing/staging-s0-commercial/control
      releases/adult-publishing/staging-s0-commercial/venv
    -C /etc tu1nz/adult-publishing/staging-s0-commercial
    -C /var/lib tausendunde1nz/adult-publishing/staging-s0-commercial
    -C "$COMMERCIAL_DUMP_DIR" commercial-s0-database.dump
  )
fi

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
  -C "$S1_DUMP_DIR" staging-s1-database.dump \
  "${COMMERCIAL_TAR_ARGS[@]}"

/usr/bin/rclone copyto "$ARCHIVE" "gcrypt01:backups/$(basename "$ARCHIVE")" \
  --transfers=2 --checkers=4 --bwlimit=2M \
  --log-file="$LOG_FILE" --log-level INFO

/usr/bin/find "$BACKUP_DIR" -type f -name '*.tar.gz' -mtime +7 -delete

COUNT=$(/usr/bin/find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | /usr/bin/wc -l)
TOTAL=$(/usr/bin/du -ch "$BACKUP_DIR"/*.tar.gz 2>/dev/null | /usr/bin/tail -1 | /usr/bin/awk '{print $1}')
if (( COMMERCIAL_INCLUDED == 1 )); then
  COMMERCIAL_SUMMARY=" + commercial S0 release/config/state/PostgreSQL"
else
  COMMERCIAL_SUMMARY="; commercial S0 noch nicht provisioniert"
fi
notify "🟢 Backup fertig auf $(hostname) - $(date -Is). Dateien: $COUNT, lokal belegt: ${TOTAL:-0}, Ziel: gcrypt01:backups, enthält: control + adult-publishing-core + STAGING-S1 release/config/state/PostgreSQL${COMMERCIAL_SUMMARY}, Log: $LOG_FILE"
