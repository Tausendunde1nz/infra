#!/usr/bin/env bash
set -Eeuo pipefail

RESTORE_BASE="/root/restore_test"
LOG="/project_tausendunde1nz/logs/restore_test.log"
REMOTE="gcrypt01:backups"
FAILURES=0

log() {
  printf '%s\n' "$*" | tee -a "$LOG"
}

fail() {
  log "FAIL $*"
  FAILURES=$((FAILURES + 1))
}

RUN_DIR="$RESTORE_BASE/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN_DIR"
log "=== $(date -Is) Restore-Test start ==="

LATEST="$(rclone lsjson "$REMOTE" --recursive --files-only --fast-list | jq -r 'if length == 0 then empty else max_by(.ModTime).Path end')"
if [[ -z "$LATEST" ]]; then
  fail "no remote backup found"
  exit 1
fi

LOCAL_ARCHIVE="$RUN_DIR/$(basename "$LATEST")"
log "Remote backup selected"
if ! rclone copyto "$REMOTE/$LATEST" "$LOCAL_ARCHIVE" -v 2>&1 | tee -a "$LOG"; then
  fail "remote download"
fi

if [[ "$LOCAL_ARCHIVE" != *.tar.gz ]]; then
  fail "unsupported backup format"
elif ! tar -xzf "$LOCAL_ARCHIVE" -C "$RUN_DIR"; then
  fail "archive extraction"
fi

if [[ ! -f "$RUN_DIR/nginx/nginx.conf" && ! -f "$RUN_DIR/etc/nginx/nginx.conf" ]]; then
  fail "restored nginx configuration missing"
fi

if [[ ! -d "$RUN_DIR/control" ]]; then
  fail "restored Control SSOT missing"
fi

COMPOSE_SEEN=0
while IFS= read -r -d '' yaml; do
  COMPOSE_SEEN=1
  log "docker compose config check"
  if (cd "$(dirname "$yaml")" && docker compose -f "$yaml" config >/dev/null 2>&1); then
    log "OK active docker compose config"
  else
    fail "active docker compose config"
  fi
done < <(find "$RUN_DIR" -path '*/backup_old/*' -prune -o -name docker-compose.yml -print0)

if (( COMPOSE_SEEN == 0 )); then
  log "No active docker-compose files found; configuration-only backup accepted"
fi

if (( FAILURES > 0 )); then
  log "=== $(date -Is) Restore-Test FAILED failures=$FAILURES ==="
  exit 1
fi

log "=== $(date -Is) Restore-Test SUCCESS ==="
