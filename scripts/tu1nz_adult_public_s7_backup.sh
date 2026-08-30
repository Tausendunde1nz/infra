#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-public-s7.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s7-public-soft-launch/"
readonly DATABASE="tu1nz_adult_commercial_s3"

fail() {
  printf 'S7_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

service_inactive() {
  [ "$(systemctl show "$SERVICE" -p LoadState --value 2>/dev/null || true)" = "not-found" ] && return
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "S7_SERVICE_NOT_INACTIVE"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" = "0" ] || fail "S7_SERVICE_PROCESS_PRESENT"
}

service_active() {
  [ "$(systemctl show "$SERVICE" -p LoadState --value 2>/dev/null || true)" = "loaded" ] || fail "S7_SERVICE_NOT_LOADED"
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "active" ] || fail "S7_SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" != "0" ] || fail "S7_SERVICE_PROCESS_MISSING"
}

verify_backup() {
  local path="$1"
  [ -d "$path" ] || fail "BACKUP_PATH_MISSING"
  [ ! -L "$path" ] || fail "BACKUP_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$path")" = "root:root" ] || fail "BACKUP_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$path")" in
    700|2700) ;;
    *) fail "BACKUP_MODE_DRIFT" ;;
  esac
  [ -f "$path/SHA256SUMS" ] || fail "BACKUP_HASH_INDEX_MISSING"
  (cd "$path" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "BACKUP_HASH_INVALID"
  [ ! -s "$path/application-status.txt" ] || fail "APPLICATION_STATUS_NOT_CLEAN"
  [ ! -s "$path/control-status.txt" ] || fail "CONTROL_STATUS_NOT_CLEAN"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$path/control.bundle" >/dev/null
  pg_restore --list "$path/database-before.dump" >/dev/null
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
if [ "$#" -eq 2 ] && [ "$1" = "verify-existing" ]; then
  readonly ACTION="verify"
  readonly SERVICE_MODE="inactive"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 2 ] && [ "$1" = "verify-live-existing" ]; then
  readonly ACTION="verify"
  readonly SERVICE_MODE="active"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 2 ] && [ "$1" = "create-live" ]; then
  readonly ACTION="create"
  readonly SERVICE_MODE="active"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 1 ]; then
  readonly ACTION="create"
  readonly SERVICE_MODE="inactive"
  readonly BACKUP_PATH="$1"
else
  fail "USAGE"
fi
case "$BACKUP_PATH" in
  "${BACKUP_PREFIX}"*) ;;
  *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
esac
if [ "$SERVICE_MODE" = "active" ]; then
  service_active
else
  service_inactive
fi
[ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
[ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"

if [ "$ACTION" = "verify" ]; then
  verify_backup "$BACKUP_PATH"
  printf '{"ok":true,"safe_code":"S7_BACKUP_EXISTING_GREEN","path":"%s","index_sha256":"%s"}\n' \
    "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
  exit 0
fi

[ ! -e "$BACKUP_PATH" ] || fail "BACKUP_PATH_EXISTS"
install -d -o root -g root -m 0700 "${BACKUP_PATH%/*}" "$BACKUP_PATH"
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle create "$BACKUP_PATH/application.bundle" --all
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle create "$BACKUP_PATH/control.bundle" --all
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/application-provenance.txt"
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/control-provenance.txt"
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" status --porcelain=v1 >"$BACKUP_PATH/application-status.txt"
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" status --porcelain=v1 >"$BACKUP_PATH/control-status.txt"
runuser -u postgres -- pg_dump -Fc "$DATABASE" >"$BACKUP_PATH/database-before.dump"
cp --archive /etc/nginx/sites-enabled/tu1nz.conf "$BACKUP_PATH/nginx-enabled-before.conf"
cp --archive /etc/nginx/sites-available/tu1nz.conf "$BACKUP_PATH/nginx-available-before.conf"
(
  cd /etc/tu1nz
  find . -maxdepth 1 -type f -name 'adult-commercial-s7-*' -print0 \
    | sort -z | tar --null -T - -cpf "$BACKUP_PATH/s7-configuration-before.tar"
)
(
  cd /etc/systemd/system
  find . -maxdepth 1 -type f -name 'tu1nz-adult-public-s7*' -print0 \
    | sort -z | tar --null -T - -cpf "$BACKUP_PATH/s7-units-before.tar"
)
systemctl show "$SERVICE" >"$BACKUP_PATH/service-before.txt" 2>/dev/null || true
printf '%s\n' \
  "Kill switch first: stop and disable the S7 service and health timer, install the versioned disabled Nginx configuration, validate and reload Nginx." \
  "Verify SHA256SUMS before any restore." \
  "Restore Git objects from the two bundles to the recorded commits." \
  "Restore both Nginx files and validate before reload." \
  "Restore the database only after a separate rollback decision." \
  >"$BACKUP_PATH/RESTORE.txt"
find "$BACKUP_PATH" -maxdepth 1 -type f -exec chmod 0600 {} +
(
  cd "$BACKUP_PATH"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum >SHA256SUMS
  chmod 0600 SHA256SUMS
)
verify_backup "$BACKUP_PATH"
printf '{"ok":true,"safe_code":"S7_BACKUP_GREEN","path":"%s","index_sha256":"%s"}\n' \
  "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
