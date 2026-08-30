#!/usr/bin/env bash
set -euo pipefail
umask 0007

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"

fail() {
  printf 'S8_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

service_state() {
  local service="$1"
  systemctl show "$service" -p ActiveState --value 2>/dev/null || printf 'not-found\n'
}

require_git_index_safe() {
  local repository="$1"
  [ "$(stat -c '%U:%G' "$repository/.git/index")" = "chatops:chatops" ] \
    || fail "GIT_INDEX_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$repository/.git/index")" in
    600|660) ;;
    *) fail "GIT_INDEX_MODE_DRIFT" ;;
  esac
}

normalize_git_index_mode() {
  local repository="$1"
  local index="$repository/.git/index"
  [ -f "$index" ] && [ ! -L "$index" ] || fail "GIT_INDEX_UNSAFE_TYPE"
  [ "$(stat -c '%U:%G' "$index")" = "chatops:chatops" ] \
    || fail "GIT_INDEX_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$index")" in
    600|660) ;;
    644) chmod 0660 "$index" ;;
    *) fail "GIT_INDEX_MODE_UNEXPECTED" ;;
  esac
  require_git_index_safe "$repository"
}

verify_bundle_isolated() {
  local bundle="$1"
  local verify_root
  verify_root="$(mktemp -d /run/tu1nz-s8-bundle-verify.XXXXXX)"
  git init --bare --quiet "$verify_root/repository.git"
  if ! git -C "$verify_root/repository.git" bundle verify "$bundle" >/dev/null; then
    find "$verify_root" -depth -delete
    return 1
  fi
  find "$verify_root" -depth -delete
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
  [ -z "$(find "$path" -maxdepth 1 -type f -iname '*token*' -print -quit)" ] || fail "SECRET_MATERIAL_IN_BACKUP"
  verify_bundle_isolated "$path/application.bundle"
  verify_bundle_isolated "$path/control.bundle"
  pg_restore --list "$path/database-before.dump" >/dev/null
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
if [ "$#" -eq 1 ] && [ "$1" = "normalize-index-modes" ]; then
  normalize_git_index_mode "$APPLICATION_ROOT"
  normalize_git_index_mode "$CONTROL_ROOT"
  printf '{"ok":true,"safe_code":"S8_GIT_INDEX_MODES_GREEN"}\n'
  exit 0
elif [ "$#" -eq 2 ] && [ "$1" = "verify-existing" ]; then
  readonly ACTION="verify"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 2 ] && [ "$1" = "create" ]; then
  readonly ACTION="create"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 2 ] && [ "$1" = "create-s7-recovery" ]; then
  readonly ACTION="create-s7-recovery"
  readonly BACKUP_PATH="$2"
else
  fail "USAGE"
fi
case "$BACKUP_PATH" in
  "${BACKUP_PREFIX}"*) ;;
  *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
esac
[ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
[ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"
require_git_index_safe "$APPLICATION_ROOT"
require_git_index_safe "$CONTROL_ROOT"

if [ "$ACTION" = "verify" ]; then
  verify_backup "$BACKUP_PATH"
  printf '{"ok":true,"safe_code":"S8_BACKUP_EXISTING_GREEN","path":"%s","index_sha256":"%s"}\n' \
    "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
  exit 0
fi

if [ "$ACTION" = "create" ]; then
  [ "$(service_state "$S7_SERVICE")" = "active" ] || fail "S7_SERVICE_NOT_ACTIVE"
else
  [ "$(service_state "$S7_SERVICE")" = "failed" ] || fail "S7_RECOVERY_STATE_NOT_FAILED"
  [ "$(systemctl show "$S7_SERVICE" -p Result --value)" = "start-limit-hit" ] \
    || fail "S7_RECOVERY_RESULT_NOT_START_LIMIT_HIT"
  [ "$(systemctl show "$S7_SERVICE" -p MainPID --value)" = "0" ] \
    || fail "S7_RECOVERY_PROCESS_PRESENT"
  [ "$(service_state "$S8_SERVICE")" = "inactive" ] || fail "S8_SERVICE_NOT_INACTIVE"
  [ "$(systemctl is-enabled "$S8_SERVICE" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_SERVICE_NOT_DISABLED"
  case "$(service_state "$HEALTH_TIMER")" in
    inactive|not-found) ;;
    *) fail "S8_HEALTH_TIMER_ACTIVE" ;;
  esac
fi
[ ! -e "$BACKUP_PATH" ] || fail "BACKUP_PATH_EXISTS"
install -d -o root -g root -m 0700 "${BACKUP_PATH%/*}" "$BACKUP_PATH"
runuser -u chatops -- git -C "$APPLICATION_ROOT" bundle create - --all >"$BACKUP_PATH/application.bundle"
runuser -u chatops -- git -C "$CONTROL_ROOT" bundle create - --all >"$BACKUP_PATH/control.bundle"
runuser -u chatops -- git -C "$APPLICATION_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/application-provenance.txt"
runuser -u chatops -- git -C "$CONTROL_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/control-provenance.txt"
runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1 >"$BACKUP_PATH/application-status.txt"
runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1 >"$BACKUP_PATH/control-status.txt"
runuser -u postgres -- pg_dump -Fc "$DATABASE" >"$BACKUP_PATH/database-before.dump"
cp --archive /etc/nginx/sites-enabled/tu1nz.conf "$BACKUP_PATH/nginx-enabled-before.conf"
cp --archive /etc/nginx/sites-available/tu1nz.conf "$BACKUP_PATH/nginx-available-before.conf"
(
  cd /etc/tu1nz
  find . -maxdepth 1 -type f \
    \( -name 'adult-commercial-s7-public.json' -o -name 'adult-commercial-s8-public-telegram.json' -o -name 'adult-commercial-s8-copy.json' \) \
    -print0 | sort -z | tar --null -T - -cpf "$BACKUP_PATH/public-configuration-before.tar"
)
(
  cd /etc/systemd/system
  find . -maxdepth 1 -type f \
    \( -name 'tu1nz-adult-public-s7*' -o -name 'tu1nz-adult-public-s8*' \) \
    -print0 | sort -z | tar --null -T - -cpf "$BACKUP_PATH/public-units-before.tar"
)
systemctl show "$S7_SERVICE" >"$BACKUP_PATH/s7-service-before.txt" 2>/dev/null || true
systemctl show "$S8_SERVICE" >"$BACKUP_PATH/s8-service-before.txt" 2>/dev/null || true
if [ -e /etc/tu1nz/adult-commercial-s8-telegram.token ]; then
  stat --printf='owner=%U:%G\nmode=%a\nsize=%s\ntype=%F\nlinks=%h\n' \
    /etc/tu1nz/adult-commercial-s8-telegram.token >"$BACKUP_PATH/credential-metadata-before.txt"
else
  printf 'absent=true\n' >"$BACKUP_PATH/credential-metadata-before.txt"
fi
printf '%s\n' \
  "Close the database kill switch before rollback: public, joins and notifications false." \
  "Stop and disable the S8 service and health timer; preserve S8 database records." \
  "Verify SHA256SUMS before any restore." \
  "Restore Git objects from the bundles to the recorded commits." \
  "Restore the public configuration and units archive without restoring any credential." \
  "Restore the database only after a separate destructive rollback decision." \
  >"$BACKUP_PATH/RESTORE.txt"
find "$BACKUP_PATH" -maxdepth 1 -type f -exec chmod 0600 {} +
(
  cd "$BACKUP_PATH"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum >SHA256SUMS
  chmod 0600 SHA256SUMS
)
verify_backup "$BACKUP_PATH"
require_git_index_safe "$APPLICATION_ROOT"
require_git_index_safe "$CONTROL_ROOT"
if [ "$ACTION" = "create-s7-recovery" ]; then
  readonly SAFE_CODE="S8_S7_RECOVERY_BACKUP_GREEN"
else
  readonly SAFE_CODE="S8_BACKUP_GREEN"
fi
printf '{"ok":true,"safe_code":"%s","path":"%s","index_sha256":"%s"}\n' \
  "$SAFE_CODE" "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
