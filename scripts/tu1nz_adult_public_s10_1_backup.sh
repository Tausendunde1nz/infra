#!/usr/bin/env bash
set -euo pipefail
umask 0007

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly S8_BACKUP="$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_backup.sh"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"

fail() {
  printf 'S10_1_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

require_boundary() {
  local canonical
  canonical="$(readlink -m -- "$1")"
  [ "$canonical" = "$1" ] || fail "BACKUP_PATH_NOT_CANONICAL"
  case "$canonical" in
    "${BACKUP_PREFIX}"[0-9]*) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
}

require_s10_surface() {
  local path="$1" indexed
  "$S8_BACKUP" verify-existing "$path" >/dev/null
  [ -f "$path/s10-migration-binding-before.txt" ] || fail "S10_MIGRATION_BINDING_MISSING"
  [ -f "$path/s10-configuration-before.tar" ] || fail "S10_CONFIGURATION_BACKUP_MISSING"
  [ -f "$path/s10-units-before.tar" ] || fail "S10_UNITS_BACKUP_MISSING"
  [ -f "$path/s10-runtime-executables-before.tar" ] || fail "S10_RUNTIME_EXECUTABLES_BACKUP_MISSING"
  tar -tf "$path/s10-runtime-executables-before.tar" \
    | grep -qx './tu1nz_adult_public_s8_health.py' \
    || fail "S10_RUNTIME_EXECUTABLES_BACKUP_INCOMPLETE"
  [ -f "$path/s10-nginx-state-before.txt" ] || fail "S10_NGINX_STATE_MISSING"
  [ -f "$path/s10-s9-timer-state-before.txt" ] || fail "S10_S9_TIMER_STATE_MISSING"
  [ "$(wc -l <"$path/s10-s9-timer-state-before.txt" | tr -d '[:space:]')" = "4" ] \
    || fail "S10_S9_TIMER_STATE_INCOMPLETE"
  if grep -qx 'enabled=symlink' "$path/s10-nginx-state-before.txt"; then
    [ -f "$path/s10-nginx-enabled-link-before.txt" ] || fail "S10_NGINX_ENABLED_LINK_MISSING"
  fi
  while IFS= read -r -d '' indexed; do
    indexed="$(basename "$indexed")"
    awk -v expected="./$indexed" '$2 == expected { found=1 } END { exit !found }' "$path/SHA256SUMS" \
      || fail "S10_CHECKSUM_INDEX_INCOMPLETE"
  done < <(find "$path" -maxdepth 1 -type f -name 's10-*' -print0)
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
[ "$#" -eq 2 ] || fail "USAGE"
readonly ACTION="$1"
readonly BACKUP_PATH="$2"
require_boundary "$BACKUP_PATH"

if [ "$ACTION" = "verify-existing" ]; then
  require_s10_surface "$BACKUP_PATH"
  printf '{"ok":true,"safe_code":"S10_1_BACKUP_EXISTING_GREEN","path":"%s"}\n' "$BACKUP_PATH"
  exit 0
fi
[ "$ACTION" = "create" ] || fail "USAGE"

"$S8_BACKUP" create "$BACKUP_PATH" >/dev/null

: >"$BACKUP_PATH/s10-s9-timer-state-before.txt"
for unit in \
  tu1nz-adult-public-s9-audience.timer \
  tu1nz-adult-public-s9-nurture.timer \
  tu1nz-adult-public-s9-report.timer \
  tu1nz-adult-public-s9-health.timer
do
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  active="$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"
  case "$enabled" in enabled|disabled) ;; *) fail "S10_S9_TIMER_ENABLEMENT_UNEXPECTED" ;; esac
  case "$active" in active|inactive) ;; *) fail "S10_S9_TIMER_ACTIVITY_UNEXPECTED" ;; esac
  printf '%s|%s|%s\n' "$unit" "$enabled" "$active" >>"$BACKUP_PATH/s10-s9-timer-state-before.txt"
done

: >"$BACKUP_PATH/s10-migration-binding-before.txt"
for migration in \
  0026_commercial_s9_telegram_channel \
  0027_commercial_s9_publication_completion \
  0028_commercial_s10_1_wms_public_growth
do
  for suffix in sql down.sql; do
    path="$APPLICATION_ROOT/migrations/${migration}.${suffix}"
    if [ -f "$path" ]; then
      sha256sum "$path" >>"$BACKUP_PATH/s10-migration-binding-before.txt"
    fi
  done
done

(
  cd /etc/tu1nz
  find . -maxdepth 1 -type f \
    -name 'adult-commercial-s10-wms*.json' \
    -print0 | sort -z | tar --null -T - -cpf "$BACKUP_PATH/s10-configuration-before.tar"
)
(
  cd /etc/systemd/system
  find . -maxdepth 3 -type f \
    \( -name 'tu1nz-adult-public-s10*' -o -path './tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf' -o -path './tu1nz-adult-public-s9-*.service.d/s10-wms.conf' \) \
    -print0 | sort -z | tar --null -T - -cpf "$BACKUP_PATH/s10-units-before.tar"
)
[ -f /usr/local/bin/tu1nz_adult_public_s8_health.py ] \
  && [ ! -L /usr/local/bin/tu1nz_adult_public_s8_health.py ] \
  || fail "S10_RUNTIME_EXECUTABLE_UNSAFE"
tar -C /usr/local/bin -cpf "$BACKUP_PATH/s10-runtime-executables-before.tar" \
  ./tu1nz_adult_public_s8_health.py

{
  if [ -e /etc/nginx/sites-available/wantmeseen.conf ]; then
    [ ! -L /etc/nginx/sites-available/wantmeseen.conf ] || fail "S10_NGINX_AVAILABLE_SYMLINK_UNSAFE"
    printf 'available=present\n'
    cp --preserve=mode,timestamps /etc/nginx/sites-available/wantmeseen.conf "$BACKUP_PATH/s10-nginx-available-before.conf"
  else
    printf 'available=absent\n'
  fi
  if [ -L /etc/nginx/sites-enabled/wantmeseen.conf ]; then
    enabled_target="$(readlink /etc/nginx/sites-enabled/wantmeseen.conf)"
    case "$enabled_target" in
      /etc/nginx/sites-available/wantmeseen.conf|../sites-available/wantmeseen.conf) ;;
      *) fail "S10_NGINX_ENABLED_LINK_UNSAFE" ;;
    esac
    printf 'enabled=symlink\n'
    printf '%s\n' "$enabled_target" >"$BACKUP_PATH/s10-nginx-enabled-link-before.txt"
  elif [ -e /etc/nginx/sites-enabled/wantmeseen.conf ]; then
    printf 'enabled=file\n'
    cp --preserve=mode,timestamps /etc/nginx/sites-enabled/wantmeseen.conf "$BACKUP_PATH/s10-nginx-enabled-before.conf"
  else
    printf 'enabled=absent\n'
  fi
} >"$BACKUP_PATH/s10-nginx-state-before.txt"

find "$BACKUP_PATH" -maxdepth 1 -type f -exec chmod 0600 {} +
(
  cd "$BACKUP_PATH"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum >SHA256SUMS
  chmod 0600 SHA256SUMS
)
require_s10_surface "$BACKUP_PATH"
printf '{"ok":true,"safe_code":"S10_1_BACKUP_GREEN","path":"%s","index_sha256":"%s"}\n' \
  "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
