#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s4-extended-staging/"

fail() {
  printf 'S4_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
if [ "$#" -eq 2 ] && [ "$1" = "verify-existing" ]; then
  readonly ACTION="verify-existing"
  readonly BACKUP_PATH="$2"
elif [ "$#" -eq 1 ]; then
  readonly ACTION="create"
  readonly BACKUP_PATH="$1"
else
  fail "USAGE"
fi
case "$BACKUP_PATH" in
  "${BACKUP_PREFIX}"*) ;;
  *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
esac
[ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "SERVICE_NOT_INACTIVE"
[ "$(systemctl show "$SERVICE" -p SubState --value)" = "dead" ] || fail "SERVICE_NOT_DEAD"
[ "$(systemctl show "$SERVICE" -p MainPID --value)" = "0" ] || fail "SERVICE_PROCESS_PRESENT"
[ "$(systemctl show "$SERVICE" -p NRestarts --value)" = "0" ] || fail "SERVICE_RESTART_COUNT_NONZERO"
[ "$(systemctl show "$SERVICE" -p Restart --value)" = "no" ] || fail "SERVICE_RESTART_POLICY_DRIFT"
[ "$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)" = "static" ] || fail "SERVICE_ENABLEMENT_DRIFT"
[ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
[ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"

if [ "$ACTION" = "verify-existing" ]; then
  [ -d "$BACKUP_PATH" ] || fail "BACKUP_PATH_MISSING"
  [ ! -L "$BACKUP_PATH" ] || fail "BACKUP_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$BACKUP_PATH")" = "root:root" ] || fail "BACKUP_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$BACKUP_PATH")" in
    700|2700) ;;
    *) fail "BACKUP_MODE_DRIFT" ;;
  esac
  [ -f "$BACKUP_PATH/SHA256SUMS" ] || fail "BACKUP_HASH_INDEX_MISSING"
  (cd "$BACKUP_PATH" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "BACKUP_HASH_INVALID"
  [ ! -s "$BACKUP_PATH/application-status.txt" ] || fail "APPLICATION_STATUS_NOT_CLEAN"
  [ ! -s "$BACKUP_PATH/control-status.txt" ] || fail "CONTROL_STATUS_NOT_CLEAN"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$BACKUP_PATH/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$BACKUP_PATH/control.bundle" >/dev/null
  pg_restore --list "$BACKUP_PATH/database-before.dump" >/dev/null
  printf '{"ok":true,"safe_code":"S4_PRE_MUTATION_BACKUP_EXISTING_GREEN","path":"%s","index_sha256":"%s"}\n' \
    "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
  exit 0
fi

[ ! -e "$BACKUP_PATH" ] || fail "BACKUP_PATH_EXISTS"
[ "$(find /etc/tu1nz -maxdepth 1 -type f -name 'adult-commercial-s3.*' | wc -l)" -ge 7 ] || fail "CONFIGURATION_SET_INCOMPLETE"

install -d -o root -g root -m 0700 "${BACKUP_PATH%/*}" "$BACKUP_PATH"
chmod 0700 "$BACKUP_PATH"
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle create "$BACKUP_PATH/application.bundle" --all
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle create "$BACKUP_PATH/control.bundle" --all
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/application-provenance.txt"
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" rev-parse HEAD 'HEAD^{tree}' >"$BACKUP_PATH/control-provenance.txt"
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" status --porcelain=v1 >"$BACKUP_PATH/application-status.txt"
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" status --porcelain=v1 >"$BACKUP_PATH/control-status.txt"
cp -a "/etc/systemd/system/$SERVICE" "$BACKUP_PATH/unit-before.service"
(
  cd /etc/tu1nz
  find . -maxdepth 1 -type f -name 'adult-commercial-s3.*' -print0 \
    | sort -z \
    | tar --null -T - -cpf "$BACKUP_PATH/configuration-before.tar"
)
tar -C /var/lib/tausendunde1nz -cpf "$BACKUP_PATH/state-before.tar" adult-commercial-s3
if [ -d /var/log/tausendunde1nz ]; then
  tar -C /var/log -cpf "$BACKUP_PATH/logs-before.tar" tausendunde1nz
fi
runuser -u postgres -- pg_dump -Fc tu1nz_adult_commercial_s3 >"$BACKUP_PATH/database-before.dump"
systemctl show "$SERVICE" >"$BACKUP_PATH/service-before.txt"
stat -c '%n %U:%G %a %s %y' \
  "$APPLICATION_ROOT" "$CONTROL_ROOT" /etc/tu1nz/adult-commercial-s3.* \
  "/etc/systemd/system/$SERVICE" >"$BACKUP_PATH/filesystem-metadata-before.txt"
printf '%s\n' \
  "Restore only while $SERVICE is inactive/dead." \
  "Verify SHA256SUMS strictly before restore." \
  "Restore Git objects from application.bundle and control.bundle to the recorded commits." \
  "Restore unit-before.service and configuration-before.tar, then daemon-reload without starting or enabling." \
  "Restore database-before.dump only after a separate rollback decision; state and logs are evidence copies." \
  >"$BACKUP_PATH/RESTORE.txt"
find "$BACKUP_PATH" -maxdepth 1 -type f -exec chmod 0600 {} +
(
  cd "$BACKUP_PATH"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >SHA256SUMS
  chmod 0600 SHA256SUMS
  sha256sum --check --strict SHA256SUMS >/dev/null
)
git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$BACKUP_PATH/application.bundle" >/dev/null
git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$BACKUP_PATH/control.bundle" >/dev/null
pg_restore --list "$BACKUP_PATH/database-before.dump" >/dev/null
[ "$(stat -c '%U:%G' "$BACKUP_PATH")" = "root:root" ] || fail "BACKUP_OWNERSHIP_DRIFT"
case "$(stat -c '%a' "$BACKUP_PATH")" in
  700|2700) ;;
  *) fail "BACKUP_MODE_DRIFT" ;;
esac
printf '{"ok":true,"safe_code":"S4_PRE_MUTATION_BACKUP_GREEN","path":"%s","index_sha256":"%s"}\n' \
  "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
