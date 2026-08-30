#!/usr/bin/env bash
set -euo pipefail

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly PROBE_SERVICE="tu1nz-adult-public-s8-probe.service"
readonly HEALTH_SERVICE="tu1nz-adult-public-s8-health.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly APPLICATION_BRANCH="feat/commercial-s8-public-telegram-early-access"
readonly SOURCE_SHA="935518614d4e9e6ce302c75bf81d6e5ca2a4f1d4"
readonly SOURCE_TREE="29679c2029d40eefce7dbd3857c5cf4e1f129013"
readonly TARGET_SHA="210e80484edac1541bcb832d846ee4a324c2faee"
readonly TARGET_TREE="7eda3fd4dbf4819d0c14c42d5f7b1be31a79eef3"
readonly MIGRATION_CHAIN_SHA="b793eb9c5200956f5de52cc536fb125d60df7c7fb8a567808ed47ad71ebd82b8"
readonly MIGRATION_SHA="5d3abd9bb863d3001c6af9c8775799b3bde69d6079af6062d4d607f07f4e7ec6"
readonly RECOVERY_MIGRATION_SHA="feb157b5625113a3c4774b570d8a73265356a87c5fe70d491c36b5b7a25a6691"
readonly S7_CONTRACT_SHA="a2c654487bc9c7567d3794da4d3a948c5e888fe4e3c92e36dece5ed77bb45802"
readonly S8_CONTRACT_SHA="2a2bf47221b9ef708c07e30af7f3b726b402726e04e81f158585bf3052425e58"
readonly COPY_SHA="95c4d6f62d4319417a0bac601cd7ee8f4567541fb616220016eec408b5853093"
readonly UNIT_SHA="e17604818a7ca1e0eb37ca90f2602afb9650b0fe41c14b2fc32b878c16a058a1"
readonly HEALTH_SCRIPT_SHA="d28c7270757c73017a3015b68fb741b33e8af98ab605dda9a32962613b193f4f"
readonly HEALTH_UNIT_SHA="292284dde579f533bbbc7b6e7d0ed0304c6cedf9a3131040ff2bea0134af6767"
readonly PROBE_UNIT_SHA="8135714e7c4ff952dd90fc9e4a66678138bf79fe2fb642781f4bed610d6d2665"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"

fail() {
  printf 'S8_PUBLIC_TELEGRAM_CONTROL_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_control() {
  local expected_sha="$1"
  local expected_tree="$2"
  [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
  [[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$expected_sha" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$expected_tree" ] || fail "CONTROL_TREE_MISMATCH"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"
}

require_backup() {
  case "$1" in
    "${BACKUP_PREFIX}"*) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_backup.sh" verify-existing "$1" >/dev/null
}

require_application_clean() {
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
}

require_application_source_or_target() {
  local sha tree
  sha="$(git_value "$APPLICATION_ROOT" HEAD)"
  tree="$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
  if [ "$sha" = "$SOURCE_SHA" ] && [ "$tree" = "$SOURCE_TREE" ]; then
    return
  fi
  [ "$sha" = "$TARGET_SHA" ] && [ "$tree" = "$TARGET_TREE" ] || fail "APPLICATION_RELEASE_UNEXPECTED"
}

require_adult_runtime_closed() {
  local unit
  for unit in tu1nz-adult-commercial-s0.service tu1nz-adult-commercial-s3.service; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = "inactive" ] || fail "ADULT_RUNTIME_ACTIVE"
    [ "$(systemctl show "$unit" -p MainPID --value)" = "0" ] || fail "ADULT_PROCESS_PRESENT"
  done
}

is_s7_green() {
  [ "$(systemctl show "$S7_SERVICE" -p ActiveState --value)" = "active" ] || fail "S7_SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$S7_SERVICE" -p MainPID --value)" != "0" ] || fail "S7_PROCESS_MISSING"
  /usr/local/bin/tu1nz_adult_public_s7_health.py >/dev/null
}

require_s7_green() {
  is_s7_green || fail "S7_HEALTH_RED"
}

await_s7_green() {
  local attempt
  for attempt in $(seq 1 30); do
    if (is_s7_green) >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

await_external_landing_green() {
  local attempt
  for attempt in $(seq 1 30); do
    if external_landing_health >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

require_s8_inactive_or_absent() {
  local loaded
  loaded="$(systemctl show "$S8_SERVICE" -p LoadState --value 2>/dev/null || true)"
  [ "$loaded" = "not-found" ] && return
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "inactive" ] || fail "S8_SERVICE_ALREADY_ACTIVE"
  [ "$(systemctl show "$S8_SERVICE" -p MainPID --value)" = "0" ] || fail "S8_PROCESS_PRESENT"
}

require_bot_secret() {
  [ -f "$TOKEN_PATH" ] && [ ! -L "$TOKEN_PATH" ] || fail "S8_TOKEN_MISSING_OR_UNSAFE"
  [ "$(stat -c '%U:%G' "$TOKEN_PATH")" = "root:root" ] || fail "S8_TOKEN_OWNER_DRIFT"
  [ "$(stat -c '%a' "$TOKEN_PATH")" = "600" ] || fail "S8_TOKEN_MODE_DRIFT"
  [ "$(stat -c '%h' "$TOKEN_PATH")" = "1" ] || fail "S8_TOKEN_LINK_COUNT_DRIFT"
  python3 - "$TOKEN_PATH" <<'PY' || fail "S8_TOKEN_FORMAT_INVALID"
import re
import sys
from pathlib import Path

value = Path(sys.argv[1]).read_bytes().rstrip(b"\r\n")
raise SystemExit(0 if re.fullmatch(rb"[0-9]{6,16}:[A-Za-z0-9_-]{30,96}", value) else 2)
PY
  [ -f "$DATABASE_DSN_PATH" ] && [ ! -L "$DATABASE_DSN_PATH" ] || fail "DATABASE_DSN_UNSAFE"
  [ "$(stat -c '%U:%G' "$DATABASE_DSN_PATH")" = "root:root" ] || fail "DATABASE_DSN_OWNER_DRIFT"
  [ "$(stat -c '%a' "$DATABASE_DSN_PATH")" = "600" ] || fail "DATABASE_DSN_MODE_DRIFT"
}

require_source_hashes() {
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0022_commercial_s8_public_telegram_early_access.sql" | awk '{print $1}')" = "$MIGRATION_SHA" ] || fail "MIGRATION_0022_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0023_commercial_s8_health_recovery.sql" | awk '{print $1}')" = "$RECOVERY_MIGRATION_SHA" ] || fail "MIGRATION_0023_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s7-public-launch.sfw.json" | awk '{print $1}')" = "$S7_CONTRACT_SHA" ] || fail "S7_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "S8_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" | awk '{print $1}')" = "$COPY_SHA" ] || fail "S8_COPY_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$S8_SERVICE" | awk '{print $1}')" = "$UNIT_SHA" ] || fail "S8_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" | awk '{print $1}')" = "$HEALTH_SCRIPT_SHA" ] || fail "S8_HEALTH_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$HEALTH_SERVICE" | awk '{print $1}')" = "$HEALTH_UNIT_SHA" ] || fail "S8_HEALTH_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$PROBE_SERVICE" | awk '{print $1}')" = "$PROBE_UNIT_SHA" ] || fail "S8_PROBE_UNIT_DRIFT"
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" - <<PY || fail "MIGRATION_CHAIN_DRIFT"
from pathlib import Path
from tu1nz_commercial_s3.migrations import inspect_migration_chain

evidence = inspect_migration_chain(Path("$APPLICATION_ROOT/migrations"))
raise SystemExit(0 if evidence.chain_sha256 == "$MIGRATION_CHAIN_SHA" else 2)
PY
}

s8_table_count() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" --command="SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'commercial_s8_%';" \
    | tr -d '[:space:]'
}

set_runtime_control() {
  local enabled="$1"
  local safe_code="$2"
  runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
    --command="UPDATE commercial_s8_runtime_control SET public_telegram_early_access_enabled=${enabled}, new_waitlist_joins_enabled=${enabled}, notifications_enabled=${enabled}, invite_automation_enabled=false, reason_safe_code='${safe_code}', updated_at=CURRENT_TIMESTAMP WHERE singleton;" >/dev/null
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_application_clean
  require_application_source_or_target
  require_adult_runtime_closed
  require_s7_green
  require_s8_inactive_or_absent
  require_bot_secret
  [ "$(systemctl show postgresql.service -p ActiveState --value)" = "active" ] || fail "POSTGRES_NOT_ACTIVE"
  [ "$(findmnt -rn -o TARGET / | head -n 1)" = "/" ] || fail "ROOT_FILESYSTEM_UNRESOLVED"
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "/opt/tu1nz_repos/adult-publishing-core" | grep -q -E 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_PREFLIGHT_GREEN"}\n'
}

install_release() {
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" != "$TARGET_SHA" ]; then
    runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin \
      "refs/heads/$APPLICATION_BRANCH:refs/remotes/origin/$APPLICATION_BRANCH"
    [ "$(git_value "$APPLICATION_ROOT" "origin/$APPLICATION_BRANCH")" = "$TARGET_SHA" ] || fail "REMOTE_TARGET_SHA_MISMATCH"
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
  fi
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_application_clean
  require_source_hashes
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
}

install_database() {
  local count
  count="$(s8_table_count)"
  if [ "$count" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0022_commercial_s8_public_telegram_early_access.sql" >/dev/null
  elif [ "$count" != "9" ]; then
    fail "MIGRATION_0022_PARTIAL_STATE"
  fi
  if [ "$(runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --dbname="$DATABASE" --command="SELECT has_table_privilege('tu1nz_adult_commercial_s3_runtime','commercial_s8_broadcasts','UPDATE')::int;" | tr -d '[:space:]')" != "1" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0023_commercial_s8_health_recovery.sql" >/dev/null
  fi
}

install_files() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s7-public-launch.sfw.json" /etc/tu1nz/adult-commercial-s7-public.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$S8_SERVICE" "/etc/systemd/system/$S8_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$PROBE_SERVICE" "/etc/systemd/system/$PROBE_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_TIMER" "/etc/systemd/system/$HEALTH_TIMER"
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" /usr/local/bin/tu1nz_adult_public_s8_health.py
  systemd-analyze verify "/etc/systemd/system/$S8_SERVICE" "/etc/systemd/system/$PROBE_SERVICE" "/etc/systemd/system/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_TIMER"
}

configure_bot() {
  "$APPLICATION_ROOT/.venv/bin/tu1nz-public-s8-telegram" \
    --contract /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    --copy /etc/tu1nz/adult-commercial-s8-copy.json \
    --telegram-token "$TOKEN_PATH" \
    --database-dsn "$DATABASE_DSN_PATH" \
    --configure-only >/dev/null
}

unit_evidence() {
  journalctl -u "$1" -n 20 --no-pager -o cat 2>/dev/null \
    | grep -E '^\{"components":' | tail -n 1
}

diagnostic_probe() {
  systemctl reset-failed "$PROBE_SERVICE" >/dev/null 2>&1 || true
  systemctl start "$PROBE_SERVICE" >/dev/null 2>&1
}

runtime_health() {
  systemctl reset-failed "$HEALTH_SERVICE" >/dev/null 2>&1 || true
  systemctl start "$HEALTH_SERVICE" >/dev/null 2>&1
}

await_runtime_ready() {
  local started_at="$1"
  local attempt
  for attempt in $(seq 1 45); do
    [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "active" ] || return 1
    [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = "0" ] || return 1
    if journalctl -u "$S8_SERVICE" --since "$started_at" --no-pager -o cat 2>/dev/null \
      | grep -F '"event":"S8_PUBLIC_TELEGRAM_READY"' >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

external_landing_health() {
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/ \
    | grep -F 'https://t.me/tu1nz_adult_early_access_bot?start=landing_s8_launch' >/dev/null
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())'
}

abort_deploy() {
  local backup="$1"
  set_runtime_control false S8_PUBLIC_EARLY_ACCESS_ABORTED 2>/dev/null || true
  systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" >/dev/null 2>&1 || true
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ]; then
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA" >/dev/null 2>&1 || true
    runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
      --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null 2>&1 || true
  fi
  if [ -f "$backup/public-configuration-before.tar" ]; then
    tar -xpf "$backup/public-configuration-before.tar" -C /etc/tu1nz >/dev/null 2>&1 || true
  fi
  if ! (is_s7_green) >/dev/null 2>&1; then
    systemctl stop "$S7_SERVICE" >/dev/null 2>&1 || true
    systemctl start "$S7_SERVICE" >/dev/null 2>&1 || true
    await_s7_green >/dev/null 2>&1 || true
  fi
  printf 'S8_PUBLIC_TELEGRAM_CONTROL_RED DEPLOYMENT_ABORTED\n' >&2
  exit 2
}

diagnose() {
  preflight "$1" "$2" "$3" >/dev/null
  if ! install_release || ! install_files; then
    abort_deploy "$3"
  fi
  systemctl daemon-reload
  set_runtime_control false S8_DIAGNOSTIC_KILL_SWITCH_CLOSED
  if diagnostic_probe; then
    fail "EXPECTED_PRE_RECOVERY_DIAGNOSTIC_RED"
  fi
  local evidence
  evidence="$(unit_evidence "$PROBE_SERVICE")"
  printf '%s\n' "$evidence"
  printf '%s\n' "$evidence" | grep -F 'S8_NOTIFIER_BROADCAST_UPDATE_PRIVILEGE_MISSING' >/dev/null \
    || fail "ROOT_CAUSE_NOT_PROVEN"
  printf 'S8_HEALTH_ROOT_CAUSE=S8_NOTIFIER_BROADCAST_UPDATE_PRIVILEGE_MISSING\n'
}

recover() {
  preflight "$1" "$2" "$3" >/dev/null
  if ! install_release || ! install_files || ! install_database || ! configure_bot; then
    abort_deploy "$3"
  fi
  systemctl daemon-reload
  set_runtime_control false S8_RECOVERY_PRESTART_KILL_SWITCH_CLOSED
  if ! diagnostic_probe; then
    unit_evidence "$PROBE_SERVICE" >&2 || true
    abort_deploy "$3"
  fi
  local started_at
  started_at="$(date -Is)"
  if ! systemctl start "$S8_SERVICE" || ! await_runtime_ready "$started_at" || ! runtime_health; then
    unit_evidence "$HEALTH_SERVICE" >&2 || true
    abort_deploy "$3"
  fi
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_RECOVERY_STAGING_GREEN","public_enabled":false,"adult_content":false,"avs":false,"payments":false,"publishing":false}\n'
}

open_acceptance() {
  require_root
  require_control "$1" "$2"
  require_s7_green
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "active" ] || fail "S8_SERVICE_NOT_ACTIVE"
  runtime_health || fail "S8_HEALTH_RED"
  set_runtime_control true S8_INTERNAL_ACCEPTANCE_OPEN
  printf '{"ok":true,"safe_code":"S8_INTERNAL_ACCEPTANCE_OPEN","adult_content":false,"avs":false,"payments":false,"publishing":false}\n'
}

activate_public() {
  require_root
  require_control "$1" "$2"
  require_s7_green
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "active" ] || fail "S8_SERVICE_NOT_ACTIVE"
  runtime_health || fail "S8_HEALTH_RED"
  set_runtime_control true S8_PUBLIC_EARLY_ACCESS_ENABLED
  systemctl stop "$S7_SERVICE"
  systemctl start "$S7_SERVICE"
  await_s7_green || fail "S7_READINESS_TIMEOUT"
  await_external_landing_green || fail "S8_LANDING_READINESS_TIMEOUT"
  systemctl enable "$S8_SERVICE" >/dev/null
  systemctl enable --now "$HEALTH_TIMER" >/dev/null
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_ACTIVATION_GREEN","adult_content":false,"avs":false,"payments":false,"publishing":false}\n'
}

verify() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  require_adult_runtime_closed
  require_s7_green
  require_bot_secret
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_source_hashes
  [ "$(s8_table_count)" = "9" ] || fail "MIGRATION_0022_NOT_INSTALLED"
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "active" ] || fail "S8_SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$S8_SERVICE" -p MainPID --value)" != "0" ] || fail "S8_PROCESS_MISSING"
  [ "$(systemctl is-enabled "$S8_SERVICE")" = "enabled" ] || fail "S8_SERVICE_NOT_ENABLED"
  [ "$(systemctl is-enabled "$HEALTH_TIMER")" = "enabled" ] || fail "S8_HEALTH_TIMER_NOT_ENABLED"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s8-public-telegram.json | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "INSTALLED_S8_CONTRACT_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s8-copy.json | awk '{print $1}')" = "$COPY_SHA" ] || fail "INSTALLED_S8_COPY_DRIFT"
  runtime_health || fail "S8_HEALTH_RED"
  external_landing_health || fail "S8_LANDING_RED"
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_VERIFY_GREEN","waitlist":"READY","notifier":"READY","avs":"DISABLED_EXPECTED","payment":"DISABLED_EXPECTED","adult_workflow":"INACCESSIBLE"}\n'
}

kill_switch() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  [ "$(s8_table_count)" = "9" ] || fail "MIGRATION_0022_NOT_INSTALLED"
  set_runtime_control false S8_PUBLIC_EARLY_ACCESS_PAUSED
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_KILL_SWITCH_CLOSED","data_preserved":true}\n'
}

rollback() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  set_runtime_control false S8_PUBLIC_EARLY_ACCESS_ROLLED_BACK
  systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" >/dev/null 2>&1 || true
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "ROLLBACK_TREE_MISMATCH"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  tar -xpf "$3/public-configuration-before.tar" -C /etc/tu1nz
  systemctl daemon-reload
  systemctl stop "$S7_SERVICE"
  systemctl start "$S7_SERVICE"
  await_s7_green || fail "S7_READINESS_TIMEOUT"
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_ROLLBACK_GREEN","waitlist_data_preserved":true}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 4 ] || fail "USAGE"
    preflight "$2" "$3" "$4"
    ;;
  diagnose)
    [ "$#" -eq 4 ] || fail "USAGE"
    diagnose "$2" "$3" "$4"
    ;;
  recover)
    [ "$#" -eq 4 ] || fail "USAGE"
    recover "$2" "$3" "$4"
    ;;
  open-acceptance)
    [ "$#" -eq 3 ] || fail "USAGE"
    open_acceptance "$2" "$3"
    ;;
  activate-public)
    [ "$#" -eq 3 ] || fail "USAGE"
    activate_public "$2" "$3"
    ;;
  verify)
    [ "$#" -eq 3 ] || fail "USAGE"
    verify "$2" "$3"
    ;;
  kill-switch)
    [ "$#" -eq 4 ] || fail "USAGE"
    kill_switch "$2" "$3" "$4"
    ;;
  rollback)
    [ "$#" -eq 4 ] || fail "USAGE"
    rollback "$2" "$3" "$4"
    ;;
  *) fail "USAGE" ;;
esac
