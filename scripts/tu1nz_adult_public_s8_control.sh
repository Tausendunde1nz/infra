#!/usr/bin/env bash
set -euo pipefail
umask 0007

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly PROBE_SERVICE="tu1nz-adult-public-s8-probe.service"
readonly HEALTH_SERVICE="tu1nz-adult-public-s8-health.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly APPLICATION_BRANCH="fix/commercial-s8-public-recovery"
readonly SOURCE_SHA="935518614d4e9e6ce302c75bf81d6e5ca2a4f1d4"
readonly SOURCE_TREE="29679c2029d40eefce7dbd3857c5cf4e1f129013"
readonly TARGET_SHA="9170b66a464f8a2cffa075360addb9aea755769b"
readonly TARGET_TREE="96f8a52d5b06c795cc819f7d8ae176d045aca6fd"
readonly MIGRATION_CHAIN_SHA="b793eb9c5200956f5de52cc536fb125d60df7c7fb8a567808ed47ad71ebd82b8"
readonly MIGRATION_SHA="5d3abd9bb863d3001c6af9c8775799b3bde69d6079af6062d4d607f07f4e7ec6"
readonly RECOVERY_MIGRATION_SHA="feb157b5625113a3c4774b570d8a73265356a87c5fe70d491c36b5b7a25a6691"
readonly S8_CONTRACT_SHA="cb5fdca02192211850b6dd66943a1db5cd6ea7349770776c119fc1e60a1ca927"
readonly S8_LANDING_CONTRACT_SHA="ecf9fc7908e0e2fc0208b9af27c5670df3463b34dcab213659ce410111af149e"
readonly COPY_SHA="95c4d6f62d4319417a0bac601cd7ee8f4567541fb616220016eec408b5853093"
readonly UNIT_SHA="26fbb08113ecb6609806e549f980eecb94f0d90d4eae1b411e1208c9c16d1a69"
readonly HEALTH_SCRIPT_SHA="8e0f79d64a1803df85b0363aa23a71f637b9e89a23229056425c31358da8cba2"
readonly HEALTH_UNIT_SHA="75546b697daea81328daf190f7475442b921d95439dd7b66e724d1de7ce5b855"
readonly PROBE_UNIT_SHA="7c0e1d03dfb89bc6397a1c49c90edc68d694b39395107c491e58bf9a58d4949c"
readonly LANDING_UNIT_SHA="f2663c4f1e57e91aa938d67bc5533fa5324dd355282bdf6e52fe40102b7b994d"
readonly PUBLIC_PROXY_SHA="65c0bc9d12981a4532d5453c668f8b2f9a4ad32cf5a7a18b8ef4ed3b56a0f062"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"
readonly ROOT_CAUSE="NOTIFIER_UPDATE_PRIVILEGE_42501_THEN_UNTYPED_POLLING_HEARTBEAT_42P18_COMPOUNDED_BY_S7_START_LIMIT_ORCHESTRATION"

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
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8095/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())'
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

await_landing_green() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18096/adult/ \
      | grep -F 'https://t.me/tu1nz_adult_early_access_bot?start=landing_s8_launch' >/dev/null \
      && curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18096/adult/health \
      | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())'; then
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

start_s7_once() {
  systemctl reset-failed "$S7_SERVICE"
  systemctl start "$S7_SERVICE"
}

require_s7_start_limit_failure() {
  [ "$(systemctl show "$S7_SERVICE" -p ActiveState --value)" = "failed" ] \
    || fail "S7_RECOVERY_STATE_NOT_FAILED"
  [ "$(systemctl show "$S7_SERVICE" -p Result --value)" = "start-limit-hit" ] \
    || fail "S7_RECOVERY_RESULT_NOT_START_LIMIT_HIT"
  [ "$(systemctl show "$S7_SERVICE" -p MainPID --value)" = "0" ] \
    || fail "S7_RECOVERY_PROCESS_PRESENT"
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "inactive" ] \
    || fail "S8_SERVICE_NOT_INACTIVE"
  [ "$(systemctl is-enabled "$S8_SERVICE" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_SERVICE_NOT_DISABLED"
  case "$(systemctl show "$HEALTH_TIMER" -p ActiveState --value 2>/dev/null || true)" in
    inactive|not-found|'') ;;
    *) fail "S8_HEALTH_TIMER_ACTIVE" ;;
  esac
}

external_s7_health() {
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())'
}

require_s8_inactive_or_absent() {
  local loaded state
  loaded="$(systemctl show "$S8_SERVICE" -p LoadState --value 2>/dev/null || true)"
  [ "$loaded" = "not-found" ] && return
  state="$(systemctl show "$S8_SERVICE" -p ActiveState --value)"
  case "$state" in
    inactive|failed) ;;
    *) fail "S8_SERVICE_ALREADY_ACTIVE" ;;
  esac
  [ "$(systemctl show "$S8_SERVICE" -p MainPID --value)" = "0" ] || fail "S8_PROCESS_PRESENT"
  [ "$(systemctl is-enabled "$S8_SERVICE" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_SERVICE_NOT_DISABLED"
}

require_landing_inactive_or_absent() {
  local loaded state
  loaded="$(systemctl show "$LANDING_SERVICE" -p LoadState --value 2>/dev/null || true)"
  [ "$loaded" = "not-found" ] && return
  state="$(systemctl show "$LANDING_SERVICE" -p ActiveState --value)"
  case "$state" in
    inactive|failed) ;;
    *) fail "S8_LANDING_ALREADY_ACTIVE" ;;
  esac
  [ "$(systemctl show "$LANDING_SERVICE" -p MainPID --value)" = "0" ] || fail "S8_LANDING_PROCESS_PRESENT"
  [ "$(systemctl is-enabled "$LANDING_SERVICE" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_LANDING_NOT_DISABLED"
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
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "S8_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-landing.sfw.json" | awk '{print $1}')" = "$S8_LANDING_CONTRACT_SHA" ] || fail "S8_LANDING_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" | awk '{print $1}')" = "$COPY_SHA" ] || fail "S8_COPY_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$S8_SERVICE" | awk '{print $1}')" = "$UNIT_SHA" ] || fail "S8_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" | awk '{print $1}')" = "$HEALTH_SCRIPT_SHA" ] || fail "S8_HEALTH_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$HEALTH_SERVICE" | awk '{print $1}')" = "$HEALTH_UNIT_SHA" ] || fail "S8_HEALTH_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$PROBE_SERVICE" | awk '{print $1}')" = "$PROBE_UNIT_SHA" ] || fail "S8_PROBE_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$LANDING_SERVICE" | awk '{print $1}')" = "$LANDING_UNIT_SHA" ] || fail "S8_LANDING_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/nginx/current/tu1nz.s8-public.conf" | awk '{print $1}')" = "$PUBLIC_PROXY_SHA" ] || fail "S8_PUBLIC_PROXY_SSOT_DRIFT"
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
  require_landing_inactive_or_absent
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
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-landing.sfw.json" /etc/tu1nz/adult-commercial-s8-landing.json
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$S8_SERVICE" "/etc/systemd/system/$S8_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$LANDING_SERVICE" "/etc/systemd/system/$LANDING_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$PROBE_SERVICE" "/etc/systemd/system/$PROBE_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_TIMER" "/etc/systemd/system/$HEALTH_TIMER"
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" /usr/local/bin/tu1nz_adult_public_s8_health.py
  systemd-analyze verify "/etc/systemd/system/$S8_SERVICE" "/etc/systemd/system/$LANDING_SERVICE" "/etc/systemd/system/$PROBE_SERVICE" "/etc/systemd/system/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_TIMER"
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

require_public_proxy_installed() {
  [ "$(sha256sum /etc/nginx/sites-enabled/tu1nz.conf | awk '{print $1}')" = "$PUBLIC_PROXY_SHA" ] \
    || fail "S8_PUBLIC_PROXY_NOT_INSTALLED"
  nginx -t >/dev/null 2>&1 || fail "S8_PUBLIC_PROXY_CONFIG_INVALID"
}

abort_deploy() {
  local backup="$1"
  set_runtime_control false S8_PUBLIC_EARLY_ACCESS_ABORTED 2>/dev/null || true
  systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" "$LANDING_SERVICE" >/dev/null 2>&1 || true
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ]; then
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA" >/dev/null 2>&1 || true
    runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
      --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null 2>&1 || true
  fi
  if [ -f "$backup/public-configuration-before.tar" ]; then
    tar -xpf "$backup/public-configuration-before.tar" -C /etc/tu1nz >/dev/null 2>&1 || true
  fi
  (is_s7_green) >/dev/null 2>&1 || printf 'S8_PUBLIC_TELEGRAM_CONTROL_RED S7_BASELINE_UNSTABLE\n' >&2
  printf 'S8_PUBLIC_TELEGRAM_CONTROL_RED DEPLOYMENT_ABORTED\n' >&2
  exit 2
}

diagnose() {
  preflight "$1" "$2" "$3" >/dev/null
  if ! install_release || ! install_files || ! install_database || ! configure_bot; then
    abort_deploy "$3"
  fi
  systemctl daemon-reload
  set_runtime_control false S8_DIAGNOSTIC_KILL_SWITCH_CLOSED
  if ! systemctl start "$LANDING_SERVICE" || ! await_landing_green || ! diagnostic_probe; then
    unit_evidence "$PROBE_SERVICE" >&2 || true
    abort_deploy "$3"
  fi
  unit_evidence "$PROBE_SERVICE"
  systemctl stop "$LANDING_SERVICE"
  require_s7_green
  printf 'S8_ROOT_CAUSE=%s\n' "$ROOT_CAUSE"
}

recover() {
  preflight "$1" "$2" "$3" >/dev/null
  if ! install_release || ! install_files || ! install_database || ! configure_bot; then
    abort_deploy "$3"
  fi
  systemctl daemon-reload
  set_runtime_control false S8_RECOVERY_PRESTART_KILL_SWITCH_CLOSED
  systemctl reset-failed "$LANDING_SERVICE" >/dev/null 2>&1 || true
  if ! systemctl start "$LANDING_SERVICE" || ! await_landing_green; then
    abort_deploy "$3"
  fi
  if ! diagnostic_probe; then
    unit_evidence "$PROBE_SERVICE" >&2 || true
    abort_deploy "$3"
  fi
  local started_at
  started_at="$(date -Is)"
  systemctl reset-failed "$S8_SERVICE" >/dev/null 2>&1 || true
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
  [ "$(systemctl show "$LANDING_SERVICE" -p ActiveState --value)" = "active" ] || fail "S8_LANDING_NOT_ACTIVE"
  runtime_health || fail "S8_HEALTH_RED"
  require_public_proxy_installed
  set_runtime_control true S8_PUBLIC_EARLY_ACCESS_ENABLED
  systemctl reload nginx.service
  await_external_landing_green || fail "S8_LANDING_READINESS_TIMEOUT"
  systemctl enable "$S8_SERVICE" >/dev/null
  systemctl enable "$LANDING_SERVICE" >/dev/null
  systemctl enable --now "$HEALTH_TIMER" >/dev/null
  require_s7_green
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
  [ "$(systemctl show "$LANDING_SERVICE" -p ActiveState --value)" = "active" ] || fail "S8_LANDING_NOT_ACTIVE"
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
  systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" "$LANDING_SERVICE" >/dev/null 2>&1 || true
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "ROLLBACK_TREE_MISMATCH"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  tar -xpf "$3/public-configuration-before.tar" -C /etc/tu1nz
  systemctl daemon-reload
  require_s7_green
  printf '{"ok":true,"safe_code":"S8_PUBLIC_TELEGRAM_ROLLBACK_GREEN","waitlist_data_preserved":true}\n'
}

recover_s7_start_limit() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_application_clean
  require_application_source_or_target
  require_adult_runtime_closed
  require_s7_start_limit_failure
  start_s7_once
  await_s7_green || fail "S7_RECOVERY_READINESS_TIMEOUT"
  external_s7_health || fail "S7_RECOVERY_EXTERNAL_HEALTH_RED"
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = "inactive" ] \
    || fail "S8_SERVICE_BECAME_ACTIVE"
  [ "$(systemctl is-enabled "$S8_SERVICE" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_SERVICE_BECAME_ENABLED"
  printf '{"ok":true,"safe_code":"S7_RECOVERY_GREEN","s8_active":false,"s8_enabled":false,"adult_content":false,"avs":false,"payments":false,"publishing":false}\n'
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
  recover-s7-start-limit)
    [ "$#" -eq 4 ] || fail "USAGE"
    recover_s7_start_limit "$2" "$3" "$4"
    ;;
  *) fail "USAGE" ;;
esac
