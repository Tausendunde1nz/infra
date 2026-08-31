#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly APPLICATION_BRANCH="main"
readonly SOURCE_SHA="ef19c7b2a6d0b42cfe55e1e090878f72b29c64c2"
readonly SOURCE_TREE="250985b5464943b981a7654c39fa256ac7b695b4"
readonly TARGET_SHA="d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79"
readonly TARGET_TREE="c9fa052bceb1e7ec3b84a5254d399acde9ff0989"
readonly S9_CONTRACT_SHA="12022dbc0c6dd8c748db91d526b374a690c6bb9f43c7ac89ea525aef7c9b28a0"
readonly S8_CONTRACT_SHA="fe20aea4b80206a5eaa79b94d2b74c85d2883240ea68b6d4734618daadac452d"
readonly LANDING_CONTRACT_SHA="ecf9fc7908e0e2fc0208b9af27c5670df3463b34dcab213659ce410111af149e"
readonly MIGRATION_SHA="b0b64bc6ca8d549f15b423fed66172ec16d764fbd5b7c97c129f9be03da583a1"
readonly DOWN_MIGRATION_SHA="4c45973a570e12ca8727cf80261b5669ee8b9d16b53a68309ea5afa879183c99"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S8_HEALTH_SERVICE="tu1nz-adult-public-s8-health.service"
readonly S8_HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly S9_SEED_SERVICE="tu1nz-adult-public-s9-seed.service"
readonly S9_AUDIENCE_SERVICE="tu1nz-adult-public-s9-audience.service"
readonly S9_AUDIENCE_TIMER="tu1nz-adult-public-s9-audience.timer"
readonly S9_NURTURE_SERVICE="tu1nz-adult-public-s9-nurture.service"
readonly S9_NURTURE_TIMER="tu1nz-adult-public-s9-nurture.timer"
readonly S9_REPORT_SERVICE="tu1nz-adult-public-s9-report.service"
readonly S9_REPORT_TIMER="tu1nz-adult-public-s9-report.timer"
readonly S9_HEALTH_SERVICE="tu1nz-adult-public-s9-health.service"
readonly S9_HEALTH_TIMER="tu1nz-adult-public-s9-health.timer"
readonly S9_TIMERS=("$S9_AUDIENCE_TIMER" "$S9_NURTURE_TIMER" "$S9_REPORT_TIMER" "$S9_HEALTH_TIMER")

fail() {
  printf 'S9_PUBLIC_GROWTH_CONTROL_RED %s\n' "$1" >&2
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
  [ -d "$CONTROL_ROOT/.git" ] && [ ! -L "$CONTROL_ROOT" ] || fail "CONTROL_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] || fail "CONTROL_DIRTY"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$expected_sha" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$expected_tree" ] || fail "CONTROL_TREE_MISMATCH"
}

require_application_clean() {
  [ -d "$APPLICATION_ROOT/.git" ] && [ ! -L "$APPLICATION_ROOT" ] || fail "APPLICATION_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1)" ] || fail "APPLICATION_DIRTY"
}

require_application_source_or_target() {
  local current_sha current_tree
  current_sha="$(git_value "$APPLICATION_ROOT" HEAD)"
  current_tree="$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
  case "$current_sha:$current_tree" in
    "$SOURCE_SHA:$SOURCE_TREE"|"$TARGET_SHA:$TARGET_TREE") ;;
    *) fail "APPLICATION_BASELINE_UNEXPECTED" ;;
  esac
}

service_value() {
  systemctl show "$1" -p "$2" --value 2>/dev/null || true
}

require_service_green() {
  [ "$(service_value "$1" ActiveState)" = "active" ] || fail "$2_NOT_ACTIVE"
  [ "$(service_value "$1" NRestarts)" = "0" ] || fail "$2_RESTARTED"
}

require_s8_green() {
  require_service_green "$S7_SERVICE" "S7_SERVICE"
  require_service_green "$S8_SERVICE" "S8_SERVICE"
  require_service_green "$LANDING_SERVICE" "S8_LANDING"
  require_service_green "nginx.service" "NGINX"
  [ "$(systemctl is-enabled "$S8_HEALTH_TIMER" 2>/dev/null || true)" = "enabled" ] || fail "S8_HEALTH_TIMER_NOT_ENABLED"
  [ "$(service_value "$S8_HEALTH_TIMER" ActiveState)" = "active" ] || fail "S8_HEALTH_TIMER_NOT_ACTIVE"
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())' \
    || fail "S8_EXTERNAL_HEALTH_RED"
}

require_adult_runtime_closed() {
  local unit_name
  for unit_name in \
    tu1nz-adult-commercial-s0.service \
    tu1nz-adult-commercial-s3.service \
    tu1nz-adult-commercial-s3-s3-1.service \
    tu1nz-adult-commercial-s4.service
  do
    case "$(service_value "$unit_name" ActiveState)" in
      inactive|failed|"") ;;
      *) fail "ADULT_RUNTIME_NOT_CLOSED" ;;
    esac
  done
}

require_credentials_metadata() {
  local secret_file
  for secret_file in "$DATABASE_DSN_PATH" "$TOKEN_PATH"; do
    [ -f "$secret_file" ] && [ ! -L "$secret_file" ] || fail "CREDENTIAL_PATH_UNSAFE"
    [ "$(stat -c '%U:%G' "$secret_file")" = "root:root" ] || fail "CREDENTIAL_OWNER_DRIFT"
    [ "$(stat -c '%a' "$secret_file")" = "600" ] || fail "CREDENTIAL_MODE_DRIFT"
    [ "$(stat -c '%h' "$secret_file")" = "1" ] || fail "CREDENTIAL_LINK_DRIFT"
  done
}

require_source_hashes() {
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s9-growth.sfw.json" | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] || fail "S9_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "S8_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-landing.sfw.json" | awk '{print $1}')" = "$LANDING_CONTRACT_SHA" ] || fail "LANDING_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.sql" | awk '{print $1}')" = "$MIGRATION_SHA" ] || fail "MIGRATION_0025_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.down.sql" | awk '{print $1}')" = "$DOWN_MIGRATION_SHA" ] || fail "MIGRATION_0025_DOWN_DRIFT"
}

require_backup() {
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_backup.sh" verify-existing "$1" >/dev/null
}

database_scalar() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" --command="$1" | tr -d '[:space:]'
}

s9_table_count() {
  database_scalar "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'commercial_s9_%';"
}

s8_aggregate_fingerprint() {
  database_scalar "SELECT md5(json_build_array(
    (SELECT count(*) FROM commercial_s8_users),
    (SELECT count(*) FROM commercial_s8_processed_updates),
    (SELECT count(*) FROM commercial_s8_analytics_events),
    (SELECT count(*) FROM commercial_s8_notification_deliveries)
  )::text);"
}

require_s9_database() {
  [ "$(s9_table_count)" = "11" ] || fail "MIGRATION_0025_NOT_INSTALLED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND public_sfw_growth_enabled AND organic_discovery_enabled AND nurture_enabled AND NOT audience_seeding_enabled AND NOT telegram_channel_enabled AND NOT x_enabled AND NOT reddit_enabled AND NOT invite_automation_enabled AND NOT controlled_beta AND pricing_mode='FREE_EARLY_ACCESS' AND beta_creator_cap=20;")" = "1" ] || fail "S9_RUNTIME_BOUNDARY_DRIFT"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_channel_state WHERE (platform='telegram_channel' OR platform='x' OR platform='reddit') AND status='DISABLED_FOR_NOW';")" = "3" ] || fail "S9_CHANNEL_BOUNDARY_DRIFT"
}

install_release() {
  runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin \
    "refs/heads/$APPLICATION_BRANCH:refs/remotes/origin/$APPLICATION_BRANCH" \
    || fail "CANONICAL_APPLICATION_FETCH_FAILED"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" cat-file -e "${TARGET_SHA}^{commit}" \
    || fail "PINNED_TARGET_COMMIT_MISSING"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" merge-base --is-ancestor \
    "$TARGET_SHA" "origin/$APPLICATION_BRANCH" || fail "PINNED_TARGET_NOT_CANONICAL"
  [ "$(git_value "$APPLICATION_ROOT" "${TARGET_SHA}^{tree}")" = "$TARGET_TREE" ] || fail "PINNED_TARGET_TREE_MISMATCH"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
  require_application_clean
  require_source_hashes
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
}

install_database() {
  local before_fingerprint after_fingerprint table_count
  before_fingerprint="$(s8_aggregate_fingerprint)"
  table_count="$(s9_table_count)"
  if [ "$table_count" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.sql" >/dev/null
  elif [ "$table_count" != "11" ]; then
    fail "MIGRATION_0025_PARTIAL_STATE"
  fi
  require_s9_database
  after_fingerprint="$(s8_aggregate_fingerprint)"
  [ "$after_fingerprint" = "$before_fingerprint" ] || fail "S8_DATA_FINGERPRINT_DRIFT"
}

install_files() {
  local unit_name
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s9-growth.sfw.json" /etc/tu1nz/adult-commercial-s9-growth.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-landing.sfw.json" /etc/tu1nz/adult-commercial-s8-landing.json
  install -d -o root -g root -m 0755 "/etc/systemd/system/$LANDING_SERVICE.d"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$LANDING_SERVICE.d/s9-growth.conf" "/etc/systemd/system/$LANDING_SERVICE.d/s9-growth.conf"
  for unit_name in \
    "$LANDING_SERVICE" "$S9_SEED_SERVICE" "$S9_AUDIENCE_SERVICE" "$S9_AUDIENCE_TIMER" \
    "$S9_NURTURE_SERVICE" "$S9_NURTURE_TIMER" "$S9_REPORT_SERVICE" "$S9_REPORT_TIMER" \
    "$S9_HEALTH_SERVICE" "$S9_HEALTH_TIMER"
  do
    install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$unit_name" "/etc/systemd/system/$unit_name"
  done
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s9_health.py" /usr/local/bin/tu1nz_adult_public_s9_health.py
  systemd-analyze verify \
    "/etc/systemd/system/$LANDING_SERVICE" \
    "/etc/systemd/system/$S9_SEED_SERVICE" \
    "/etc/systemd/system/$S9_AUDIENCE_SERVICE" "/etc/systemd/system/$S9_AUDIENCE_TIMER" \
    "/etc/systemd/system/$S9_NURTURE_SERVICE" "/etc/systemd/system/$S9_NURTURE_TIMER" \
    "/etc/systemd/system/$S9_REPORT_SERVICE" "/etc/systemd/system/$S9_REPORT_TIMER" \
    "/etc/systemd/system/$S9_HEALTH_SERVICE" "/etc/systemd/system/$S9_HEALTH_TIMER"
}

disable_s9() {
  systemctl disable --now "${S9_TIMERS[@]}" >/dev/null 2>&1 || true
  systemctl stop "$S9_AUDIENCE_SERVICE" "$S9_NURTURE_SERVICE" "$S9_REPORT_SERVICE" "$S9_HEALTH_SERVICE" >/dev/null 2>&1 || true
}

restore_baseline() {
  local backup_path="$1"
  disable_s9
  systemctl stop "$S8_SERVICE" >/dev/null 2>&1 || true
  systemctl stop "$LANDING_SERVICE" >/dev/null 2>&1 || true
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "ROLLBACK_TREE_MISMATCH"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  tar -xpf "$backup_path/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup_path/public-units-before.tar" -C /etc/systemd/system
  if [ -f "/etc/systemd/system/$LANDING_SERVICE.d/s9-growth.conf" ]; then
    unlink "/etc/systemd/system/$LANDING_SERVICE.d/s9-growth.conf"
  fi
  systemctl daemon-reload
  systemctl start "$LANDING_SERVICE"
  systemctl start "$S8_SERVICE"
  systemctl enable --now "$S8_HEALTH_TIMER" >/dev/null
  require_s8_green
}

abort_deploy() {
  local backup_path="$1"
  restore_baseline "$backup_path" || true
  printf 'S9_PUBLIC_GROWTH_CONTROL_RED DEPLOYMENT_ABORTED_S8_STABLE\n' >&2
  exit 2
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  require_application_source_or_target
  require_adult_runtime_closed
  require_credentials_metadata
  require_s8_green
  [ "$(service_value postgresql.service ActiveState)" = "active" ] || fail "POSTGRES_NOT_ACTIVE"
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$APPLICATION_ROOT" | grep -q -E 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  printf '{"ok":true,"safe_code":"S9_PUBLIC_GROWTH_PREFLIGHT_GREEN","adult_content":false,"avs":false,"payments":false,"creator_invite":false}\n'
}

deploy() {
  local control_sha="$1"
  local control_tree="$2"
  local backup_path="$3"
  preflight "$control_sha" "$control_tree" >/dev/null
  require_backup "$backup_path"
  disable_s9
  systemctl disable --now "$S8_HEALTH_TIMER" >/dev/null
  systemctl stop "$S8_SERVICE"
  systemctl stop "$LANDING_SERVICE"
  if ! install_release || ! install_database || ! install_files; then
    abort_deploy "$backup_path"
  fi
  systemctl daemon-reload
  if ! systemctl start "$LANDING_SERVICE"; then
    abort_deploy "$backup_path"
  fi
  if ! systemctl start "$S8_SERVICE"; then
    abort_deploy "$backup_path"
  fi
  if ! systemctl start "$S9_SEED_SERVICE"; then
    abort_deploy "$backup_path"
  fi
  systemctl enable --now "${S9_TIMERS[@]}" >/dev/null
  if ! systemctl start "$S9_AUDIENCE_SERVICE" || ! systemctl start "$S9_NURTURE_SERVICE" || ! systemctl start "$S9_REPORT_SERVICE" || ! systemctl start "$S9_HEALTH_SERVICE"; then
    journalctl -u "$S9_HEALTH_SERVICE" -n 20 --no-pager -o cat >&2 || true
    abort_deploy "$backup_path"
  fi
  verify "$control_sha" "$control_tree"
}

verify() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  require_adult_runtime_closed
  require_credentials_metadata
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_source_hashes
  require_s9_database
  require_service_green "$S7_SERVICE" "S7_SERVICE"
  require_service_green "$S8_SERVICE" "S8_SERVICE"
  require_service_green "$LANDING_SERVICE" "S8_LANDING"
  require_service_green "nginx.service" "NGINX"
  local timer_name
  for timer_name in "${S9_TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer_name" 2>/dev/null || true)" = "enabled" ] || fail "S9_TIMER_NOT_ENABLED"
    [ "$(service_value "$timer_name" ActiveState)" = "active" ] || fail "S9_TIMER_NOT_ACTIVE"
  done
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s9-growth.json | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] || fail "INSTALLED_S9_CONTRACT_DRIFT"
  systemctl start "$S9_HEALTH_SERVICE" || fail "S9_HEALTH_RED"
  printf '{"ok":true,"safe_code":"S9_PUBLIC_SFW_GROWTH_GREEN","organic_search":"AUTOMATED_SUPPORTED","telegram_channel":"DISABLED_FOR_NOW","x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW","creator_invite":false,"adult_content":false,"avs":false,"payments":false,"external_adult_publishing":false}\n'
}

rollback() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_application_clean
  restore_baseline "$3"
  printf '{"ok":true,"safe_code":"S9_ROLLBACK_TO_S8_GREEN","s9_database_evidence_preserved":true}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 3 ] || fail "USAGE"
    preflight "$2" "$3"
    ;;
  deploy)
    [ "$#" -eq 4 ] || fail "USAGE"
    deploy "$2" "$3" "$4"
    ;;
  verify)
    [ "$#" -eq 3 ] || fail "USAGE"
    verify "$2" "$3"
    ;;
  rollback)
    [ "$#" -eq 4 ] || fail "USAGE"
    rollback "$2" "$3" "$4"
    ;;
  *) fail "USAGE" ;;
esac
