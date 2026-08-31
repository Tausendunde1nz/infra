#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly APPLICATION_BRANCH="main"
readonly SOURCE_SHA="d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79"
readonly SOURCE_TREE="c9fa052bceb1e7ec3b84a5254d399acde9ff0989"
readonly SOURCE_CONTROL_SHA="14432278c5a228d2cb72b7389e56a80193eee04b"
readonly TARGET_SHA="8ea16db18c683c89bf38c9b2b02e920d3da84e4f"
readonly TARGET_TREE="b446b84c5d9d23a7ac10b052892a275febd7fb2c"
readonly SOURCE_S9_CONTRACT_SHA="12022dbc0c6dd8c748db91d526b374a690c6bb9f43c7ac89ea525aef7c9b28a0"
readonly S9_CONTRACT_SHA="b09b6917d076bc5a0bd3de6f224aac4fd5db326919c3c2ee82ef7d8fa41ac681"
readonly S8_CONTRACT_SHA="fe20aea4b80206a5eaa79b94d2b74c85d2883240ea68b6d4734618daadac452d"
readonly LANDING_CONTRACT_SHA="ecf9fc7908e0e2fc0208b9af27c5670df3463b34dcab213659ce410111af149e"
readonly MIGRATION_0025_SHA="b0b64bc6ca8d549f15b423fed66172ec16d764fbd5b7c97c129f9be03da583a1"
readonly DOWN_MIGRATION_0025_SHA="4c45973a570e12ca8727cf80261b5669ee8b9d16b53a68309ea5afa879183c99"
readonly MIGRATION_0026_SHA="0b5e4ff8d6073cf4a23ea3136962c43a6dc6cbfadd1066a7b446f0ea488c760f"
readonly DOWN_MIGRATION_0026_SHA="35cb7182bcaa038bc47fd3b1246d8616fd31f446540de9ace5202825ad241ef4"
readonly TELEGRAM_CHANNEL="@tu1nz_adult_publishing"
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

normalize_s9_control_index_mode() {
  local index="$CONTROL_ROOT/.git/index"
  [ -f "$index" ] && [ ! -L "$index" ] || fail "CONTROL_INDEX_UNSAFE_TYPE"
  [ "$(stat -c '%U:%G' "$index")" = "chatops:chatops" ] || fail "CONTROL_INDEX_OWNER_DRIFT"
  case "$(stat -c '%a' "$index")" in
    660) ;;
    640) chmod 0660 "$index" ;;
    *) fail "CONTROL_INDEX_MODE_UNEXPECTED" ;;
  esac
  [ "$(stat -c '%a' "$index")" = "660" ] || fail "CONTROL_INDEX_MODE_DRIFT"
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
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.sql" | awk '{print $1}')" = "$MIGRATION_0025_SHA" ] || fail "MIGRATION_0025_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.down.sql" | awk '{print $1}')" = "$DOWN_MIGRATION_0025_SHA" ] || fail "MIGRATION_0025_DOWN_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0026_commercial_s9_telegram_channel.sql" | awk '{print $1}')" = "$MIGRATION_0026_SHA" ] || fail "MIGRATION_0026_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0026_commercial_s9_telegram_channel.down.sql" | awk '{print $1}')" = "$DOWN_MIGRATION_0026_SHA" ] || fail "MIGRATION_0026_DOWN_DRIFT"
}

require_backup() {
  local backup_path="$1"
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_backup.sh" verify-existing "$backup_path" >/dev/null
  tar -tf "$backup_path/public-configuration-before.tar" \
    | grep -Fx './adult-commercial-s9-growth.json' >/dev/null \
    || fail "BACKUP_S9_CONFIGURATION_MISSING"
  tar -tf "$backup_path/public-units-before.tar" \
    | grep -Fx './tu1nz-adult-public-s9-audience.service' >/dev/null \
    || fail "BACKUP_S9_AUDIENCE_UNIT_MISSING"
  tar -tf "$backup_path/public-units-before.tar" \
    | grep -Fx './tu1nz-adult-public-s9-health.service' >/dev/null \
    || fail "BACKUP_S9_HEALTH_UNIT_MISSING"
  tar -tf "$backup_path/public-units-before.tar" \
    | grep -Fx './tu1nz-adult-public-s8-landing.service.d/s9-growth.conf' >/dev/null \
    || fail "BACKUP_S9_LANDING_DROP_IN_MISSING"
  grep -F "$MIGRATION_0025_SHA  $APPLICATION_ROOT/migrations/0025_commercial_s9_automated_growth.sql" \
    "$backup_path/migration-binding-before.txt" >/dev/null \
    || fail "BACKUP_S9_MIGRATION_BINDING_MISSING"
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

require_s9_organic_database() {
  [ "$(s9_table_count)" = "11" ] || fail "MIGRATION_0025_NOT_INSTALLED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND public_sfw_growth_enabled AND organic_discovery_enabled AND nurture_enabled AND NOT audience_seeding_enabled AND NOT telegram_channel_enabled AND NOT x_enabled AND NOT reddit_enabled AND NOT invite_automation_enabled AND NOT controlled_beta AND pricing_mode='FREE_EARLY_ACCESS' AND beta_creator_cap=20;")" = "1" ] || fail "S9_RUNTIME_BOUNDARY_DRIFT"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_channel_state WHERE (platform='telegram_channel' OR platform='x' OR platform='reddit') AND status='DISABLED_FOR_NOW';")" = "3" ] || fail "S9_CHANNEL_BOUNDARY_DRIFT"
}

require_s9_channel_database() {
  [ "$(s9_table_count)" = "11" ] || fail "MIGRATION_0025_NOT_INSTALLED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND public_sfw_growth_enabled AND organic_discovery_enabled AND nurture_enabled AND audience_seeding_enabled AND telegram_channel_enabled AND NOT x_enabled AND NOT reddit_enabled AND NOT invite_automation_enabled AND NOT controlled_beta AND pricing_mode='FREE_EARLY_ACCESS' AND beta_creator_cap=20;")" = "1" ] || fail "S9_RUNTIME_BOUNDARY_DRIFT"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_channel_state WHERE platform='telegram_channel' AND status='AUTOMATED_SUPPORTED';")" = "1" ] || fail "S9_TELEGRAM_CHANNEL_BOUNDARY_DRIFT"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_channel_state WHERE platform IN ('x','reddit') AND status='DISABLED_FOR_NOW';")" = "2" ] || fail "S9_DISABLED_CHANNEL_BOUNDARY_DRIFT"
}

s9_evidence_fingerprint() {
  database_scalar "SELECT md5(json_build_array(
    (SELECT count(*) FROM commercial_s9_content_items),
    (SELECT count(*) FROM commercial_s9_publication_queue),
    (SELECT count(*) FROM commercial_s9_nurture_deliveries),
    (SELECT count(*) FROM commercial_s9_funnel_events)
  )::text);"
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

activate_channel_database() {
  local before_fingerprint after_fingerprint before_s9 after_s9 organic active
  before_fingerprint="$(s8_aggregate_fingerprint)"
  before_s9="$(s9_evidence_fingerprint)"
  organic="$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND NOT audience_seeding_enabled AND NOT telegram_channel_enabled;")"
  active="$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND audience_seeding_enabled AND telegram_channel_enabled;")"
  if [ "$organic" = "1" ] && [ "$active" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0026_commercial_s9_telegram_channel.sql" >/dev/null
  elif [ "$organic" != "0" ] || [ "$active" != "1" ]; then
    fail "MIGRATION_0026_STATE_DIVERGED"
  fi
  require_s9_channel_database
  after_fingerprint="$(s8_aggregate_fingerprint)"
  after_s9="$(s9_evidence_fingerprint)"
  [ "$after_fingerprint" = "$before_fingerprint" ] || fail "S8_DATA_FINGERPRINT_DRIFT"
  [ "$after_s9" = "$before_s9" ] || fail "S9_EVIDENCE_FINGERPRINT_DRIFT"
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

require_base_public_green() {
  require_service_green "$S7_SERVICE" "S7_SERVICE"
  require_service_green "$S8_SERVICE" "S8_SERVICE"
  require_service_green "$LANDING_SERVICE" "S8_LANDING"
  require_service_green "nginx.service" "NGINX"
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())' \
    || fail "PUBLIC_EXTERNAL_HEALTH_RED"
}

require_s9_timers_green() {
  local timer_name
  for timer_name in "${S9_TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer_name" 2>/dev/null || true)" = "enabled" ] || fail "S9_TIMER_NOT_ENABLED"
    [ "$(service_value "$timer_name" ActiveState)" = "active" ] || fail "S9_TIMER_NOT_ACTIVE"
  done
}

require_channel_provider_green() {
  "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s9-growth" \
    --contract /etc/tu1nz/adult-commercial-s9-growth.json \
    --database-dsn "$DATABASE_DSN_PATH" \
    --channel-health \
    --s8-contract /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    --telegram-token "$TOKEN_PATH" \
    --telegram-channel "$TELEGRAM_CHANNEL" \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p == {"bot_can_post":True,"channel_bound":True,"ok":True,"safe_code":"S9_TELEGRAM_CHANNEL_GREEN"}' \
    || fail "S9_TELEGRAM_CHANNEL_PROVIDER_RED"
}

restore_source_health_script() {
  local temporary_health
  temporary_health="$(mktemp /run/tu1nz-s9-health-restore.XXXXXX)"
  if ! runuser -u chatops -- git -C "$CONTROL_ROOT" show \
    "$SOURCE_CONTROL_SHA:scripts/tu1nz_adult_public_s9_health.py" >"$temporary_health"; then
    unlink "$temporary_health"
    fail "SOURCE_HEALTH_SCRIPT_MISSING"
  fi
  install -o root -g root -m 0755 "$temporary_health" /usr/local/bin/tu1nz_adult_public_s9_health.py
  unlink "$temporary_health"
}

deactivate_channel_database() {
  local active organic
  active="$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND audience_seeding_enabled AND telegram_channel_enabled;")"
  organic="$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND NOT audience_seeding_enabled AND NOT telegram_channel_enabled;")"
  if [ "$active" = "1" ] && [ "$organic" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0026_commercial_s9_telegram_channel.down.sql" >/dev/null
  elif [ "$active" != "0" ] || [ "$organic" != "1" ]; then
    fail "MIGRATION_0026_ROLLBACK_STATE_DIVERGED"
  fi
}

restore_organic_baseline() {
  local backup_path="$1"
  disable_s9
  systemctl stop "$S8_SERVICE" >/dev/null 2>&1 || true
  systemctl stop "$LANDING_SERVICE" >/dev/null 2>&1 || true
  deactivate_channel_database
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "ROLLBACK_TREE_MISMATCH"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  tar -xpf "$backup_path/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup_path/public-units-before.tar" -C /etc/systemd/system
  restore_source_health_script
  systemctl daemon-reload
  systemctl start "$LANDING_SERVICE"
  systemctl start "$S8_SERVICE"
  systemctl enable --now "${S9_TIMERS[@]}" >/dev/null
  require_s9_organic_database
  require_base_public_green
  require_s9_timers_green
  systemctl start "$S9_HEALTH_SERVICE" || fail "S9_ORGANIC_HEALTH_RED"
}

abort_channel_activation() {
  local backup_path="$1"
  (restore_organic_baseline "$backup_path") || true
  printf 'S9_PUBLIC_GROWTH_CONTROL_RED CHANNEL_ACTIVATION_ABORTED_ORGANIC_S9_STABLE\n' >&2
  exit 2
}

channel_preflight() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$SOURCE_SHA" ] || fail "APPLICATION_SOURCE_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "APPLICATION_SOURCE_TREE_MISMATCH"
  require_adult_runtime_closed
  require_credentials_metadata
  runuser -u chatops -- git -C "$CONTROL_ROOT" cat-file -e "${SOURCE_CONTROL_SHA}^{commit}" \
    || fail "SOURCE_CONTROL_COMMIT_MISSING"
  runuser -u chatops -- git -C "$CONTROL_ROOT" cat-file -e \
    "${SOURCE_CONTROL_SHA}:scripts/tu1nz_adult_public_s9_health.py" \
    || fail "SOURCE_HEALTH_SCRIPT_MISSING"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s9-growth.json | awk '{print $1}')" = "$SOURCE_S9_CONTRACT_SHA" ] || fail "INSTALLED_SOURCE_S9_CONTRACT_DRIFT"
  require_s9_organic_database
  require_base_public_green
  require_s9_timers_green
  [ "$(service_value postgresql.service ActiveState)" = "active" ] || fail "POSTGRES_NOT_ACTIVE"
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$APPLICATION_ROOT" | grep -q -E 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  printf '{"ok":true,"safe_code":"S9_TELEGRAM_CHANNEL_PREFLIGHT_GREEN","adult_content":false,"avs":false,"payments":false,"creator_invite":false}\n'
}

activate_channel() {
  local control_sha="$1"
  local control_tree="$2"
  local backup_path="$3"
  channel_preflight "$control_sha" "$control_tree" >/dev/null
  normalize_s9_control_index_mode
  require_backup "$backup_path"
  disable_s9
  systemctl disable --now "$S8_HEALTH_TIMER" >/dev/null 2>&1 || true
  systemctl stop "$S8_SERVICE"
  systemctl stop "$LANDING_SERVICE"
  if ! (install_release && activate_channel_database && install_files); then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl daemon-reload; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$LANDING_SERVICE"; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S8_SERVICE"; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S9_SEED_SERVICE"; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl enable "${S9_TIMERS[@]}" >/dev/null; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S9_NURTURE_TIMER" "$S9_REPORT_TIMER" "$S9_HEALTH_TIMER"; then
    abort_channel_activation "$backup_path"
  fi
  if ! (require_channel_provider_green); then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S9_AUDIENCE_SERVICE"; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S9_AUDIENCE_TIMER"; then
    abort_channel_activation "$backup_path"
  fi
  if ! systemctl start "$S9_HEALTH_SERVICE"; then
    journalctl -u "$S9_HEALTH_SERVICE" -n 20 --no-pager -o cat >&2 || true
    abort_channel_activation "$backup_path"
  fi
  if ! (verify_channel "$control_sha" "$control_tree"); then
    abort_channel_activation "$backup_path"
  fi
}

verify_channel() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  require_adult_runtime_closed
  require_credentials_metadata
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_source_hashes
  require_s9_channel_database
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_publication_queue WHERE status='PUBLISHED';")" -ge 1 ] || fail "S9_TELEGRAM_ACCEPTANCE_PUBLICATION_MISSING"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_publication_queue WHERE status='FAILED';")" = "0" ] || fail "S9_TELEGRAM_PUBLICATION_FAILED"
  require_base_public_green
  require_s9_timers_green
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s9-growth.json | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] || fail "INSTALLED_S9_CONTRACT_DRIFT"
  require_channel_provider_green
  systemctl start "$S9_HEALTH_SERVICE" || fail "S9_HEALTH_RED"
  printf '{"ok":true,"safe_code":"S9_PUBLIC_SFW_TELEGRAM_GREEN","organic_search":"AUTOMATED_SUPPORTED","telegram_channel":"AUTOMATED_SUPPORTED","x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW","creator_invite":false,"adult_content":false,"avs":false,"payments":false,"external_adult_publishing":false}\n'
}

rollback_channel() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_application_clean
  restore_organic_baseline "$3"
  printf '{"ok":true,"safe_code":"S9_CHANNEL_ROLLBACK_TO_ORGANIC_GREEN","s9_database_evidence_preserved":true}\n'
}

case "${1:-}" in
  channel-preflight)
    [ "$#" -eq 3 ] || fail "USAGE"
    channel_preflight "$2" "$3"
    ;;
  activate-channel)
    [ "$#" -eq 4 ] || fail "USAGE"
    activate_channel "$2" "$3" "$4"
    ;;
  verify-channel)
    [ "$#" -eq 3 ] || fail "USAGE"
    verify_channel "$2" "$3"
    ;;
  rollback-channel)
    [ "$#" -eq 4 ] || fail "USAGE"
    rollback_channel "$2" "$3" "$4"
    ;;
  *) fail "USAGE" ;;
esac
