#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly CONFIG_ROOT="/etc/tu1nz"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly BASELINE_SHA="a745540b81a368b2e5f09d1fcdb49342b686ae0e"
readonly BASELINE_TREE="6e7c869d1194b28baad67698a93ab2254b0d8739"
readonly TARGET_SHA="99a179990ae67aeab420eccef984915ae2aebfbd"
readonly TARGET_TREE="ecd67fa84fbd1248dd2b7b29a6cafba7bdc0d527"
readonly MIGRATION_CHAIN_SHA="84fe9df14d3e37b45fde96bf541f8cdcc7cb8947a0ed3765699abdf4bdb2cf5b"
readonly YOTI_CONTRACT_SHA="a8933f970ae78d47fadba69ea831f559ce16c3c8234a652bb5939a53f9baa19d"
readonly SEGPAY_CONTRACT_SHA="03bccf3c24a281eaffb4fdc530df7d57bf0b870ee5b2ee3e6ee5ebb02ed3ffb1"
readonly REQUIREMENTS_SHA="3e363326c3342b4f507886387a4ee8aa10a0e54269ee6f2d39ebf18b37cabe91"
readonly MIGRATION_SHA="615f59aead6ca5451cba8bd010c5f7bfa771c15170ff9e634f9f941f6ba34ce4"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s4-extended-staging/"

fail() {
  printf 'S5_S6_OFFLINE_STAGE_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_stopped() {
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "SERVICE_NOT_INACTIVE"
  [ "$(systemctl show "$SERVICE" -p SubState --value)" = "dead" ] || fail "SERVICE_NOT_DEAD"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" = "0" ] || fail "SERVICE_PROCESS_PRESENT"
  [ "$(systemctl show "$SERVICE" -p NRestarts --value)" = "0" ] || fail "SERVICE_RESTART_COUNT_NONZERO"
  [ "$(systemctl show "$SERVICE" -p Restart --value)" = "no" ] || fail "SERVICE_RESTART_POLICY_DRIFT"
  [ "$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)" = "static" ] || fail "SERVICE_ENABLEMENT_DRIFT"
  ! pgrep -f '[t]u1nz-commercial-s3-runtime' >/dev/null || fail "CANDIDATE_PROCESS_PRESENT"
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
  [ -d "$1" ] || fail "BACKUP_PATH_MISSING"
  [ ! -L "$1" ] || fail "BACKUP_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$1")" = "root:root" ] || fail "BACKUP_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$1")" in
    700|2700) ;;
    *) fail "BACKUP_MODE_DRIFT" ;;
  esac
  [ -f "$1/SHA256SUMS" ] || fail "BACKUP_HASH_INDEX_MISSING"
  (cd "$1" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "BACKUP_HASH_INVALID"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$1/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$1/control.bundle" >/dev/null
  pg_restore --list "$1/database-before.dump" >/dev/null
}

require_source_hashes() {
  [ "$(sha256sum "$APPLICATION_ROOT/requirements-s5.lock" | awk '{print $1}')" = "$REQUIREMENTS_SHA" ] || fail "REQUIREMENTS_LOCK_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0020_commercial_s6_payment_readiness.sql" | awk '{print $1}')" = "$MIGRATION_SHA" ] || fail "MIGRATION_0020_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s5-yoti-sandbox.disabled.json" | awk '{print $1}')" = "$YOTI_CONTRACT_SHA" ] || fail "YOTI_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s6-segpay.disabled.json" | awk '{print $1}')" = "$SEGPAY_CONTRACT_SHA" ] || fail "SEGPAY_CONTRACT_DRIFT"
}

require_application_clean() {
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
}

require_baseline_or_target() {
  local sha tree
  sha="$(git_value "$APPLICATION_ROOT" HEAD)"
  tree="$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
  if [ "$sha" = "$BASELINE_SHA" ] && [ "$tree" = "$BASELINE_TREE" ]; then
    return
  fi
  [ "$sha" = "$TARGET_SHA" ] && [ "$tree" = "$TARGET_TREE" ] || fail "APPLICATION_RELEASE_UNEXPECTED"
}

database_table_count() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" --command="SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('commercial_s6_payment_grants','commercial_s6_payment_reversals','commercial_s6_provider_payment_events');" \
    | tr -d '[:space:]'
}

offline_health() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
from datetime import datetime, timezone
from tu1nz_commercial_s3.health import S3HealthProbe, S3HealthState

report = S3HealthProbe().check(
    checked_at=datetime.now(timezone.utc),
    process=True,
    database=True,
    migration=True,
    telegram_transport_config=True,
    telegram_identity_bound=True,
    telegram_reachable=True,
    polling=True,
    worker=True,
    outbox=True,
    audit=True,
    product_boundary=True,
    avs_active=False,
    avs_offline_staged=True,
    avs_adapter_ready=True,
    avs_config_ready=True,
    payment_active=False,
)
expected = {
    "AVS_ADAPTER": S3HealthState.GREEN,
    "AVS_CONFIG": S3HealthState.GREEN,
    "AVS_NETWORK": S3HealthState.DISABLED_EXPECTED,
    "AVS_AUTH": S3HealthState.DISABLED_EXPECTED,
    "PAYMENT_CONFIG": S3HealthState.DISABLED_EXPECTED,
    "PAYMENT_NETWORK": S3HealthState.DISABLED_EXPECTED,
}
if any(report.components[key] is not value for key, value in expected.items()):
    raise SystemExit(2)
print('{"ok":true,"safe_code":"S5_S6_OFFLINE_HEALTH_GREEN"}')
PY
}

preflight() {
  require_root
  require_stopped
  require_control "$1" "$2"
  require_application_clean
  require_baseline_or_target
  require_backup "$3"
  printf '{"ok":true,"safe_code":"S5_S6_OFFLINE_PREFLIGHT_GREEN","service_started":false}\n'
}

stage() {
  preflight "$1" "$2" "$3"
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$BASELINE_SHA" ]; then
    runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin main
    [ "$(git_value "$APPLICATION_ROOT" origin/main)" = "$TARGET_SHA" ] || fail "REMOTE_TARGET_SHA_MISMATCH"
    runuser -u chatops -- git -C "$APPLICATION_ROOT" merge --ff-only "$TARGET_SHA"
  fi
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_application_clean
  require_source_hashes
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --require-hashes -r "$APPLICATION_ROOT/requirements-s5.lock"
  local count
  count="$(database_table_count)"
  if [ "$count" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      --file=- <"$APPLICATION_ROOT/migrations/0020_commercial_s6_payment_readiness.sql" >/dev/null
  elif [ "$count" != "3" ]; then
    fail "MIGRATION_0020_PARTIAL_STATE"
  fi
  install -o root -g root -m 0600 "$APPLICATION_ROOT/config/commercial-s5-yoti-sandbox.disabled.json" "$CONFIG_ROOT/adult-commercial-s5-yoti.disabled.json"
  install -o root -g root -m 0600 "$APPLICATION_ROOT/config/commercial-s6-segpay.disabled.json" "$CONFIG_ROOT/adult-commercial-s6-segpay.disabled.json"
  offline_health
  printf '{"ok":true,"safe_code":"S5_S6_OFFLINE_STAGING_GREEN","service_started":false,"provider_called":false}\n'
}

verify() {
  require_root
  require_stopped
  require_control "$1" "$2"
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_source_hashes
  [ "$(database_table_count)" = "3" ] || fail "MIGRATION_0020_NOT_INSTALLED"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s5-yoti.disabled.json" | awk '{print $1}')" = "$YOTI_CONTRACT_SHA" ] || fail "INSTALLED_YOTI_CONTRACT_DRIFT"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s6-segpay.disabled.json" | awk '{print $1}')" = "$SEGPAY_CONTRACT_SHA" ] || fail "INSTALLED_SEGPAY_CONTRACT_DRIFT"
  offline_health
  printf '{"ok":true,"safe_code":"S5_S6_OFFLINE_VERIFY_GREEN","service_started":false,"provider_called":false}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 4 ] || fail "USAGE"
    preflight "$2" "$3" "$4"
    ;;
  stage)
    [ "$#" -eq 4 ] || fail "USAGE"
    stage "$2" "$3" "$4"
    ;;
  verify)
    [ "$#" -eq 3 ] || fail "USAGE"
    verify "$2" "$3"
    ;;
  *) fail "USAGE" ;;
esac
