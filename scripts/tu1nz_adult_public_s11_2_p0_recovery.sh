#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly SOURCE_APPLICATION_COMMIT="ecc73e2557b3f5bf643fa89d06bda57a9c4d26cc"
readonly SOURCE_APPLICATION_TREE="1acc0300ca099bd57f2455753c0a2700867a68d5"
readonly SOURCE_CONTROL_COMMIT="3efd84b3e66fa9c79d58e60943e3be864fa715d4"
readonly SOURCE_CONTROL_TREE="78f5b52f1def8a78608033088454a15940639d99"
readonly FINAL_CONTROL_TAG="s11-2-canary-bootstrap-freeze-r3"
readonly ORIGINAL_DEPLOY_BACKUP="/opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260920T202117Z-predeploy"
readonly WMS_COPY="/etc/tu1nz/adult-commercial-s10-wms-copy.json"
readonly FAILED_WMS_COPY_SHA="cdc9a48da4380f6730183bd2de23bf582cc7060513aba2f071f0e1ce96f9bf46"
readonly RECOVERY_WMS_COPY_SHA="86b07436a51fded974286f5a2fbbd60b93b5ae175fc9106c63136f5462da53b2"
readonly AGGREGATE_STATE="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly QUALITY_STATE="/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly WMS_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly HEALTH_SERVICES=(
  tu1nz-adult-public-s8-health.service
  tu1nz-adult-public-s9-health.service
  tu1nz-adult-public-s10-health.service
)
readonly SERVICES=(
  tu1nz-adult-public-s7.service
  tu1nz-adult-public-s8-landing.service
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s10-wms.service
  nginx.service
)
readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)

fail() {
  printf '{"ok":false,"safe_code":"%s"}\n' "$1" >&2
  return 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "S11_2_P0_ROOT_REQUIRED"
}

acquire_lock() {
  exec 9> /run/tu1nz-adult-public-s11-2-p0-recovery.lock
  flock -n 9 || fail "S11_2_P0_RECOVERY_ALREADY_RUNNING"
}

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S11_2_P0_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-2-p0-recovery/[0-9]{8}T[0-9]{6}Z-prerecovery$ ]] \
    || fail "S11_2_P0_BACKUP_PATH_INVALID"
}

database_scalar() {
  local statement="$1"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_STATEMENT="$statement" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    row = connection.execute(os.environ["S11_STATEMENT"]).fetchone()
if row is None or len(row) != 1:
    raise SystemExit(2)
value = row[0]
print("true" if value is True else "false" if value is False else value)
PY
}

require_clean_commit() {
  local repository="$1" commit="$2" tree="$3" code="$4"
  [ "$(git_chatops "$repository" rev-parse HEAD)" = "$commit" ] \
    || { fail "S11_2_P0_${code}_COMMIT_DRIFT"; return 2; }
  [ "$(git_chatops "$repository" rev-parse 'HEAD^{tree}')" = "$tree" ] \
    || { fail "S11_2_P0_${code}_TREE_DRIFT"; return 2; }
  [ -z "$(git_chatops "$repository" status --porcelain)" ] \
    || { fail "S11_2_P0_${code}_WORKTREE_DIRTY"; return 2; }
}

require_remote_recovery() {
  local target_control="$1"
  [ "$(git_chatops "$CONTROL_ROOT" ls-remote origin "refs/tags/${FINAL_CONTROL_TAG}^{}" | awk 'NR == 1 {print $1}')" = "$target_control" ] \
    || fail "S11_2_P0_REMOTE_RECOVERY_FREEZE_DRIFT"
}

require_candidate_binding() {
  runuser -u chatops -- env PYTHONPATH="$APPLICATION_ROOT/src" \
    "$APPLICATION_ROOT/.venv/bin/python" - \
    3< <(git_chatops "$APPLICATION_ROOT" show "${SOURCE_APPLICATION_COMMIT}:config/commercial-s10-1-wms-copy.v1.json") <<'PY'
import json
import os
import sys
from pathlib import Path

from tu1nz_exposure_s10.contract import S10ExposureContract
from tu1nz_exposure_s10.copy import ExposureCopy
from tu1nz_exposure_s10.runtime import WMSLandingApplication
from tu1nz_exposure_s10.traffic import TrafficQualityCounter
from tu1nz_growth_s9.counter import AggregateCounter
from tu1nz_public_s8.community import CommunityContract
from tu1nz_public_s8.contract import S8Contract

raw = json.load(os.fdopen(3))
copy = ExposureCopy(
    raw["version"], raw["brand"], raw["design_tokens"], raw["public_copy"],
    raw["persona_modes"], raw["content_copy"], raw["nurture_copy"], raw["messages"],
)
copy.validate()
WMSLandingApplication(
    S10ExposureContract.load(Path("/etc/tu1nz/adult-commercial-s10-wms.json")),
    copy,
    S8Contract.load(Path("/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json")),
    AggregateCounter(Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json")),
    CommunityContract.load(Path("/etc/tu1nz/adult-commercial-s10-2d-community.json")),
    "s10-2d-r3-5",
    TrafficQualityCounter(Path("/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json")),
)
PY
}

require_database_safety() {
  local release_state
  release_state="$(database_scalar "SELECT release_state||'|'||promotion_state||'|'||enabled::text FROM commercial_s11_runtime_control WHERE singleton;")"
  case "$release_state" in
    S11_DISABLED\|NOT_STARTED\|false|S11_DISABLED\|CANARY_RED\|false) ;;
    *) fail "S11_2_P0_S11_STATE_UNSAFE"; return 2 ;;
  esac
  [ "$(database_scalar "SELECT (NOT community_user_content_publishing_enabled AND NOT adult_media_enabled AND NOT real_avs_enabled AND NOT payments_enabled AND NOT external_publishing_enabled AND NOT controlled_beta_enabled AND NOT production_enabled)::text FROM commercial_s11_runtime_control WHERE singleton;")" = true ] \
    || { fail "S11_2_P0_PRODUCT_BOUNDARY_RED"; return 2; }
  [ "$(database_scalar "SELECT wms_real_acquisition_ready::text||'|'||to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM commercial_s10_2d_runtime_control WHERE singleton;")" = "true|${ACQUISITION_BASELINE}" ] \
    || { fail "S11_2_P0_ACQUISITION_STATE_RED"; return 2; }
}

require_failure_state() {
  [ "$(systemctl show "$WMS_SERVICE" -p ActiveState --value)" = failed ] \
    || fail "S11_2_P0_WMS_NOT_FAILED"
  [ "$(systemctl show "$WMS_SERVICE" -p ExecMainStatus --value)" = 2 ] \
    || fail "S11_2_P0_WMS_FAILURE_SIGNATURE_DRIFT"
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.com/health)" = 502 ] \
    || fail "S11_2_P0_PUBLIC_FAILURE_SIGNATURE_DRIFT"
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p LoadState --value)" = not-found ] \
    || fail "S11_2_P0_PARTIAL_CONTROLLER_PRESENT"
  [ "$(sha256sum "$WMS_COPY" | awk '{print $1}')" = "$FAILED_WMS_COPY_SHA" ] \
    || fail "S11_2_P0_FAILED_COPY_DRIFT"
  [ "$(git_chatops "$APPLICATION_ROOT" show "${SOURCE_APPLICATION_COMMIT}:config/commercial-s10-1-wms-copy.v1.json" | sha256sum | awk '{print $1}')" = "$RECOVERY_WMS_COPY_SHA" ] \
    || fail "S11_2_P0_RECOVERY_COPY_DRIFT"
  [ -d "$ORIGINAL_DEPLOY_BACKUP" ] && [ ! -L "$ORIGINAL_DEPLOY_BACKUP" ] \
    || fail "S11_2_P0_ORIGINAL_BACKUP_MISSING"
  [ "$(stat -c '%U:%G:%a' "$ORIGINAL_DEPLOY_BACKUP")" = root:root:700 ] \
    || fail "S11_2_P0_ORIGINAL_BACKUP_MODE_RED"
  (cd "$ORIGINAL_DEPLOY_BACKUP" && sha256sum -c SHA256SUMS >/dev/null) \
    || fail "S11_2_P0_ORIGINAL_BACKUP_INTEGRITY_RED"
}

preflight() {
  local target_control="$1" backup_path="$2"
  require_root
  require_sha "$target_control"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S11_2_P0_BACKUP_ALREADY_EXISTS"
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" CONTROL
  require_remote_recovery "$target_control"
  require_failure_state
  require_candidate_binding \
    || { fail "S11_2_P0_CANDIDATE_BINDING_RED"; return 2; }
  require_database_safety
  printf '{"ok":true,"safe_code":"S11_2_P0_PREFLIGHT_GREEN"}\n'
}

database_evidence() {
  local destination="$1"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_DESTINATION="$destination" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    evidence = {
        "s11": connection.execute(
            "SELECT enabled,release_state,promotion_state,canary_evidence_start IS NOT NULL,"
            "canary_live_start IS NOT NULL,full_live_start IS NOT NULL,"
            "community_user_content_publishing_enabled,adult_media_enabled,real_avs_enabled,"
            "payments_enabled,external_publishing_enabled,controlled_beta_enabled,production_enabled "
            "FROM commercial_s11_runtime_control WHERE singleton"
        ).fetchone(),
        "acquisition": connection.execute(
            "SELECT wms_real_acquisition_ready,real_acquisition_baseline_start "
            "FROM commercial_s10_2d_runtime_control WHERE singleton"
        ).fetchone(),
        "latency_counts": connection.execute(
            "SELECT evidence_class,sample_type,interaction_path,count(*) "
            "FROM commercial_s10_2d_latency_samples GROUP BY 1,2,3 ORDER BY 1,2,3"
        ).fetchall(),
    }
Path(os.environ["S11_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

backup_runtime() {
  local backup_path="$1" target_control="$2"
  install -d -o root -g root -m 0700 "$backup_path"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null
  runuser -u postgres -- pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE" \
    > "$backup_path/database.dump"
  pg_restore --list "$backup_path/database.dump" > "$backup_path/database.restore-list.txt"
  [ -s "$backup_path/database.restore-list.txt" ] || fail "S11_2_P0_DATABASE_BACKUP_RED"
  install -m 0600 "$WMS_COPY" "$backup_path/failed-wms-copy.json"
  install -m 0600 /etc/tu1nz/adult-commercial-s10-wms.json "$backup_path/wms-contract.json"
  install -m 0600 /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json "$backup_path/wms-bot-contract.json"
  install -m 0600 /etc/tu1nz/adult-commercial-s10-2d-community.json "$backup_path/community-contract.json"
  install -m 0600 "$AGGREGATE_STATE" "$backup_path/landing-aggregates.exact"
  install -m 0600 "$QUALITY_STATE" "$backup_path/wms-traffic-quality.exact"
  install -m 0600 /etc/systemd/system/tu1nz-adult-public-s10-wms.service "$backup_path/wms.service"
  git_chatops "$APPLICATION_ROOT" show "${SOURCE_APPLICATION_COMMIT}:config/commercial-s10-1-wms-copy.v1.json" \
    | install -o root -g root -m 0600 /dev/stdin "$backup_path/recovery-wms-copy.json"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" "${HEALTH_SERVICES[@]}" \
    > "$backup_path/runtime-manifest.txt"
  database_evidence "$backup_path/database-aggregate.json"
  printf 'source_application_commit=%s\nsource_application_tree=%s\nsource_control_commit=%s\nsource_control_tree=%s\ntarget_control_commit=%s\nfailed_copy_sha=%s\nrecovery_copy_sha=%s\noriginal_deploy_backup=%s\n' \
    "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" \
    "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" "$target_control" \
    "$FAILED_WMS_COPY_SHA" "$RECOVERY_WMS_COPY_SHA" "$ORIGINAL_DEPLOY_BACKUP" \
    > "$backup_path/provenance.txt"
  (
    cd "$backup_path"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  chmod -R go-rwx "$backup_path"
  chmod 0700 "$backup_path"
  printf '{"ok":true,"safe_code":"S11_2_P0_BACKUP_GREEN"}\n'
}

require_backup() {
  local backup_path="$1" target_control="$2"
  [ -d "$backup_path" ] && [ ! -L "$backup_path" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] || return 1
  grep -Fqx "target_control_commit=${target_control}" "$backup_path/provenance.txt" || return 1
  [ "$(sha256sum "$backup_path/failed-wms-copy.json" | awk '{print $1}')" = "$FAILED_WMS_COPY_SHA" ] || return 1
  [ "$(sha256sum "$backup_path/recovery-wms-copy.json" | awk '{print $1}')" = "$RECOVERY_WMS_COPY_SHA" ] || return 1
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null || return 1
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null || return 1
  pg_restore --list "$backup_path/database.dump" >/dev/null || return 1
}

require_public_health() {
  local path code
  for path in / /privacy /terms /imprint; do
    code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${path}")"
    [ "$code" = 200 ] || { fail "S11_2_P0_PUBLIC_ENDPOINT_RED"; return 2; }
  done
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] \
    || { fail "S11_2_P0_LEGACY_REDIRECT_RED"; return 2; }
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities",{}).values()) else 1)' \
    >/dev/null || { fail "S11_2_P0_PUBLIC_HEALTH_RED"; return 2; }
}

wait_wms() {
  local attempt
  for attempt in {1..30}; do
    if [ "$(systemctl show "$WMS_SERVICE" -p ActiveState --value)" = active ]; then
      return 0
    fi
    sleep 1
  done
  fail "S11_2_P0_WMS_RECOVERY_TIMEOUT"
}

require_runtime_health() {
  local unit next_realtime next_monotonic
  for unit in "${SERVICES[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_P0_SERVICE_RED"; return 2; }
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] \
      || { fail "S11_2_P0_SERVICE_RESTART_RED"; return 2; }
  done
  for unit in "${TIMERS[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_P0_TIMER_RED"; return 2; }
    [ "$(systemctl is-enabled "$unit")" = enabled ] \
      || { fail "S11_2_P0_TIMER_DISABLED"; return 2; }
    next_realtime="$(systemctl show "$unit" -p NextElapseUSecRealtime --value)"
    next_monotonic="$(systemctl show "$unit" -p NextElapseUSecMonotonic --value)"
    if { [ -z "$next_realtime" ] || [ "$next_realtime" = n/a ]; } \
      && { [ -z "$next_monotonic" ] || [ "$next_monotonic" = n/a ] || [ "$next_monotonic" = 0 ]; }; then
      fail "S11_2_P0_TIMER_FUTURE_RUN_MISSING"
      return 2
    fi
  done
  [ "$(systemctl is-enabled tu1nz-adult-public-s8-health.timer)" = disabled ] \
    || { fail "S11_2_P0_RETIRED_S8_TIMER_ENABLED"; return 2; }
  [ "$(systemctl show tu1nz-adult-public-s8-health.timer -p ActiveState --value)" = inactive ] \
    || { fail "S11_2_P0_RETIRED_S8_TIMER_ACTIVE"; return 2; }
}

run_health_services() {
  local unit
  for unit in "${HEALTH_SERVICES[@]}"; do
    systemctl reset-failed "$unit" || true
    systemctl start "$unit"
    [ "$(systemctl show "$unit" -p Result --value)" = success ] \
      || { fail "S11_2_P0_HEALTH_SERVICE_RED"; return 2; }
  done
}

recovery_error() {
  local status=$?
  trap - ERR
  if [ "${S11_2_P0_MUTATION_ARMED:-false}" = true ]; then
    systemctl stop "$WMS_SERVICE" >/dev/null 2>&1 || true
    install -o root -g root -m 0644 "$S11_2_P0_BACKUP_PATH/failed-wms-copy.json" "$WMS_COPY" || true
    systemctl reset-failed "$WMS_SERVICE" >/dev/null 2>&1 || true
    systemctl start "$WMS_SERVICE" >/dev/null 2>&1 || true
    printf '{"ok":false,"safe_code":"S11_2_P0_RECOVERY_REVERTED_TO_INPUT_RED"}\n' >&2
  elif [ "${S11_2_P0_PUBLIC_COMMITTED:-false}" = true ]; then
    printf '{"ok":false,"safe_code":"S11_2_P0_POSTPUBLIC_HEALTH_RED"}\n' >&2
  else
    printf '{"ok":false,"safe_code":"S11_2_P0_RECOVERY_PREMUTATION_RED"}\n' >&2
  fi
  exit "$status"
}

recover() {
  local target_control="$1" backup_path="$2" release_before release_after
  require_root
  acquire_lock
  preflight "$target_control" "$backup_path"
  release_before="$(database_scalar "SELECT release_state||'|'||promotion_state||'|'||enabled::text FROM commercial_s11_runtime_control WHERE singleton;")"
  backup_runtime "$backup_path" "$target_control"
  require_backup "$backup_path" "$target_control" || fail "S11_2_P0_BACKUP_VERIFY_RED"
  S11_2_P0_BACKUP_PATH="$backup_path"
  S11_2_P0_MUTATION_ARMED=true
  S11_2_P0_PUBLIC_COMMITTED=false
  trap 'recovery_error' ERR

  install -o root -g root -m 0644 "$backup_path/recovery-wms-copy.json" "$WMS_COPY"
  [ "$(sha256sum "$WMS_COPY" | awk '{print $1}')" = "$RECOVERY_WMS_COPY_SHA" ] \
    || fail "S11_2_P0_INSTALLED_COPY_DRIFT"
  require_candidate_binding
  systemctl reset-failed "$WMS_SERVICE" || true
  systemctl restart "$WMS_SERVICE"
  wait_wms
  require_public_health

  S11_2_P0_MUTATION_ARMED=false
  S11_2_P0_PUBLIC_COMMITTED=true
  run_health_services
  require_runtime_health
  require_database_safety
  release_after="$(database_scalar "SELECT release_state||'|'||promotion_state||'|'||enabled::text FROM commercial_s11_runtime_control WHERE singleton;")"
  [ "$release_after" = "$release_before" ] || fail "S11_2_P0_S11_STATE_MUTATED"
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" CONTROL
  require_public_health

  install -d -o root -g root -m 0700 "$backup_path/postrecovery"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" "${HEALTH_SERVICES[@]}" \
    > "$backup_path/postrecovery/runtime-manifest.txt"
  database_evidence "$backup_path/postrecovery/database-aggregate.json"
  printf 'release_state=%s\npublic_health=GREEN\nwms_copy_sha=%s\n' \
    "$release_after" "$RECOVERY_WMS_COPY_SHA" > "$backup_path/postrecovery/result.txt"
  (
    cd "$backup_path/postrecovery"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  chmod -R go-rwx "$backup_path/postrecovery"
  trap - ERR
  printf '{"ok":true,"safe_code":"S11_2_P0_PUBLIC_WMS_RECOVERY_GREEN","s11_mutated":false}\n'
}

usage() {
  printf 'usage: %s preflight TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s recover TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  return 2
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 3 ] || { usage; exit 2; }
    preflight "$2" "$3"
    ;;
  recover)
    [ "$#" -eq 3 ] || { usage; exit 2; }
    recover "$2" "$3"
    ;;
  *)
    usage
    ;;
esac
