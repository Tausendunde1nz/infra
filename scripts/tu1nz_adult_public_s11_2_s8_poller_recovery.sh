#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly AGGREGATE_STATE="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly QUALITY_STATE="/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json"
readonly SOURCE_APPLICATION_COMMIT="ecc73e2557b3f5bf643fa89d06bda57a9c4d26cc"
readonly SOURCE_APPLICATION_TREE="1acc0300ca099bd57f2455753c0a2700867a68d5"
readonly SOURCE_CONTROL_COMMIT="3efd84b3e66fa9c79d58e60943e3be864fa715d4"
readonly SOURCE_CONTROL_TREE="78f5b52f1def8a78608033088454a15940639d99"
readonly FAILED_DEPLOY_CONTROL_COMMIT="42fcbbefda36718540e8a7208f7b5cfaa6902ea0"
readonly FAILED_DEPLOY_BACKUP="/opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260921T161900Z-predeploy"
readonly FINAL_CONTROL_TAG="s11-2-canary-bootstrap-freeze-r8"
readonly RECOVERY_DIAGNOSTIC="$CONTROL_ROOT/scripts/tu1nz_adult_public_s11_2_recovery_diagnostic.py"
readonly INCIDENT_EPOCH="2026-09-21T16:21:59.148938Z"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly RUNTIME_RELEASE_ID="s10-2d-r3-5"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly ROTATION_SERVICE="tu1nz-adult-public-s10-2d-rotate.service"
readonly S11_CONTROLLER="/usr/local/bin/tu1nz_adult_public_s11_2_control.sh"
readonly S11_GATE="/usr/local/bin/tu1nz_adult_public_s11_2_gate.py"
readonly S11_UNIT="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service"
readonly S11_TIMER="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer"
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
  [ "$(id -u)" -eq 0 ] || fail "S11_2_R7_S8_ROOT_REQUIRED"
}

acquire_lock() {
  exec 9> /run/tu1nz-adult-public-s11-2-control.lock
  flock -n 9 || fail "S11_2_R7_S8_RECOVERY_ALREADY_RUNNING"
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S11_2_R7_S8_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-2-s8-poller-recovery/[0-9]{8}T[0-9]{6}Z-prerecovery$ ]] \
    || fail "S11_2_R7_S8_BACKUP_PATH_INVALID"
}

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
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
    || { fail "S11_2_R7_S8_${code}_COMMIT_DRIFT"; return 2; }
  [ "$(git_chatops "$repository" rev-parse 'HEAD^{tree}')" = "$tree" ] \
    || { fail "S11_2_R7_S8_${code}_TREE_DRIFT"; return 2; }
  [ -z "$(git_chatops "$repository" status --porcelain)" ] \
    || { fail "S11_2_R7_S8_${code}_WORKTREE_DIRTY"; return 2; }
}

require_remote_recovery() {
  local target_control="$1"
  [ "$(git_chatops "$CONTROL_ROOT" ls-remote origin "refs/tags/${FINAL_CONTROL_TAG}^{}" | awk 'NR == 1 {print $1}')" = "$target_control" ] \
    || fail "S11_2_R7_S8_REMOTE_FREEZE_DRIFT"
}

require_failed_deploy_backup() {
  [ -d "$FAILED_DEPLOY_BACKUP" ] && [ ! -L "$FAILED_DEPLOY_BACKUP" ] \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_BACKUP_MISSING"
  [ "$(stat -c '%U:%G:%a' "$FAILED_DEPLOY_BACKUP")" = root:root:700 ] \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_BACKUP_MODE_RED"
  grep -Fqx "source_application_commit=${SOURCE_APPLICATION_COMMIT}" "$FAILED_DEPLOY_BACKUP/provenance.txt" \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_APPLICATION_BINDING_RED"
  grep -Fqx "source_control_commit=${SOURCE_CONTROL_COMMIT}" "$FAILED_DEPLOY_BACKUP/provenance.txt" \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_SOURCE_CONTROL_BINDING_RED"
  grep -Fqx "target_control_commit=${FAILED_DEPLOY_CONTROL_COMMIT}" "$FAILED_DEPLOY_BACKUP/provenance.txt" \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_TARGET_CONTROL_BINDING_RED"
  (cd "$FAILED_DEPLOY_BACKUP" && sha256sum -c SHA256SUMS >/dev/null) \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_BACKUP_INTEGRITY_RED"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$FAILED_DEPLOY_BACKUP/application.bundle" >/dev/null \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_APPLICATION_BUNDLE_RED"
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$FAILED_DEPLOY_BACKUP/control.bundle" >/dev/null \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_CONTROL_BUNDLE_RED"
  pg_restore --list "$FAILED_DEPLOY_BACKUP/database.dump" >/dev/null \
    || fail "S11_2_R7_S8_FAILED_DEPLOY_DATABASE_BACKUP_RED"
}

require_public_health() {
  local path code
  for path in / /privacy /terms /imprint; do
    code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${path}")"
    [ "$code" = 200 ] || { fail "S11_2_R7_S8_PUBLIC_ENDPOINT_RED"; return 2; }
  done
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] \
    || { fail "S11_2_R7_S8_LEGACY_REDIRECT_RED"; return 2; }
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities",{}).values()) else 1)' \
    >/dev/null || { fail "S11_2_R7_S8_PUBLIC_HEALTH_RED"; return 2; }
}

require_s11_closed() {
  [ "$(database_scalar "SELECT release_state||'|'||promotion_state||'|'||enabled::text FROM commercial_s11_runtime_control WHERE singleton;")" = "S11_DISABLED|CANARY_RED|false" ] \
    || { fail "S11_2_R7_S8_S11_STATE_DRIFT"; return 2; }
  [ "$(database_scalar "SELECT (NOT community_user_content_publishing_enabled AND NOT adult_media_enabled AND NOT real_avs_enabled AND NOT payments_enabled AND NOT external_publishing_enabled AND NOT controlled_beta_enabled AND NOT production_enabled)::text FROM commercial_s11_runtime_control WHERE singleton;")" = true ] \
    || { fail "S11_2_R7_S8_PRODUCT_BOUNDARY_RED"; return 2; }
  [ "$(database_scalar "SELECT wms_real_acquisition_ready::text||'|'||to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM commercial_s10_2d_runtime_control WHERE singleton;")" = "true|${ACQUISITION_BASELINE}" ] \
    || { fail "S11_2_R7_S8_ACQUISITION_STATE_RED"; return 2; }
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE recorded_at >= '${INCIDENT_EPOCH}'::timestamptz AND (evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN');")" = 0 ] \
    || { fail "S11_2_R7_S8_NEW_UNKNOWN_EVIDENCE_RED"; return 2; }
  for path in "$S11_CONTROLLER" "$S11_GATE" "$S11_UNIT" "$S11_TIMER"; do
    [ ! -e "$path" ] || { fail "S11_2_R7_S8_PARTIAL_S11_INSTALLATION_PRESENT"; return 2; }
  done
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p LoadState --value)" = not-found ] \
    || { fail "S11_2_R7_S8_S11_TIMER_PRESENT"; return 2; }
}

require_failure_state() {
  local unit
  [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = failed ] \
    || { fail "S11_2_R7_S8_SERVICE_NOT_FAILED"; return 2; }
  [ "$(systemctl show "$S8_SERVICE" -p Result --value)" = start-limit-hit ] \
    || { fail "S11_2_R7_S8_FAILURE_SIGNATURE_DRIFT"; return 2; }
  [ "$(systemctl show "$S8_SERVICE" -p MainPID --value)" = 0 ] \
    || { fail "S11_2_R7_S8_UNEXPECTED_PROCESS_PRESENT"; return 2; }
  [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = 0 ] \
    || { fail "S11_2_R7_S8_RESTART_COUNT_DRIFT"; return 2; }
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='${RUNTIME_RELEASE_ID}' AND (lease_owner_id IS NULL OR lease_expires_at IS NULL OR lease_expires_at<=CURRENT_TIMESTAMP) AND (last_successful_poll_at IS NULL OR last_successful_poll_at<CURRENT_TIMESTAMP-INTERVAL '90 seconds') AND last_event_path_code='BOT_POLLER_NOT_RUNNING';")" = 1 ] \
    || { fail "S11_2_R7_S8_POLLER_FAILURE_SIGNATURE_DRIFT"; return 2; }
  [ "$(systemctl show tu1nz-adult-public-s9-health.service -p ExecMainStatus --value)" = 44 ] \
    || { fail "S11_2_R7_S8_S9_HEALTH_SIGNATURE_DRIFT"; return 2; }
  for unit in tu1nz-adult-public-s7.service tu1nz-adult-public-s8-landing.service \
    tu1nz-adult-public-s10-wms.service nginx.service; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_R7_S8_UNRELATED_SERVICE_RED"; return 2; }
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] \
      || { fail "S11_2_R7_S8_UNRELATED_SERVICE_RESTART_RED"; return 2; }
  done
  [ "$(systemctl show "$ROTATION_SERVICE" -p Result --value)" = success ] \
    || { fail "S11_2_R7_S8_PUBLICATION_ROTATION_RED"; return 2; }
}

require_timers_green() {
  local unit next_realtime next_monotonic
  for unit in "${TIMERS[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_R7_S8_TIMER_RED"; return 2; }
    [ "$(systemctl is-enabled "$unit")" = enabled ] \
      || { fail "S11_2_R7_S8_TIMER_DISABLED"; return 2; }
    next_realtime="$(systemctl show "$unit" -p NextElapseUSecRealtime --value)"
    next_monotonic="$(systemctl show "$unit" -p NextElapseUSecMonotonic --value)"
    if { [ -z "$next_realtime" ] || [ "$next_realtime" = n/a ]; } \
      && { [ -z "$next_monotonic" ] || [ "$next_monotonic" = n/a ] || [ "$next_monotonic" = 0 ]; }; then
      fail "S11_2_R7_S8_TIMER_FUTURE_RUN_MISSING"
      return 2
    fi
  done
  [ "$(systemctl is-enabled tu1nz-adult-public-s8-health.timer)" = disabled ] \
    || { fail "S11_2_R7_S8_RETIRED_TIMER_ENABLED"; return 2; }
  [ "$(systemctl show tu1nz-adult-public-s8-health.timer -p ActiveState --value)" = inactive ] \
    || { fail "S11_2_R7_S8_RETIRED_TIMER_ACTIVE"; return 2; }
}

require_poller_green() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='${RUNTIME_RELEASE_ID}' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds' AND last_event_path_code IN ('BOT_EVENT_PATH_GREEN','BOT_UPDATE_NOT_RECEIVED');")" = 1 ] \
    || { fail "S11_2_R7_S8_POLLER_LEASE_RED"; return 2; }
}

wait_poller_green() {
  local attempt
  for attempt in {1..90}; do
    if [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = active ] \
      && [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = 0 ] \
      && require_poller_green >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "S11_2_R7_S8_POLLER_READY_TIMEOUT"
}

run_health_services() {
  local unit result status invocation diagnostic
  for unit in "${HEALTH_SERVICES[@]}"; do
    if [ "$(systemctl show "$unit" -p ActiveState --value)" = failed ]; then
      systemctl reset-failed "$unit"
    fi
    status=0
    systemctl start "$unit" || status=$?
    result="$(systemctl show "$unit" -p Result --value)"
    if [ "$status" -ne 0 ] || [ "$result" != success ] \
      || [ "$(systemctl show "$unit" -p ExecMainStatus --value)" != 0 ]; then
      invocation="$(systemctl show "$unit" -p InvocationID --value)"
      [[ "$invocation" =~ ^[0-9a-fA-F]{32}$ ]] \
        || { fail "S11_2_R8_HEALTH_INVOCATION_ID_RED"; return 2; }
      diagnostic="$(journalctl --no-pager -o cat -n 20 \
        "_SYSTEMD_INVOCATION_ID=${invocation}" \
        | "$RECOVERY_DIAGNOSTIC" --parse-stream)" || true
      printf '%s\n' "$diagnostic" >&2
      fail "S11_2_R8_HEALTH_SERVICE_CHILD_RED"
      return 2
    fi
  done
}

require_runtime_green() {
  local unit
  for unit in "${SERVICES[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_R7_S8_SERVICE_RED"; return 2; }
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] \
      || { fail "S11_2_R7_S8_SERVICE_RESTART_RED"; return 2; }
  done
  require_timers_green
  require_poller_green
  [ "$(systemctl show "$ROTATION_SERVICE" -p Result --value)" = success ] \
    || { fail "S11_2_R7_S8_PUBLICATION_ROTATION_RED"; return 2; }
  require_public_health
}

database_evidence() {
  local destination="$1"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_DESTINATION="$destination" S11_INCIDENT_EPOCH="$INCIDENT_EPOCH" \
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
        "new_unknown_count": connection.execute(
            "SELECT count(*) FROM commercial_s10_2d_latency_samples "
            "WHERE recorded_at >= %s::timestamptz AND (evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') "
            "OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN')",
            (os.environ["S11_INCIDENT_EPOCH"],),
        ).fetchone()[0],
        "poller": connection.execute(
            "SELECT release_id,lease_owner_id IS NOT NULL,lease_expires_at>CURRENT_TIMESTAMP,"
            "last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds',last_event_path_code "
            "FROM commercial_s10_2d_bot_polling_state ORDER BY release_id"
        ).fetchall(),
    }
Path(os.environ["S11_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

preflight() {
  local target_control="$1" backup_path="$2"
  require_root
  require_sha "$target_control"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S11_2_R7_S8_BACKUP_ALREADY_EXISTS"
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" CONTROL
  require_remote_recovery "$target_control"
  require_failed_deploy_backup
  require_s11_closed
  require_failure_state
  require_timers_green
  require_public_health
  printf '{"ok":true,"safe_code":"S11_2_R7_S8_RECOVERY_PREFLIGHT_GREEN"}\n'
}

backup_runtime() {
  local backup_path="$1" target_control="$2"
  install -d -o root -g root -m 0700 "$backup_path"
  chown root:root "$backup_path"
  chmod g-s "$backup_path"
  chmod 0700 "$backup_path"
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] \
    || fail "S11_2_R7_S8_BACKUP_MODE_RED"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$backup_path/control.bundle" >/dev/null
  runuser -u postgres -- pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE" \
    > "$backup_path/database.dump"
  pg_restore --list "$backup_path/database.dump" > "$backup_path/database.restore-list.txt"
  [ -s "$backup_path/database.restore-list.txt" ] || fail "S11_2_R7_S8_DATABASE_BACKUP_RED"
  install -m 0600 /etc/systemd/system/tu1nz-adult-public-s8-telegram.service \
    "$backup_path/s8-telegram.service"
  install -m 0600 "$AGGREGATE_STATE" "$backup_path/landing-aggregates.exact"
  install -m 0600 "$QUALITY_STATE" "$backup_path/wms-traffic-quality.exact"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" "${HEALTH_SERVICES[@]}" "$ROTATION_SERVICE" \
    > "$backup_path/runtime-manifest.txt"
  database_evidence "$backup_path/database-aggregate.json"
  printf 'source_application_commit=%s\nsource_application_tree=%s\nsource_control_commit=%s\nsource_control_tree=%s\ntarget_control_commit=%s\nfailed_deploy_control_commit=%s\nfailed_deploy_backup=%s\nincident_epoch=%s\noperation=S8_POLLER_START_LIMIT_RECOVERY_ONLY\n' \
    "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" \
    "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" "$target_control" \
    "$FAILED_DEPLOY_CONTROL_COMMIT" "$FAILED_DEPLOY_BACKUP" "$INCIDENT_EPOCH" \
    > "$backup_path/provenance.txt"
  (
    cd "$backup_path"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  chmod -R go-rwx "$backup_path"
  chmod g-s "$backup_path"
  chmod 0700 "$backup_path"
  printf '{"ok":true,"safe_code":"S11_2_R7_S8_RECOVERY_BACKUP_GREEN"}\n'
}

require_backup() {
  local backup_path="$1" target_control="$2"
  [ -d "$backup_path" ] && [ ! -L "$backup_path" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] || return 1
  grep -Fqx "target_control_commit=${target_control}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "operation=S8_POLLER_START_LIMIT_RECOVERY_ONLY" "$backup_path/provenance.txt" || return 1
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$backup_path/application.bundle" >/dev/null || return 1
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$backup_path/control.bundle" >/dev/null || return 1
  pg_restore --list "$backup_path/database.dump" >/dev/null || return 1
}

recovery_error() {
  local status=$?
  trap - ERR
  if [ "${S11_2_R7_S8_MUTATION_ARMED:-false}" = true ]; then
    systemctl stop "$S8_SERVICE" >/dev/null 2>&1 || true
    printf '{"ok":false,"safe_code":"S11_2_R7_S8_RECOVERY_FAILED_CLOSED"}\n' >&2
  else
    printf '{"ok":false,"safe_code":"S11_2_R7_S8_RECOVERY_PREMUTATION_RED"}\n' >&2
  fi
  exit "$status"
}

recover() {
  local target_control="$1" backup_path="$2" release_before release_after
  require_root
  acquire_lock
  preflight "$target_control" "$backup_path"
  release_before="$(database_scalar "SELECT enabled::text||'|'||release_state||'|'||promotion_state FROM commercial_s11_runtime_control WHERE singleton;")"
  backup_runtime "$backup_path" "$target_control"
  require_backup "$backup_path" "$target_control" \
    || fail "S11_2_R7_S8_RECOVERY_BACKUP_VERIFY_RED"
  S11_2_R7_S8_MUTATION_ARMED=true
  trap 'recovery_error' ERR

  systemctl reset-failed "$S8_SERVICE"
  systemctl start "$S8_SERVICE"
  wait_poller_green
  run_health_services
  require_runtime_green
  require_s11_closed
  release_after="$(database_scalar "SELECT enabled::text||'|'||release_state||'|'||promotion_state FROM commercial_s11_runtime_control WHERE singleton;")"
  [ "$release_after" = "$release_before" ] \
    || fail "S11_2_R7_S8_S11_STATE_MUTATED"
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" CONTROL

  install -d -o root -g root -m 0700 "$backup_path/postrecovery"
  chmod g-s "$backup_path/postrecovery"
  chmod 0700 "$backup_path/postrecovery"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" "${HEALTH_SERVICES[@]}" "$ROTATION_SERVICE" \
    > "$backup_path/postrecovery/runtime-manifest.txt"
  database_evidence "$backup_path/postrecovery/database-aggregate.json"
  printf 'release_state=%s\ns8_poller=GREEN\npublic_health=GREEN\ns11_mutated=false\n' \
    "$release_after" > "$backup_path/postrecovery/result.txt"
  (
    cd "$backup_path/postrecovery"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  chmod -R go-rwx "$backup_path/postrecovery"
  trap - ERR
  S11_2_R7_S8_MUTATION_ARMED=false
  printf '{"ok":true,"safe_code":"S11_2_R7_S8_POLLER_RECOVERY_GREEN","s11_mutated":false,"canary_retry":false}\n'
}

usage() {
  printf 'usage: %s preflight TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s recover TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s simulate-diagnostic\n' "$0" >&2
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
  simulate-diagnostic)
    [ "$#" -eq 1 ] || { usage; exit 2; }
    "$RECOVERY_DIAGNOSTIC" --simulate-contract
    ;;
  *)
    usage
    ;;
esac
