#!/usr/bin/env bash
set -Eeuo pipefail

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly STATE_ROOT="/var/lib/tu1nz-adult-public-s9"
readonly AGGREGATE_STATE="${STATE_ROOT}/landing-aggregates.json"
readonly QUALITY_STATE="${STATE_ROOT}/wms-traffic-quality.json"
readonly CHANGESET_STATE="${STATE_ROOT}/s10-2f-changeset.json"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly SOURCE_APPLICATION_COMMIT="312db84d5db6d76c9d6bb448459c9404b1dfcbe4"
readonly SOURCE_APPLICATION_TREE="ac4f8bca1fd796626742a8ef6c6afcdda482fc68"
readonly SOURCE_CONTROL_COMMIT="66e5b18c9d3bfc1082b1e2d0188cf14418f586a3"
readonly SOURCE_CONTROL_TREE="04eec54c23ba15e5787712bac434ae2f5bf4ae36"
readonly TARGET_APPLICATION_COMMIT="1d0dbb88603be49ea172178b77d86451036035a1"
readonly TARGET_APPLICATION_TREE="49f82e23ba16f06ddc27ef13e0b3f3643bc9da3e"
readonly TARGET_CONTROL_ARTIFACT_COMMIT="1d5e0d84451d35cb4148d0b52209002048db7e88"
readonly TARGET_CONTROL_ARTIFACT_TREE="3e6ab73b929cd19a796cc8528cce06809e801d4c"
readonly TARGET_CONTROL_ARTIFACT_TAG="s10-2f-control-artifacts-r1"
readonly FINAL_CONTROL_TAG="s10-2f-conversion-recovery-freeze-r1"
readonly WMS_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly HEALTH_SERVICE="tu1nz-adult-public-s10-health.service"
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

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
}

require_sha() {
  if [[ ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
    fail "S10_2F_SHA_INVALID"
    return $?
  fi
}

require_backup_path() {
  if [[ ! "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s10-2f-conversion/[0-9]{8}T[0-9]{6}Z-predeploy$ ]]; then
    fail "S10_2F_BACKUP_PATH_INVALID"
    return $?
  fi
}

require_clean_commit() {
  local repository="$1" expected="$2" code="$3"
  if [ "$(git_chatops "$repository" rev-parse HEAD)" != "$expected" ]; then
    fail "${code}_COMMIT_DRIFT"
    return $?
  fi
  if [ -n "$(git_chatops "$repository" status --porcelain)" ]; then
    fail "${code}_WORKTREE_DIRTY"
    return $?
  fi
}

require_service_health() {
  local unit active restarts
  for unit in "${SERVICES[@]}"; do
    active="$(systemctl show "$unit" -p ActiveState --value)"
    restarts="$(systemctl show "$unit" -p NRestarts --value)"
    if [ "$active" != active ] || [ "$restarts" != 0 ]; then
      fail "S10_2F_SERVICE_RED"
      return $?
    fi
  done
  for unit in "${TIMERS[@]}"; do
    if [ "$(systemctl show "$unit" -p ActiveState --value)" != active ] \
      || [ "$(systemctl is-enabled "$unit")" != enabled ]; then
      fail "S10_2F_TIMER_RED"
      return $?
    fi
  done
}

require_acquisition_state() {
  S10_2F_DATABASE_DSN="$DATABASE_DSN" S10_2F_ACQUISITION_BASELINE="$ACQUISITION_BASELINE" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S10_2F_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    row = connection.execute(
        "SELECT wms_real_acquisition_ready, real_acquisition_baseline_start "
        "FROM commercial_s10_2d_runtime_control WHERE singleton"
    ).fetchone()
if row is None or row[0] is not True or row[1] is None:
    raise SystemExit(2)
value = row[1].isoformat().replace("+00:00", "Z")
if value != os.environ["S10_2F_ACQUISITION_BASELINE"]:
    raise SystemExit(2)
PY
}

preflight() {
  local source_application="$1" source_control="$2"
  [ "$source_application" = "$SOURCE_APPLICATION_COMMIT" ] || fail "S10_2F_SOURCE_APPLICATION_DRIFT"
  [ "$source_control" = "$SOURCE_CONTROL_COMMIT" ] || fail "S10_2F_SOURCE_CONTROL_DRIFT"
  require_clean_commit "$APPLICATION_ROOT" "$source_application" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$source_control" CONTROL
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse "${source_application}^{tree}")" = "$SOURCE_APPLICATION_TREE" ] \
    || fail "S10_2F_SOURCE_APPLICATION_TREE_DRIFT"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "${source_control}^{tree}")" = "$SOURCE_CONTROL_TREE" ] \
    || fail "S10_2F_SOURCE_CONTROL_TREE_DRIFT"
  require_service_health
  require_acquisition_state || fail "S10_2F_ACQUISITION_STATE_RED"
  [ -f "$AGGREGATE_STATE" ] && [ ! -L "$AGGREGATE_STATE" ] || fail "S10_2F_AGGREGATE_RED"
  if [ -e "$QUALITY_STATE" ] || [ -L "$QUALITY_STATE" ] \
    || [ -e "$CHANGESET_STATE" ] || [ -L "$CHANGESET_STATE" ]; then
    fail "S10_2F_PREEXISTING_STATE_RED"
  fi
  printf '{"ok":true,"safe_code":"S10_2F_PREFLIGHT_GREEN"}\n'
}

database_evidence() {
  local destination="$1"
  S10_2F_DESTINATION="$destination" S10_2F_DATABASE_DSN="$DATABASE_DSN" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S10_2F_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
evidence = {}
with psycopg.connect(dsn) as connection:
    evidence["acquisition"] = connection.execute(
        "SELECT wms_real_acquisition_ready, real_acquisition_baseline_start IS NOT NULL "
        "FROM commercial_s10_2d_runtime_control WHERE singleton"
    ).fetchone()
    evidence["direct_events"] = connection.execute(
        "SELECT event_type, count(*) FROM commercial_s8_analytics_events "
        "GROUP BY event_type ORDER BY event_type"
    ).fetchall()
    evidence["community_events"] = connection.execute(
        "SELECT event_type, count(*) FROM commercial_s10_2d_community_events "
        "GROUP BY event_type ORDER BY event_type"
    ).fetchall()
    evidence["schema"] = connection.execute(
        "SELECT table_name, column_name, data_type, is_nullable "
        "FROM information_schema.columns WHERE table_schema='public' "
        "AND (table_name LIKE 'commercial_s8_%' OR table_name LIKE 'commercial_s10_2d_%') "
        "ORDER BY table_name, ordinal_position"
    ).fetchall()
Path(os.environ["S10_2F_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

backup() {
  local backup_path="$1" source_application="$2" source_control="$3"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S10_2F_BACKUP_EXISTS"
  install -d -o root -g chatops -m 0750 "$backup_path"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  chown root:chatops "$backup_path/application.bundle" "$backup_path/control.bundle"
  chmod 0640 "$backup_path/application.bundle" "$backup_path/control.bundle"
  git_chatops "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null
  git_chatops "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null
  install -m 0600 /etc/systemd/system/tu1nz-adult-public-s10-wms.service "$backup_path/wms.service"
  install -m 0600 /etc/systemd/system/tu1nz-adult-public-s10-health.service "$backup_path/health.service"
  install -m 0600 /usr/local/bin/tu1nz_adult_public_s10_1_health.py "$backup_path/health.py"
  install -m 0600 /etc/tu1nz/adult-commercial-s10-wms-copy.json "$backup_path/wms-copy.json"
  install -m 0600 "$AGGREGATE_STATE" "$backup_path/landing-aggregates.json"
  if [ -f "$QUALITY_STATE" ] && [ ! -L "$QUALITY_STATE" ]; then
    install -m 0600 "$QUALITY_STATE" "$backup_path/wms-traffic-quality.json"
  else
    : > "$backup_path/QUALITY_STATE_ABSENT"
  fi
  if [ -f "$CHANGESET_STATE" ] && [ ! -L "$CHANGESET_STATE" ]; then
    install -m 0600 "$CHANGESET_STATE" "$backup_path/s10-2f-changeset.json"
  else
    : > "$backup_path/CHANGESET_STATE_ABSENT"
  fi
  systemctl show "$WMS_SERVICE" "$HEALTH_SERVICE" > "$backup_path/runtime-manifest.txt"
  database_evidence "$backup_path/database-aggregate-and-schema.json"
  printf 'application_commit=%s\ncontrol_commit=%s\nacquisition_baseline=%s\n' \
    "$source_application" "$source_control" "$ACQUISITION_BASELINE" > "$backup_path/provenance.txt"
  (
    cd "$backup_path"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  chown -R root:root "$backup_path"
  chmod -R go-rwx "$backup_path"
  printf '{"ok":true,"safe_code":"S10_2F_BACKUP_GREEN","path":"%s"}\n' "$backup_path"
}

restore_source() {
  local backup_path="$1" source_application="$2" source_control="$3"
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  grep -Fqx "application_commit=${source_application}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "control_commit=${source_control}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "acquisition_baseline=${ACQUISITION_BASELINE}" "$backup_path/provenance.txt" || return 1
  git_chatops "$APPLICATION_ROOT" switch --detach "$source_application" >/dev/null || return 1
  git_chatops "$CONTROL_ROOT" switch --detach "$source_control" >/dev/null || return 1
  install -o root -g root -m 0644 "$backup_path/wms.service" /etc/systemd/system/tu1nz-adult-public-s10-wms.service || return 1
  install -o root -g root -m 0644 "$backup_path/health.service" /etc/systemd/system/tu1nz-adult-public-s10-health.service || return 1
  install -o root -g root -m 0755 "$backup_path/health.py" /usr/local/bin/tu1nz_adult_public_s10_1_health.py || return 1
  install -o root -g root -m 0644 "$backup_path/wms-copy.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json || return 1
  if [ -f "$backup_path/wms-traffic-quality.json" ]; then
    install -o chatops -g chatops -m 0600 "$backup_path/wms-traffic-quality.json" "$QUALITY_STATE" || return 1
  else
    rm -f "$QUALITY_STATE" || return 1
  fi
  if [ -f "$backup_path/s10-2f-changeset.json" ]; then
    install -o chatops -g chatops -m 0600 "$backup_path/s10-2f-changeset.json" "$CHANGESET_STATE" || return 1
  else
    rm -f "$CHANGESET_STATE" || return 1
  fi
  systemctl daemon-reload || return 1
  systemctl restart "$WMS_SERVICE" || return 1
  require_clean_commit "$APPLICATION_ROOT" "$source_application" APPLICATION || return 1
  require_clean_commit "$CONTROL_ROOT" "$source_control" CONTROL || return 1
  require_service_health || return 1
  require_acquisition_state || return 1
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/)" = 200 ] || return 1
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/health)" = 200 ] || return 1
  [ "$(curl -sS -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] || return 1
}

install_quality_state() {
  local temporary
  temporary="$(mktemp "${STATE_ROOT}/.wms-traffic-quality.XXXXXX")"
  printf '{}\n' > "$temporary"
  chown chatops:chatops "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$QUALITY_STATE"
}

wait_target_runtime() {
  local attempt
  for attempt in {1..40}; do
    if curl -fsS http://127.0.0.1:18110/health \
      | /usr/bin/python3 -c 'import json,sys; value=json.load(sys.stdin); raise SystemExit(0 if value.get("ok") is True and value.get("funnel_measurement_semantics") == "HUMAN_LIKE_BROWSER_NAVIGATION_V1" else 1)' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  fail "S10_2F_TARGET_LISTENER_RED"
}

install_changeset_state() {
  local temporary started_at
  started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
  temporary="$(mktemp "${STATE_ROOT}/.s10-2f-changeset.XXXXXX")"
  S10_2F_STARTED_AT="$started_at" S10_2F_ACQUISITION_BASELINE="$ACQUISITION_BASELINE" \
    /usr/bin/python3 - <<'PY' > "$temporary"
import json
import os
print(json.dumps({
    "version": "S10_2F",
    "started_at": os.environ["S10_2F_STARTED_AT"],
    "acquisition_baseline_start": os.environ["S10_2F_ACQUISITION_BASELINE"],
    "measurement_semantics": "HUMAN_LIKE_BROWSER_NAVIGATION_V1",
}, sort_keys=True, separators=(",", ":")))
PY
  chown chatops:chatops "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$CHANGESET_STATE"
}

require_target_release() {
  local target_application="$1" target_control="$2" target_control_tree
  [ "$target_application" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S10_2F_APPLICATION_RELEASE_DRIFT"
  git_chatops "$APPLICATION_ROOT" cat-file -e "${target_application}^{commit}" \
    || fail "S10_2F_APPLICATION_TARGET_MISSING"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse "${target_application}^{tree}")" = "$TARGET_APPLICATION_TREE" ] \
    || fail "S10_2F_APPLICATION_TREE_DRIFT"
  git_chatops "$CONTROL_ROOT" cat-file -e "${TARGET_CONTROL_ARTIFACT_COMMIT}^{commit}" \
    || fail "S10_2F_CONTROL_ARTIFACT_MISSING"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "${TARGET_CONTROL_ARTIFACT_COMMIT}^{tree}")" = "$TARGET_CONTROL_ARTIFACT_TREE" ] \
    || fail "S10_2F_CONTROL_ARTIFACT_TREE_DRIFT"
  [ "$(git_chatops "$CONTROL_ROOT" cat-file -t "refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}")" = tag ] \
    || fail "S10_2F_CONTROL_RELEASE_TAG_RED"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}^{commit}")" = "$TARGET_CONTROL_ARTIFACT_COMMIT" ] \
    || fail "S10_2F_CONTROL_ARTIFACT_RELEASE_DRIFT"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}" \
    | grep -Fqx "control_commit=${TARGET_CONTROL_ARTIFACT_COMMIT}" \
    || fail "S10_2F_CONTROL_RELEASE_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}" \
    | grep -Fqx "control_tree=${TARGET_CONTROL_ARTIFACT_TREE}" \
    || fail "S10_2F_CONTROL_RELEASE_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" cat-file -e "${target_control}^{commit}" \
    || fail "S10_2F_CONTROL_TARGET_MISSING"
  git_chatops "$CONTROL_ROOT" merge-base --is-ancestor "$TARGET_CONTROL_ARTIFACT_COMMIT" "$target_control" \
    || fail "S10_2F_CONTROL_ARTIFACT_NOT_IN_RELEASE"
  [ "$(git_chatops "$CONTROL_ROOT" cat-file -t "refs/tags/${FINAL_CONTROL_TAG}")" = tag ] \
    || fail "S10_2F_FINAL_CONTROL_TAG_RED"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${FINAL_CONTROL_TAG}^{commit}")" = "$target_control" ] \
    || fail "S10_2F_FINAL_CONTROL_RELEASE_DRIFT"
  target_control_tree="$(git_chatops "$CONTROL_ROOT" rev-parse "${target_control}^{tree}")"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "control_commit=${target_control}" \
    || fail "S10_2F_FINAL_CONTROL_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "control_tree=${target_control_tree}" \
    || fail "S10_2F_FINAL_CONTROL_PROVENANCE_RED"
}

install_control_artifact() {
  local path="$1" mode="$2" destination="$3"
  git_chatops "$CONTROL_ROOT" show "${TARGET_CONTROL_ARTIFACT_COMMIT}:${path}" \
    | install -o root -g root -m "$mode" /dev/stdin "$destination"
}

verify_target() {
  local target_application="$1" target_control="$2"
  require_target_release "$target_application" "$target_control"
  require_clean_commit "$APPLICATION_ROOT" "$target_application" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$target_control" CONTROL
  require_service_health
  require_acquisition_state || fail "S10_2F_ACQUISITION_STATE_RED"
  [ "$(stat -c '%U:%G:%a' "$QUALITY_STATE")" = chatops:chatops:600 ] || fail "S10_2F_QUALITY_MODE_RED"
  [ "$(stat -c '%U:%G:%a' "$CHANGESET_STATE")" = chatops:chatops:600 ] || fail "S10_2F_CHANGESET_MODE_RED"
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/)" = 200 ] || fail "S10_2F_PUBLIC_RED"
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/health)" = 200 ] || fail "S10_2F_PUBLIC_RED"
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/privacy)" = 200 ] || fail "S10_2F_PUBLIC_RED"
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/terms)" = 200 ] || fail "S10_2F_PUBLIC_RED"
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/imprint)" = 200 ] || fail "S10_2F_PUBLIC_RED"
  [ "$(curl -sS -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] || fail "S10_2F_LEGACY_REDIRECT_RED"
  systemctl start "$HEALTH_SERVICE"
  [ "$(systemctl show "$HEALTH_SERVICE" -p Result --value)" = success ] || fail "S10_2F_HEALTH_RED"
  printf '{"ok":true,"safe_code":"S10_2F_DEPLOYMENT_GREEN"}\n'
}

deploy() {
  local backup_path="$1" source_application="$2" source_control="$3" target_application="$4" target_control="$5"
  preflight "$source_application" "$source_control" >/dev/null
  git_chatops "$APPLICATION_ROOT" fetch origin main >/dev/null
  git_chatops "$CONTROL_ROOT" fetch --no-tags origin control-main \
    "refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}:refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}" \
    "refs/tags/${FINAL_CONTROL_TAG}:refs/tags/${FINAL_CONTROL_TAG}" >/dev/null
  require_target_release "$target_application" "$target_control"
  git_chatops "$APPLICATION_ROOT" merge-base --is-ancestor "$target_application" origin/main \
    || fail "S10_2F_APPLICATION_RELEASE_NOT_ON_MAIN"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse origin/control-main)" = "$target_control" ] \
    || fail "S10_2F_FINAL_CONTROL_NOT_ON_MAIN"
  backup "$backup_path" "$source_application" "$source_control" >/dev/null
  local mutated=0
  rollback_on_error() {
    local status=$?
    trap - ERR
    if [ "$mutated" = 1 ]; then
      if ! restore_source "$backup_path" "$source_application" "$source_control"; then
        printf '{"ok":false,"safe_code":"S10_2F_ROLLBACK_RED"}\n' >&2
        exit 3
      fi
    fi
    printf '{"ok":false,"safe_code":"S10_2F_DEPLOYMENT_ROLLED_BACK"}\n' >&2
    exit "$status"
  }
  trap rollback_on_error ERR
  mutated=1
  git_chatops "$APPLICATION_ROOT" switch --detach "$target_application" >/dev/null
  git_chatops "$CONTROL_ROOT" switch --detach "$target_control" >/dev/null
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json
  install_control_artifact systemd/tu1nz-adult-public-s10-wms.service 0644 /etc/systemd/system/tu1nz-adult-public-s10-wms.service
  install_control_artifact systemd/tu1nz-adult-public-s10-health.service 0644 /etc/systemd/system/tu1nz-adult-public-s10-health.service
  install_control_artifact scripts/tu1nz_adult_public_s10_1_health.py 0755 /usr/local/bin/tu1nz_adult_public_s10_1_health.py
  install_quality_state
  systemctl daemon-reload
  systemctl restart "$WMS_SERVICE"
  wait_target_runtime
  install_changeset_state
  verify_target "$target_application" "$target_control"
  trap - ERR
}

main() {
  [ "$#" -ge 3 ] || fail "S10_2F_ARGUMENTS_INVALID"
  local action="$1" source_application="$2" source_control="$3"
  require_sha "$source_application"
  require_sha "$source_control"
  case "$action" in
    preflight)
      [ "$#" = 3 ] || fail "S10_2F_ARGUMENTS_INVALID"
      preflight "$source_application" "$source_control"
      ;;
    deploy)
      [ "$#" = 6 ] || fail "S10_2F_ARGUMENTS_INVALID"
      require_backup_path "$4"
      require_sha "$5"
      require_sha "$6"
      deploy "$4" "$source_application" "$source_control" "$5" "$6"
      ;;
    verify)
      [ "$#" = 5 ] || fail "S10_2F_ARGUMENTS_INVALID"
      require_sha "$4"
      require_sha "$5"
      verify_target "$4" "$5"
      ;;
    rollback)
      [ "$#" = 4 ] || fail "S10_2F_ARGUMENTS_INVALID"
      require_backup_path "$4"
      restore_source "$4" "$source_application" "$source_control"
      printf '{"ok":true,"safe_code":"S10_2F_ROLLBACK_GREEN"}\n'
      ;;
    *) fail "S10_2F_ACTION_INVALID" ;;
  esac
}

main "$@"
