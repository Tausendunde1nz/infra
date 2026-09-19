#!/usr/bin/env bash
set -Eeuo pipefail

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly AGGREGATE_STATE="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly SOURCE_APPLICATION_COMMIT="1d0dbb88603be49ea172178b77d86451036035a1"
readonly SOURCE_APPLICATION_TREE="49f82e23ba16f06ddc27ef13e0b3f3643bc9da3e"
readonly SOURCE_CONTROL_COMMIT="5f0b5878888a5d48317e28ce75a6f0f552d6a419"
readonly SOURCE_CONTROL_TREE="6aebbeed942cd235a292dc8fcafcc29b6e2dab80"
readonly TARGET_APPLICATION_COMMIT="65707b079183151cfe7ea508f9270c31389f2334"
readonly TARGET_APPLICATION_TREE="79d60a5b8d791f65c0de06d0ae7861fb0d032ed4"
readonly FINAL_CONTROL_TAG="s11-interactive-experience-mvp-freeze-r4"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly EXPERIENCE_RELEASE_ID="s11-interactive-experience-mvp-r1"
readonly RUNTIME_RELEASE_ID="s10-2d-r3-5"
readonly EXPERIENCE_CONTRACT_SHA="faf4fe20887f7b9d7b31d8f35518db1dea2faa861c84acd791f9f0a739db425d"
readonly EXPERIENCE_COPY_SHA="bd842016355f7efd7dfdceedbe89e6e7ea0c7ada09dfe5587b37ad4e42abc972"
readonly MIGRATION_UP_SHA="5792180ca628740d6a3b644958b3ba0c4f82d68bc93bd17673f3445d02429606"
readonly MIGRATION_DOWN_SHA="bf4d3ce5e082d813a4f637ac010babb0c4835b94f204167b287657de90aaa157"
readonly WMS_LANDING_COPY_SHA="86b07436a51fded974286f5a2fbbd60b93b5ae175fc9106c63136f5462da53b2"
readonly EXPERIENCE_CONTRACT="/etc/tu1nz/adult-commercial-s11-interactive-experience.json"
readonly EXPERIENCE_COPY="/etc/tu1nz/adult-commercial-s11-interactive-copy.json"
readonly WMS_LANDING_COPY="/etc/tu1nz/adult-commercial-s10-wms-copy.json"
readonly S8_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-telegram.service"
readonly S8_HEALTH_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-health.service"
readonly S8_HEALTH_SCRIPT="/usr/local/bin/tu1nz_adult_public_s8_health.py"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
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
  [ "$(id -u)" -eq 0 ] || fail "S11_ROOT_REQUIRED"
}

acquire_lock() {
  exec 9> /run/tu1nz-adult-public-s11-control.lock
  flock -n 9 || fail "S11_CONTROL_ALREADY_RUNNING"
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S11_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-interactive-experience/[0-9]{8}T[0-9]{6}Z-predeploy$ ]] \
    || fail "S11_BACKUP_PATH_INVALID"
}

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
}

require_clean_commit() {
  local repository="$1" expected_commit="$2" expected_tree="$3" code="$4"
  [ "$(git_chatops "$repository" rev-parse HEAD)" = "$expected_commit" ] \
    || fail "S11_${code}_COMMIT_DRIFT"
  [ "$(git_chatops "$repository" rev-parse 'HEAD^{tree}')" = "$expected_tree" ] \
    || fail "S11_${code}_TREE_DRIFT"
  [ -z "$(git_chatops "$repository" status --porcelain)" ] \
    || fail "S11_${code}_WORKTREE_DIRTY"
}

remote_ref() {
  local repository="$1" reference="$2"
  git_chatops "$repository" ls-remote origin "$reference" | awk 'NR == 1 {print $1}'
}

require_remote_release() {
  local target_control="$1"
  [ "$(remote_ref "$APPLICATION_ROOT" refs/heads/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_REMOTE_APPLICATION_DRIFT"
  [ "$(remote_ref "$CONTROL_ROOT" "refs/tags/${FINAL_CONTROL_TAG}^{}")" = "$target_control" ] \
    || fail "S11_REMOTE_FREEZE_DRIFT"
}

require_local_freeze() {
  local target_control="$1" target_control_tree
  [ "$(git_chatops "$CONTROL_ROOT" cat-file -t "refs/tags/${FINAL_CONTROL_TAG}")" = tag ] \
    || fail "S11_FREEZE_NOT_ANNOTATED"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${FINAL_CONTROL_TAG}^{commit}")" = "$target_control" ] \
    || fail "S11_FREEZE_COMMIT_DRIFT"
  target_control_tree="$(git_chatops "$CONTROL_ROOT" rev-parse "${target_control}^{tree}")"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "application_commit=${TARGET_APPLICATION_COMMIT}" \
    || fail "S11_FREEZE_APPLICATION_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "application_tree=${TARGET_APPLICATION_TREE}" \
    || fail "S11_FREEZE_APPLICATION_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "control_commit=${target_control}" \
    || fail "S11_FREEZE_CONTROL_PROVENANCE_RED"
  git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
    | grep -Fqx "control_tree=${target_control_tree}" \
    || fail "S11_FREEZE_CONTROL_PROVENANCE_RED"
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
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

require_acquisition_state() {
  local state
  state="$(database_scalar \
    "SELECT wms_real_acquisition_ready::text || '|' || to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM commercial_s10_2d_runtime_control WHERE singleton;")" \
    || return 1
  [ "$state" = "true|${ACQUISITION_BASELINE}" ]
}

require_services_and_timers() {
  local unit next_realtime next_monotonic
  for unit in "${SERVICES[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || fail "S11_SERVICE_RED"
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] \
      || fail "S11_SERVICE_RESTART_RED"
  done
  for unit in "${TIMERS[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || fail "S11_TIMER_RED"
    [ "$(systemctl is-enabled "$unit")" = enabled ] \
      || fail "S11_TIMER_DISABLED"
    next_realtime="$(systemctl show "$unit" -p NextElapseUSecRealtime --value)"
    next_monotonic="$(systemctl show "$unit" -p NextElapseUSecMonotonic --value)"
    if { [ -z "$next_realtime" ] || [ "$next_realtime" = n/a ]; } \
      && { [ -z "$next_monotonic" ] || [ "$next_monotonic" = n/a ] || [ "$next_monotonic" = 0 ]; }; then
      fail "S11_TIMER_FUTURE_RUN_MISSING"
    fi
  done
}

require_public_health() {
  local path code
  for path in / /privacy /terms /imprint; do
    code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${path}")"
    [ "$code" = 200 ] || fail "S11_PUBLIC_ENDPOINT_RED"
  done
  code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)"
  [ "$code" = 308 ] || fail "S11_LEGACY_REDIRECT_RED"
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys; p=json.load(sys.stdin); raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities", {}).values()) else 1)' \
    >/dev/null || fail "S11_PUBLIC_HEALTH_RED"
}

require_source_state() {
  local source_application="$1" source_control="$2"
  [ "$source_application" = "$SOURCE_APPLICATION_COMMIT" ] \
    || fail "S11_SOURCE_APPLICATION_ARGUMENT_DRIFT"
  [ "$source_control" = "$SOURCE_CONTROL_COMMIT" ] \
    || fail "S11_SOURCE_CONTROL_ARGUMENT_DRIFT"
  require_clean_commit "$APPLICATION_ROOT" "$source_application" "$SOURCE_APPLICATION_TREE" SOURCE_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$source_control" "$SOURCE_CONTROL_TREE" SOURCE_CONTROL
  [ -f "$DATABASE_DSN" ] && [ ! -L "$DATABASE_DSN" ] || fail "S11_DATABASE_CREDENTIAL_RED"
  [ -f "$AGGREGATE_STATE" ] && [ ! -L "$AGGREGATE_STATE" ] || fail "S11_AGGREGATE_STATE_RED"
  [ ! -e "$EXPERIENCE_CONTRACT" ] && [ ! -L "$EXPERIENCE_CONTRACT" ] \
    || fail "S11_SOURCE_CONTRACT_ALREADY_PRESENT"
  [ ! -e "$EXPERIENCE_COPY" ] && [ ! -L "$EXPERIENCE_COPY" ] \
    || fail "S11_SOURCE_COPY_ALREADY_PRESENT"
  require_s11_schema_absent_or_disabled
  require_acquisition_state || fail "S11_ACQUISITION_STATE_RED"
  require_services_and_timers
  require_public_health
}

require_s11_schema_absent_or_disabled() {
  local table_count shape_count trigger_count
  table_count="$(database_scalar \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'commercial_s11_%';")" \
    || fail "S11_SCHEMA_INSPECTION_RED"
  if [ "$table_count" = 0 ]; then
    return 0
  fi
  [ "$table_count" = 3 ] || fail "S11_SCHEMA_PARTIAL_RED"
  require_feature_state off || fail "S11_PRESERVED_SCHEMA_CONTROL_RED"
  shape_count="$(database_scalar \
    "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND (table_name,column_name) IN (('commercial_s11_runtime_control','enabled'),('commercial_s11_runtime_control','live_start'),('commercial_s11_runtime_control','catalog_version'),('commercial_s11_runtime_control','state_machine_version'),('commercial_s11_experience_sessions','subject_id'),('commercial_s11_experience_sessions','revision'),('commercial_s11_product_events','event_type'),('commercial_s11_product_events','evidence_class')); ")" \
    || fail "S11_SCHEMA_INSPECTION_RED"
  [ "$shape_count" = 8 ] || fail "S11_SCHEMA_SHAPE_RED"
  trigger_count="$(database_scalar \
    "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ('commercial_s11_experience_session_guard','commercial_s11_product_events_append_only');")" \
    || fail "S11_SCHEMA_INSPECTION_RED"
  [ "$trigger_count" = 2 ] || fail "S11_SCHEMA_TRIGGER_RED"
}

preflight() {
  local source_application="$1" source_control="$2" target_control="$3" backup_path="$4"
  require_root
  require_sha "$source_application"
  require_sha "$source_control"
  require_sha "$target_control"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S11_BACKUP_ALREADY_EXISTS"
  require_source_state "$source_application" "$source_control"
  require_remote_release "$target_control"
  printf '{"ok":true,"safe_code":"S11_PREFLIGHT_GREEN"}\n'
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
evidence = {}
with psycopg.connect(dsn) as connection:
    evidence["acquisition"] = connection.execute(
        "SELECT wms_real_acquisition_ready, real_acquisition_baseline_start "
        "FROM commercial_s10_2d_runtime_control WHERE singleton"
    ).fetchone()
    evidence["schema"] = connection.execute(
        "SELECT table_name, column_name, data_type, is_nullable "
        "FROM information_schema.columns WHERE table_schema='public' AND "
        "(table_name LIKE 'commercial_s8_%' OR table_name LIKE 'commercial_s10_2d_%' "
        "OR table_name LIKE 'commercial_s11_%') ORDER BY table_name, ordinal_position"
    ).fetchall()
    evidence["funnel_counts"] = connection.execute(
        "SELECT event_type, count(*) FROM commercial_s8_analytics_events "
        "GROUP BY event_type ORDER BY event_type"
    ).fetchall()
    has_s11 = connection.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' "
        "AND table_name='commercial_s11_runtime_control')"
    ).fetchone()[0]
    evidence["s11_schema_present"] = has_s11
    if has_s11:
        evidence["s11_control"] = connection.execute(
            "SELECT enabled, live_start IS NOT NULL, catalog_version, state_machine_version, "
            "community_user_content_publishing_enabled, adult_media_enabled, real_avs_enabled, "
            "payments_enabled, external_publishing_enabled, controlled_beta_enabled, "
            "production_enabled FROM commercial_s11_runtime_control WHERE singleton"
        ).fetchone()
        evidence["s11_sessions"] = connection.execute(
            "SELECT count(*) FROM commercial_s11_experience_sessions"
        ).fetchone()[0]
        evidence["s11_events"] = connection.execute(
            "SELECT evidence_class, event_type, count(*) FROM commercial_s11_product_events "
            "GROUP BY evidence_class, event_type ORDER BY evidence_class, event_type"
        ).fetchall()
Path(os.environ["S11_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

backup_runtime() {
  local backup_path="$1" source_application="$2" source_control="$3"
  install -d -o root -g root -m 0700 "$backup_path"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$backup_path/control.bundle" >/dev/null
  install -m 0600 "$S8_UNIT" "$backup_path/s8-telegram.service"
  install -m 0600 "$S8_HEALTH_UNIT" "$backup_path/s8-health.service"
  install -m 0600 "$S8_HEALTH_SCRIPT" "$backup_path/s8-health.py"
  install -m 0600 "$WMS_LANDING_COPY" "$backup_path/wms-landing-copy.json"
  install -m 0600 "$AGGREGATE_STATE" "$backup_path/landing-aggregates.exact"
  : > "$backup_path/EXPERIENCE_CONTRACT_ABSENT"
  : > "$backup_path/EXPERIENCE_COPY_ABSENT"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" > "$backup_path/runtime-manifest.txt"
  database_evidence "$backup_path/database-aggregate-and-schema.json"
  printf 'application_commit=%s\napplication_tree=%s\ncontrol_commit=%s\ncontrol_tree=%s\nacquisition_baseline=%s\n' \
    "$source_application" "$SOURCE_APPLICATION_TREE" "$source_control" "$SOURCE_CONTROL_TREE" \
    "$ACQUISITION_BASELINE" > "$backup_path/provenance.txt"
  : > "$backup_path/owners-and-modes.txt"
  chmod -R go-rwx "$backup_path"
  chmod 0700 "$backup_path"
  chmod g-s "$backup_path"
  find "$backup_path" -maxdepth 1 -type f -exec stat -c '%n|%U|%G|%a' {} + \
    | sort > "$backup_path/owners-and-modes.txt"
  (
    cd "$backup_path"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$backup_path/control.bundle" >/dev/null
  printf '{"ok":true,"safe_code":"S11_RUNTIME_BACKUP_GREEN","path":"%s"}\n' "$backup_path"
}

require_backup() {
  local backup_path="$1" source_application="$2" source_control="$3"
  require_backup_path "$backup_path"
  [ -d "$backup_path" ] && [ ! -L "$backup_path" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] || return 1
  grep -Fqx "application_commit=${source_application}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "control_commit=${source_control}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "acquisition_baseline=${ACQUISITION_BASELINE}" "$backup_path/provenance.txt" || return 1
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" \
    bundle verify "$backup_path/application.bundle" >/dev/null || return 1
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" \
    bundle verify "$backup_path/control.bundle" >/dev/null || return 1
}

fetch_and_require_target() {
  local target_control="$1" path expected actual
  git_chatops "$APPLICATION_ROOT" fetch --quiet --no-tags origin main
  git_chatops "$CONTROL_ROOT" fetch --quiet --no-tags origin control-main \
    "refs/tags/${FINAL_CONTROL_TAG}:refs/tags/${FINAL_CONTROL_TAG}"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse origin/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_FETCHED_APPLICATION_DRIFT"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse "${TARGET_APPLICATION_COMMIT}^{tree}")" = "$TARGET_APPLICATION_TREE" ] \
    || fail "S11_TARGET_APPLICATION_TREE_DRIFT"
  git_chatops "$CONTROL_ROOT" merge-base --is-ancestor "$target_control" origin/control-main \
    || fail "S11_CONTROL_NOT_ON_CANONICAL_BRANCH"
  require_local_freeze "$target_control"
  while read -r path expected; do
    actual="$(git_chatops "$APPLICATION_ROOT" show "${TARGET_APPLICATION_COMMIT}:${path}" | sha256sum | awk '{print $1}')"
    [ "$actual" = "$expected" ] || fail "S11_APPLICATION_ARTIFACT_DRIFT"
  done <<EOF
config/commercial-s11-interactive-experience.sfw.json ${EXPERIENCE_CONTRACT_SHA}
config/commercial-s11-interactive-copy.v1.json ${EXPERIENCE_COPY_SHA}
migrations/0031_commercial_s11_interactive_experience.sql ${MIGRATION_UP_SHA}
migrations/0031_commercial_s11_interactive_experience.down.sql ${MIGRATION_DOWN_SHA}
config/commercial-s10-1-wms-copy.v1.json ${WMS_LANDING_COPY_SHA}
EOF
}

install_from_git() {
  local repository="$1" commit="$2" path="$3" mode="$4" destination="$5"
  git_chatops "$repository" show "${commit}:${path}" \
    | install -o root -g root -m "$mode" /dev/stdin "$destination"
}

apply_migration() {
  if [ "$(database_scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'commercial_s11_%';")" != 0 ]; then
    require_s11_schema_absent_or_disabled
    return 0
  fi
  S11_DATABASE_DSN="$DATABASE_DSN" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY' 2>/dev/null
from pathlib import Path
import os
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
sql = Path("/opt/tu1nz_repos/adult-publishing-core/migrations/0031_commercial_s11_interactive_experience.sql").read_text(encoding="utf-8")
with psycopg.connect(dsn, autocommit=True) as connection:
    present = connection.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' "
        "AND table_name LIKE 'commercial_s11_%'"
    ).fetchone()[0]
    if present != 0:
        raise SystemExit(2)
    connection.execute(sql)
PY
}

set_feature() {
  local enabled="$1" reason="$2"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_ENABLED="$enabled" S11_REASON="$reason" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY' 2>/dev/null
from pathlib import Path
import os
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
enabled = os.environ["S11_ENABLED"] == "true"
with psycopg.connect(dsn) as connection:
    cursor = connection.execute(
        "UPDATE commercial_s11_runtime_control SET enabled=%s, "
        "live_start=CASE WHEN %s THEN COALESCE(live_start, CURRENT_TIMESTAMP) ELSE NULL END, "
        "reason_safe_code=%s, updated_at=CURRENT_TIMESTAMP WHERE singleton",
        (enabled, enabled, os.environ["S11_REASON"]),
    )
    if cursor.rowcount != 1:
        raise SystemExit(2)
PY
}

require_feature_state() {
  local expected="$1" state
  state="$(database_scalar \
    "SELECT enabled::text || '|' || (live_start IS NOT NULL)::text || '|' || catalog_version || '|' || state_machine_version || '|' || community_user_content_publishing_enabled::text || '|' || adult_media_enabled::text || '|' || real_avs_enabled::text || '|' || payments_enabled::text || '|' || external_publishing_enabled::text || '|' || controlled_beta_enabled::text || '|' || production_enabled::text FROM commercial_s11_runtime_control WHERE singleton;")" \
    || return 1
  if [ "$expected" = off ]; then
    [ "$state" = "false|false|s11-curated-sfw-challenges-v1|s11-experience-state-v1|false|false|false|false|false|false|false" ]
  else
    [ "$state" = "true|true|s11-curated-sfw-challenges-v1|s11-experience-state-v1|false|false|false|false|false|false|false" ]
  fi
}

run_synthetic_journeys() {
  local destination="$1"
  "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s11-experience-journey" \
    --contract "$EXPERIENCE_CONTRACT" --copy "$EXPERIENCE_COPY" \
    --release-id "$EXPERIENCE_RELEASE_ID" > "$destination"
  /usr/bin/python3 - "$destination" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("ok") is not True or payload.get("safe_code") != "S11_SYNTHETIC_JOURNEYS_GREEN":
    raise SystemExit(2)
if payload.get("journey_count") != 8 or payload.get("journeys") != [
    "A_COMPLETE", "B_SAFER_COMPLETE", "C_BOLDEST_SFW", "D_SKIP_ALL",
    "E_STOP_RETURN", "F_SECOND_SESSION", "G_EXISTING_WAITLIST", "H_AGE_REJECTION",
]:
    raise SystemExit(2)
if any(payload.get(key) is not False for key in (
    "adult_media", "real_avs", "payments", "publishing",
    "community_user_content_publishing",
)):
    raise SystemExit(2)
PY
}

wait_runtime() {
  local attempt
  for attempt in {1..60}; do
    if [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = active ] \
      && [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = 0 ] \
      && [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='${RUNTIME_RELEASE_ID}' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds' AND last_event_path_code='BOT_EVENT_PATH_GREEN';")" = 1 ]; then
      return 0
    fi
    sleep 1
  done
  fail "S11_RUNTIME_READY_TIMEOUT"
}

run_runtime_health() {
  systemctl start tu1nz-adult-public-s8-health.service
  [ "$(systemctl show tu1nz-adult-public-s8-health.service -p Result --value)" = success ] \
    || fail "S11_S8_HEALTH_RED"
  systemctl start tu1nz-adult-public-s9-health.service
  [ "$(systemctl show tu1nz-adult-public-s9-health.service -p Result --value)" = success ] \
    || fail "S11_S9_HEALTH_RED"
  systemctl start tu1nz-adult-public-s10-health.service
  [ "$(systemctl show tu1nz-adult-public-s10-health.service -p Result --value)" = success ] \
    || fail "S11_S10_HEALTH_RED"
}

verify_target() {
  local target_control="$1"
  require_clean_commit "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE" TARGET_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$target_control" \
    "$(git_chatops "$CONTROL_ROOT" rev-parse "${target_control}^{tree}")" TARGET_CONTROL
  require_local_freeze "$target_control"
  [ "$(sha256sum "$EXPERIENCE_CONTRACT" | awk '{print $1}')" = "$EXPERIENCE_CONTRACT_SHA" ] \
    || fail "S11_INSTALLED_CONTRACT_DRIFT"
  [ "$(sha256sum "$EXPERIENCE_COPY" | awk '{print $1}')" = "$EXPERIENCE_COPY_SHA" ] \
    || fail "S11_INSTALLED_COPY_DRIFT"
  [ "$(sha256sum "$WMS_LANDING_COPY" | awk '{print $1}')" = "$WMS_LANDING_COPY_SHA" ] \
    || fail "S11_INSTALLED_LANDING_COPY_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s8-telegram.service" "$S8_UNIT" \
    || fail "S11_INSTALLED_S8_UNIT_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s8-health.service" "$S8_HEALTH_UNIT" \
    || fail "S11_INSTALLED_HEALTH_UNIT_DRIFT"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" "$S8_HEALTH_SCRIPT" \
    || fail "S11_INSTALLED_HEALTH_SCRIPT_DRIFT"
  require_feature_state on || fail "S11_FEATURE_NOT_LIVE"
  require_acquisition_state || fail "S11_ACQUISITION_STATE_RED"
  require_services_and_timers
  wait_runtime
  [ "$(systemctl show tu1nz-adult-public-s10-2d-rotate.service -p Result --value)" = success ] \
    || fail "S11_PUBLICATION_ROTATION_RED"
  require_public_health
  printf '{"ok":true,"safe_code":"S11_RUNTIME_GREEN"}\n'
}

restore_source() {
  local backup_path="$1" source_application="$2" source_control="$3"
  require_backup "$backup_path" "$source_application" "$source_control" || return 1
  if [ "$(database_scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='commercial_s11_runtime_control';")" = 1 ]; then
    set_feature false S11_ROLLBACK_DISABLED || return 1
  fi
  git_chatops "$APPLICATION_ROOT" switch --detach "$source_application" >/dev/null || return 1
  git_chatops "$CONTROL_ROOT" switch --detach "$source_control" >/dev/null || return 1
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null || return 1
  install -o root -g root -m 0644 "$backup_path/s8-telegram.service" "$S8_UNIT" || return 1
  install -o root -g root -m 0644 "$backup_path/s8-health.service" "$S8_HEALTH_UNIT" || return 1
  install -o root -g root -m 0755 "$backup_path/s8-health.py" "$S8_HEALTH_SCRIPT" || return 1
  install -o root -g root -m 0644 "$backup_path/wms-landing-copy.json" "$WMS_LANDING_COPY" || return 1
  rm -f -- "$EXPERIENCE_CONTRACT" "$EXPERIENCE_COPY"
  systemctl daemon-reload || return 1
  systemctl restart "$S8_SERVICE" || return 1
  systemctl restart tu1nz-adult-public-s10-wms.service || return 1
  wait_runtime || return 1
  require_clean_commit "$APPLICATION_ROOT" "$source_application" "$SOURCE_APPLICATION_TREE" SOURCE_APPLICATION || return 1
  require_clean_commit "$CONTROL_ROOT" "$source_control" "$SOURCE_CONTROL_TREE" SOURCE_CONTROL || return 1
  require_acquisition_state || return 1
  require_services_and_timers || return 1
  require_public_health || return 1
}

deploy() {
  local source_application="$1" source_control="$2" target_control="$3" backup_path="$4"
  acquire_lock
  preflight "$source_application" "$source_control" "$target_control" "$backup_path"
  backup_runtime "$backup_path" "$source_application" "$source_control"
  require_backup "$backup_path" "$source_application" "$source_control" \
    || fail "S11_BACKUP_VERIFY_RED"
  S11_ROLLBACK_ARMED=true
  S11_BACKUP_PATH="$backup_path"
  S11_SOURCE_APPLICATION="$source_application"
  S11_SOURCE_CONTROL="$source_control"
  trap 'deployment_error' ERR

  fetch_and_require_target "$target_control"
  git_chatops "$APPLICATION_ROOT" switch --detach "$TARGET_APPLICATION_COMMIT" >/dev/null
  git_chatops "$CONTROL_ROOT" switch --detach "$target_control" >/dev/null
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" \
    config/commercial-s11-interactive-experience.sfw.json 0644 "$EXPERIENCE_CONTRACT"
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" \
    config/commercial-s11-interactive-copy.v1.json 0644 "$EXPERIENCE_COPY"
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" \
    config/commercial-s10-1-wms-copy.v1.json 0644 "$WMS_LANDING_COPY"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    systemd/tu1nz-adult-public-s8-telegram.service 0644 "$S8_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    systemd/tu1nz-adult-public-s8-health.service 0644 "$S8_HEALTH_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    scripts/tu1nz_adult_public_s8_health.py 0755 "$S8_HEALTH_SCRIPT"
  apply_migration
  require_feature_state off || fail "S11_SOURCE_DEFAULT_NOT_OFF"
  systemctl daemon-reload
  systemctl restart "$S8_SERVICE"
  systemctl restart tu1nz-adult-public-s10-wms.service
  wait_runtime
  run_runtime_health
  run_synthetic_journeys "$backup_path/synthetic-journeys.json"
  set_feature true S11_INTERACTIVE_EXPERIENCE_LIVE
  systemctl restart "$S8_SERVICE"
  wait_runtime
  run_runtime_health
  verify_target "$target_control"
  install -d -o root -g root -m 0700 "$backup_path/postdeploy"
  mv "$backup_path/synthetic-journeys.json" "$backup_path/postdeploy/synthetic-journeys.json"
  database_evidence "$backup_path/postdeploy/database-aggregate.json"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" > "$backup_path/postdeploy/runtime-manifest.txt"
  chmod 0600 "$backup_path/postdeploy/synthetic-journeys.json" \
    "$backup_path/postdeploy/database-aggregate.json" "$backup_path/postdeploy/runtime-manifest.txt"
  find "$backup_path/postdeploy" -maxdepth 1 -type f ! -name POSTDEPLOY_SHA256SUMS \
    -exec stat -c '%n|%U|%G|%a' {} + | sort > "$backup_path/postdeploy/owners-and-modes.txt"
  (
    cd "$backup_path/postdeploy"
    find . -type f ! -name POSTDEPLOY_SHA256SUMS ! -name .POSTDEPLOY_SHA256SUMS.tmp \
      -print0 | sort -z \
      | xargs -0 sha256sum > .POSTDEPLOY_SHA256SUMS.tmp
    sha256sum -c .POSTDEPLOY_SHA256SUMS.tmp >/dev/null
    mv .POSTDEPLOY_SHA256SUMS.tmp POSTDEPLOY_SHA256SUMS
  )
  chmod 0600 "$backup_path/postdeploy/POSTDEPLOY_SHA256SUMS"
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null)
  trap - ERR
  S11_ROLLBACK_ARMED=false
  printf '{"ok":true,"safe_code":"S11_DEPLOYMENT_GREEN","human_acceptance":"DEFERRED"}\n'
}

deployment_error() {
  local status=$?
  trap - ERR
  if [ "${S11_ROLLBACK_ARMED:-false}" = true ] \
    && restore_source "$S11_BACKUP_PATH" "$S11_SOURCE_APPLICATION" "$S11_SOURCE_CONTROL"; then
    printf '{"ok":false,"safe_code":"S11_DEPLOYMENT_ROLLED_BACK"}\n' >&2
  else
    printf '{"ok":false,"safe_code":"S11_DEPLOYMENT_ROLLBACK_RED"}\n' >&2
  fi
  exit "$status"
}

rollback() {
  local backup_path="$1" source_application="$2" source_control="$3"
  require_root
  acquire_lock
  require_sha "$source_application"
  require_sha "$source_control"
  require_backup_path "$backup_path"
  restore_source "$backup_path" "$source_application" "$source_control" \
    || fail "S11_ROLLBACK_RED"
  printf '{"ok":true,"safe_code":"S11_ROLLBACK_GREEN"}\n'
}

usage() {
  printf 'usage: %s preflight|deploy SOURCE_APP SOURCE_CONTROL TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s verify TARGET_CONTROL\n' "$0" >&2
  printf '       %s rollback BACKUP_PATH SOURCE_APP SOURCE_CONTROL\n' "$0" >&2
  return 2
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 5 ] || usage
    preflight "$2" "$3" "$4" "$5"
    ;;
  deploy)
    [ "$#" -eq 5 ] || usage
    deploy "$2" "$3" "$4" "$5"
    ;;
  verify)
    [ "$#" -eq 2 ] || usage
    require_root
    acquire_lock
    require_sha "$2"
    require_remote_release "$2"
    verify_target "$2"
    ;;
  rollback)
    [ "$#" -eq 4 ] || usage
    rollback "$2" "$3" "$4"
    ;;
  *) usage ;;
esac
