#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly R14_APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly R14_CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly R14_DATABASE="tu1nz_adult_commercial_s3"
readonly R14_DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly R14_RELEASE_ID="s10-2d-r3-5"
readonly R14_PROBE_UNIT="tu1nz-adult-public-s8-technical-latency-probe.service"
readonly R14_PROBE_UNIT_PATH="/etc/systemd/system/${R14_PROBE_UNIT}"
readonly R14_RECONCILIATION="${R14_CONTROL_ROOT}/evidence/commercial-s11-1-latency-provenance-reconciliation.json"
readonly R14_LATENCY_READER="${R14_CONTROL_ROOT}/scripts/tu1nz_adult_public_s11_latency_slo.py"
readonly R14_S11_CONTROLLER="/usr/local/bin/tu1nz_adult_public_s11_2_control.sh"
readonly R14_S11_GATE="/usr/local/bin/tu1nz_adult_public_s11_2_gate.py"
readonly R14_S11_UNIT="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service"
readonly R14_S11_TIMER="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer"
readonly R14_SERVICES=(
  tu1nz-adult-public-s7.service
  tu1nz-adult-public-s8-landing.service
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s10-wms.service
  nginx.service
)
readonly R14_HEALTH_SERVICES=(
  tu1nz-adult-public-s8-health.service
  tu1nz-adult-public-s9-health.service
  tu1nz-adult-public-s10-health.service
)
readonly R14_TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)

r14_fail() {
  printf '{"ok":false,"safe_code":"%s"}\n' "$1" >&2
  return 2
}

r14_git_chatops() {
  local r14_repository="$1"
  shift
  runuser -u chatops -- git -C "$r14_repository" "$@"
}

r14_database_scalar() {
  local r14_statement="$1"
  R14_DSN_PATH="$R14_DATABASE_DSN" R14_STATEMENT="$r14_statement" \
    "$R14_APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["R14_DSN_PATH"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    row = connection.execute(os.environ["R14_STATEMENT"]).fetchone()
if row is None or len(row) != 1:
    raise SystemExit(2)
value = row[0]
print("true" if value is True else "false" if value is False else value)
PY
}

r14_require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || r14_fail "S11_2_R14_SHA_INVALID"
}

r14_require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-2-r14-technical-runtime-latency/[0-9]{8}T[0-9]{6}Z$ ]] \
    || r14_fail "S11_2_R14_BACKUP_PATH_INVALID"
}

r14_require_clean_commit() {
  local r14_repository="$1" r14_commit="$2" r14_code="$3"
  [ "$(r14_git_chatops "$r14_repository" rev-parse HEAD)" = "$r14_commit" ] \
    || { r14_fail "S11_2_R14_${r14_code}_COMMIT_DRIFT"; return 2; }
  [ -z "$(r14_git_chatops "$r14_repository" status --porcelain=v1)" ] \
    || { r14_fail "S11_2_R14_${r14_code}_WORKTREE_DIRTY"; return 2; }
}

r14_require_public_health() {
  local r14_path r14_code
  for r14_path in / /privacy /terms /imprint; do
    r14_code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${r14_path}")"
    [ "$r14_code" = 200 ] || { r14_fail "S11_2_R14_PUBLIC_ENDPOINT_RED"; return 2; }
  done
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] \
    || { r14_fail "S11_2_R14_LEGACY_REDIRECT_RED"; return 2; }
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities",{}).values()) else 1)' \
    >/dev/null || { r14_fail "S11_2_R14_PUBLIC_HEALTH_RED"; return 2; }
}

r14_require_runtime_green() {
  local r14_unit r14_next_realtime r14_next_monotonic
  for r14_unit in "${R14_SERVICES[@]}"; do
    [ "$(systemctl show "$r14_unit" -p ActiveState --value)" = active ] \
      || { r14_fail "S11_2_R14_SERVICE_RED"; return 2; }
    [ "$(systemctl show "$r14_unit" -p SubState --value)" = running ] \
      || { r14_fail "S11_2_R14_SERVICE_SUBSTATE_RED"; return 2; }
    [ "$(systemctl show "$r14_unit" -p NRestarts --value)" = 0 ] \
      || { r14_fail "S11_2_R14_RESTART_COUNT_RED"; return 2; }
  done
  for r14_unit in "${R14_TIMERS[@]}"; do
    [ "$(systemctl show "$r14_unit" -p ActiveState --value)" = active ] \
      || { r14_fail "S11_2_R14_TIMER_RED"; return 2; }
    [ "$(systemctl is-enabled "$r14_unit")" = enabled ] \
      || { r14_fail "S11_2_R14_TIMER_DISABLED"; return 2; }
    r14_next_realtime="$(systemctl show "$r14_unit" -p NextElapseUSecRealtime --value)"
    r14_next_monotonic="$(systemctl show "$r14_unit" -p NextElapseUSecMonotonic --value)"
    if { [ -z "$r14_next_realtime" ] || [ "$r14_next_realtime" = n/a ] || [ "$r14_next_realtime" = infinity ]; } \
      && { [ -z "$r14_next_monotonic" ] || [ "$r14_next_monotonic" = n/a ] || [ "$r14_next_monotonic" = 0 ] || [ "$r14_next_monotonic" = infinity ]; }; then
      r14_fail "S11_2_R14_TIMER_FUTURE_RUN_MISSING"
      return 2
    fi
  done
  [ "$(r14_database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='${R14_RELEASE_ID}' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds' AND last_event_path_code IN ('BOT_EVENT_PATH_GREEN','BOT_UPDATE_NOT_RECEIVED');")" = 1 ] \
    || { r14_fail "S11_2_R14_POLLER_RED"; return 2; }
  [ "$(systemctl show tu1nz-adult-public-s10-2d-rotate.service -p Result --value)" = success ] \
    || { r14_fail "S11_2_R14_PUBLICATION_ROTATION_RED"; return 2; }
  r14_require_public_health
}

r14_require_s11_closed() {
  [ "$(r14_database_scalar "SELECT release_state||'|'||promotion_state||'|'||enabled::text FROM commercial_s11_runtime_control WHERE singleton;")" = "S11_DISABLED|CANARY_RED|false" ] \
    || { r14_fail "S11_2_R14_S11_STATE_RED"; return 2; }
  [ "$(r14_database_scalar "SELECT (NOT community_user_content_publishing_enabled AND NOT adult_media_enabled AND NOT real_avs_enabled AND NOT payments_enabled AND NOT external_publishing_enabled AND NOT controlled_beta_enabled AND NOT production_enabled)::text FROM commercial_s11_runtime_control WHERE singleton;")" = true ] \
    || { r14_fail "S11_2_R14_PRODUCT_BOUNDARY_RED"; return 2; }
  for r14_path in "$R14_S11_CONTROLLER" "$R14_S11_GATE" "$R14_S11_UNIT" "$R14_S11_TIMER"; do
    [ ! -e "$r14_path" ] || { r14_fail "S11_2_R14_S11_INSTALLATION_PRESENT"; return 2; }
  done
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p LoadState --value)" = not-found ] \
    || { r14_fail "S11_2_R14_S11_TIMER_PRESENT"; return 2; }
}

r14_snapshot_database() {
  local r14_destination="$1" r14_epoch="$2"
  R14_DSN_PATH="$R14_DATABASE_DSN" R14_DESTINATION="$r14_destination" R14_EPOCH="$r14_epoch" \
    "$R14_APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["R14_DSN_PATH"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    def scalar(statement, params=()):
        return connection.execute(statement, params).fetchone()[0]

    evidence = {
        "captured_at": scalar("SELECT CURRENT_TIMESTAMP"),
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
        "product_counts": {
            "s7_analytics": scalar("SELECT count(*) FROM commercial_s7_analytics_events"),
            "s8_users": scalar("SELECT count(*) FROM commercial_s8_users"),
            "s8_analytics": scalar("SELECT count(*) FROM commercial_s8_analytics_events"),
            "s9_funnel": scalar("SELECT count(*) FROM commercial_s9_funnel_events"),
            "community_members": scalar("SELECT count(*) FROM commercial_s10_2d_community_members"),
            "community_events": scalar("SELECT count(*) FROM commercial_s10_2d_community_events"),
            "moderation_events": scalar("SELECT count(*) FROM commercial_s10_2d_moderation_events"),
            "moderation_outbox": scalar("SELECT count(*) FROM commercial_s10_2d_moderation_outbox"),
        },
        "community_states": connection.execute(
            "SELECT community_state,count(*) FROM commercial_s10_2d_community_members "
            "GROUP BY 1 ORDER BY 1"
        ).fetchall(),
        "latency_counts": connection.execute(
            "SELECT evidence_class,sample_type,interaction_path,count(*) "
            "FROM commercial_s10_2d_latency_samples GROUP BY 1,2,3 ORDER BY 1,2,3"
        ).fetchall(),
        "technical_window": connection.execute(
            "SELECT recorded_at,handler_duration_ms,release_id,run_id IS NOT NULL,"
            "evidence_class,sample_type,interaction_path "
            "FROM commercial_s10_2d_latency_samples "
            "WHERE recorded_at>=CURRENT_TIMESTAMP-INTERVAL '24 hours' AND source='DIRECT' "
            "AND evidence_class='INTERNAL_TEST' AND sample_type='DIRECT_BOT_RESPONSE' "
            "ORDER BY recorded_at"
        ).fetchall(),
        "r14_new_real": scalar(
            "SELECT count(*) FROM commercial_s10_2d_latency_samples "
            "WHERE recorded_at>=%s::timestamptz AND evidence_class='REAL'",
            (os.environ["R14_EPOCH"],),
        ),
        "r14_new_unknown": scalar(
            "SELECT count(*) FROM commercial_s10_2d_latency_samples "
            "WHERE recorded_at>=%s::timestamptz AND "
            "(evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') "
            "OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN')",
            (os.environ["R14_EPOCH"],),
        ),
        "r14_technical": connection.execute(
            "SELECT recorded_at,handler_duration_ms,release_id,run_id IS NOT NULL,"
            "evidence_class,sample_type,interaction_path "
            "FROM commercial_s10_2d_latency_samples WHERE recorded_at>=%s::timestamptz "
            "AND source='DIRECT' AND evidence_class='INTERNAL_TEST' "
            "AND sample_type='DIRECT_BOT_RESPONSE' ORDER BY recorded_at",
            (os.environ["R14_EPOCH"],),
        ).fetchall(),
    }
Path(os.environ["R14_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

r14_preflight() {
  local r14_application_commit="$1" r14_control_commit="$2" r14_freeze_tag="$3" r14_backup_path="$4"
  [ "$(id -u)" -eq 0 ] || r14_fail "S11_2_R14_ROOT_REQUIRED"
  r14_require_sha "$r14_application_commit"
  r14_require_sha "$r14_control_commit"
  [[ "$r14_freeze_tag" =~ ^s11-2-r14-[a-z0-9-]+$ ]] || r14_fail "S11_2_R14_FREEZE_TAG_INVALID"
  r14_require_backup_path "$r14_backup_path"
  [ -d "$r14_backup_path/source-prechange" ] || r14_fail "S11_2_R14_SOURCE_BACKUP_MISSING"
  (cd "$r14_backup_path/source-prechange" && sha256sum -c SHA256SUMS >/dev/null) \
    || r14_fail "S11_2_R14_SOURCE_BACKUP_RED"
  r14_require_clean_commit "$R14_APPLICATION_ROOT" "$r14_application_commit" APPLICATION
  r14_require_clean_commit "$R14_CONTROL_ROOT" "$r14_control_commit" CONTROL
  [ "$(r14_git_chatops "$R14_APPLICATION_ROOT" ls-remote origin refs/heads/main | awk 'NR==1 {print $1}')" = "$r14_application_commit" ] \
    || r14_fail "S11_2_R14_REMOTE_APPLICATION_DRIFT"
  [ "$(r14_git_chatops "$R14_CONTROL_ROOT" ls-remote origin refs/heads/control-main | awk 'NR==1 {print $1}')" = "$r14_control_commit" ] \
    || r14_fail "S11_2_R14_REMOTE_CONTROL_DRIFT"
  [ "$(r14_git_chatops "$R14_CONTROL_ROOT" rev-parse "refs/tags/${r14_freeze_tag}^{commit}")" = "$r14_control_commit" ] \
    || r14_fail "S11_2_R14_LOCAL_FREEZE_DRIFT"
  [ "$(r14_git_chatops "$R14_CONTROL_ROOT" ls-remote origin "refs/tags/${r14_freeze_tag}^{}" | awk 'NR==1 {print $1}')" = "$r14_control_commit" ] \
    || r14_fail "S11_2_R14_REMOTE_FREEZE_DRIFT"
  [ ! -e "$R14_PROBE_UNIT_PATH" ] || r14_fail "S11_2_R14_PROBE_UNIT_ALREADY_PRESENT"
  [ "$(r14_database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE recorded_at>=CURRENT_TIMESTAMP-INTERVAL '24 hours' AND source='DIRECT' AND evidence_class='INTERNAL_TEST' AND sample_type='DIRECT_BOT_RESPONSE';")" = 0 ] \
    || r14_fail "S11_2_R14_STARTING_SAMPLE_DRIFT"
  r14_require_s11_closed
  r14_require_runtime_green
}

r14_backup() {
  local r14_application_commit="$1" r14_control_commit="$2" r14_freeze_tag="$3" r14_backup_path="$4"
  local r14_runtime_backup="$r14_backup_path/runtime-preprobe"
  chown -R root:root "$r14_backup_path"
  chmod g-s "$r14_backup_path"
  chmod 0700 "$r14_backup_path"
  install -d -o root -g root -m 0700 "$r14_runtime_backup"
  r14_git_chatops "$R14_APPLICATION_ROOT" bundle create - HEAD > "$r14_runtime_backup/application.bundle"
  r14_git_chatops "$R14_CONTROL_ROOT" bundle create - HEAD > "$r14_runtime_backup/control.bundle"
  git -c safe.directory="$R14_APPLICATION_ROOT" -C "$R14_APPLICATION_ROOT" bundle verify "$r14_runtime_backup/application.bundle" >/dev/null
  git -c safe.directory="$R14_CONTROL_ROOT" -C "$R14_CONTROL_ROOT" bundle verify "$r14_runtime_backup/control.bundle" >/dev/null
  runuser -u postgres -- pg_dump --format=custom --no-owner --no-privileges --dbname="$R14_DATABASE" > "$r14_runtime_backup/database.dump"
  pg_restore --list "$r14_runtime_backup/database.dump" > "$r14_runtime_backup/database.restore-list.txt"
  [ -s "$r14_runtime_backup/database.restore-list.txt" ] || r14_fail "S11_2_R14_DATABASE_BACKUP_RED"
  install -m 0600 /etc/systemd/system/tu1nz-adult-public-s8-telegram.service "$r14_runtime_backup/s8-telegram.service"
  install -m 0600 "$R14_CONTROL_ROOT/systemd/$R14_PROBE_UNIT" "$r14_runtime_backup/r14-probe.service"
  install -m 0600 "$R14_APPLICATION_ROOT/src/tu1nz_public_s8/technical_latency_probe.py" "$r14_runtime_backup/technical-latency-probe.py"
  systemctl show "${R14_SERVICES[@]}" "${R14_TIMERS[@]}" "${R14_HEALTH_SERVICES[@]}" \
    tu1nz-adult-public-s10-2d-rotate.service > "$r14_runtime_backup/runtime-manifest.txt"
  printf 'application_commit=%s\napplication_tree=%s\ncontrol_commit=%s\ncontrol_tree=%s\nfreeze_tag=%s\noperation=S11_2_R14_TECHNICAL_RUNTIME_LATENCY_EVIDENCE\nrestore=git_bundles_plus_database_custom_dump\n' \
    "$r14_application_commit" "$(r14_git_chatops "$R14_APPLICATION_ROOT" rev-parse 'HEAD^{tree}')" \
    "$r14_control_commit" "$(r14_git_chatops "$R14_CONTROL_ROOT" rev-parse 'HEAD^{tree}')" \
    "$r14_freeze_tag" > "$r14_runtime_backup/provenance.txt"
  sha256sum "$r14_runtime_backup/"* > "$r14_runtime_backup/SHA256SUMS"
  (cd "$r14_runtime_backup" && sha256sum -c SHA256SUMS >/dev/null)
  pg_restore --list "$r14_runtime_backup/database.dump" >/dev/null
}

r14_install_probe_unit() {
  local r14_control_commit="$1"
  r14_git_chatops "$R14_CONTROL_ROOT" show "${r14_control_commit}:systemd/${R14_PROBE_UNIT}" \
    | install -o root -g root -m 0644 /dev/stdin "$R14_PROBE_UNIT_PATH"
  cmp -s "$R14_CONTROL_ROOT/systemd/$R14_PROBE_UNIT" "$R14_PROBE_UNIT_PATH" \
    || r14_fail "S11_2_R14_PROBE_UNIT_DRIFT"
  systemctl daemon-reload
  [ "$(systemctl is-enabled "$R14_PROBE_UNIT" 2>/dev/null || true)" = static ] \
    || r14_fail "S11_2_R14_PROBE_UNIT_ENABLEMENT_RED"
}

r14_run_one_probe() {
  local r14_iteration="$1" r14_epoch="$2" r14_destination="$3"
  local r14_invocation r14_count r14_unknown
  systemctl start "$R14_PROBE_UNIT"
  [ "$(systemctl show "$R14_PROBE_UNIT" -p Result --value)" = success ] \
    || r14_fail "S11_2_R14_PROBE_SERVICE_RED"
  [ "$(systemctl show "$R14_PROBE_UNIT" -p ExecMainStatus --value)" = 0 ] \
    || r14_fail "S11_2_R14_PROBE_EXIT_RED"
  r14_invocation="$(systemctl show "$R14_PROBE_UNIT" -p InvocationID --value)"
  [[ "$r14_invocation" =~ ^[0-9a-fA-F]{32}$ ]] || r14_fail "S11_2_R14_PROBE_INVOCATION_RED"
  journalctl --no-pager -o cat "_SYSTEMD_INVOCATION_ID=${r14_invocation}" \
    | /usr/bin/python3 -c \
      'import json,sys; rows=[]
for line in sys.stdin:
 try:
  value=json.loads(line)
 except json.JSONDecodeError:
  continue
 if value.get("safe_code")=="S11_2_R14_TECHNICAL_RUNTIME_PROBE_GREEN": rows.append(value)
assert len(rows)==1 and rows[0].get("evidence_class")=="INTERNAL_TEST" and rows[0].get("samples_written")==1 and rows[0].get("telegram_requests")==0 and rows[0].get("product_state_writes")==0
print(json.dumps(rows[0],sort_keys=True,separators=(",",":")))' \
    > "$r14_destination"
  r14_count="$(r14_database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE recorded_at>='${r14_epoch}'::timestamptz AND source='DIRECT' AND evidence_class='INTERNAL_TEST' AND sample_type='DIRECT_BOT_RESPONSE' AND interaction_path='INTERNAL_ACCEPTANCE' AND release_id='${R14_RELEASE_ID}' AND run_id IS NOT NULL AND bot_response_latency_ms=0 AND poll_lag_ms=0 AND handler_duration_ms BETWEEN 0 AND 300000 AND send_ack_ms=0;")"
  [ "$r14_count" = "$r14_iteration" ] || r14_fail "S11_2_R14_PROBE_COUNT_RED"
  r14_unknown="$(r14_database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE recorded_at>='${r14_epoch}'::timestamptz AND (evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN');")"
  [ "$r14_unknown" = 0 ] || r14_fail "S11_2_R14_NEW_UNKNOWN_RED"
  r14_require_runtime_green
}

r14_run_health_services() {
  local r14_unit
  for r14_unit in "${R14_HEALTH_SERVICES[@]}"; do
    [ "$(systemctl show "$r14_unit" -p ActiveState --value)" != failed ] \
      || { r14_fail "S11_2_R14_HEALTH_PRESTATE_RED"; return 2; }
    systemctl start "$r14_unit"
    [ "$(systemctl show "$r14_unit" -p Result --value)" = success ] \
      || { r14_fail "S11_2_R14_HEALTH_RESULT_RED"; return 2; }
    [ "$(systemctl show "$r14_unit" -p ExecMainStatus --value)" = 0 ] \
      || { r14_fail "S11_2_R14_HEALTH_EXIT_RED"; return 2; }
  done
}

r14_compare_product_state() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import json
import sys
from pathlib import Path

before = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
after = json.loads(Path(sys.argv[2]).read_text(encoding="ascii"))
if before["s11"] != after["s11"]:
    raise SystemExit(2)
if before["acquisition"] != after["acquisition"]:
    raise SystemExit(2)
if before["product_counts"] != after["product_counts"]:
    raise SystemExit(2)
if before["community_states"] != after["community_states"]:
    raise SystemExit(2)
if after["r14_new_real"] != 0 or after["r14_new_unknown"] != 0 or len(after["r14_technical"]) != 5:
    raise SystemExit(2)
PY
}

r14_finalize() {
  local r14_application_commit="$1" r14_control_commit="$2" r14_freeze_tag="$3"
  local r14_backup_path="$4" r14_epoch="$5"
  local r14_final="$r14_backup_path/final"
  install -d -o root -g root -m 0700 "$r14_final/probes"
  r14_snapshot_database "$r14_final/before.json" "$r14_epoch"
  local r14_iteration
  for r14_iteration in 1 2 3 4 5; do
    r14_run_one_probe "$r14_iteration" "$r14_epoch" \
      "$r14_final/probes/$(printf '%02d' "$r14_iteration").json"
  done
  "$R14_APPLICATION_ROOT/.venv/bin/python" "$R14_LATENCY_READER" \
    --dsn-file "$R14_DATABASE_DSN" --reconciliation "$R14_RECONCILIATION" \
    --profile TECHNICAL_RUNTIME_LATENCY > "$r14_final/technical-runtime-slo.json"
  /usr/bin/python3 - "$r14_final/technical-runtime-slo.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if payload.get("state") != "GREEN" or payload.get("samples") != 5:
    raise SystemExit(2)
if payload.get("metric") != "handler_duration_ms":
    raise SystemExit(2)
PY
  r14_run_health_services
  r14_require_runtime_green
  r14_require_s11_closed
  r14_snapshot_database "$r14_final/after.json" "$r14_epoch"
  r14_compare_product_state "$r14_final/before.json" "$r14_final/after.json" \
    || r14_fail "S11_2_R14_PRODUCT_STATE_MUTATION_RED"
  r14_require_clean_commit "$R14_APPLICATION_ROOT" "$r14_application_commit" APPLICATION
  r14_require_clean_commit "$R14_CONTROL_ROOT" "$r14_control_commit" CONTROL
  R14_FINAL_DIR="$r14_final" R14_APPLICATION_COMMIT="$r14_application_commit" \
    R14_CONTROL_COMMIT="$r14_control_commit" R14_FREEZE_TAG="$r14_freeze_tag" \
    /usr/bin/python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["R14_FINAL_DIR"])
slo = json.loads((root / "technical-runtime-slo.json").read_text(encoding="ascii"))
after = json.loads((root / "after.json").read_text(encoding="ascii"))
result = {
    "ok": True,
    "safe_code": "S11_2_R14_TECHNICAL_RUNTIME_LATENCY_GREEN",
    "application_commit": os.environ["R14_APPLICATION_COMMIT"],
    "control_commit": os.environ["R14_CONTROL_COMMIT"],
    "freeze_tag": os.environ["R14_FREEZE_TAG"],
    "technical_runtime_latency": slo,
    "new_real_count": after["r14_new_real"],
    "new_unknown_count": after["r14_new_unknown"],
    "technical_samples_written": len(after["r14_technical"]),
    "acquisition_contamination": False,
    "community_state_mutation": False,
    "p0_recovery": "CLOSED",
    "next_s11_canary_runtime_ready": True,
    "s11_state": "S11_DISABLED",
}
(root / "result.json").write_text(
    json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
  sha256sum "$r14_final/"*.json "$r14_final/probes/"*.json > "$r14_final/SHA256SUMS"
  (cd "$r14_final" && sha256sum -c SHA256SUMS >/dev/null)
}

main() {
  [ "$#" -eq 4 ] || { r14_fail "S11_2_R14_ARGUMENT_RED"; return 2; }
  local r14_application_commit="$1" r14_control_commit="$2" r14_freeze_tag="$3" r14_backup_path="$4"
  local r14_epoch
  exec 9> /run/tu1nz-adult-public-s11-2-r14.lock
  flock -n 9 || { r14_fail "S11_2_R14_ALREADY_RUNNING"; return 2; }
  r14_preflight "$r14_application_commit" "$r14_control_commit" "$r14_freeze_tag" "$r14_backup_path"
  r14_backup "$r14_application_commit" "$r14_control_commit" "$r14_freeze_tag" "$r14_backup_path"
  r14_install_probe_unit "$r14_control_commit"
  r14_epoch="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  r14_finalize "$r14_application_commit" "$r14_control_commit" "$r14_freeze_tag" "$r14_backup_path" "$r14_epoch"
}

main "$@"
