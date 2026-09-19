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
  exit 2
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S10_2F_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s10-2f-conversion/[0-9]{8}T[0-9]{6}Z-predeploy$ ]] \
    || fail "S10_2F_BACKUP_PATH_INVALID"
}

require_clean_commit() {
  local repository="$1" expected="$2" code="$3"
  [ "$(git -C "$repository" rev-parse HEAD)" = "$expected" ] || fail "${code}_COMMIT_DRIFT"
  [ -z "$(git -C "$repository" status --porcelain)" ] || fail "${code}_WORKTREE_DIRTY"
}

require_service_health() {
  local unit active restarts
  for unit in "${SERVICES[@]}"; do
    active="$(systemctl show "$unit" -p ActiveState --value)"
    restarts="$(systemctl show "$unit" -p NRestarts --value)"
    [ "$active" = active ] && [ "$restarts" = 0 ] || fail "S10_2F_SERVICE_RED"
  done
  for unit in "${TIMERS[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] || fail "S10_2F_TIMER_RED"
    [ "$(systemctl is-enabled "$unit")" = enabled ] || fail "S10_2F_TIMER_RED"
  done
}

require_acquisition_state() {
  APPLICATION_ROOT="$APPLICATION_ROOT" DATABASE_DSN="$DATABASE_DSN" ACQUISITION_BASELINE="$ACQUISITION_BASELINE" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["DATABASE_DSN"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    row = connection.execute(
        "SELECT wms_real_acquisition_ready, real_acquisition_baseline_start "
        "FROM commercial_s10_2d_runtime_control WHERE singleton"
    ).fetchone()
if row is None or row[0] is not True or row[1] is None:
    raise SystemExit(2)
value = row[1].isoformat().replace("+00:00", "Z")
if value != os.environ["ACQUISITION_BASELINE"]:
    raise SystemExit(2)
PY
}

preflight() {
  local source_application="$1" source_control="$2"
  require_clean_commit "$APPLICATION_ROOT" "$source_application" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$source_control" CONTROL
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
  DESTINATION="$destination" DATABASE_DSN="$DATABASE_DSN" \
    "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["DATABASE_DSN"]).read_text(encoding="utf-8").strip()
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
Path(os.environ["DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

backup() {
  local backup_path="$1" source_application="$2" source_control="$3"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S10_2F_BACKUP_EXISTS"
  install -d -o root -g root -m 0700 "$backup_path"
  git -C "$APPLICATION_ROOT" bundle create "$backup_path/application.bundle" HEAD
  git -C "$CONTROL_ROOT" bundle create "$backup_path/control.bundle" HEAD
  git -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null
  git -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null
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
  chmod -R go-rwx "$backup_path"
  printf '{"ok":true,"safe_code":"S10_2F_BACKUP_GREEN","path":"%s"}\n' "$backup_path"
}

restore_source() {
  local backup_path="$1" source_application="$2" source_control="$3"
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  git -C "$APPLICATION_ROOT" switch --detach "$source_application" >/dev/null || return 1
  git -C "$CONTROL_ROOT" switch --detach "$source_control" >/dev/null || return 1
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
  require_clean_commit "$APPLICATION_ROOT" "$source_application" APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$source_control" CONTROL
  require_service_health
  require_acquisition_state || return 1
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/)" = 200 ] || return 1
  [ "$(curl -fsS -o /dev/null -w '%{http_code}' https://wantmeseen.com/health)" = 200 ] || return 1
  [ "$(curl -sS -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] || return 1
}

install_state() {
  local temporary started_at
  temporary="$(mktemp "${STATE_ROOT}/.wms-traffic-quality.XXXXXX")"
  printf '{}\n' > "$temporary"
  chown chatops:chatops "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$QUALITY_STATE"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
  temporary="$(mktemp "${STATE_ROOT}/.s10-2f-changeset.XXXXXX")"
  STARTED_AT="$started_at" ACQUISITION_BASELINE="$ACQUISITION_BASELINE" \
    /usr/bin/python3 - <<'PY' > "$temporary"
import json
import os
print(json.dumps({
    "version": "S10_2F",
    "started_at": os.environ["STARTED_AT"],
    "acquisition_baseline_start": os.environ["ACQUISITION_BASELINE"],
    "measurement_semantics": "HUMAN_LIKE_BROWSER_NAVIGATION_V1",
}, sort_keys=True, separators=(",", ":")))
PY
  chown chatops:chatops "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$CHANGESET_STATE"
}

verify_target() {
  local target_application="$1" target_control="$2"
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
  git -C "$APPLICATION_ROOT" fetch origin main >/dev/null
  git -C "$CONTROL_ROOT" fetch origin control-main >/dev/null
  [ "$(git -C "$APPLICATION_ROOT" rev-parse origin/main)" = "$target_application" ] \
    || fail "S10_2F_APPLICATION_REMOTE_DRIFT"
  [ "$(git -C "$CONTROL_ROOT" rev-parse origin/control-main)" = "$target_control" ] \
    || fail "S10_2F_CONTROL_REMOTE_DRIFT"
  git -C "$APPLICATION_ROOT" cat-file -e "${target_application}^{commit}" || fail "S10_2F_APPLICATION_TARGET_MISSING"
  git -C "$CONTROL_ROOT" cat-file -e "${target_control}^{commit}" || fail "S10_2F_CONTROL_TARGET_MISSING"
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
  git -C "$APPLICATION_ROOT" switch --detach "$target_application" >/dev/null
  git -C "$CONTROL_ROOT" switch --detach "$target_control" >/dev/null
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/tu1nz-adult-public-s10-wms.service" /etc/systemd/system/tu1nz-adult-public-s10-wms.service
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/tu1nz-adult-public-s10-health.service" /etc/systemd/system/tu1nz-adult-public-s10-health.service
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_health.py" /usr/local/bin/tu1nz_adult_public_s10_1_health.py
  install_state
  systemctl daemon-reload
  systemctl restart "$WMS_SERVICE"
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
