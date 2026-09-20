#!/usr/bin/env bash
set -Eeuo pipefail

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly SOURCE_APPLICATION_COMMIT="1d0dbb88603be49ea172178b77d86451036035a1"
readonly SOURCE_APPLICATION_TREE="49f82e23ba16f06ddc27ef13e0b3f3643bc9da3e"
readonly SOURCE_CONTROL_COMMIT="5f0b5878888a5d48317e28ce75a6f0f552d6a419"
readonly SOURCE_CONTROL_TREE="6aebbeed942cd235a292dc8fcafcc29b6e2dab80"
readonly TARGET_APPLICATION_COMMIT="ecc73e2557b3f5bf643fa89d06bda57a9c4d26cc"
readonly TARGET_APPLICATION_TREE="1acc0300ca099bd57f2455753c0a2700867a68d5"
readonly FINAL_CONTROL_TAG="s11-1-latency-provenance-slo-freeze-r3"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly S8_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-telegram.service"
readonly S8_HEALTH_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-health.service"
readonly S8_HEALTH_SCRIPT="/usr/local/bin/tu1nz_adult_public_s8_health.py"
readonly SLO_READER="/usr/local/bin/tu1nz_adult_public_s11_latency_slo.py"
readonly RECONCILIATION="/etc/tu1nz/adult-commercial-s11-1-latency-provenance-reconciliation.json"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly SERVICES=(
  tu1nz-adult-public-s7.service
  tu1nz-adult-public-s8-landing.service
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s10-wms.service
  nginx.service
)

fail() {
  printf '{"ok":false,"safe_code":"%s"}\n' "$1" >&2
  return 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "S11_1_ROOT_REQUIRED"
}

acquire_lock() {
  exec 9> /run/tu1nz-adult-public-s11-1-control.lock
  flock -n 9 || fail "S11_1_CONTROL_ALREADY_RUNNING"
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S11_1_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-1-latency-provenance/[0-9]{8}T[0-9]{6}Z-predeploy$ ]] \
    || fail "S11_1_BACKUP_PATH_INVALID"
}

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
}

remote_ref() {
  git_chatops "$1" ls-remote origin "$2" | awk 'NR == 1 {print $1}'
}

require_clean_commit() {
  local repository="$1" commit="$2" tree="$3" code="$4"
  [ "$(git_chatops "$repository" rev-parse HEAD)" = "$commit" ] || fail "S11_1_${code}_COMMIT_DRIFT"
  [ "$(git_chatops "$repository" rev-parse 'HEAD^{tree}')" = "$tree" ] || fail "S11_1_${code}_TREE_DRIFT"
  [ -z "$(git_chatops "$repository" status --porcelain)" ] || fail "S11_1_${code}_WORKTREE_DIRTY"
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

require_acquisition_and_s11_off() {
  local state
  state="$(database_scalar \
    "SELECT wms_real_acquisition_ready::text||'|'||to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')||'|'||enabled::text||'|'||(live_start IS NULL)::text FROM commercial_s10_2d_runtime_control CROSS JOIN commercial_s11_runtime_control WHERE commercial_s10_2d_runtime_control.singleton AND commercial_s11_runtime_control.singleton;")" \
    || return 1
  [ "$state" = "true|${ACQUISITION_BASELINE}|false|true" ]
}

require_services_and_public() {
  local unit code
  for unit in "${SERVICES[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] || fail "S11_1_SERVICE_RED"
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] || fail "S11_1_SERVICE_RESTART_RED"
  done
  for path in / /privacy /terms /imprint; do
    code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${path}")"
    [ "$code" = 200 ] || fail "S11_1_PUBLIC_ENDPOINT_RED"
  done
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] \
    || fail "S11_1_LEGACY_REDIRECT_RED"
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys; p=json.load(sys.stdin); raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities", {}).values()) else 1)' \
    >/dev/null || fail "S11_1_PUBLIC_HEALTH_RED"
}

require_source() {
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" SOURCE_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" SOURCE_CONTROL
  require_acquisition_and_s11_off || fail "S11_1_PRODUCT_STATE_RED"
  require_services_and_public
}

require_remote_target() {
  local target_control="$1"
  [ "$(remote_ref "$APPLICATION_ROOT" refs/heads/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_1_REMOTE_APPLICATION_DRIFT"
  [ "$(remote_ref "$CONTROL_ROOT" "refs/tags/${FINAL_CONTROL_TAG}^{}")" = "$target_control" ] \
    || fail "S11_1_REMOTE_FREEZE_DRIFT"
}

preflight() {
  local target_control="$1" backup_path="$2"
  require_root
  require_sha "$target_control"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S11_1_BACKUP_ALREADY_EXISTS"
  require_source
  require_remote_target "$target_control"
  printf '{"ok":true,"safe_code":"S11_1_PREFLIGHT_GREEN"}\n'
}

backup_runtime() {
  local backup_path="$1"
  install -d -o root -g root -m 0700 "$backup_path"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null
  install -m 0600 "$S8_UNIT" "$backup_path/s8-telegram.service"
  install -m 0600 "$S8_HEALTH_UNIT" "$backup_path/s8-health.service"
  install -m 0600 "$S8_HEALTH_SCRIPT" "$backup_path/s8-health.py"
  [ -e "$SLO_READER" ] && install -m 0600 "$SLO_READER" "$backup_path/s11-latency-slo.py" \
    || : > "$backup_path/SLO_READER_ABSENT"
  [ -e "$RECONCILIATION" ] && install -m 0600 "$RECONCILIATION" "$backup_path/reconciliation.json" \
    || : > "$backup_path/RECONCILIATION_ABSENT"
  printf 'application_commit=%s\napplication_tree=%s\ncontrol_commit=%s\ncontrol_tree=%s\nacquisition_baseline=%s\n' \
    "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" \
    "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" "$ACQUISITION_BASELINE" \
    > "$backup_path/provenance.txt"
  systemctl show "${SERVICES[@]}" > "$backup_path/runtime-manifest.txt"
  database_scalar "SELECT json_build_object('s11_enabled',enabled,'s11_live_start_present',live_start IS NOT NULL,'acquisition_active',wms_real_acquisition_ready,'baseline',real_acquisition_baseline_start,'latency_samples',count(sample_id))::text FROM commercial_s11_runtime_control CROSS JOIN commercial_s10_2d_runtime_control LEFT JOIN commercial_s10_2d_latency_samples ON true WHERE commercial_s11_runtime_control.singleton AND commercial_s10_2d_runtime_control.singleton GROUP BY enabled,live_start,wms_real_acquisition_ready,real_acquisition_baseline_start;" \
    > "$backup_path/database-aggregate.json"
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
}

require_backup() {
  local backup_path="$1"
  [ -d "$backup_path" ] && [ ! -L "$backup_path" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] || return 1
  grep -Fqx "application_commit=${SOURCE_APPLICATION_COMMIT}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "control_commit=${SOURCE_CONTROL_COMMIT}" "$backup_path/provenance.txt" || return 1
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
}

fetch_target() {
  local target_control="$1"
  git_chatops "$APPLICATION_ROOT" fetch --quiet --no-tags origin main
  git_chatops "$CONTROL_ROOT" fetch --quiet --no-tags origin control-main \
    "refs/tags/${FINAL_CONTROL_TAG}:refs/tags/${FINAL_CONTROL_TAG}"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse origin/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_1_FETCHED_APPLICATION_DRIFT"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse "${TARGET_APPLICATION_COMMIT}^{tree}")" = "$TARGET_APPLICATION_TREE" ] \
    || fail "S11_1_TARGET_APPLICATION_TREE_DRIFT"
  [ "$(git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${FINAL_CONTROL_TAG}^{commit}")" = "$target_control" ] \
    || fail "S11_1_FETCHED_FREEZE_DRIFT"
  git_chatops "$CONTROL_ROOT" merge-base --is-ancestor "$target_control" origin/control-main \
    || fail "S11_1_CONTROL_NOT_CANONICAL"
}

install_from_git() {
  git_chatops "$1" show "$2:$3" | install -o root -g root -m "$4" /dev/stdin "$5"
}

apply_provenance_migration() {
  local installed
  installed="$(database_scalar \
    "SELECT count(*)=3 FROM information_schema.columns WHERE table_schema='public' AND table_name='commercial_s10_2d_latency_samples' AND column_name IN ('sample_type','recorded_at','interaction_path');")"
  if [ "$installed" = true ]; then
    return 0
  fi
  runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" \
    < "$APPLICATION_ROOT/migrations/0032_commercial_s11_1_latency_provenance.sql" \
    >/dev/null
}

wait_runtime() {
  local attempt
  for attempt in {1..60}; do
    if [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = active ] \
      && [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = 0 ] \
      && [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='s10-2d-r3-5' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds';")" = 1 ]; then
      return 0
    fi
    sleep 1
  done
  fail "S11_1_RUNTIME_READY_TIMEOUT"
}

verify_target() {
  local target_control="$1" state
  require_clean_commit "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE" TARGET_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$target_control" \
    "$(git_chatops "$CONTROL_ROOT" rev-parse "${target_control}^{tree}")" TARGET_CONTROL
  require_acquisition_and_s11_off || fail "S11_1_PRODUCT_STATE_RED"
  [ "$(database_scalar "SELECT count(*)=3 FROM information_schema.columns WHERE table_schema='public' AND table_name='commercial_s10_2d_latency_samples' AND column_name IN ('sample_type','recorded_at','interaction_path');")" = true ] \
    || fail "S11_1_SCHEMA_RED"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s8-telegram-s11-1-provenance.service" "$S8_UNIT" \
    || fail "S11_1_S8_UNIT_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s8-health-s11-1-provenance.service" "$S8_HEALTH_UNIT" \
    || fail "S11_1_HEALTH_UNIT_DRIFT"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s11_latency_slo.py" "$SLO_READER" \
    || fail "S11_1_READER_DRIFT"
  cmp -s "$CONTROL_ROOT/evidence/commercial-s11-1-latency-provenance-reconciliation.json" "$RECONCILIATION" \
    || fail "S11_1_RECONCILIATION_DRIFT"
  state="$("$APPLICATION_ROOT/.venv/bin/python" "$SLO_READER" \
    --dsn-file "$DATABASE_DSN" --reconciliation "$RECONCILIATION" \
    --profile REAL_USER_DIRECT_LATENCY | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
  case "$state" in GREEN|RED|INSUFFICIENT_EVIDENCE) ;; *) fail "S11_1_GATE_STATE_INVALID" ;; esac
  require_services_and_public
  printf '{"ok":true,"safe_code":"S11_1_PROVENANCE_RUNTIME_GREEN","slo_state":"%s"}\n' "$state"
}

restore_source() {
  local backup_path="$1"
  require_backup "$backup_path" || return 1
  git_chatops "$APPLICATION_ROOT" switch --detach "$SOURCE_APPLICATION_COMMIT" >/dev/null || return 1
  git_chatops "$CONTROL_ROOT" switch --detach "$SOURCE_CONTROL_COMMIT" >/dev/null || return 1
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null || return 1
  install -o root -g root -m 0644 "$backup_path/s8-telegram.service" "$S8_UNIT" || return 1
  install -o root -g root -m 0644 "$backup_path/s8-health.service" "$S8_HEALTH_UNIT" || return 1
  install -o root -g root -m 0755 "$backup_path/s8-health.py" "$S8_HEALTH_SCRIPT" || return 1
  if [ -f "$backup_path/SLO_READER_ABSENT" ]; then rm -f -- "$SLO_READER"; else install -o root -g root -m 0755 "$backup_path/s11-latency-slo.py" "$SLO_READER"; fi
  if [ -f "$backup_path/RECONCILIATION_ABSENT" ]; then rm -f -- "$RECONCILIATION"; else install -o root -g root -m 0644 "$backup_path/reconciliation.json" "$RECONCILIATION"; fi
  systemctl daemon-reload || return 1
  systemctl restart "$S8_SERVICE" || return 1
  wait_runtime || return 1
  require_source || return 1
}

deploy_contract() {
  local target_control="$1" backup_path="$2"
  acquire_lock
  preflight "$target_control" "$backup_path"
  backup_runtime "$backup_path"
  require_backup "$backup_path" || fail "S11_1_BACKUP_VERIFY_RED"
  S11_1_ROLLBACK_ARMED=true
  S11_1_BACKUP_PATH="$backup_path"
  trap 'deployment_error' ERR
  fetch_target "$target_control"
  git_chatops "$APPLICATION_ROOT" switch --detach "$TARGET_APPLICATION_COMMIT" >/dev/null
  git_chatops "$CONTROL_ROOT" switch --detach "$target_control" >/dev/null
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null
  install_from_git "$CONTROL_ROOT" "$target_control" \
    systemd/tu1nz-adult-public-s8-telegram-s11-1-provenance.service 0644 "$S8_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    systemd/tu1nz-adult-public-s8-health-s11-1-provenance.service 0644 "$S8_HEALTH_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    scripts/tu1nz_adult_public_s8_health.py 0755 "$S8_HEALTH_SCRIPT"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    scripts/tu1nz_adult_public_s11_latency_slo.py 0755 "$SLO_READER"
  install_from_git "$CONTROL_ROOT" "$target_control" \
    evidence/commercial-s11-1-latency-provenance-reconciliation.json 0644 "$RECONCILIATION"
  apply_provenance_migration
  require_acquisition_and_s11_off || fail "S11_1_PRODUCT_STATE_RED"
  systemctl daemon-reload
  systemctl restart "$S8_SERVICE"
  wait_runtime
  systemctl start tu1nz-adult-public-s8-health.service
  [ "$(systemctl show tu1nz-adult-public-s8-health.service -p Result --value)" = success ] \
    || fail "S11_1_S8_HEALTH_RED"
  verify_target "$target_control"
  trap - ERR
  S11_1_ROLLBACK_ARMED=false
}

deployment_error() {
  local status=$?
  trap - ERR
  if [ "${S11_1_ROLLBACK_ARMED:-false}" = true ] && restore_source "$S11_1_BACKUP_PATH"; then
    printf '{"ok":false,"safe_code":"S11_1_DEPLOYMENT_ROLLED_BACK"}\n' >&2
  else
    printf '{"ok":false,"safe_code":"S11_1_DEPLOYMENT_ROLLBACK_RED"}\n' >&2
  fi
  exit "$status"
}

gate() {
  require_root
  "$APPLICATION_ROOT/.venv/bin/python" "$SLO_READER" \
    --dsn-file "$DATABASE_DSN" --reconciliation "$RECONCILIATION" \
    --profile REAL_USER_DIRECT_LATENCY
}

usage() {
  printf 'usage: %s preflight|deploy-contract TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s verify TARGET_CONTROL\n' "$0" >&2
  printf '       %s gate\n' "$0" >&2
  return 2
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 3 ] || usage
    preflight "$2" "$3"
    ;;
  deploy-contract)
    [ "$#" -eq 3 ] || usage
    deploy_contract "$2" "$3"
    ;;
  verify)
    [ "$#" -eq 2 ] || usage
    require_root
    acquire_lock
    verify_target "$2"
    ;;
  gate)
    [ "$#" -eq 1 ] || usage
    gate
    ;;
  *) usage ;;
esac
