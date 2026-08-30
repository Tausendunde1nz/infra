#!/usr/bin/env bash
set -euo pipefail

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly SERVICE="tu1nz-adult-public-s7.service"
readonly HEALTH_SERVICE="tu1nz-adult-public-s7-health.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s7-health.timer"
readonly BASELINE_SHA="99a179990ae67aeab420eccef984915ae2aebfbd"
readonly BASELINE_TREE="ecd67fa84fbd1248dd2b7b29a6cafba7bdc0d527"
readonly PREVIOUS_TARGET_SHA="79a9d88d51ba5747cdfb0b6400a61506d82ccc6b"
readonly PREVIOUS_TARGET_TREE="f3ae60f4c690a3b023db4e5953ca14050a9272b3"
readonly TARGET_SHA="935518614d4e9e6ce302c75bf81d6e5ca2a4f1d4"
readonly TARGET_TREE="29679c2029d40eefce7dbd3857c5cf4e1f129013"
readonly MIGRATION_CHAIN_SHA="7db9b568bdb3439aa1d0d05990afb6c8230b750d710e9319f20e1a15cddd1a51"
readonly MIGRATION_SHA="a71350ae6d9ce544558ced38b0b032b28ac9885d0e3b4b9855e4c2db88d8b021"
readonly CONTRACT_SHA="f4e2b473905f6c82afe2ad6473989604e47f26eff70356db74da6fd49af50214"
readonly UNIT_SHA="ad098f7533716f2e26f9aff500bc82a7b98c939b5b021a442f37d778edc7b692"
readonly HEALTH_SCRIPT_SHA="66a895b6b4e3ae662970e561a638431d220aa6f4b94421a7c0082284114ea3a9"
readonly NGINX_ACTIVE_SHA="ddf14f890cf9d991b631371102663e8984f9586e3a2ee2afb7dace3b30a27843"
readonly NGINX_DISABLED_SHA="312cdc7ea9181d79382e95eb6531b1b5e5c5f00131f99a5b84379eb4182b875e"
readonly NGINX_PREVIOUS_ACTIVE_SHA="e1a4c514f895d6b137e857adbe4b7811ca8915e389949ea24d14dbf96ccf6974"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s7-public-soft-launch/"

fail() {
  printf 'S7_PUBLIC_CONTROL_RED %s\n' "$1" >&2
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
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s7_backup.sh" verify-existing "$1" >/dev/null
}

require_other_adult_services_stopped() {
  local unit
  for unit in tu1nz-adult-commercial-s0.service tu1nz-adult-commercial-s3.service; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = "inactive" ] || fail "OTHER_ADULT_SERVICE_ACTIVE"
    [ "$(systemctl show "$unit" -p MainPID --value)" = "0" ] || fail "OTHER_ADULT_PROCESS_PRESENT"
  done
}

require_s7_inactive_or_absent() {
  local loaded
  loaded="$(systemctl show "$SERVICE" -p LoadState --value 2>/dev/null || true)"
  [ "$loaded" = "not-found" ] && return
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "S7_SERVICE_ALREADY_ACTIVE"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" = "0" ] || fail "S7_PROCESS_PRESENT"
}

require_application_clean() {
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
}

require_application_baseline_or_target() {
  local sha tree
  sha="$(git_value "$APPLICATION_ROOT" HEAD)"
  tree="$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
  if [ "$sha" = "$BASELINE_SHA" ] && [ "$tree" = "$BASELINE_TREE" ]; then
    return
  fi
  if [ "$sha" = "$PREVIOUS_TARGET_SHA" ] && [ "$tree" = "$PREVIOUS_TARGET_TREE" ]; then
    return
  fi
  [ "$sha" = "$TARGET_SHA" ] && [ "$tree" = "$TARGET_TREE" ] || fail "APPLICATION_RELEASE_UNEXPECTED"
}

require_source_hashes() {
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0021_commercial_s7_public_soft_launch.sql" | awk '{print $1}')" = "$MIGRATION_SHA" ] || fail "MIGRATION_0021_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s7-public-launch.sfw.json" | awk '{print $1}')" = "$CONTRACT_SHA" ] || fail "S7_CONTRACT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/systemd/$SERVICE" | awk '{print $1}')" = "$UNIT_SHA" ] || fail "S7_UNIT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/scripts/tu1nz_adult_public_s7_health.py" | awk '{print $1}')" = "$HEALTH_SCRIPT_SHA" ] || fail "S7_HEALTH_SCRIPT_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/nginx/current/tu1nz.conf" | awk '{print $1}')" = "$NGINX_ACTIVE_SHA" ] || fail "S7_NGINX_ACTIVE_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/nginx/current/tu1nz.s7-disabled.conf" | awk '{print $1}')" = "$NGINX_DISABLED_SHA" ] || fail "S7_NGINX_DISABLED_DRIFT"
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" - <<'PY'
from pathlib import Path
from tu1nz_commercial_s3.migrations import inspect_migration_chain

evidence = inspect_migration_chain(Path("/opt/tu1nz_repos/adult-publishing-core/migrations"))
if evidence.chain_sha256 != "7db9b568bdb3439aa1d0d05990afb6c8230b750d710e9319f20e1a15cddd1a51":
    raise SystemExit(2)
PY
}

s7_table_count() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" --command="SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('commercial_s7_waitlist','commercial_s7_analytics_events','commercial_s7_content_templates','commercial_s7_channel_state','commercial_s7_publication_queue');" \
    | tr -d '[:space:]'
}

require_port_free() {
  if ss -H -ltn 'sport = :8095' | grep -q .; then
    fail "S7_PORT_ALREADY_BOUND"
  fi
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_other_adult_services_stopped
  require_s7_inactive_or_absent
  require_application_clean
  require_application_baseline_or_target
  require_port_free
  [ "$(systemctl show nginx.service -p ActiveState --value)" = "active" ] || fail "NGINX_NOT_ACTIVE"
  [ "$(systemctl show postgresql.service -p ActiveState --value)" = "active" ] || fail "POSTGRES_NOT_ACTIVE"
  [ "$(findmnt -rn -o TARGET / | head -n 1)" = "/" ] || fail "ROOT_FILESYSTEM_UNRESOLVED"
  printf '{"ok":true,"safe_code":"S7_PUBLIC_PREFLIGHT_GREEN"}\n'
}

install_release() {
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" != "$TARGET_SHA" ]; then
    require_application_baseline_or_target
    runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin main
    [ "$(git_value "$APPLICATION_ROOT" origin/main)" = "$TARGET_SHA" ] || fail "REMOTE_TARGET_SHA_MISMATCH"
    runuser -u chatops -- git -C "$APPLICATION_ROOT" merge --ff-only "$TARGET_SHA"
  fi
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_application_clean
  require_source_hashes
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
    --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
}

install_database() {
  local count
  count="$(s7_table_count)"
  if [ "$count" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
      <"$APPLICATION_ROOT/migrations/0021_commercial_s7_public_soft_launch.sql" >/dev/null
  elif [ "$count" != "5" ]; then
    fail "MIGRATION_0021_PARTIAL_STATE"
  fi
}

install_static_files() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s7-public-launch.sfw.json" /etc/tu1nz/adult-commercial-s7-public.json
  if [ ! -e /etc/tu1nz/adult-commercial-s7-form.secret ]; then
    umask 0077
    openssl rand -base64 48 >/etc/tu1nz/adult-commercial-s7-form.secret
  fi
  [ ! -L /etc/tu1nz/adult-commercial-s7-form.secret ] || fail "FORM_SECRET_SYMLINK"
  chmod 0600 /etc/tu1nz/adult-commercial-s7-form.secret
  chown root:root /etc/tu1nz/adult-commercial-s7-form.secret
  install -o root -g root -m 0600 /etc/tu1nz/adult-commercial-s3.postgres-dsn /etc/tu1nz/adult-commercial-s7-database.dsn
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$SERVICE" "/etc/systemd/system/$SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_SERVICE"
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$HEALTH_TIMER" "/etc/systemd/system/$HEALTH_TIMER"
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s7_health.py" /usr/local/bin/tu1nz_adult_public_s7_health.py
  systemd-analyze verify "/etc/systemd/system/$SERVICE" "/etc/systemd/system/$HEALTH_SERVICE" "/etc/systemd/system/$HEALTH_TIMER"
}

install_active_nginx() {
  install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/tu1nz.conf" /etc/nginx/sites-available/tu1nz.conf
  install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/tu1nz.conf" /etc/nginx/sites-enabled/tu1nz.conf
  nginx -t >/dev/null
  systemctl reload nginx.service
}

local_health() {
  local attempt
  for attempt in $(seq 1 20); do
    if /usr/local/bin/tu1nz_adult_public_s7_health.py >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  return 1
}

external_health() {
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert p["components"]["WAITLIST"] == "READY"; assert p["components"]["X"] == "DISABLED_FOR_NOW"; assert not any(p["forbidden_capabilities"].values())'
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/ \
    | grep -F 'Upload once.' >/dev/null
  curl --fail --silent --show-error --head --max-time 10 https://tu1nz.com/adult/ \
    | grep -F '200' >/dev/null
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/robots.txt \
    | grep -F 'Sitemap: https://tu1nz.com/sitemap.xml' >/dev/null
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/sitemap.xml \
    | grep -F '<loc>https://tu1nz.com/adult/</loc>' >/dev/null
}

rollback_live_refresh() {
  local backup="$1"
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ]; then
    runuser -u chatops -- git -C "$APPLICATION_ROOT" update-ref refs/heads/main "$PREVIOUS_TARGET_SHA" "$TARGET_SHA"
    runuser -u chatops -- git -C "$APPLICATION_ROOT" restore --source="$PREVIOUS_TARGET_SHA" --staged --worktree -- .
    runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/pip" install \
      --disable-pip-version-check --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  fi
  install -o root -g root -m 0644 "$backup/nginx-available-before.conf" /etc/nginx/sites-available/tu1nz.conf
  install -o root -g root -m 0644 "$backup/nginx-enabled-before.conf" /etc/nginx/sites-enabled/tu1nz.conf
  nginx -t >/dev/null 2>&1 && systemctl reload nginx.service || true
  systemctl start "$SERVICE" >/dev/null 2>&1 || true
  printf 'S7_PUBLIC_CONTROL_RED LIVE_REFRESH_ABORTED\n' >&2
  exit 2
}

live_refresh() {
  require_root
  require_control "$1" "$2"
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s7_backup.sh" verify-live-existing "$3" >/dev/null
  require_other_adult_services_stopped
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$PREVIOUS_TARGET_SHA" ] || fail "LIVE_REFRESH_SOURCE_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$PREVIOUS_TARGET_TREE" ] || fail "LIVE_REFRESH_SOURCE_TREE_MISMATCH"
  [ "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" symbolic-ref -q HEAD)" = "refs/heads/main" ] || fail "APPLICATION_BRANCH_NOT_MAIN"
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "active" ] || fail "S7_SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" != "0" ] || fail "S7_SERVICE_PROCESS_MISSING"
  [ "$(systemctl show "$HEALTH_TIMER" -p ActiveState --value)" = "active" ] || fail "S7_HEALTH_TIMER_NOT_ACTIVE"
  [ "$(sha256sum /etc/nginx/sites-enabled/tu1nz.conf | awk '{print $1}')" = "$NGINX_PREVIOUS_ACTIVE_SHA" ] || fail "LIVE_REFRESH_NGINX_SOURCE_DRIFT"
  local_health || fail "LIVE_REFRESH_INITIAL_HEALTH_RED"

  install_release
  if ! install_active_nginx; then
    rollback_live_refresh "$3"
  fi
  if ! systemctl restart "$SERVICE"; then
    rollback_live_refresh "$3"
  fi
  if ! local_health || ! external_health; then
    rollback_live_refresh "$3"
  fi
  if ! systemctl start "$HEALTH_SERVICE"; then
    rollback_live_refresh "$3"
  fi
  printf '{"ok":true,"safe_code":"S7_PUBLIC_LIVE_REFRESH_GREEN","head":true,"root_discovery":true}\n'
}

abort_public_deploy() {
  local backup="$1"
  systemctl disable --now "$HEALTH_TIMER" "$SERVICE" >/dev/null 2>&1 || true
  install -o root -g root -m 0644 "$backup/nginx-available-before.conf" /etc/nginx/sites-available/tu1nz.conf
  install -o root -g root -m 0644 "$backup/nginx-enabled-before.conf" /etc/nginx/sites-enabled/tu1nz.conf
  nginx -t >/dev/null 2>&1 && systemctl reload nginx.service || true
  printf 'S7_PUBLIC_CONTROL_RED PUBLIC_DEPLOYMENT_ABORTED\n' >&2
  exit 2
}

deploy() {
  preflight "$1" "$2" "$3" >/dev/null
  install_release
  install_database
  install_static_files
  systemctl daemon-reload
  if ! systemctl start "$SERVICE"; then
    abort_public_deploy "$3"
  fi
  if ! local_health; then
    abort_public_deploy "$3"
  fi
  if ! install_active_nginx; then
    abort_public_deploy "$3"
  fi
  if ! external_health; then
    abort_public_deploy "$3"
  fi
  if ! systemctl enable "$SERVICE" >/dev/null; then
    abort_public_deploy "$3"
  fi
  if ! systemctl enable --now "$HEALTH_TIMER" >/dev/null; then
    abort_public_deploy "$3"
  fi
  if ! systemctl start "$HEALTH_SERVICE"; then
    abort_public_deploy "$3"
  fi
  printf '{"ok":true,"safe_code":"S7_PUBLIC_SOFT_LAUNCH_GREEN","adult_content":false,"payments":false,"x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW"}\n'
}

verify() {
  require_root
  require_control "$1" "$2"
  require_other_adult_services_stopped
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  require_source_hashes
  [ "$(s7_table_count)" = "5" ] || fail "MIGRATION_0021_NOT_INSTALLED"
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "active" ] || fail "S7_SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" != "0" ] || fail "S7_SERVICE_PROCESS_MISSING"
  [ "$(systemctl is-enabled "$SERVICE")" = "enabled" ] || fail "S7_SERVICE_NOT_ENABLED"
  [ "$(systemctl is-enabled "$HEALTH_TIMER")" = "enabled" ] || fail "S7_HEALTH_TIMER_NOT_ENABLED"
  [ "$(sha256sum /etc/nginx/sites-enabled/tu1nz.conf | awk '{print $1}')" = "$NGINX_ACTIVE_SHA" ] || fail "INSTALLED_NGINX_DRIFT"
  [ "$(sha256sum /etc/nginx/sites-available/tu1nz.conf | awk '{print $1}')" = "$NGINX_ACTIVE_SHA" ] || fail "AVAILABLE_NGINX_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s7-public.json | awk '{print $1}')" = "$CONTRACT_SHA" ] || fail "INSTALLED_CONTRACT_DRIFT"
  local_health || fail "LOCAL_HEALTH_RED"
  external_health || fail "EXTERNAL_HEALTH_RED"
  printf '{"ok":true,"safe_code":"S7_PUBLIC_VERIFY_GREEN","waitlist":"READY","telegram":"DISABLED_EXPECTED","x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW"}\n'
}

kill_switch() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  systemctl disable --now "$HEALTH_TIMER" "$SERVICE" >/dev/null 2>&1 || true
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s7-public-launch.disabled.json" /etc/tu1nz/adult-commercial-s7-public.json
  install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/tu1nz.s7-disabled.conf" /etc/nginx/sites-available/tu1nz.conf
  install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/tu1nz.s7-disabled.conf" /etc/nginx/sites-enabled/tu1nz.conf
  nginx -t >/dev/null
  systemctl reload nginx.service
  printf '{"ok":true,"safe_code":"S7_PUBLIC_KILL_SWITCH_CLOSED"}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 4 ] || fail "USAGE"
    preflight "$2" "$3" "$4"
    ;;
  deploy)
    [ "$#" -eq 4 ] || fail "USAGE"
    deploy "$2" "$3" "$4"
    ;;
  verify)
    [ "$#" -eq 3 ] || fail "USAGE"
    verify "$2" "$3"
    ;;
  live-refresh)
    [ "$#" -eq 4 ] || fail "USAGE"
    live_refresh "$2" "$3" "$4"
    ;;
  kill-switch)
    [ "$#" -eq 4 ] || fail "USAGE"
    kill_switch "$2" "$3" "$4"
    ;;
  *) fail "USAGE" ;;
esac
