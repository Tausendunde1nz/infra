#!/usr/bin/env bash
set -euo pipefail
umask 0077

readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROLLER="$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_control.sh"
readonly BACKUP_TOOL="$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_backup.sh"
readonly APPLICATION_SHA="ef19c7b2a6d0b42cfe55e1e090878f72b29c64c2"
readonly APPLICATION_TREE="250985b5464943b981a7654c39fa256ac7b695b4"
readonly OLD_PROXY_SHA="ddf14f890cf9d991b631371102663e8984f9586e3a2ee2afb7dace3b30a27843"
readonly NEW_PROXY_SHA="65c0bc9d12981a4532d5453c668f8b2f9a4ad32cf5a7a18b8ef4ed3b56a0f062"
readonly ACTIVE_PROXY="/etc/nginx/sites-enabled/tu1nz.conf"
readonly CANDIDATE_PROXY="$CONTROL_ROOT/nginx/current/tu1nz.s8-public.conf"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly LOG="/var/log/tausendunde1nz/commercial-s8-2-public-activation.log"

fail() {
  printf 'S8_PUBLIC_ACTIVATION_RED %s\n' "$1" >&2
  exit 2
}

[ "$#" -eq 2 ] || fail "USAGE"
readonly CONTROL_SHA="$1"
readonly CONTROL_TREE="$2"
[[ "$CONTROL_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
[[ "$CONTROL_TREE" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
readonly BACKUP="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/${timestamp}-pre-public-activation"
activation_attempted=0

exec > >(tee -a "$LOG") 2>&1

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_service_green() {
  local unit="$1"
  [ "$(systemctl show "$unit" -p ActiveState --value)" = "active" ]
  [ "$(systemctl show "$unit" -p MainPID --value)" != "0" ]
  [ "$(systemctl show "$unit" -p NRestarts --value)" = "0" ]
}

s7_green() {
  require_service_green "$S7_SERVICE"
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8095/adult/health \
    | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())'
}

rollback_public_attempt() {
  set +e
  "$CONTROLLER" kill-switch "$CONTROL_SHA" "$CONTROL_TREE" "$BACKUP" >/dev/null 2>&1
  systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" "$LANDING_SERVICE" >/dev/null 2>&1
  install -o root -g root -m 0644 "$BACKUP/nginx-enabled-before.conf" "$ACTIVE_PROXY"
  if nginx -t; then
    systemctl reload nginx.service
  fi
  if s7_green \
    && curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health >/dev/null; then
    printf '{"ok":true,"safe_code":"S8_PUBLIC_ACTIVATION_ROLLBACK_GREEN","data_preserved":true}\n'
  else
    printf '{"ok":false,"safe_code":"S8_PUBLIC_ACTIVATION_ROLLBACK_S7_RED"}\n' >&2
  fi
  set -e
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && [ "$activation_attempted" -eq 1 ] && [ -d "$BACKUP" ]; then
    rollback_public_attempt
  fi
  exit "$status"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
[ "$(git_value "$CONTROL_ROOT" HEAD)" = "$CONTROL_SHA" ] || fail "CONTROL_SHA_MISMATCH"
[ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$CONTROL_TREE" ] || fail "CONTROL_TREE_MISMATCH"
[ -z "$(GIT_OPTIONAL_LOCKS=0 runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] \
  || fail "CONTROL_DIRTY"
[ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$APPLICATION_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
[ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$APPLICATION_TREE" ] \
  || fail "APPLICATION_TREE_MISMATCH"
[ -z "$(GIT_OPTIONAL_LOCKS=0 runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1)" ] \
  || fail "APPLICATION_DIRTY"
require_service_green "$S7_SERVICE" || fail "S7_SERVICE_RED"
require_service_green "$S8_SERVICE" || fail "S8_SERVICE_RED"
require_service_green "$LANDING_SERVICE" || fail "S8_LANDING_RED"
[ "$(systemctl is-enabled "$S8_SERVICE")" = "disabled" ] || fail "S8_ALREADY_ENABLED"
[ "$(systemctl is-enabled "$LANDING_SERVICE")" = "disabled" ] || fail "S8_LANDING_ALREADY_ENABLED"
[ "$(systemctl is-enabled "$HEALTH_TIMER")" = "disabled" ] || fail "S8_TIMER_ALREADY_ENABLED"
[ "$(systemctl show tu1nz-adult-commercial-s0.service -p ActiveState --value)" = "inactive" ] \
  || fail "ADULT_S0_ACTIVE"
[ "$(systemctl show tu1nz-adult-commercial-s3.service -p ActiveState --value)" = "inactive" ] \
  || fail "ADULT_S3_ACTIVE"
current_proxy_sha="$(sha256sum "$ACTIVE_PROXY" | awk '{print $1}')"
case "$current_proxy_sha" in
  "$OLD_PROXY_SHA"|"$NEW_PROXY_SHA") ;;
  *) fail "CURRENT_PROXY_DRIFT" ;;
esac
[ "$(sha256sum "$CANDIDATE_PROXY" | awk '{print $1}')" = "$NEW_PROXY_SHA" ] \
  || fail "CANDIDATE_PROXY_DRIFT"
[ "$(runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
    --dbname=tu1nz_adult_commercial_s3 \
    --command="SELECT public_telegram_early_access_enabled,new_waitlist_joins_enabled,notifications_enabled,invite_automation_enabled FROM commercial_s8_runtime_control WHERE singleton;" \
    | tr -d '[:space:]')" = "f|f|f|f" ] || fail "KILL_SWITCH_NOT_CLOSED"
nginx -t || fail "CURRENT_NGINX_CONFIG_RED"
s7_green || fail "S7_HEALTH_RED"
curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health >/dev/null \
  || fail "EXTERNAL_S7_HEALTH_RED"
printf '{"ok":true,"safe_code":"S8_PUBLIC_ACTIVATION_PRECHECK_GREEN"}\n'

"$BACKUP_TOOL" create "$BACKUP"
"$BACKUP_TOOL" verify-existing "$BACKUP" >/dev/null
printf '{"ok":true,"safe_code":"S8_PUBLIC_ACTIVATION_BACKUP_GREEN","path":"%s"}\n' "$BACKUP"

activation_attempted=1
install -o root -g root -m 0644 "$CANDIDATE_PROXY" "$ACTIVE_PROXY"
[ "$(sha256sum "$ACTIVE_PROXY" | awk '{print $1}')" = "$NEW_PROXY_SHA" ] \
  || fail "INSTALLED_PROXY_DRIFT"
nginx -t || fail "CANDIDATE_NGINX_CONFIG_RED"

"$CONTROLLER" activate-public "$CONTROL_SHA" "$CONTROL_TREE"
"$CONTROLLER" verify "$CONTROL_SHA" "$CONTROL_TREE"

[ "$(sha256sum "$ACTIVE_PROXY" | awk '{print $1}')" = "$NEW_PROXY_SHA" ] \
  || fail "ACTIVE_PROXY_DRIFT"
[ "$(systemctl is-enabled "$S8_SERVICE")" = "enabled" ] || fail "S8_NOT_ENABLED"
[ "$(systemctl is-enabled "$LANDING_SERVICE")" = "enabled" ] || fail "S8_LANDING_NOT_ENABLED"
[ "$(systemctl is-enabled "$HEALTH_TIMER")" = "enabled" ] || fail "S8_TIMER_NOT_ENABLED"
require_service_green "$S7_SERVICE" || fail "S7_POST_ACTIVATION_RED"
require_service_green "$S8_SERVICE" || fail "S8_POST_ACTIVATION_RED"
require_service_green "$LANDING_SERVICE" || fail "S8_LANDING_POST_ACTIVATION_RED"
curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/ \
  | grep -F 'https://t.me/tu1nz_adult_early_access_bot?start=landing_s8_launch' >/dev/null \
  || fail "EXTERNAL_DEEP_LINK_RED"
curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
  | "$APPLICATION_ROOT/.venv/bin/python" -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] is True; assert not any(p["forbidden_capabilities"].values())' \
  || fail "EXTERNAL_S8_HEALTH_RED"
s7_green || fail "S7_FALLBACK_POST_ACTIVATION_RED"

printf '{"ok":true,"safe_code":"S8_PUBLIC_ACTIVATION_AND_VERIFY_GREEN","backup":"%s","adult_content":false,"avs":false,"payments":false,"publishing":false}\n' "$BACKUP"
