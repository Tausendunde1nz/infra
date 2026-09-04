#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly OLD_TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly NEW_TOKEN_PATH="/etc/tu1nz/adult-commercial-s10-2b-telegram.token"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"
readonly BACKUP_SCRIPT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_backup.sh"

readonly SOURCE_SHA="deeb38c30427066989eb85e1c115d2aeccf140cf"
readonly SOURCE_TREE="3619e7dc557b49c632efa713bb0bc4214fd83fca"
readonly TARGET_SHA="f9747088a31ec6c671e82de24e293ebdec99f717"
readonly TARGET_TREE="7defedef032f6af38bbce0165eb6c2bdec327df7"
readonly APPLICATION_POST_MERGE_CI="33809025595"
readonly OLD_BOT_ID="8622690874"
readonly NEW_BOT_ID="8861935205"
readonly CHANNEL="@WantMeSeen"

readonly PROTECTED_S7_SHA="f4e2b473905f6c82afe2ad6473989604e47f26eff70356db74da6fd49af50214"
readonly SOURCE_S8_LANDING_SHA="ecf9fc7908e0e2fc0208b9af27c5670df3463b34dcab213659ce410111af149e"
readonly TARGET_S8_LANDING_SHA="f8b7215b35d7d871cbc775f5b35c0469dfb047a29c1cf56789373a70dad76469"
readonly SOURCE_S8_CONTRACT_SHA="cea242a0c749f5e10b15c527248a60a9c429ad7a3f3d655ca0a71e61d7ff6193"
readonly TARGET_S8_CONTRACT_SHA="7879bf2ddb503d4b16d5095773166bbeb6d7ffc507f18da5502394c8c7a71d55"
readonly SOURCE_S8_COPY_SHA="6da055fa206ae3705c07051901cdc6e5d7ff3c83e0afe1568e2f24cc00f70e09"
readonly TARGET_S8_COPY_SHA="35050d02636630c23b7c97ae0184945b4587695f9a121e908f5f638bd668bd01"
readonly S9_CONTRACT_SHA="274677854b3067cf970f103fc3f541f31e4244df017f9bbcaa0da0c707aa2bf5"
readonly SOURCE_S10_CONTRACT_SHA="dfdd3a5f6e90ce25e96ff6d4f8f895bb473d3d0bb9f072b7959be2a006c7b28b"
readonly TARGET_S10_CONTRACT_SHA="675fdb138014b06094549183a55f916829a0ba5a8fb6c999039278ded1fe5698"
readonly SOURCE_S10_COPY_SHA="7b0f8e286894a3ad1b5f014cb140db4a672564277bd66ad456965baf4b22b9c2"
readonly TARGET_S10_COPY_SHA="f995929dd9fe037fcc469e2c0573607f1d90fc757a76df89ef51d0f59c899fdc"

readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly S10_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly NGINX_SERVICE="nginx.service"
readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)
readonly RETIRED_S8_HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly WORKERS=(
  tu1nz-adult-public-s8-health.service
  tu1nz-adult-public-s8-probe.service
  tu1nz-adult-public-s9-audience.service
  tu1nz-adult-public-s9-nurture.service
  tu1nz-adult-public-s9-report.service
  tu1nz-adult-public-s9-health.service
  tu1nz-adult-public-s10-health.service
)
readonly UNIT_FILES=(
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s8-health.service
  tu1nz-adult-public-s8-probe.service
  tu1nz-adult-public-s9-audience.service
  tu1nz-adult-public-s9-nurture.service
  tu1nz-adult-public-s9-health.service
)

fail() {
  printf 'S10_2B_PUBLIC_TELEGRAM_CONTROL_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

unit_value() {
  systemctl show "$1" -p "$2" --value 2>/dev/null || true
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_control() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
  [[ "$2" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"
  [ -d "$CONTROL_ROOT/.git" ] && [ ! -L "$CONTROL_ROOT" ] || fail "CONTROL_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] || fail "CONTROL_DIRTY"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$1" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$2" ] || fail "CONTROL_TREE_MISMATCH"
}

require_application_clean() {
  [ -d "$APPLICATION_ROOT/.git" ] && [ ! -L "$APPLICATION_ROOT" ] || fail "APPLICATION_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1)" ] || fail "APPLICATION_DIRTY"
}

require_application_state() {
  require_application_clean
  case "$(git_value "$APPLICATION_ROOT" HEAD):$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" in
    "$SOURCE_SHA:$SOURCE_TREE"|"$TARGET_SHA:$TARGET_TREE") ;;
    *) fail "APPLICATION_BASELINE_UNEXPECTED" ;;
  esac
}

require_application_source() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$SOURCE_SHA" ] || fail "APPLICATION_SOURCE_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "APPLICATION_SOURCE_TREE_MISMATCH"
}

require_application_target() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
}

require_paths_unshared() {
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$APPLICATION_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$CONTROL_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "CONTROL_PATH_CONTAINER_MOUNTED"
  fi
}

require_secret_metadata() {
  local path
  for path in "$DATABASE_DSN_PATH" "$OLD_TOKEN_PATH" "$NEW_TOKEN_PATH"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "CREDENTIAL_PATH_UNSAFE"
    [ "$(stat -c '%U:%G' "$path")" = "root:root" ] || fail "CREDENTIAL_OWNER_DRIFT"
    [ "$(stat -c '%a' "$path")" = "600" ] || fail "CREDENTIAL_MODE_DRIFT"
    [ "$(stat -c '%h' "$path")" = "1" ] || fail "CREDENTIAL_LINK_DRIFT"
  done
}

require_service_green() {
  [ "$(unit_value "$1" ActiveState)" = "active" ] || fail "$2_NOT_ACTIVE"
  [ "$(unit_value "$1" NRestarts)" = "0" ] || fail "$2_RESTARTED"
}

timer_has_future() {
  local realtime monotonic
  realtime="$(unit_value "$1" NextElapseUSecRealtime)"
  monotonic="$(unit_value "$1" NextElapseUSecMonotonic)"
  [ -n "$realtime" ] && [ "$realtime" != "0" ] && [ "$realtime" != "infinity" ] && return 0
  [ -n "$monotonic" ] && [ "$monotonic" != "0" ] && [ "$monotonic" != "infinity" ]
}

require_timers_green() {
  local timer
  for timer in "${TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = "enabled" ] || fail "TIMER_NOT_ENABLED"
    [ "$(unit_value "$timer" ActiveState)" = "active" ] || fail "TIMER_NOT_ACTIVE"
    [ "$(unit_value "$timer" SubState)" = "waiting" ] || fail "TIMER_NOT_WAITING"
    timer_has_future "$timer" || fail "TIMER_FUTURE_RUN_MISSING"
  done
}

require_s8_health_timer_retired() {
  [ "$(systemctl is-enabled "$RETIRED_S8_HEALTH_TIMER" 2>/dev/null || true)" = "disabled" ] \
    || fail "S8_HEALTH_TIMER_NOT_RETIRED"
  [ "$(unit_value "$RETIRED_S8_HEALTH_TIMER" ActiveState)" = "inactive" ] \
    || fail "S8_HEALTH_TIMER_UNEXPECTEDLY_ACTIVE"
  [ "$(unit_value "$RETIRED_S8_HEALTH_TIMER" SubState)" = "dead" ] \
    || fail "S8_HEALTH_TIMER_UNEXPECTED_SUBSTATE"
  cmp -s "$CONTROL_ROOT/systemd/$RETIRED_S8_HEALTH_TIMER" \
    "/etc/systemd/system/$RETIRED_S8_HEALTH_TIMER" \
    || fail "S8_HEALTH_TIMER_UNIT_DRIFT"
}

require_adult_runtime_closed() {
  local unit
  for unit in \
    tu1nz-adult-commercial-s0.service \
    tu1nz-adult-commercial-s3.service \
    tu1nz-adult-commercial-s3-s3-1.service \
    tu1nz-adult-commercial-s4.service
  do
    case "$(unit_value "$unit" ActiveState)" in
      inactive|failed|"") ;;
      *) fail "ADULT_RUNTIME_NOT_CLOSED" ;;
    esac
  done
}

require_public_green() {
  require_service_green "$S7_SERVICE" "S7"
  require_service_green "$S8_LANDING_SERVICE" "S8_LANDING"
  require_service_green "$S8_SERVICE" "S8_TELEGRAM"
  require_service_green "$S10_SERVICE" "S10_WMS"
  require_service_green "$NGINX_SERVICE" "NGINX"
  require_s8_health_timer_retired
  require_timers_green
  require_adult_runtime_closed
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/health \
    | /usr/bin/python3 -c 'import json,sys; p=json.load(sys.stdin); keys=("adult_content","media_intake","identity_documents","real_avs","payments","external_publishing","controlled_beta","production"); valid=p.get("ok") is True and p.get("brand")=="Want Me Seen" and p.get("mode")=="SFW_PUBLIC_EARLY_ACCESS" and all(p.get(k) is False for k in keys); sys.exit(0 if valid else 2)' \
    || fail "PUBLIC_HEALTH_RED"
}

require_hash() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "$3_PATH_UNSAFE"
  [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ] || fail "$3_DRIFT"
}

require_source_configuration() {
  require_hash /etc/tu1nz/adult-commercial-s7-public.json "$PROTECTED_S7_SHA" "S7_PROTECTED_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-landing.json "$SOURCE_S8_LANDING_SHA" "S8_LANDING_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-public-telegram.json "$SOURCE_S8_CONTRACT_SHA" "S8_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-copy.json "$SOURCE_S8_COPY_SHA" "S8_COPY"
  require_hash /etc/tu1nz/adult-commercial-s9-growth.json "$S9_CONTRACT_SHA" "S9_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms.json "$SOURCE_S10_CONTRACT_SHA" "S10_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-copy.json "$SOURCE_S10_COPY_SHA" "S10_COPY"
}

require_target_configuration() {
  require_hash /etc/tu1nz/adult-commercial-s7-public.json "$PROTECTED_S7_SHA" "S7_PROTECTED_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-landing.json "$TARGET_S8_LANDING_SHA" "S8_LANDING_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-public-telegram.json "$TARGET_S8_CONTRACT_SHA" "S8_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-copy.json "$TARGET_S8_COPY_SHA" "S8_COPY"
  require_hash /etc/tu1nz/adult-commercial-s9-growth.json "$S9_CONTRACT_SHA" "S9_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms.json "$TARGET_S10_CONTRACT_SHA" "S10_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-copy.json "$TARGET_S10_COPY_SHA" "S10_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json "$TARGET_S8_CONTRACT_SHA" "S10_BOT_IDENTITY"
}

require_product_boundary() {
  /usr/bin/python3 - \
    /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    /etc/tu1nz/adult-commercial-s9-growth.json \
    /etc/tu1nz/adult-commercial-s10-wms.json <<'PY' || fail "PRODUCT_BOUNDARY_RED"
import json
import sys

s8, s9, s10 = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
checks = (
    all(s8[name] is False for name in (
        "invite_automation_enabled", "adult_content", "media_intake",
        "real_submissions", "real_avs", "payments", "publishing",
        "controlled_beta", "production_adult_workflow",
    )),
    all(s9[name] is False for name in (
        "x_enabled", "reddit_enabled", "invite_automation_enabled",
        "controlled_beta", "adult_content", "media_intake", "real_avs",
        "payments", "external_adult_publishing", "production_adult_workflow",
    )),
    all(s10[name] is False for name in (
        "adult_content", "media_intake", "identity_documents", "real_avs",
        "payments", "external_publishing", "creator_activation",
        "controlled_beta", "production",
    )),
    s8.get("bot_username") == "wantmeseenbot",
    s8.get("expected_bot_id") == 8861935205,
    s10.get("expected_future_bot_username") == "wantmeseenbot",
    s10.get("expected_future_channel") == "@WantMeSeen",
    s10.get("channel_rename_enabled") is True,
    s10.get("telegram_bot_rename_enabled") is True,
)
raise SystemExit(0 if all(checks) else 2)
PY
}

require_backup() {
  case "$1" in
    "${BACKUP_PREFIX}"[0-9]*-pre-s10-2b-public-telegram) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
  "$BACKUP_SCRIPT" verify-existing "$1" >/dev/null || fail "BACKUP_VERIFY_RED"
  [ "$(sed -n '1p' "$1/application-provenance.txt")" = "$SOURCE_SHA" ] || fail "BACKUP_APPLICATION_SHA_MISMATCH"
  [ "$(sed -n '2p' "$1/application-provenance.txt")" = "$SOURCE_TREE" ] || fail "BACKUP_APPLICATION_TREE_MISMATCH"
}

fetch_target() {
  runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin main
  [ "$(git_value "$APPLICATION_ROOT" origin/main)" = "$TARGET_SHA" ] || fail "REMOTE_TARGET_SHA_MISMATCH"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" cat-file -e "${TARGET_SHA}^{commit}" || fail "TARGET_COMMIT_MISSING"
  [ "$(git_value "$APPLICATION_ROOT" "${TARGET_SHA}^{tree}")" = "$TARGET_TREE" ] || fail "TARGET_TREE_MISMATCH"
}

verify_channel_admin() {
  /usr/bin/python3 - "$1" "$2" "$CHANNEL" <<'PY' || return 1
import json
import sys
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

token_path, expected_id, channel = sys.argv[1:]
try:
    token = open(token_path, encoding="utf-8").read().strip()
    if not token or any(ch.isspace() for ch in token):
        raise ValueError

    def telegram(method, data):
        url = f"https://api.telegram.org/bot{token}/{method}"
        request = Request(url, data=urlencode(data).encode(), method="POST")
        with build_opener(ProxyHandler({}), RejectRedirect(), HTTPSHandler()).open(request, timeout=10) as response:
            payload = json.load(response)
        return payload.get("result", {}) if payload.get("ok") is True else {}

    chat = telegram("getChat", {"chat_id": channel})
    member = telegram("getChatMember", {"chat_id": channel, "user_id": expected_id})

    # Bot API channel promotions default can_restrict_members to true for
    # backward compatibility even though Telegram's broadcast-channel admin UI
    # exposes no independent switch. Accept that compatibility boolean only for
    # the exact broadcast channel; every exposed subscriber and promotion right
    # remains fail-closed below.
    valid = (
        chat.get("type") == "channel"
        and member.get("status") in {"administrator", "creator"}
        and member.get("can_change_info") is True
        and member.get("can_post_messages") is True
        and member.get("can_edit_messages") is True
        and type(member.get("can_restrict_members")) is bool
        and all(member.get(name, False) is False for name in (
            "is_anonymous", "can_delete_messages", "can_invite_users",
            "can_manage_video_chats",
            "can_promote_members", "can_post_stories", "can_edit_stories",
            "can_delete_stories", "can_manage_direct_messages",
        ))
    )
except Exception:
    valid = False
raise SystemExit(0 if valid else 2)
PY
}

require_cloud_rollback_ready() {
  verify_channel_admin "$NEW_TOKEN_PATH" "$NEW_BOT_ID" || fail "NEW_BOT_CHANNEL_PERMISSION_MISSING"
  verify_channel_admin "$OLD_TOKEN_PATH" "$OLD_BOT_ID" || fail "OLD_BOT_FALLBACK_PERMISSION_MISSING"
}

database_floor() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
    --command="SELECT (SELECT count(*) FROM commercial_s8_users) || ':' || (SELECT count(*) FROM commercial_s8_processed_updates) || ':' || (SELECT count(*) FROM commercial_s8_analytics_events);" \
    | tr -d '[:space:]'
}

require_database_continuity() {
  /usr/bin/python3 - "$1" "$2" <<'PY' || fail "DATABASE_CONTINUITY_RED"
import sys
before = tuple(int(value) for value in sys.argv[1].split(":"))
after = tuple(int(value) for value in sys.argv[2].split(":"))
raise SystemExit(0 if len(before) == 3 and len(after) == 3 and all(a >= b for a, b in zip(after, before)) else 2)
PY
}

install_target_configuration() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-landing.sfw.json" /etc/tu1nz/adult-commercial-s8-landing.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s9-growth.sfw.json" /etc/tu1nz/adult-commercial-s9-growth.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-public.sfw.json" /etc/tu1nz/adult-commercial-s10-wms.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json
}

install_target_health_script() {
  install -o root -g root -m 0755 \
    "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" \
    /usr/local/bin/tu1nz_adult_public_s8_health.py
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" \
    /usr/local/bin/tu1nz_adult_public_s8_health.py || fail "INSTALLED_HEALTH_SCRIPT_DRIFT"
}

install_target_units() {
  local unit
  for unit in "${UNIT_FILES[@]}"; do
    install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$unit" "/etc/systemd/system/$unit"
  done
  install -d -o root -g root -m 0755 /etc/systemd/system/tu1nz-adult-public-s9-audience.service.d
  install -o root -g root -m 0644 \
    "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-audience.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-audience.service.d/s10-wms.conf
  install -d -o root -g root -m 0755 /etc/systemd/system/tu1nz-adult-public-s9-health.service.d
  install -o root -g root -m 0644 \
    "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf
  systemctl daemon-reload
  systemd-analyze verify \
    /etc/systemd/system/tu1nz-adult-public-s8-telegram.service \
    /etc/systemd/system/tu1nz-adult-public-s8-health.service \
    /etc/systemd/system/tu1nz-adult-public-s8-probe.service \
    /etc/systemd/system/tu1nz-adult-public-s9-audience.service \
    /etc/systemd/system/tu1nz-adult-public-s9-nurture.service \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service \
    >/dev/null || fail "SYSTEMD_VERIFY_RED"
}

require_target_units() {
  local unit
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" \
    /usr/local/bin/tu1nz_adult_public_s8_health.py || fail "INSTALLED_HEALTH_SCRIPT_DRIFT"
  for unit in "${UNIT_FILES[@]}"; do
    cmp -s "$CONTROL_ROOT/systemd/$unit" "/etc/systemd/system/$unit" || fail "INSTALLED_UNIT_DRIFT"
  done
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-audience.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-audience.service.d/s10-wms.conf || fail "AUDIENCE_DROPIN_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf || fail "HEALTH_DROPIN_DRIFT"
}

brand_action() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" -m tu1nz_public_s8.brand_migration \
    "$1" \
    --bot-contract "$2" \
    --brand-contract /etc/tu1nz/adult-commercial-s10-wms.json \
    --brand-copy /etc/tu1nz/adult-commercial-s10-wms-copy.json \
    --telegram-token "$3"
}

configure_new_identity() {
  brand_action --configure-bot /etc/tu1nz/adult-commercial-s8-public-telegram.json "$NEW_TOKEN_PATH" >/dev/null \
    || fail "NEW_BOT_PROFILE_CONFIGURATION_RED"
  brand_action --configure-channel /etc/tu1nz/adult-commercial-s8-public-telegram.json "$NEW_TOKEN_PATH" >/dev/null \
    || fail "NEW_CHANNEL_CONFIGURATION_RED"
}

verify_new_identity() {
  brand_action --verify-bot /etc/tu1nz/adult-commercial-s8-public-telegram.json "$NEW_TOKEN_PATH" >/dev/null \
    || fail "NEW_BOT_PROFILE_VERIFY_RED"
  brand_action --verify-channel /etc/tu1nz/adult-commercial-s8-public-telegram.json "$NEW_TOKEN_PATH" >/dev/null \
    || fail "NEW_CHANNEL_VERIFY_RED"
}

restore_fallback_channel() {
  local old_contract
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || return 1
  old_contract="$(mktemp /run/tu1nz-s10-2b-old-contract.XXXXXX)" || return 1
  chmod 0600 "$old_contract"
  if ! runuser -u chatops -- git -C "$APPLICATION_ROOT" show \
    "$SOURCE_SHA:config/commercial-s8-public-telegram-early-access.sfw.json" >"$old_contract"; then
    rm -f -- "$old_contract"
    return 1
  fi
  if ! brand_action --configure-channel "$old_contract" "$OLD_TOKEN_PATH" >/dev/null; then
    rm -f -- "$old_contract"
    return 1
  fi
  rm -f -- "$old_contract"
}

quiesce() {
  systemctl stop "${TIMERS[@]}" || fail "TIMER_QUIESCE_RED"
  systemctl stop "${WORKERS[@]}" || fail "WORKER_QUIESCE_RED"
  systemctl stop "$S7_SERVICE" "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" \
    || fail "PUBLIC_SERVICE_QUIESCE_RED"
}

start_public() {
  systemctl reset-failed "$S7_SERVICE" "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" >/dev/null || true
  systemctl start "$S7_SERVICE" "$S8_LANDING_SERVICE" "$S10_SERVICE" || fail "PUBLIC_HTTP_START_RED"
  local attempt
  for attempt in {1..30}; do
    if curl --fail --silent --show-error --output /dev/null --max-time 2 http://127.0.0.1:18110/health; then
      break
    fi
    [ "$attempt" -lt 30 ] || fail "S10_WMS_READINESS_RED"
    sleep 1
  done
  systemctl start "$S8_SERVICE" || fail "S8_TELEGRAM_START_RED"
  systemctl start "${TIMERS[@]}" || fail "TIMER_RESUME_RED"
  systemctl reset-failed tu1nz-adult-public-s8-health.service tu1nz-adult-public-s9-health.service tu1nz-adult-public-s10-health.service >/dev/null || true
  systemctl start tu1nz-adult-public-s8-health.service || fail "S8_HEALTH_RED"
  systemctl start tu1nz-adult-public-s9-health.service || fail "S9_HEALTH_RED"
  systemctl start tu1nz-adult-public-s10-health.service || fail "S10_HEALTH_RED"
  [ "$(unit_value tu1nz-adult-public-s8-health.service Result)" = "success" ] || fail "S8_HEALTH_RESULT_RED"
  [ "$(unit_value tu1nz-adult-public-s9-health.service Result)" = "success" ] || fail "S9_HEALTH_RESULT_RED"
  [ "$(unit_value tu1nz-adult-public-s10-health.service Result)" = "success" ] || fail "S10_HEALTH_RESULT_RED"
}

restore_technical_state() {
  local backup="$1"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  tar -xpf "$backup/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup/s10-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup/public-units-before.tar" -C /etc/systemd/system
  tar -xpf "$backup/s10-units-before.tar" -C /etc/systemd/system
  systemctl daemon-reload
}

require_new_deep_link() {
  local redirect
  redirect="$(curl --head --silent --show-error --max-time 10 --output /dev/null --write-out '%{redirect_url}' \
    'https://wantmeseen.com/go/telegram?campaign=s10_wms_launch&source=landing')"
  case "$redirect" in
    https://t.me/wantmeseenbot?start=*) ;;
    *) fail "PUBLIC_TELEGRAM_DEEP_LINK_RED" ;;
  esac
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_paths_unshared
  require_application_state
  require_secret_metadata
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$SOURCE_SHA" ]; then
    require_source_configuration
  else
    require_target_configuration
  fi
  require_public_green
  fetch_target
  require_cloud_rollback_ready
  printf '{"ok":true,"safe_code":"S10_2B_PUBLIC_TELEGRAM_PREFLIGHT_GREEN","application_ci":%s,"channel":"%s","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$APPLICATION_POST_MERGE_CI" "$CHANNEL"
}

verify_target() {
  require_root
  require_control "$1" "$2"
  require_paths_unshared
  require_application_target
  require_secret_metadata
  require_target_configuration
  require_target_units
  require_product_boundary
  verify_new_identity
  require_public_green
  require_new_deep_link
  printf '{"ok":true,"safe_code":"S10_2B_PUBLIC_TELEGRAM_GREEN","channel":"%s","bot":"@wantmeseenbot","bot_id":%s,"legacy_bot":"FALLBACK_ONLY","database_migration":false,"adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$CHANNEL" "$NEW_BOT_ID"
}

verify_source() {
  require_application_source
  require_secret_metadata
  require_source_configuration
  require_public_green
}

rollback() {
  local cloud_restored=true
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  quiesce
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ]; then
    restore_fallback_channel || cloud_restored=false
  fi
  restore_technical_state "$3"
  start_public
  verify_source
  [ "$cloud_restored" = true ] || fail "ROLLBACK_CHANNEL_RESTORE_RED"
  printf '{"ok":true,"safe_code":"S10_2B_ROLLBACK_TO_S10_2_GREEN","database_restored":false,"channel":"%s","bot":"@tu1nz_adult_early_access_bot"}\n' "$CHANNEL"
}

deploy() {
  local before after
  require_root
  preflight "$1" "$2" >/dev/null
  require_application_source
  require_backup "$3"
  before="$(database_floor)"
  if ! (
    # Install the source-compatible health guard first so every later failure
    # can execute the versioned rollback health gate successfully.
    install_target_health_script
    quiesce
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
    install_target_configuration
    install_target_units
    require_target_configuration
    require_product_boundary
    configure_new_identity
    start_public
    verify_target "$1" "$2" >/dev/null
  ); then
    rollback "$1" "$2" "$3" >/dev/null || fail "DEPLOY_AND_ROLLBACK_RED"
    fail "DEPLOY_ROLLED_BACK"
  fi
  after="$(database_floor)"
  require_database_continuity "$before" "$after"
  printf '{"ok":true,"safe_code":"S10_2B_PUBLIC_TELEGRAM_DEPLOYED","backup":"%s","channel":"%s","bot":"@wantmeseenbot","bot_id":%s,"database_migration":false}\n' \
    "$(basename "$3")" "$CHANNEL" "$NEW_BOT_ID"
}

case "${1:-}" in
  preflight) [ "$#" -eq 3 ] || fail "USAGE"; preflight "$2" "$3" ;;
  deploy) [ "$#" -eq 4 ] || fail "USAGE"; deploy "$2" "$3" "$4" ;;
  verify) [ "$#" -eq 3 ] || fail "USAGE"; verify_target "$2" "$3" ;;
  rollback) [ "$#" -eq 4 ] || fail "USAGE"; rollback "$2" "$3" "$4" ;;
  *) fail "USAGE" ;;
esac
