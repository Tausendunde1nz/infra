#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s10-2b-telegram.token"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"
readonly BACKUP_SCRIPT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_backup.sh"
readonly HEALTH_GATE_SCRIPT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_health_gate.py"
readonly AGGREGATE_CONTRACT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py"
readonly STATE_RECONCILER="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_state_reconcile.py"

readonly SOURCE_SHA="f9747088a31ec6c671e82de24e293ebdec99f717"
readonly SOURCE_TREE="7defedef032f6af38bbce0165eb6c2bdec327df7"
readonly TARGET_SHA="312db84d5db6d76c9d6bb448459c9404b1dfcbe4"
readonly TARGET_TREE="ac4f8bca1fd796626742a8ef6c6afcdda482fc68"
readonly APPLICATION_POST_MERGE_CI="34057828638"
readonly COMMUNITY="@WantMeSeenCommunity"
readonly CHANNEL="@WantMeSeen"
readonly BOT_ID="8861935205"
readonly TARGET_RELEASE_ID="s10-2d-r3-5"
readonly LEGACY_FAILED_RELEASE_ID="s10-2d-r3-4"

readonly PROTECTED_S7_SHA="f4e2b473905f6c82afe2ad6473989604e47f26eff70356db74da6fd49af50214"
readonly S8_LANDING_SHA="f8b7215b35d7d871cbc775f5b35c0469dfb047a29c1cf56789373a70dad76469"
readonly S9_CONTRACT_SHA="274677854b3067cf970f103fc3f541f31e4244df017f9bbcaa0da0c707aa2bf5"
readonly SOURCE_S8_CONTRACT_SHA="7879bf2ddb503d4b16d5095773166bbeb6d7ffc507f18da5502394c8c7a71d55"
readonly SOURCE_S8_COPY_SHA="35050d02636630c23b7c97ae0184945b4587695f9a121e908f5f638bd668bd01"
readonly SOURCE_S10_CONTRACT_SHA="675fdb138014b06094549183a55f916829a0ba5a8fb6c999039278ded1fe5698"
readonly SOURCE_S10_COPY_SHA="f995929dd9fe037fcc469e2c0573607f1d90fc757a76df89ef51d0f59c899fdc"
readonly TARGET_S8_CONTRACT_SHA="7505ecf4acf3d1a1b5deed6e6ca0c41aa2d7519742494c325341d8428f31ffeb"
readonly TARGET_S8_COPY_SHA="86f7d44796892c96c2f66e3325ffe75648cc2ea46dc73a14278be0a6f89ea743"
readonly TARGET_S10_CONTRACT_SHA="7312a75fa11b6e30e37bd90c30c8b212a20971ea8657facf7a11d785381d96f7"
readonly TARGET_S10_COPY_SHA="0cefe8915b45f175c09cad369f40a09d7665a91c3f84a5ccb52f9812f40989d4"
readonly TARGET_COMMUNITY_SHA="e93b7f67a4963d10028e177d944c068b4444f0c9de5b5802a13f58789a27a586"
readonly TARGET_COMMUNITY_COPY_SHA="8cf0f716ba6f0a751c862f69c65fe639ddc07106929195d2cbe65507d304cb6f"
readonly TARGET_BUSINESS_LOOP_SHA="aaee5878825272c14d41c34e859370bf49b7bd1617851dcafe9cbff2c019a6e6"
readonly MIGRATION_SHA="66eae1c5022e5e005b278984d3b5580928fdd4133a0cfe9653e63957bb933d20"
readonly MIGRATION_DOWN_SHA="e2421a6eb83dc4a8d5af8e2d592f6fb54e45fcf6549c4c85c517c6b5de272ad2"
readonly STABILIZATION_MIGRATION_SHA="9e39223ae7c129355185f2fa48723a4034bfc4a8bb987e448b0d45ac567ed58b"
readonly STABILIZATION_MIGRATION_DOWN_SHA="a1bdec916a607e14e151c237c032d814c78f58eada41b75f16dcccb9a4ff208b"
readonly SOURCE_S8_UNIT_SHA="2a83f8ccb2945315d98191831cc2c0059d14a30122e23f5db149f90ea308deee"
readonly S8_SOURCE_DROPIN="/etc/systemd/system/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf"
readonly SOURCE_S8_DROPIN_SHA="2eaa68ace7a2ed4259be422cb7908eb5994735691c265d20935ca4d354d9565a"
readonly SOURCE_S8_HEALTH_UNIT_SHA="24c6d544bd12a93b8631da8fa017cc50e45432f5c9ca736359fe5f8c304f4d88"
readonly SOURCE_S10_UNIT_SHA="7016f1b110d5b87ec9455d588bf9ca502be419b3b95162a4441fc0d6187a3939"
readonly SOURCE_S10_HEALTH_UNIT_SHA="6fa111959f26a2cea7a37f5251dfe4d130aa4b64bd89963fc220afe366969eb1"
readonly SOURCE_S9_HEALTH_DROPIN_SHA="4d9506b2e9ad1bee5f30f57f50680b77705c0c0e1bdc7e2047483d5f1220d81b"
readonly SOURCE_S8_HEALTH_SCRIPT_SHA="2f3f82209c4c61fb617f74c9a094ab095af5eee2c3007fc19d2b3b68d9e02f4f"
readonly SOURCE_S10_HEALTH_SCRIPT_SHA="84eaae51dd3a208516788b183b2f5ec41609751b126870799fba48d477fc84ea"

readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly S10_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly NGINX_SERVICE="nginx.service"
readonly ROTATE_SERVICE="tu1nz-adult-public-s10-2d-rotate.service"
readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)
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
  tu1nz-adult-public-s10-wms.service
  tu1nz-adult-public-s10-health.service
  "$ROTATE_SERVICE"
)

fail() {
  printf 'S10_2D_COMMUNITY_CONTROL_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

unit_value() {
  systemctl show "$1" -p "$2" --value 2>/dev/null || true
}

database_scalar() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --dbname="$DATABASE" --command="$1" | tr -d '[:space:]'
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
  [ "$(git_value "$APPLICATION_ROOT" HEAD):$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_SHA:$SOURCE_TREE" ] \
    || fail "APPLICATION_SOURCE_MISMATCH"
}

require_application_target() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD):$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_SHA:$TARGET_TREE" ] \
    || fail "APPLICATION_TARGET_MISMATCH"
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
  for path in "$TOKEN_PATH" "$DATABASE_DSN_PATH"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "CREDENTIAL_PATH_UNSAFE"
    [ "$(stat -c '%U:%G' "$path")" = "root:root" ] || fail "CREDENTIAL_OWNER_DRIFT"
    [ "$(stat -c '%a' "$path")" = "600" ] || fail "CREDENTIAL_MODE_DRIFT"
    [ "$(stat -c '%h' "$path")" = "1" ] || fail "CREDENTIAL_LINK_DRIFT"
  done
}

require_hash() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "$3_PATH_UNSAFE"
  [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ] || fail "$3_DRIFT"
}

require_common_configuration() {
  require_hash /etc/tu1nz/adult-commercial-s7-public.json "$PROTECTED_S7_SHA" "S7_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-landing.json "$S8_LANDING_SHA" "S8_LANDING_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s9-growth.json "$S9_CONTRACT_SHA" "S9_CONTRACT"
}

require_source_configuration() {
  require_common_configuration
  require_hash /etc/tu1nz/adult-commercial-s8-public-telegram.json "$SOURCE_S8_CONTRACT_SHA" "S8_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-copy.json "$SOURCE_S8_COPY_SHA" "S8_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-wms.json "$SOURCE_S10_CONTRACT_SHA" "S10_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-copy.json "$SOURCE_S10_COPY_SHA" "S10_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json "$SOURCE_S8_CONTRACT_SHA" "S10_BOT_IDENTITY"
  [ ! -e /etc/tu1nz/adult-commercial-s10-2d-community.json ] || fail "SOURCE_COMMUNITY_CONTRACT_PRESENT"
  [ ! -e /etc/tu1nz/adult-commercial-s10-2d-community-copy.json ] || fail "SOURCE_COMMUNITY_COPY_PRESENT"
}

require_target_configuration() {
  require_common_configuration
  require_hash /etc/tu1nz/adult-commercial-s8-public-telegram.json "$TARGET_S8_CONTRACT_SHA" "S8_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s8-copy.json "$TARGET_S8_COPY_SHA" "S8_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-wms.json "$TARGET_S10_CONTRACT_SHA" "S10_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-copy.json "$TARGET_S10_COPY_SHA" "S10_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json "$TARGET_S8_CONTRACT_SHA" "S10_BOT_IDENTITY"
  require_hash /etc/tu1nz/adult-commercial-s10-2d-community.json "$TARGET_COMMUNITY_SHA" "COMMUNITY_CONTRACT"
  require_hash /etc/tu1nz/adult-commercial-s10-2d-community-copy.json "$TARGET_COMMUNITY_COPY_SHA" "COMMUNITY_COPY"
  require_hash /etc/tu1nz/adult-commercial-s10-business-loop.json "$TARGET_BUSINESS_LOOP_SHA" "BUSINESS_LOOP"
}

require_source_control() {
  require_hash /etc/systemd/system/tu1nz-adult-public-s8-telegram.service "$SOURCE_S8_UNIT_SHA" "SOURCE_S8_UNIT"
  require_hash "$S8_SOURCE_DROPIN" "$SOURCE_S8_DROPIN_SHA" "SOURCE_S8_DROPIN"
  require_hash /etc/systemd/system/tu1nz-adult-public-s8-health.service "$SOURCE_S8_HEALTH_UNIT_SHA" "SOURCE_S8_HEALTH_UNIT"
  require_hash /etc/systemd/system/tu1nz-adult-public-s10-wms.service "$SOURCE_S10_UNIT_SHA" "SOURCE_S10_UNIT"
  require_hash /etc/systemd/system/tu1nz-adult-public-s10-health.service "$SOURCE_S10_HEALTH_UNIT_SHA" "SOURCE_S10_HEALTH_UNIT"
  require_hash /etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf "$SOURCE_S9_HEALTH_DROPIN_SHA" "SOURCE_S9_HEALTH_DROPIN"
  require_hash /usr/local/bin/tu1nz_adult_public_s8_health.py "$SOURCE_S8_HEALTH_SCRIPT_SHA" "SOURCE_S8_HEALTH_SCRIPT"
  require_hash /usr/local/bin/tu1nz_adult_public_s10_1_health.py "$SOURCE_S10_HEALTH_SCRIPT_SHA" "SOURCE_S10_HEALTH_SCRIPT"
  [ ! -e "/etc/systemd/system/$ROTATE_SERVICE" ] || fail "SOURCE_ROTATE_UNIT_PRESENT"
}

require_source_pid1_contract() {
  local dropins effective
  [ "$(unit_value "$S8_SERVICE" FragmentPath)" = "/etc/systemd/system/$S8_SERVICE" ] \
    || fail "SOURCE_S8_FRAGMENT_PATH_RED"
  dropins="$(unit_value "$S8_SERVICE" DropInPaths)"
  case "$dropins" in
    *"$S8_SOURCE_DROPIN"*) ;;
    *) fail "SOURCE_S8_DROPIN_NOT_EFFECTIVE" ;;
  esac
  [ "$(unit_value "$S8_SERVICE" User)" = "chatops" ] || fail "SOURCE_S8_USER_RED"
  [ "$(unit_value "$S8_SERVICE" Group)" = "chatops" ] || fail "SOURCE_S8_GROUP_RED"
  [ "$(unit_value "$S8_SERVICE" WorkingDirectory)" = "$APPLICATION_ROOT" ] \
    || fail "SOURCE_S8_WORKING_DIRECTORY_RED"
  [ -z "$(unit_value "$S8_SERVICE" EnvironmentFiles)" ] || fail "SOURCE_S8_ENVIRONMENT_FILE_PRESENT"
  effective="$(unit_value "$S8_SERVICE" ExecStart)"
  case "$effective" in
    *"$APPLICATION_ROOT/.venv/bin/python -m tu1nz_public_s8.runtime"*) ;;
    *) fail "SOURCE_S8_EXECUTABLE_RED" ;;
  esac
  case "$effective" in
    *--community-contract*|*--community-copy*) fail "SOURCE_PID1_COMMUNITY_CONTRACT_PRESENT" ;;
  esac
}

require_target_pid1_contract() {
  local effective
  [ "$(unit_value "$S8_SERVICE" FragmentPath)" = "/etc/systemd/system/$S8_SERVICE" ] \
    || fail "TARGET_S8_FRAGMENT_PATH_RED"
  [ -z "$(unit_value "$S8_SERVICE" DropInPaths)" ] || fail "TARGET_S8_DROPIN_PRESENT"
  [ "$(unit_value "$S8_SERVICE" User)" = "chatops" ] || fail "TARGET_S8_USER_RED"
  [ "$(unit_value "$S8_SERVICE" Group)" = "chatops" ] || fail "TARGET_S8_GROUP_RED"
  [ "$(unit_value "$S8_SERVICE" WorkingDirectory)" = "$APPLICATION_ROOT" ] \
    || fail "TARGET_S8_WORKING_DIRECTORY_RED"
  [ -z "$(unit_value "$S8_SERVICE" EnvironmentFiles)" ] || fail "TARGET_S8_ENVIRONMENT_FILE_PRESENT"
  effective="$(unit_value "$S8_SERVICE" ExecStart)"
  case "$effective" in
    *"$APPLICATION_ROOT/.venv/bin/tu1nz-public-s8-telegram"*) ;;
    *) fail "TARGET_S8_EXECUTABLE_RED" ;;
  esac
  case "$effective" in
    *"--community-contract /etc/tu1nz/adult-commercial-s10-2d-community.json"*) ;;
    *) fail "TARGET_PID1_COMMUNITY_CONTRACT_MISSING" ;;
  esac
  case "$effective" in
    *"--runtime-release-id $TARGET_RELEASE_ID"*) ;;
    *) fail "TARGET_PID1_RELEASE_BINDING_MISSING" ;;
  esac
  case "$effective" in
    *"--community-copy /etc/tu1nz/adult-commercial-s10-2d-community-copy.json"*) ;;
    *) fail "TARGET_PID1_COMMUNITY_COPY_MISSING" ;;
  esac
}

require_product_boundary() {
  /usr/bin/python3 - \
    /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    /etc/tu1nz/adult-commercial-s10-wms.json \
    /etc/tu1nz/adult-commercial-s10-2d-community.json \
    /etc/tu1nz/adult-commercial-s10-business-loop.json <<'PY' || fail "PRODUCT_BOUNDARY_RED"
import json
import sys
s8, s10, community, loop = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
checks = (
    all(s8[name] is False for name in (
        "invite_automation_enabled", "adult_content", "media_intake",
        "real_submissions", "real_avs", "payments", "publishing",
        "controlled_beta", "production_adult_workflow",
    )),
    all(s10[name] is False for name in (
        "adult_content", "media_intake", "identity_documents", "real_avs",
        "payments", "external_publishing", "creator_activation",
        "controlled_beta", "production",
    )),
    community.get("community_username") == "@WantMeSeenCommunity",
    community.get("community_media_publishing_enabled") is False,
    community.get("community_self_attestation_required") is True,
    community.get("avs_required") is True,
    all(loop[name] is False for name in (
        "adult_media", "real_avs", "payments", "external_publishing",
        "controlled_beta", "production", "autonomous_task_generation",
    )),
)
raise SystemExit(0 if all(checks) else 2)
PY
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
  local timer attempt all_waiting
  for attempt in {1..90}; do
    all_waiting=1
    for timer in "${TIMERS[@]}"; do
      [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = "enabled" ] || fail "TIMER_NOT_ENABLED"
      [ "$(unit_value "$timer" ActiveState)" = "active" ] || fail "TIMER_NOT_ACTIVE"
      if [ "$(unit_value "$timer" SubState)" != "waiting" ] || ! timer_has_future "$timer"; then
        all_waiting=0
      fi
    done
    [ "$all_waiting" -eq 1 ] && return 0
    [ "$attempt" -eq 90 ] || sleep 1
  done
  fail "TIMER_NOT_SETTLED"
}

require_adult_runtime_closed() {
  local unit
  for unit in tu1nz-adult-commercial-s0.service tu1nz-adult-commercial-s3.service \
    tu1nz-adult-commercial-s3-s3-1.service tu1nz-adult-commercial-s4.service; do
    case "$(unit_value "$unit" ActiveState)" in inactive|failed|"") ;; *) fail "ADULT_RUNTIME_NOT_CLOSED" ;; esac
  done
}

require_public_endpoints() {
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/health \
    | /usr/bin/python3 -c 'import json,sys; p=json.load(sys.stdin); keys=("adult_content","media_intake","identity_documents","real_avs","payments","external_publishing","controlled_beta","production"); sys.exit(0 if p.get("ok") is True and p.get("brand")=="Want Me Seen" and all(p.get(k) is False for k in keys) else 2)' \
    || fail "PUBLIC_HEALTH_RED"
  [ "$(curl --head --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' https://wantmeseen.de/)" = "308" ] \
    || fail "GERMAN_REDIRECT_RED"
}

require_system_green() {
  require_service_green "$S7_SERVICE" "S7"
  require_service_green "$S8_LANDING_SERVICE" "S8_LANDING"
  require_service_green "$S8_SERVICE" "S8_TELEGRAM"
  require_service_green "$S10_SERVICE" "S10_WMS"
  require_service_green "$NGINX_SERVICE" "NGINX"
  require_timers_green
  require_adult_runtime_closed
  require_public_endpoints
}

fetch_target() {
  runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin main
  [ "$(git_value "$APPLICATION_ROOT" origin/main)" = "$TARGET_SHA" ] || fail "REMOTE_TARGET_SHA_MISMATCH"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" cat-file -e "${TARGET_SHA}^{commit}" || fail "TARGET_COMMIT_MISSING"
  [ "$(git_value "$APPLICATION_ROOT" "${TARGET_SHA}^{tree}")" = "$TARGET_TREE" ] || fail "TARGET_TREE_MISMATCH"
}

target_community_verify() {
  local root status
  root="$(mktemp -d /run/tu1nz-s10-2d-target.XXXXXX)" || return 1
  if ! runuser -u chatops -- git -C "$APPLICATION_ROOT" archive "$TARGET_SHA" | tar -x -C "$root"; then
    find "$root" -depth -delete
    return 1
  fi
  PYTHONPATH="$root/src" "$APPLICATION_ROOT/.venv/bin/python" -m tu1nz_public_s8.community_admin \
    --verify \
    --bot-contract "$root/config/commercial-s8-public-telegram-early-access.sfw.json" \
    --community-contract "$root/config/commercial-s10-2d-community.sfw.json" \
    --community-copy "$root/config/commercial-s10-2d-community-copy.v1.json" \
    --telegram-token "$TOKEN_PATH" >/dev/null
  status=$?
  find "$root" -depth -delete
  return "$status"
}

target_group_capability_verify() {
  local root status
  root="$(mktemp -d /run/tu1nz-s10-2d-capability.XXXXXX)" || return 1
  if ! runuser -u chatops -- git -C "$APPLICATION_ROOT" archive "$TARGET_SHA" | tar -x -C "$root"; then
    find "$root" -depth -delete
    return 1
  fi
  PYTHONPATH="$root/src" "$APPLICATION_ROOT/.venv/bin/python" - "$root" "$TOKEN_PATH" <<'PY'
import sys
from pathlib import Path

from tu1nz_public_s8.contract import S8Contract
from tu1nz_public_s8.runtime import _token
from tu1nz_public_s8.telegram import S8TelegramClient

root = Path(sys.argv[1])
token_path = Path(sys.argv[2])
contract = S8Contract.load(root / "config/commercial-s8-public-telegram-early-access.sfw.json")
client = S8TelegramClient(_token(token_path), contract)
identity = client._call("getMe", {}, 20)
valid = (
    isinstance(identity, dict)
    and identity.get("id") == contract.expected_bot_id
    and identity.get("username") == contract.bot_username
    and identity.get("first_name") == contract.bot_display_name
    and identity.get("can_join_groups") is True
)
raise SystemExit(0 if valid else 2)
PY
  status=$?
  find "$root" -depth -delete
  return "$status"
}

current_community_verify() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" -m tu1nz_public_s8.community_admin \
    --verify \
    --bot-contract /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    --community-contract /etc/tu1nz/adult-commercial-s10-2d-community.json \
    --community-copy /etc/tu1nz/adult-commercial-s10-2d-community-copy.json \
    --telegram-token "$TOKEN_PATH" >/dev/null \
    || fail "COMMUNITY_PROVIDER_VERIFY_RED"
}

require_backup() {
  case "$3" in "${BACKUP_PREFIX}"[0-9]*-pre-s10-2d-community) ;; *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;; esac
  "$BACKUP_SCRIPT" verify-existing "$3" >/dev/null || fail "BACKUP_VERIFY_RED"
  [ "$(sed -n '1p' "$3/application-provenance.txt")" = "$SOURCE_SHA" ] || fail "BACKUP_APPLICATION_SHA_MISMATCH"
  [ "$(sed -n '2p' "$3/application-provenance.txt")" = "$SOURCE_TREE" ] || fail "BACKUP_APPLICATION_TREE_MISMATCH"
  [ "$(sed -n '1p' "$3/control-provenance.txt")" = "$1" ] || fail "BACKUP_CONTROL_SHA_MISMATCH"
  [ "$(sed -n '2p' "$3/control-provenance.txt")" = "$2" ] || fail "BACKUP_CONTROL_TREE_MISMATCH"
}

reconcile_aggregate_for_source() {
  local backup="$1" report
  if ! report="$("$AGGREGATE_CONTRACT" reconcile \
    --backup-dir "$backup" \
    --release-id "$TARGET_RELEASE_ID" \
    --run-id "$(basename "$backup")")"; then
    printf '%s\n' "$report" >&2
    fail "AGGREGATE_RECONCILIATION_RED"
  fi
}

require_source_aggregate_readable() {
  "$AGGREGATE_CONTRACT" verify-source >/dev/null \
    || fail "SOURCE_AGGREGATE_CONTRACT_RED"
  runuser -u chatops -- env PYTHONPATH="$APPLICATION_ROOT/src" \
    "$APPLICATION_ROOT/.venv/bin/python" -c \
    'from pathlib import Path; from tu1nz_growth_s9.counter import AggregateCounter; AggregateCounter(Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json")).snapshot()' \
    >/dev/null || fail "SOURCE_AGGREGATE_READER_RED"
}

require_retained_state_preflight() {
  "$STATE_RECONCILER" preflight --database "$DATABASE" >/dev/null \
    || fail "RETAINED_STATE_PREFLIGHT_RED"
}

migration_state() {
  database_scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='commercial_s10_2d_runtime_control';"
}

stabilization_migration_state() {
  database_scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='commercial_s10_2d_bot_polling_state';"
}

require_acquisition_state_contract() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND ((pre_acquisition_readiness='PENDING' AND NOT wms_real_acquisition_ready) OR (pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready) OR (pre_acquisition_readiness='GREEN' AND wms_real_acquisition_ready AND real_acquisition_baseline_start IS NOT NULL));")" = "1" ] \
    || fail "ACQUISITION_STATE_CONTRACT_RED"
}

run_bound_migration() {
  local path="$1" expected="$2" failure="$3" actual
  actual="$(runuser -u chatops -- git -C "$APPLICATION_ROOT" show "${TARGET_SHA}:$path" | sha256sum | awk '{print $1}')"
  [ "$actual" = "$expected" ] || fail "BOUND_MIGRATION_HASH_DIVERGED"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" show "${TARGET_SHA}:$path" \
    | runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" >/dev/null \
    || fail "$failure"
}

apply_migration() {
  case "$(migration_state)" in
    0) run_bound_migration migrations/0029_commercial_s10_2d_community.sql "$MIGRATION_SHA" "MIGRATION_0029_RED" ;;
    1) ;;
    *) fail "MIGRATION_0029_STATE_DIVERGED" ;;
  esac
  case "$(stabilization_migration_state)" in
    0) run_bound_migration migrations/0030_commercial_s10_2d_r3_5_stabilization.sql "$STABILIZATION_MIGRATION_SHA" "MIGRATION_0030_RED" ;;
    1) ;;
    *) fail "MIGRATION_0030_STATE_DIVERGED" ;;
  esac
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND target_release_id='$TARGET_RELEASE_ID' AND technical_evidence_run_id IS NOT NULL AND cutover_started_at IS NOT NULL;")" = "1" ] \
    || fail "TARGET_RELEASE_EVIDENCE_BINDING_RED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='PENDING' AND NOT wms_real_acquisition_ready AND pre_acquisition_baseline_reason='PRODUCT_SURFACE_CHANGED_BEFORE_ACTIVE_ACQUISITION';")" = "1" ] \
    || fail "PRE_ACQUISITION_BASELINE_RED"
  require_acquisition_state_contract
}

reset_r3_acquisition_state() {
  [ "$(migration_state)" = "1" ] || return 0
  require_acquisition_state_contract
  [ "$(database_scalar "WITH updated AS (UPDATE commercial_s10_2d_runtime_control SET pre_acquisition_readiness='PENDING',wms_real_acquisition_ready=false,real_acquisition_baseline_start=NULL,updated_at=CURRENT_TIMESTAMP WHERE singleton AND NOT wms_real_acquisition_ready RETURNING 1) SELECT count(*) FROM updated;")" = "1" ] \
    || fail "R3_ROLLBACK_ACQUISITION_ACTIVE"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='PENDING' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL;")" = "1" ] \
    || fail "R3_ROLLBACK_STATE_RED"
}

reconcile_failed_cutover_evidence() {
  [ "$(stabilization_migration_state)" = "1" ] || return 0
  runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" >/dev/null <<SQL
BEGIN;
LOCK TABLE commercial_s10_2d_latency_samples IN ACCESS EXCLUSIVE MODE;
DO \$\$
BEGIN
  IF (
    SELECT count(*)
    FROM commercial_s10_2d_runtime_control
    WHERE singleton
      AND target_release_id='$TARGET_RELEASE_ID'
      AND technical_evidence_run_id IS NOT NULL
      AND cutover_started_at IS NOT NULL
  ) <> 1 OR EXISTS (
    SELECT 1
    FROM commercial_s10_2d_latency_samples AS sample
    CROSS JOIN commercial_s10_2d_runtime_control AS control
    WHERE control.singleton
      AND (
        sample.evidence_class <> 'TECHNICAL_ACCEPTANCE'
        OR sample.run_id IS NULL
        OR sample.cutover_started_at IS NULL
        OR (
          sample.release_id='$TARGET_RELEASE_ID'
          AND (
            sample.run_id IS DISTINCT FROM control.technical_evidence_run_id
            OR sample.cutover_started_at IS DISTINCT FROM control.cutover_started_at
          )
        )
        OR sample.release_id NOT IN ('$TARGET_RELEASE_ID','$LEGACY_FAILED_RELEASE_ID')
      )
  ) OR (
    SELECT count(*) FROM commercial_s10_2d_latency_samples
    WHERE release_id='$LEGACY_FAILED_RELEASE_ID'
  ) NOT IN (0,2) OR EXISTS (
    SELECT 1 FROM commercial_s10_2d_latency_samples
    WHERE release_id='$LEGACY_FAILED_RELEASE_ID'
      AND bot_response_latency_ms <> 300000
  ) OR (
    SELECT count(DISTINCT run_id) FROM commercial_s10_2d_latency_samples
    WHERE release_id='$LEGACY_FAILED_RELEASE_ID'
  ) > 1 THEN
    RAISE EXCEPTION 'R3_ROLLBACK_EVIDENCE_OWNERSHIP_RED';
  END IF;
END;
\$\$;
ALTER TABLE commercial_s10_2d_latency_samples DISABLE TRIGGER commercial_s10_2d_latency_append_only;
DELETE FROM commercial_s10_2d_latency_samples
WHERE evidence_class='TECHNICAL_ACCEPTANCE' AND (
  (
    release_id='$TARGET_RELEASE_ID'
    AND run_id=(
      SELECT technical_evidence_run_id
      FROM commercial_s10_2d_runtime_control WHERE singleton
    )
    AND cutover_started_at=(
      SELECT cutover_started_at
      FROM commercial_s10_2d_runtime_control WHERE singleton
    )
  ) OR (
    release_id='$LEGACY_FAILED_RELEASE_ID'
    AND bot_response_latency_ms=300000
  )
);
ALTER TABLE commercial_s10_2d_latency_samples ENABLE TRIGGER commercial_s10_2d_latency_append_only;
DO \$\$
BEGIN
  IF EXISTS (SELECT 1 FROM commercial_s10_2d_latency_samples) THEN
    RAISE EXCEPTION 'R3_ROLLBACK_EVIDENCE_RECONCILIATION_RED';
  END IF;
END;
\$\$;
COMMIT;
SQL
}

rollback_migration_if_unused() {
  [ "$(migration_state)" = "1" ] || return 0
  local rows
  rows="$(database_scalar "SELECT (SELECT count(*) FROM commercial_s10_2d_community_members)+(SELECT count(*) FROM commercial_s10_2d_community_events)+(SELECT count(*) FROM commercial_s10_2d_moderation_events);")"
  if [ "$rows" = "0" ] && [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='PENDING' AND NOT wms_real_acquisition_ready;")" = "1" ]; then
    reconcile_failed_cutover_evidence
    if [ "$(stabilization_migration_state)" = "1" ]; then
      run_bound_migration migrations/0030_commercial_s10_2d_r3_5_stabilization.down.sql "$STABILIZATION_MIGRATION_DOWN_SHA" "ROLLBACK_MIGRATION_0030_RED"
    fi
    run_bound_migration migrations/0029_commercial_s10_2d_community.down.sql "$MIGRATION_DOWN_SHA" "ROLLBACK_MIGRATION_0029_RED"
  fi
}

install_target_configuration() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-public.sfw.json" /etc/tu1nz/adult-commercial-s10-wms.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-2d-community.sfw.json" /etc/tu1nz/adult-commercial-s10-2d-community.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-2d-community-copy.v1.json" /etc/tu1nz/adult-commercial-s10-2d-community-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-business-loop.sfw.json" /etc/tu1nz/adult-commercial-s10-business-loop.json
}

install_target_control() {
  local unit
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" /usr/local/bin/tu1nz_adult_public_s8_health.py
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_health.py" /usr/local/bin/tu1nz_adult_public_s10_1_health.py
  for unit in "${UNIT_FILES[@]}"; do
    install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$unit" "/etc/systemd/system/$unit"
  done
  install -d -o root -g root -m 0755 /etc/systemd/system/tu1nz-adult-public-s9-health.service.d
  install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf
  rm -f -- "$S8_SOURCE_DROPIN"
  systemctl daemon-reload
  systemd-analyze verify "${UNIT_FILES[@]/#//etc/systemd/system/}" \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service >/dev/null \
    || fail "SYSTEMD_VERIFY_RED"
  require_target_pid1_contract
}

configure_current_bot_profile() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" \
    -m tu1nz_public_s8.brand_migration \
    --configure-bot \
    --bot-contract /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    --brand-contract /etc/tu1nz/adult-commercial-s10-wms.json \
    --brand-copy /etc/tu1nz/adult-commercial-s10-wms-copy.json \
    --telegram-token "$TOKEN_PATH"
}

reconcile_source_bot_commands() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" - \
    /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    /etc/tu1nz/adult-commercial-s10-wms-copy.json \
    "$TOKEN_PATH" <<'PY'
import json
import sys
from pathlib import Path

from tu1nz_exposure_s10.copy import ExposureCopy
from tu1nz_public_s8.brand_migration import _commands, verify_bot_profile
from tu1nz_public_s8.contract import S8Contract
from tu1nz_public_s8.runtime import _token
from tu1nz_public_s8.telegram import S8TelegramClient, TelegramApiError

try:
    contract = S8Contract.load(Path(sys.argv[1]))
    copy = ExposureCopy.load(Path(sys.argv[2]))
    client = S8TelegramClient(_token(Path(sys.argv[3])), contract)
    client.verify_local_identity()
    scopes = (("", client.commands()), ("de", _commands("de")), ("en", _commands("en")))
    for language_code, commands in scopes:
        language = {} if not language_code else {"language_code": language_code}
        expected = [{"command": name, "description": description} for name, description in commands]
        if client.call_profile("getMyCommands", language) != expected:
            client.call_profile("setMyCommands", {"commands": expected, **language})
    print(json.dumps(verify_bot_profile(client, contract, copy), sort_keys=True, separators=(",", ":")))
except TelegramApiError as error:
    print(json.dumps({"ok": False, "safe_code": error.safe_code}, sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)
except (OSError, RuntimeError, ValueError):
    print('{"ok":false,"safe_code":"S10_2D_SOURCE_COMMAND_RECONCILE_FAILED"}')
    raise SystemExit(2)
PY
}

verify_current_bot_profile() {
  PYTHONPATH="$APPLICATION_ROOT/src" "$APPLICATION_ROOT/.venv/bin/python" \
    -m tu1nz_public_s8.brand_migration \
    --verify-bot \
    --bot-contract /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    --brand-contract /etc/tu1nz/adult-commercial-s10-wms.json \
    --brand-copy /etc/tu1nz/adult-commercial-s10-wms-copy.json \
    --telegram-token "$TOKEN_PATH"
}

restore_source_bot_profile() {
  local result status=0
  result="$(verify_current_bot_profile)" || status=$?
  [ "$status" -eq 0 ] && return 0
  [ "$status" -eq 2 ] \
    && [ "$result" = '{"ok":false,"safe_code":"S8_TELEGRAM_GROUP_CAPABILITY_MISMATCH"}' ] \
    && return 3
  status=0
  result="$(reconcile_source_bot_commands)" || status=$?
  [ "$status" -eq 0 ] && return 0
  [ "$status" -eq 2 ] \
    && { [ "$result" = '{"ok":false,"safe_code":"S8_TELEGRAM_GROUPS_ENABLED"}' ] \
      || [ "$result" = '{"ok":false,"safe_code":"S8_TELEGRAM_GROUP_CAPABILITY_MISMATCH"}' ]; } \
    && return 3
  fail "SOURCE_BOT_PROFILE_RESTORE_RED"
}

require_target_control() {
  local unit
  [ -x "$HEALTH_GATE_SCRIPT" ] || fail "HEALTH_GATE_SCRIPT_UNAVAILABLE"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s8_health.py" /usr/local/bin/tu1nz_adult_public_s8_health.py || fail "S8_HEALTH_SCRIPT_DRIFT"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_health.py" /usr/local/bin/tu1nz_adult_public_s10_1_health.py || fail "S10_HEALTH_SCRIPT_DRIFT"
  for unit in "${UNIT_FILES[@]}"; do
    cmp -s "$CONTROL_ROOT/systemd/$unit" "/etc/systemd/system/$unit" || fail "INSTALLED_UNIT_DRIFT"
  done
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf || fail "HEALTH_DROPIN_DRIFT"
  [ ! -e "$S8_SOURCE_DROPIN" ] || fail "TARGET_S8_SOURCE_DROPIN_PRESENT"
  require_target_pid1_contract
}

quiesce() {
  systemctl stop "${TIMERS[@]}" || fail "TIMER_QUIESCE_RED"
  systemctl stop "${WORKERS[@]}" || fail "WORKER_QUIESCE_RED"
  case "$(unit_value "$ROTATE_SERVICE" LoadState)" in
    loaded) systemctl stop "$ROTATE_SERVICE" || fail "ROTATE_QUIESCE_RED" ;;
    not-found|"") ;;
    *) fail "ROTATE_UNIT_STATE_UNEXPECTED" ;;
  esac
  systemctl stop "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" || fail "PUBLIC_SERVICE_QUIESCE_RED"
}

run_health_gates() {
  local report safe_code status=0
  report="$("$HEALTH_GATE_SCRIPT")" || status=$?
  if [ "$status" -ne 0 ]; then
    printf 'S10_2D_HEALTH_GATE_EVIDENCE %s\n' "$report" >&2
    safe_code="$(/usr/bin/python3 -c 'import json,sys; value=json.load(sys.stdin).get("safe_code"); assert isinstance(value,str) and value.startswith("HEALTH_GATE_"); print(value)' <<<"$report")" \
      || fail "HEALTH_GATE_EVIDENCE_INVALID"
    fail "$safe_code"
  fi
  /usr/bin/python3 -c 'import json,sys; value=json.load(sys.stdin); assert value.get("ok") is True and value.get("safe_code")=="S10_2D_HEALTH_GATES_GREEN"' <<<"$report" \
    || fail "HEALTH_GATE_EVIDENCE_INVALID"
}

target_wms_health_ready() {
  local report
  report="$(curl --fail --silent --show-error --max-time 2 http://127.0.0.1:18110/health)" || return 1
  /usr/bin/python3 -c '
import json,sys
value=json.load(sys.stdin)
valid=(
    value.get("ok") is True
    and value.get("runtime_release_id")==sys.argv[1]
    and value.get("runtime_contract")=="TARGET_COMMUNITY"
    and value.get("bot_id")==int(sys.argv[2])
    and value.get("community") is True
    and value.get("acquisition_active") is False
)
raise SystemExit(0 if valid else 2)
' "$TARGET_RELEASE_ID" "$BOT_ID" <<<"$report"
}

require_target_wms_listener() {
  local attempt
  for attempt in {1..30}; do
    systemctl is-active --quiet "$S10_SERVICE" || fail "S10_WMS_HEALTH_LISTENER_NOT_STARTED"
    if target_wms_health_ready; then
      return 0
    fi
    [ "$attempt" -lt 30 ] || fail "S10_WMS_HEALTH_CONTRACT_RED"
    sleep 1
  done
}

target_s8_poller_ready() {
  database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE bot_id=$BOT_ID AND release_id='$TARGET_RELEASE_ID' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at IS NOT NULL AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds' AND last_event_path_code='BOT_EVENT_PATH_GREEN';"
}

require_target_s8_poller() {
  local attempt state
  for attempt in {1..45}; do
    systemctl is-active --quiet "$S8_SERVICE" || fail "S8_RUNTIME_PROCESS_NOT_RUNNING"
    state="$(target_s8_poller_ready)" || fail "S8_POLLER_READINESS_DATABASE_RED"
    case "$state" in
      1) return 0 ;;
      0) ;;
      *) fail "S8_POLLER_READINESS_STATE_INVALID" ;;
    esac
    [ "$attempt" -lt 45 ] || fail "S8_POLLER_NOT_READY"
    sleep 1
  done
}

start_target() {
  systemctl reset-failed "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" >/dev/null || true
  systemctl start "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" || fail "PUBLIC_SERVICE_START_RED"
  require_target_wms_listener
  require_target_s8_poller
  systemctl start "${TIMERS[@]}" || fail "TIMER_RESUME_RED"
  run_health_gates
}

rotation_failure_code() {
  local exit_status
  exit_status="$(unit_value "$ROTATE_SERVICE" ExecMainStatus)"
  case "$exit_status" in
    20) printf '%s\n' "PUBLICATION_ROTATION_CONFIG_ERROR" ;;
    21) printf '%s\n' "PUBLICATION_ROTATION_STATE_ERROR" ;;
    22) printf '%s\n' "PUBLICATION_ROTATION_DATABASE_ERROR" ;;
    23) printf '%s\n' "PUBLICATION_ROTATION_PERMISSION_ERROR" ;;
    216|217|226) printf '%s\n' "PUBLICATION_ROTATION_PERMISSION_ERROR" ;;
    24) printf '%s\n' "PUBLICATION_ROTATION_TEMPORARY_EXTERNAL_ERROR" ;;
    25) printf '%s\n' "PUBLICATION_ROTATION_UNEXPECTED_ERROR" ;;
    200) printf '%s\n' "PUBLICATION_ROTATION_WORKDIR_ERROR" ;;
    203) printf '%s\n' "PUBLICATION_ROTATION_EXEC_NOT_FOUND" ;;
    *) printf '%s\n' "PUBLICATION_ROTATION_UNCLASSIFIED_ERROR" ;;
  esac
}

run_rotation() {
  systemctl reset-failed "$ROTATE_SERVICE" >/dev/null || true
  if ! systemctl start "$ROTATE_SERVICE"; then
    fail "$(rotation_failure_code)"
  fi
  [ "$(unit_value "$ROTATE_SERVICE" Result)" = "success" ] || fail "PUBLICATION_ROTATION_RESULT_RED"
  [ "$(unit_value "$ROTATE_SERVICE" ExecMainStatus)" = "0" ] || fail "PUBLICATION_ROTATION_STATUS_RED"
}

restore_technical_state() {
  local backup="$1"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  rm -f -- \
    /etc/tu1nz/adult-commercial-s10-2d-community.json \
    /etc/tu1nz/adult-commercial-s10-2d-community-copy.json \
    /etc/tu1nz/adult-commercial-s10-business-loop.json \
    "/etc/systemd/system/$ROTATE_SERVICE"
  tar -xpf "$backup/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup/s10-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$backup/public-units-before.tar" -C /etc/systemd/system
  tar -xpf "$backup/s10-units-before.tar" -C /etc/systemd/system
  tar -xpf "$backup/s10-runtime-executables-before.tar" -C /usr/local/bin
  systemctl daemon-reload
}

database_floor() {
  database_scalar "SELECT (SELECT count(*) FROM commercial_s8_users)||':'||(SELECT count(*) FROM commercial_s8_processed_updates)||':'||(SELECT count(*) FROM commercial_s8_analytics_events);"
}

require_database_continuity() {
  /usr/bin/python3 - "$1" "$2" <<'PY' || fail "DATABASE_CONTINUITY_RED"
import sys
before = tuple(int(value) for value in sys.argv[1].split(":"))
after = tuple(int(value) for value in sys.argv[2].split(":"))
raise SystemExit(0 if len(before) == len(after) == 3 and all(a >= b for a, b in zip(after, before)) else 2)
PY
}

require_source_green() {
  require_application_source
  require_source_configuration
  require_source_control
  require_source_pid1_contract
  require_source_aggregate_readable
  require_system_green
}

verify_target() {
  require_root
  require_control "$1" "$2"
  require_application_target
  require_secret_metadata
  require_target_configuration
  require_target_control
  [ "$(migration_state)" = "1" ] || fail "MIGRATION_0029_MISSING"
  [ "$(stabilization_migration_state)" = "1" ] || fail "MIGRATION_0030_MISSING"
  require_acquisition_state_contract
  require_product_boundary
  current_community_verify
  require_system_green
  [ "$(curl --head --silent --show-error --max-time 10 --output /dev/null \
      --write-out '%{http_code}|%{redirect_url}' \
      'https://wantmeseen.com/go/community?campaign=s10_wms_launch&source=organic_search')" \
    = "302|https://t.me/WantMeSeenCommunity" ] || fail "PUBLIC_COMMUNITY_CTA_RED"
  printf '{"ok":true,"safe_code":"S10_2D_COMMUNITY_GREEN","application_ci":%s,"community":"%s","channel":"%s","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$APPLICATION_POST_MERGE_CI" "$COMMUNITY" "$CHANNEL"
}

preflight_baseline() {
  require_root
  require_control "$1" "$2"
  require_paths_unshared
  require_application_state
  require_secret_metadata
  require_application_source
  require_source_configuration
  require_source_control
  require_source_pid1_contract
  require_system_green
  case "$(migration_state):$(stabilization_migration_state)" in
    0:0) ;;
    1:0)
      require_acquisition_state_contract
      [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_community_members;")" = "0" ] \
        || fail "MIGRATION_0029_RETAINED_PRODUCT_STATE"
      [ "$(database_scalar "SELECT CASE WHEN count(*)=0 OR (count(*)=2 AND count(*) FILTER (WHERE bot_response_latency_ms=300000)=2) THEN 1 ELSE 0 END FROM commercial_s10_2d_latency_samples;")" = "1" ] \
        || fail "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN"
      ;;
    1:1)
      require_acquisition_state_contract
      require_retained_state_preflight
      ;;
    *) fail "MIGRATION_BASELINE_UNEXPECTED" ;;
  esac
  fetch_target
}

state_preflight() {
  preflight_baseline "$1" "$2"
  printf '{"ok":true,"safe_code":"S10_2D_R8_STATE_PREFLIGHT_GREEN","application_ci":%s,"community_runtime":false,"real_acquisition":false,"adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$APPLICATION_POST_MERGE_CI"
}

preflight() {
  preflight_baseline "$1" "$2"
  require_backup "$1" "$2" "$3"
  printf '{"ok":true,"safe_code":"S10_2D_PREFLIGHT_GREEN","application_ci":%s,"community":"%s","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$APPLICATION_POST_MERGE_CI" "$COMMUNITY"
}

rollback() {
  require_root
  require_control "$1" "$2"
  require_backup "$1" "$2" "$3"
  quiesce
  reconcile_aggregate_for_source "$3"
  reset_r3_acquisition_state
  rollback_migration_if_unused
  restore_technical_state "$3"
  require_source_aggregate_readable
  if ! restore_source_bot_profile; then
    systemctl stop "$S8_SERVICE" >/dev/null || true
    fail "SOURCE_BOTFATHER_GROUPS_OPERATOR_REQUIRED"
  fi
  systemctl reset-failed "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" >/dev/null || true
  systemctl start "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE" || fail "ROLLBACK_PUBLIC_START_RED"
  systemctl start "${TIMERS[@]}" || fail "ROLLBACK_TIMER_START_RED"
  require_source_green
  printf '{"ok":true,"safe_code":"S10_2D_ROLLBACK_GREEN","database_restored":false,"community":"EXTERNAL_INACTIVE","adult_media":false}\n'
}

deploy() {
  local before after
  require_root
  preflight "$1" "$2" "$3" >/dev/null
  target_group_capability_verify || fail "TARGET_BOT_GROUP_CAPABILITY_RED"
  target_community_verify || fail "COMMUNITY_OPERATOR_PREFLIGHT_RED"
  before="$(database_floor)"
  if ! (
    quiesce
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
    install_target_configuration
    install_target_control
    configure_current_bot_profile >/dev/null || fail "TARGET_BOT_PROFILE_CONFIGURE_RED"
    apply_migration
    start_target
    verify_target "$1" "$2" >/dev/null
    run_rotation
    run_health_gates
    verify_target "$1" "$2" >/dev/null
  ); then
    rollback "$1" "$2" "$3" >/dev/null || fail "DEPLOY_AND_ROLLBACK_RED"
    fail "DEPLOY_ROLLED_BACK"
  fi
  after="$(database_floor)"
  require_database_continuity "$before" "$after"
  printf '{"ok":true,"safe_code":"S10_2D_DEPLOYED_PENDING_OBSERVATION","backup":"%s","community":"%s","readiness":"PENDING","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$(basename "$3")" "$COMMUNITY"
}

observation_snapshot() {
  require_root
  verify_target "$1" "$2" >/dev/null
  local evidence
  evidence="$(database_scalar "SELECT floor(extract(epoch FROM (CURRENT_TIMESTAMP-pre_acquisition_baseline_end)))::bigint||':'||(SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE release_id='$TARGET_RELEASE_ID' AND run_id=technical_evidence_run_id AND occurred_at>=pre_acquisition_baseline_end)||':'||(SELECT count(*) FROM commercial_s10_2d_moderation_outbox WHERE delivery_state='PENDING')||':'||(SELECT count(*) FROM commercial_s10_2d_community_members WHERE community_state='RESTRICTED' AND restriction_until<CURRENT_TIMESTAMP)||':'||CASE WHEN pre_acquisition_readiness='GREEN' THEN 'true' ELSE 'false' END||':'||CASE WHEN wms_real_acquisition_ready THEN 'true' ELSE 'false' END||':'||CASE WHEN real_acquisition_baseline_start IS NULL THEN 'false' ELSE 'true' END||':'||CASE WHEN pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL THEN 'WAITING_OPERATOR_ACQUISITION_GO' WHEN pre_acquisition_readiness='GREEN' AND wms_real_acquisition_ready AND real_acquisition_baseline_start IS NOT NULL THEN 'REAL_ACQUISITION_ACTIVE' ELSE 'PRE_CUTOVER' END FROM commercial_s10_2d_runtime_control WHERE singleton;")"
  IFS=: read -r elapsed samples pending stuck technical_ready acquisition_active baseline_present loop_state <<<"$evidence"
  printf '{"ok":true,"safe_code":"S10_2D_OBSERVATION_GREEN","elapsed_seconds":%s,"latency_samples":%s,"pending_moderation":%s,"stuck_restrictions":%s,"WMS_REAL_ACQUISITION_TECHNICALLY_READY":%s,"REAL_ACQUISITION_ACTIVE":%s,"REAL_ACQUISITION_BASELINE_START_PRESENT":%s,"business_loop_state":"%s"}\n' \
    "$elapsed" "$samples" "$pending" "$stuck" "$technical_ready" "$acquisition_active" "$baseline_present" "$loop_state"
}

mark_ready() {
  require_root
  verify_target "$1" "$2" >/dev/null
  local evidence
  evidence="$(database_scalar "SELECT floor(extract(epoch FROM (CURRENT_TIMESTAMP-pre_acquisition_baseline_end)))::bigint||':'||count(s.sample_id)||':'||coalesce(percentile_cont(0.50) WITHIN GROUP (ORDER BY s.bot_response_latency_ms)::bigint,-1)||':'||coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY s.bot_response_latency_ms)::bigint,-1)||':'||coalesce(percentile_cont(0.99) WITHIN GROUP (ORDER BY s.bot_response_latency_ms)::bigint,-1)||':'||(SELECT count(*) FROM commercial_s10_2d_moderation_outbox WHERE delivery_state='PENDING')||':'||(SELECT count(*) FROM commercial_s10_2d_community_members WHERE community_state='RESTRICTED' AND restriction_until<CURRENT_TIMESTAMP) FROM commercial_s10_2d_runtime_control c LEFT JOIN commercial_s10_2d_latency_samples s ON s.release_id='$TARGET_RELEASE_ID' AND s.run_id=c.technical_evidence_run_id AND s.occurred_at>=c.pre_acquisition_baseline_end WHERE c.singleton GROUP BY c.pre_acquisition_baseline_end;")"
  IFS=: read -r elapsed samples p50 p95 p99 pending stuck <<<"$evidence"
  [ "$elapsed" -ge 1800 ] || fail "OBSERVATION_WINDOW_INCOMPLETE"
  [ "$samples" -ge 5 ] || fail "LATENCY_SAMPLE_FLOOR_MISSING"
  [ "$p50" -ge 0 ] && [ "$p50" -lt 1000 ] || fail "LATENCY_P50_RED"
  [ "$p95" -ge 0 ] && [ "$p95" -lt 2000 ] || fail "LATENCY_P95_RED"
  [ "$p99" -ge 0 ] && [ "$p99" -lt 5000 ] || fail "LATENCY_P99_RED"
  [ "$pending" = "0" ] || fail "MODERATION_OUTBOX_PENDING"
  [ "$stuck" = "0" ] || fail "COMMUNITY_RESTRICTION_STUCK"
  [ "$(database_scalar "WITH updated AS (UPDATE commercial_s10_2d_runtime_control SET pre_acquisition_readiness='GREEN',updated_at=CURRENT_TIMESTAMP WHERE singleton AND pre_acquisition_readiness='PENDING' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL RETURNING 1) SELECT count(*) FROM updated;")" = "1" ] \
    || fail "READINESS_STATE_DIVERGED"
  require_acquisition_state_contract
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL;")" = "1" ] \
    || fail "R3_TARGET_STATE_RED"
  printf '{"ok":true,"safe_code":"S10_2D_COMMUNITY_RUNTIME_GO","elapsed_seconds":%s,"latency_samples":%s,"p50_ms":%s,"p95_ms":%s,"p99_ms":%s,"WMS_REAL_ACQUISITION_TECHNICALLY_READY":true,"REAL_ACQUISITION_ACTIVE":false,"REAL_ACQUISITION_BASELINE_START":null,"business_loop_state":"WAITING_OPERATOR_ACQUISITION_GO","automatic_link_seeding":false,"adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$elapsed" "$samples" "$p50" "$p95" "$p99"
}

case "${1:-}" in
  state-preflight) [ "$#" -eq 3 ] || fail "USAGE"; state_preflight "$2" "$3" ;;
  preflight) [ "$#" -eq 4 ] || fail "USAGE"; preflight "$2" "$3" "$4" ;;
  deploy) [ "$#" -eq 4 ] || fail "USAGE"; deploy "$2" "$3" "$4" ;;
  verify) [ "$#" -eq 3 ] || fail "USAGE"; verify_target "$2" "$3" ;;
  observe) [ "$#" -eq 3 ] || fail "USAGE"; observation_snapshot "$2" "$3" ;;
  mark-ready) [ "$#" -eq 3 ] || fail "USAGE"; mark_ready "$2" "$3" ;;
  rollback) [ "$#" -eq 4 ] || fail "USAGE"; rollback "$2" "$3" "$4" ;;
  *) fail "USAGE" ;;
esac
