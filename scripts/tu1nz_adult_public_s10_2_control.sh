#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"
readonly BACKUP_SCRIPT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_backup.sh"

readonly SOURCE_SHA="cdeab77c17c28f4ade46c27975f1c20e74cb8737"
readonly SOURCE_TREE="88d8869fbbb9931b16451f7bb1483e1fa6d483df"
readonly TARGET_SHA="deeb38c30427066989eb85e1c115d2aeccf140cf"
readonly TARGET_TREE="3619e7dc557b49c632efa713bb0bc4214fd83fca"
readonly SOURCE_S8_COPY_SHA="28fe75b7ff10d121e59dba30e09b8c90278df706956015fec5b7120b2653a124"
readonly TARGET_S8_COPY_SHA="6da055fa206ae3705c07051901cdc6e5d7ff3c83e0afe1568e2f24cc00f70e09"
readonly SOURCE_S10_CONTRACT_SHA="cf0dd7f72b9501fef98a640ee7f48faefa69a6de014c9a21c1c510f827079856"
readonly TARGET_S10_CONTRACT_SHA="dfdd3a5f6e90ce25e96ff6d4f8f895bb473d3d0bb9f072b7959be2a006c7b28b"
readonly SOURCE_S10_COPY_SHA="a7a4a79cdd2dd3795d0603d8c9976242403805a0b14557ad17bc2824cb59b24f"
readonly TARGET_S10_COPY_SHA="7b0f8e286894a3ad1b5f014cb140db4a672564277bd66ad456965baf4b22b9c2"
readonly S8_CONTRACT_SHA="cea242a0c749f5e10b15c527248a60a9c429ad7a3f3d655ca0a71e61d7ff6193"
readonly S9_CONTRACT_SHA="274677854b3067cf970f103fc3f541f31e4244df017f9bbcaa0da0c707aa2bf5"

readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S8_LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly S10_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly NGINX_SERVICE="nginx.service"
readonly S10_HEALTH_SERVICE="tu1nz-adult-public-s10-health.service"
readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)
readonly WORKERS=(
  tu1nz-adult-public-s9-audience.service
  tu1nz-adult-public-s9-nurture.service
  tu1nz-adult-public-s9-report.service
  tu1nz-adult-public-s9-health.service
  tu1nz-adult-public-s10-health.service
)

fail() {
  printf 'S10_2_PRODUCT_GROWTH_RED %s\n' "$1" >&2
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

require_application_target() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
}

require_application_source() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$SOURCE_SHA" ] || fail "APPLICATION_SOURCE_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$SOURCE_TREE" ] || fail "APPLICATION_SOURCE_TREE_MISMATCH"
}

require_paths_unshared() {
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$APPLICATION_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$CONTROL_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "CONTROL_PATH_CONTAINER_MOUNTED"
  fi
}

require_service_green() {
  [ "$(unit_value "$1" ActiveState)" = "active" ] || fail "$2_NOT_ACTIVE"
  [ "$(unit_value "$1" NRestarts)" = "0" ] || fail "$2_RESTARTED"
}

require_timers_green() {
  local timer
  for timer in "${TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = "enabled" ] || fail "TIMER_NOT_ENABLED"
    [ "$(unit_value "$timer" ActiveState)" = "active" ] || fail "TIMER_NOT_ACTIVE"
  done
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

require_config_hashes() {
  local s8_copy="$1" s10_contract="$2" s10_copy="$3"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s8-copy.json | awk '{print $1}')" = "$s8_copy" ] || fail "S8_COPY_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s10-wms.json | awk '{print $1}')" = "$s10_contract" ] || fail "S10_CONTRACT_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s10-wms-copy.json | awk '{print $1}')" = "$s10_copy" ] || fail "S10_COPY_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s8-public-telegram.json | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "S8_CONTRACT_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s9-growth.json | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] || fail "S9_CONTRACT_DRIFT"
}

require_product_boundary() {
  /usr/bin/python3 - \
    /etc/tu1nz/adult-commercial-s8-public-telegram.json \
    /etc/tu1nz/adult-commercial-s9-growth.json \
    /etc/tu1nz/adult-commercial-s10-wms.json \
    "$SOURCE_S10_CONTRACT_SHA" \
    "$TARGET_S10_CONTRACT_SHA" <<'PY' || fail "PRODUCT_BOUNDARY_RED"
import hashlib
import json
import sys

s8, s9, s10 = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:4])
s10_path = sys.argv[3]
s10_hash = hashlib.sha256(open(s10_path, "rb").read()).hexdigest()
source_hash, target_hash = sys.argv[4:6]
required_events = {
    "LANDING_VIEW", "TELEGRAM_CTA", "BOT_START", "WAITLIST_JOINED",
    "OPT_IN", "OPT_OUT",
}
if s10_hash == target_hash:
    required_events.add("INTRO_COMPLETED")
elif s10_hash != source_hash:
    raise SystemExit(2)
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
    required_events.issubset(s10["allowed_events"]),
)
raise SystemExit(0 if all(checks) else 2)
PY
}

require_public_green() {
  require_service_green "$S7_SERVICE" "S7"
  require_service_green "$S8_LANDING_SERVICE" "S8_LANDING"
  require_service_green "$S8_SERVICE" "S8_TELEGRAM"
  require_service_green "$S10_SERVICE" "S10_WMS"
  require_service_green "$NGINX_SERVICE" "NGINX"
  require_timers_green
  require_adult_runtime_closed
  require_product_boundary
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/health \
    | /usr/bin/python3 -c 'import json,sys; p=json.load(sys.stdin); f=p.get("forbidden_capabilities"); sys.exit(0 if p.get("ok") is True and isinstance(f,dict) and all(v is False for v in f.values()) else 2)' \
    || fail "PUBLIC_HEALTH_RED"
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/ \
    | grep -Fq 'Want Me Seen' || fail "PUBLIC_PAGE_RED"
}

require_backup() {
  case "$1" in
    "${BACKUP_PREFIX}"[0-9]*-pre-s10-2-product-growth) ;;
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

quiesce() {
  systemctl stop "${TIMERS[@]}" || fail "TIMER_QUIESCE_RED"
  systemctl stop "${WORKERS[@]}" || fail "WORKER_QUIESCE_RED"
  systemctl stop "$S8_SERVICE" "$S10_SERVICE" || fail "PUBLIC_SERVICE_QUIESCE_RED"
}

start_public() {
  systemctl reset-failed "$S8_SERVICE" "$S10_SERVICE" >/dev/null || true
  systemctl start "$S10_SERVICE" || fail "S10_WMS_START_RED"
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
  systemctl reset-failed "$S10_HEALTH_SERVICE" >/dev/null || true
  systemctl start "$S10_HEALTH_SERVICE" || fail "S10_HEALTH_RED"
  [ "$(unit_value "$S10_HEALTH_SERVICE" Result)" = "success" ] || fail "S10_HEALTH_RESULT_RED"
  [ "$(unit_value "$S10_HEALTH_SERVICE" ExecMainStatus)" = "0" ] || fail "S10_HEALTH_STATUS_RED"
}

install_target_configuration() {
  install -o root -g root -m 0644 \
    "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" \
    /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 \
    "$APPLICATION_ROOT/config/commercial-s10-1-wms-public.sfw.json" \
    /etc/tu1nz/adult-commercial-s10-wms.json
  install -o root -g root -m 0644 \
    "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" \
    /etc/tu1nz/adult-commercial-s10-wms-copy.json
}

restore_configuration() {
  tar -xpf "$1/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$1/s10-configuration-before.tar" -C /etc/tu1nz
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_paths_unshared
  require_application_state
  if [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$SOURCE_SHA" ]; then
    require_config_hashes "$SOURCE_S8_COPY_SHA" "$SOURCE_S10_CONTRACT_SHA" "$SOURCE_S10_COPY_SHA"
  else
    require_config_hashes "$TARGET_S8_COPY_SHA" "$TARGET_S10_CONTRACT_SHA" "$TARGET_S10_COPY_SHA"
  fi
  require_public_green
  fetch_target
  printf '{"ok":true,"safe_code":"S10_2_PRODUCT_GROWTH_PREFLIGHT_GREEN","schema_migration":false,"adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

verify_target() {
  require_root
  require_control "$1" "$2"
  require_paths_unshared
  require_application_target
  require_config_hashes "$TARGET_S8_COPY_SHA" "$TARGET_S10_CONTRACT_SHA" "$TARGET_S10_COPY_SHA"
  require_public_green
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/ \
    | grep -Fq '30-second preview' || fail "PRODUCT_JOURNEY_NOT_PUBLIC"
  printf '{"ok":true,"safe_code":"S10_2_PRODUCT_GROWTH_GREEN","schema_migration":false,"referrals":"COHORT_ONLY","adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

verify_source() {
  require_application_source
  require_config_hashes "$SOURCE_S8_COPY_SHA" "$SOURCE_S10_CONTRACT_SHA" "$SOURCE_S10_COPY_SHA"
  require_public_green
}

rollback() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  quiesce
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$SOURCE_SHA"
  restore_configuration "$3"
  start_public
  verify_source
  printf '{"ok":true,"safe_code":"S10_2_ROLLBACK_TO_S10_1_GREEN","database_restored":false}\n'
}

deploy() {
  require_root
  preflight "$1" "$2" >/dev/null
  require_application_source
  require_backup "$3"
  if ! (
    quiesce
    runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
    install_target_configuration
    start_public
    verify_target "$1" "$2" >/dev/null
  ); then
    rollback "$1" "$2" "$3" >/dev/null || fail "DEPLOY_AND_ROLLBACK_RED"
    fail "DEPLOY_ROLLED_BACK"
  fi
  printf '{"ok":true,"safe_code":"S10_2_PRODUCT_GROWTH_DEPLOYED","backup":"%s","schema_migration":false}\n' "$(basename "$3")"
}

case "${1:-}" in
  preflight) [ "$#" -eq 3 ] || fail "USAGE"; preflight "$2" "$3" ;;
  deploy) [ "$#" -eq 4 ] || fail "USAGE"; deploy "$2" "$3" "$4" ;;
  verify) [ "$#" -eq 3 ] || fail "USAGE"; verify_target "$2" "$3" ;;
  rollback) [ "$#" -eq 4 ] || fail "USAGE"; rollback "$2" "$3" "$4" ;;
  *) fail "USAGE" ;;
esac
