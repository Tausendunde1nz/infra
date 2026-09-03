#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly BACKUP_ROOT="/opt/tu1nz_repos/backups/commercial-s9-timer-liveness"
readonly SYSTEMD_ROOT="/etc/systemd/system"
readonly BIN_ROOT="/usr/local/bin"

readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-health.timer
)
readonly WORKERS=(
  tu1nz-adult-public-s9-audience.service
  tu1nz-adult-public-s9-nurture.service
  tu1nz-adult-public-s9-health.service
)
readonly SERVICES=(
  tu1nz-adult-public-s7.service
  tu1nz-adult-public-s8-landing.service
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s10-wms.service
  nginx.service
)
readonly HEALTH_SCRIPTS=(
  tu1nz_adult_public_s9_health.py
  tu1nz_adult_public_s10_1_health.py
  tu1nz_adult_public_s10_1_s9_health.py
)

fail() {
  printf 'S9_TIMER_LIVENESS_REPAIR_RED %s\n' "$1" >&2
  exit 2
}

unit_value() {
  systemctl show "$1" -p "$2" --value 2>/dev/null || true
}

git_value() {
  runuser -u chatops -- git -C "$CONTROL_ROOT" rev-parse "$1"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_expected_revision() {
  local expected_commit="$1" expected_tree="$2"
  [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "EXPECTED_COMMIT_INVALID"
  [[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] || fail "EXPECTED_TREE_INVALID"
  [ -d "$CONTROL_ROOT/.git" ] && [ ! -L "$CONTROL_ROOT" ] || fail "CONTROL_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] || fail "CONTROL_DIRTY"
  [ "$(git_value HEAD)" = "$expected_commit" ] || fail "CONTROL_COMMIT_MISMATCH"
  [ "$(git_value 'HEAD^{tree}')" = "$expected_tree" ] || fail "CONTROL_TREE_MISMATCH"
}

require_paths_unshared() {
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$CONTROL_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "CONTROL_PATH_CONTAINER_MOUNTED"
  fi
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

require_public_baseline() {
  local unit worker timer
  for unit in "${SERVICES[@]}"; do
    [ "$(unit_value "$unit" ActiveState)" = "active" ] || fail "PUBLIC_SERVICE_NOT_ACTIVE"
    [ "$(unit_value "$unit" NRestarts)" = "0" ] || fail "PUBLIC_SERVICE_RESTARTED"
  done
  for worker in "${WORKERS[@]}"; do
    case "$(unit_value "$worker" ActiveState)" in
      inactive|failed|"") ;;
      *) fail "S9_WORKER_BUSY" ;;
    esac
  done
  for timer in "${TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = "enabled" ] || fail "S9_TIMER_NOT_ENABLED"
    [ "$(unit_value "$timer" ActiveState)" = "active" ] || fail "S9_TIMER_NOT_ACTIVE"
  done
  curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/health \
    | /usr/bin/python3 -c 'import json,sys; p=json.load(sys.stdin); keys=("adult_content","media_intake","identity_documents","real_avs","payments","external_publishing","controlled_beta","production"); sys.exit(0 if p.get("ok") is True and all(p.get(k) is False for k in keys) else 2)' \
    || fail "PUBLIC_HEALTH_RED"
  require_adult_runtime_closed
}

require_sources() {
  local file
  for file in "${TIMERS[@]}"; do
    [ -f "$CONTROL_ROOT/systemd/$file" ] && [ ! -L "$CONTROL_ROOT/systemd/$file" ] || fail "SOURCE_TIMER_UNSAFE"
    grep -Fq 'Persistent=true' "$CONTROL_ROOT/systemd/$file" || fail "SOURCE_TIMER_NOT_PERSISTENT"
    if grep -Fq 'OnUnitActiveSec=' "$CONTROL_ROOT/systemd/$file"; then
      fail "SOURCE_TIMER_MONOTONIC_ANCHOR_PRESENT"
    fi
  done
  grep -Fq 'OnCalendar=*:0/15' "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-audience.timer" || fail "AUDIENCE_CALENDAR_MISSING"
  grep -Fq 'OnCalendar=*:3/15' "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-nurture.timer" || fail "NUDGE_CALENDAR_MISSING"
  grep -Fq 'OnCalendar=*:0/5' "$CONTROL_ROOT/systemd/tu1nz-adult-public-s9-health.timer" || fail "HEALTH_CALENDAR_MISSING"
  for file in "${HEALTH_SCRIPTS[@]}"; do
    [ -f "$CONTROL_ROOT/scripts/$file" ] && [ ! -L "$CONTROL_ROOT/scripts/$file" ] || fail "SOURCE_HEALTH_SCRIPT_UNSAFE"
  done
  systemd-analyze verify "${TIMERS[@]/#/$CONTROL_ROOT/systemd/}" >/dev/null || fail "SOURCE_TIMER_VERIFY_RED"
}

capture_backup() {
  local expected_commit="$1" expected_tree="$2" timestamp backup_path file
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_path="$BACKUP_ROOT/${timestamp}-pre-repair"
  install -d -o root -g chatops -m 0750 "$BACKUP_ROOT"
  install -d -o root -g chatops -m 0750 "$backup_path"
  printf '%s\n%s\n' "$expected_commit" "$expected_tree" >"$backup_path/control-provenance.txt"
  for file in "${TIMERS[@]}"; do
    [ -f "$SYSTEMD_ROOT/$file" ] && [ ! -L "$SYSTEMD_ROOT/$file" ] || fail "INSTALLED_TIMER_UNSAFE"
    cp -p "$SYSTEMD_ROOT/$file" "$backup_path/$file"
    systemctl show "$file" -p ActiveState -p SubState -p UnitFileState -p LastTriggerUSec -p NextElapseUSecRealtime -p NextElapseUSecMonotonic \
      >"$backup_path/$file.state"
  done
  for file in "${HEALTH_SCRIPTS[@]}"; do
    [ -f "$BIN_ROOT/$file" ] && [ ! -L "$BIN_ROOT/$file" ] || fail "INSTALLED_HEALTH_SCRIPT_UNSAFE"
    cp -p "$BIN_ROOT/$file" "$backup_path/$file"
  done
  sha256sum "$backup_path"/*.timer "$backup_path"/*.py >"$backup_path/SHA256SUMS"
  printf '%s\n' "$backup_path"
}

timer_has_future() {
  local timer="$1" realtime monotonic
  realtime="$(unit_value "$timer" NextElapseUSecRealtime)"
  monotonic="$(unit_value "$timer" NextElapseUSecMonotonic)"
  [ -n "$realtime" ] && [ "$realtime" != "0" ] && [ "$realtime" != "infinity" ] && return 0
  [ -n "$monotonic" ] && [ "$monotonic" != "0" ] && [ "$monotonic" != "infinity" ]
}

require_repaired_state() {
  local timer
  for timer in "${TIMERS[@]}"; do
    [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = "enabled" ] || return 1
    [ "$(unit_value "$timer" ActiveState)" = "active" ] || return 1
    [ "$(unit_value "$timer" SubState)" = "waiting" ] || return 1
    timer_has_future "$timer" || return 1
  done
  systemctl start tu1nz-adult-public-s9-health.service || return 1
  [ "$(unit_value tu1nz-adult-public-s9-health.service Result)" = "success" ] || return 1
  systemctl start tu1nz-adult-public-s10-health.service || return 1
  [ "$(unit_value tu1nz-adult-public-s10-health.service Result)" = "success" ] || return 1
  require_public_baseline
}

apply_repair() {
  local file
  for file in "${TIMERS[@]}"; do
    install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$file" "$SYSTEMD_ROOT/$file"
  done
  for file in "${HEALTH_SCRIPTS[@]}"; do
    install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/$file" "$BIN_ROOT/$file"
  done
  systemctl daemon-reload
  systemctl stop "${TIMERS[@]}"
  systemctl start "${TIMERS[@]}"
  require_repaired_state
}

restore_backup() {
  local backup_path="$1" file
  systemctl stop "${TIMERS[@]}" >/dev/null 2>&1 || true
  for file in "${TIMERS[@]}"; do
    install -o root -g root -m 0644 "$backup_path/$file" "$SYSTEMD_ROOT/$file"
  done
  for file in "${HEALTH_SCRIPTS[@]}"; do
    install -o root -g root -m 0755 "$backup_path/$file" "$BIN_ROOT/$file"
  done
  systemctl daemon-reload
  systemctl start "${TIMERS[@]}" >/dev/null 2>&1 || true
}

main() {
  [ "$#" -eq 2 ] || fail "USAGE"
  require_root
  require_expected_revision "$1" "$2"
  require_paths_unshared
  require_sources
  require_public_baseline
  local backup_path
  backup_path="$(capture_backup "$1" "$2")"
  if ! apply_repair; then
    restore_backup "$backup_path"
    fail "APPLY_FAILED_ROLLED_BACK"
  fi
  printf 'S9_TIMER_LIVENESS_REPAIR_GREEN %s\n' "$(basename "$backup_path")"
}

main "$@"
