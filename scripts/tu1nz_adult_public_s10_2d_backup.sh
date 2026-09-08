#!/usr/bin/env bash
set -euo pipefail
umask 0007

readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly BASE_BACKUP="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_backup.sh"
readonly AGGREGATE_CONTRACT="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py"
readonly TARGET_RELEASE_ID="s10-2d-r3-5"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"

fail() {
  printf 'S10_2D_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

require_boundary() {
  local canonical
  canonical="$(readlink -m -- "$1")"
  [ "$canonical" = "$1" ] || fail "BACKUP_PATH_NOT_CANONICAL"
  case "$canonical" in
    "${BACKUP_PREFIX}"[0-9]*-pre-s10-2d-community) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
}

verify_aggregate_index() {
  local path="$1" run_id name
  run_id="$(basename "$path")"
  "$AGGREGATE_CONTRACT" verify-backup \
    --backup-dir "$path" \
    --release-id "$TARGET_RELEASE_ID" \
    --run-id "$run_id" >/dev/null \
    || fail "CUTOVER_PREFLIGHT_RED"
  for name in \
    s10-2d-aggregate-before.json \
    s10-2d-aggregate-before.metadata.json
  do
    awk -v expected="./$name" '$2 == expected { found=1 } END { exit !found }' "$path/SHA256SUMS" \
      || fail "AGGREGATE_BACKUP_INDEX_RED"
  done
  (
    cd "$path"
    sha256sum --check --strict SHA256SUMS >/dev/null
  ) || fail "AGGREGATE_BACKUP_INDEX_HASH_RED"
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
[ "$#" -eq 2 ] || fail "USAGE"
readonly ACTION="$1"
readonly BACKUP_PATH="$2"
require_boundary "$BACKUP_PATH"

case "$ACTION" in
  verify-existing)
    "$BASE_BACKUP" verify-existing "$BACKUP_PATH" >/dev/null || fail "BASE_BACKUP_VERIFY_RED"
    verify_aggregate_index "$BACKUP_PATH"
    printf '{"ok":true,"safe_code":"S10_2D_BACKUP_EXISTING_GREEN","aggregate_backup_present":true,"aggregate_backup_hash_valid":true,"aggregate_backup_mode_valid":true,"aggregate_backup_restore_path_valid":true}\n'
    ;;
  create)
    [ ! -e "$BACKUP_PATH" ] || fail "BACKUP_PATH_EXISTS"
    "$BASE_BACKUP" create "$BACKUP_PATH" >/dev/null || fail "BASE_BACKUP_CREATE_RED"
    "$AGGREGATE_CONTRACT" create-backup \
      --backup-dir "$BACKUP_PATH" \
      --release-id "$TARGET_RELEASE_ID" \
      --run-id "$(basename "$BACKUP_PATH")" >/dev/null \
      || fail "AGGREGATE_BACKUP_CREATE_RED"
    (
      cd "$BACKUP_PATH"
      find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
      chmod 0600 SHA256SUMS
    )
    verify_aggregate_index "$BACKUP_PATH"
    printf '{"ok":true,"safe_code":"S10_2D_BACKUP_GREEN","aggregate_backup_present":true,"aggregate_backup_hash_valid":true,"aggregate_backup_mode_valid":true,"aggregate_backup_restore_path_valid":true}\n'
    ;;
  *) fail "USAGE" ;;
esac
