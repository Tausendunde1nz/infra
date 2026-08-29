#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-commercial-s3"
readonly CONFIG_ROOT="/etc/tu1nz"
readonly RECOVERY_PREFIX="/opt/tu1nz_repos/backups/commercial-s3-1-fix/"
readonly APPLICATION_SHA="2ff3af411ed58328ee4189255f13c7d5766552ad"
readonly APPLICATION_TREE="82b8f5f888309a3dce47f8609c78b96dd1bd2200"
readonly HISTORICAL_ROOT="/opt/tu1nz_repos/backups/commercial-s3-server-staging/20260829T12-48-21Z"
readonly HISTORICAL_INDEX_SHA="6d5606ebc293fef86f79a592930808a4ec324da6a615c631e9f5e72e233c2e27"
readonly HISTORICAL_RECOVERY_SHA="04421c79b292472b0f5a792cfd716d32044d31236693237cce0a498566b78888"

fail() {
  printf 'S3_1_SERVER_FIX_RED %s\n' "$1" >&2
  exit 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_recovery_path() {
  case "$1" in
    "${RECOVERY_PREFIX}"*) ;;
    *) fail "RECOVERY_PATH_OUTSIDE_BOUNDARY" ;;
  esac
}

require_stopped() {
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "SERVICE_NOT_INACTIVE"
  [ "$(systemctl show "$SERVICE" -p SubState --value)" = "dead" ] || fail "SERVICE_NOT_DEAD"
  [ "$(systemctl show "$SERVICE" -p NRestarts --value)" = "0" ] || fail "SERVICE_RESTART_COUNT_NONZERO"
  [ "$(systemctl show "$SERVICE" -p ExecMainPID --value)" = "0" ] || fail "SERVICE_PROCESS_PRESENT"
  ! pgrep -f '[t]u1nz-commercial-s3-runtime' >/dev/null || fail "CANDIDATE_PROCESS_PRESENT"
}

require_historical_evidence() {
  [ "$(sha256sum "$HISTORICAL_ROOT/final-evidence-index.json" | awk '{print $1}')" = "$HISTORICAL_INDEX_SHA" ] || fail "HISTORICAL_INDEX_DRIFT"
  [ "$(sha256sum "$HISTORICAL_ROOT/recovery.tar.gz" | awk '{print $1}')" = "$HISTORICAL_RECOVERY_SHA" ] || fail "HISTORICAL_RECOVERY_DRIFT"
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_application_release() {
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$APPLICATION_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$APPLICATION_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
}

require_control_release() {
  local expected_sha="$1"
  local expected_tree="$2"
  [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
  [[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$expected_sha" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$expected_tree" ] || fail "CONTROL_TREE_MISMATCH"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"
}

preflight() {
  require_root
  require_stopped
  require_historical_evidence
  local counts
  counts="$(runuser -u postgres -- psql -X -A -t -F '|' -v ON_ERROR_STOP=1 \
    -d tu1nz_adult_commercial_s3 \
    -c "SELECT (SELECT count(*) FROM creators),(SELECT count(*) FROM policy_versions),(SELECT count(*) FROM country_policy_rules),(SELECT count(*) FROM platform_policy_rules),(SELECT count(*) FROM integration_accounts),(SELECT count(*) FROM publication_destinations),(SELECT count(*) FROM submissions),(SELECT count(*) FROM payments),(SELECT count(*) FROM publications),(SELECT count(*) FROM platform_dispatches);")"
  [ "$counts" = "0|0|0|0|0|0|0|0|0|0" ] || fail "DATABASE_BASELINE_NOT_EMPTY"
  printf '{"ok":true,"safe_code":"S3_1_SERVER_PREFLIGHT_GREEN","service_started":false}\n'
}

snapshot() {
  require_root
  local recovery="$1"
  require_recovery_path "$recovery"
  require_stopped
  require_historical_evidence
  [ ! -e "$recovery" ] || fail "RECOVERY_PATH_ALREADY_EXISTS"
  install -d -o root -g root -m 0700 "$recovery"
  {
    printf 'captured_at=%s\n' "$(date -u +%FT%TZ)"
    printf 'application_sha=%s\n' "$(git_value "$APPLICATION_ROOT" HEAD)"
    printf 'application_tree=%s\n' "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
    printf 'control_sha=%s\n' "$(git_value "$CONTROL_ROOT" HEAD)"
    printf 'control_tree=%s\n' "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')"
    systemctl show "$SERVICE" -p LoadState -p ActiveState -p SubState -p UnitFileState -p NRestarts -p ExecMainPID -p Restart
  } >"$recovery/baseline.txt"
  chmod 0600 "$recovery/baseline.txt"
  tar --acls --xattrs --numeric-owner -czf "$recovery/recovery-delta.tar.gz" \
    /etc/systemd/system/tu1nz-adult-commercial-s3.service \
    /etc/tu1nz/adult-commercial-s3.allowlist.json \
    /etc/tu1nz/adult-commercial-s3.contract.json \
    /etc/tu1nz/adult-commercial-s3.media-manifest.json \
    /etc/tu1nz/adult-commercial-s3.postgres-dsn \
    /etc/tu1nz/adult-commercial-s3.subject-key \
    /etc/tu1nz/adult-commercial-s3.telegram-token \
    /var/lib/tausendunde1nz/adult-commercial-s3
  chmod 0600 "$recovery/recovery-delta.tar.gz"
  runuser -u postgres -- pg_dump -Fc tu1nz_adult_commercial_s3 >"$recovery/database.dump"
  runuser -u postgres -- pg_dumpall --globals-only >"$recovery/postgresql-globals.sql"
  chmod 0600 "$recovery/database.dump" "$recovery/postgresql-globals.sql"
  tar --compare --acls --xattrs --numeric-owner -zf "$recovery/recovery-delta.tar.gz" >"$recovery/tar-restore-proof.txt" 2>&1
  pg_restore --list "$recovery/database.dump" >"$recovery/database-restore-list.txt"
  chmod 0600 "$recovery/tar-restore-proof.txt" "$recovery/database-restore-list.txt"
  (
    cd "$recovery"
    sha256sum baseline.txt recovery-delta.tar.gz database.dump postgresql-globals.sql tar-restore-proof.txt database-restore-list.txt >SHA256SUMS
  )
  chmod 0600 "$recovery/SHA256SUMS"
  printf '{"ok":true,"safe_code":"S3_1_RECOVERY_DELTA_READY","service_started":false}\n'
}

require_recovery() {
  local recovery="$1"
  require_recovery_path "$recovery"
  [ -d "$recovery" ] || fail "RECOVERY_DELTA_MISSING"
  (cd "$recovery" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "RECOVERY_DELTA_INVALID"
}

install_delta() {
  require_root
  local recovery="$1"
  local control_sha="$2"
  local control_tree="$3"
  require_recovery "$recovery"
  require_stopped
  require_historical_evidence
  require_application_release
  require_control_release "$control_sha" "$control_tree"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" -m pip install \
    --no-deps --no-build-isolation --editable "$APPLICATION_ROOT" >/dev/null
  install -o root -g root -m 0600 \
    "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-bootstrap-authorization.s3-1.json" \
    "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
  install -o root -g root -m 0644 \
    "$CONTROL_ROOT/systemd/tu1nz-adult-commercial-s3-s3-1.service" \
    /etc/systemd/system/tu1nz-adult-commercial-s3.service
  systemctl daemon-reload
  require_stopped
  printf '{"ok":true,"safe_code":"S3_1_INSTALL_DELTA_READY","service_started":false}\n'
}

repair_state() {
  require_root
  local recovery="$1"
  require_recovery "$recovery"
  require_stopped
  require_application_release
  [ ! -L "$STATE_ROOT" ] || fail "STATE_ROOT_SYMLINK"
  [ "$(stat -c '%U:%G:%a' "$STATE_ROOT")" = "chatops:chatops:2700" ] || fail "LEGACY_STATE_ROOT_DIVERGED"
  [ -d "$STATE_ROOT/media" ] && [ ! -L "$STATE_ROOT/media" ] || fail "LEGACY_MEDIA_PATH_DIVERGED"
  [ -z "$(find "$STATE_ROOT/media" -mindepth 1 -print -quit)" ] || fail "LEGACY_MEDIA_NOT_EMPTY"
  [ "$(stat -c '%U:%G:%a' "$STATE_ROOT/evidence")" = "chatops:chatops:700" ] || fail "EVIDENCE_DIRECTORY_DIVERGED"
  [ "$(stat -c '%U:%G:%a' "$STATE_ROOT/media-test")" = "chatops:chatops:700" ] || fail "MEDIA_TEST_DIRECTORY_DIVERGED"
  [ ! -L "$STATE_ROOT/telegram-offset.json" ] || fail "LEGACY_CURSOR_SYMLINK"
  [ "$(stat -c '%u:%G:%a:%h' "$STATE_ROOT/telegram-offset.json")" = "0:chatops:600:1" ] || fail "LEGACY_CURSOR_DIVERGED"
  local offset
  offset="$(python3 - "$STATE_ROOT/telegram-offset.json" <<'PY'
import json
import sys
from pathlib import Path
value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if set(value) != {"next_update_id", "version"} or value["version"] != 1:
    raise SystemExit(2)
offset = value["next_update_id"]
if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
    raise SystemExit(2)
print(offset)
PY
)" || fail "LEGACY_CURSOR_INVALID"
  printf '%s\n' "$offset" >"$recovery/preserved-next-update-id.txt"
  chmod 0600 "$recovery/preserved-next-update-id.txt"
  rm -f -- "$STATE_ROOT/telegram-offset.json"
  rmdir -- "$STATE_ROOT/media"
  chmod 0700 "$STATE_ROOT"
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/python" - "$STATE_ROOT" "$offset" <<'PY'
import json
import sys
from pathlib import Path
from tu1nz_commercial_s3.state import initialize_cursor
result = initialize_cursor(Path(sys.argv[1]), int(sys.argv[2]))
print(json.dumps({"cursor_result": result, "ok": True}, sort_keys=True))
PY
  [ "$(stat -c '%U:%G:%a' "$STATE_ROOT")" = "chatops:chatops:700" ] || fail "STATE_ROOT_POSTCONDITION_FAILED"
  [ "$(stat -c '%U:%G:%a:%h' "$STATE_ROOT/telegram-offset.json")" = "chatops:chatops:600:1" ] || fail "CURSOR_POSTCONDITION_FAILED"
  printf '{"ok":true,"safe_code":"S3_1_STATE_OWNERSHIP_READY","service_started":false}\n'
}

private_credentials() {
  local recovery="$1"
  local contract_source="$2"
  local directory
  directory="$(runuser -u chatops -- mktemp -d "$STATE_ROOT/evidence/s31-credentials.XXXXXX")"
  install -o chatops -g chatops -m 0600 "$CONFIG_ROOT/adult-commercial-s3.postgres-dsn" "$directory/postgres-dsn"
  install -o chatops -g chatops -m 0600 "$CONFIG_ROOT/adult-commercial-s3.subject-key" "$directory/subject-key"
  install -o chatops -g chatops -m 0600 "$CONFIG_ROOT/adult-commercial-s3.allowlist.json" "$directory/allowlist"
  install -o chatops -g chatops -m 0600 "$CONFIG_ROOT/adult-commercial-s3.media-manifest.json" "$directory/media-manifest"
  install -o chatops -g chatops -m 0600 "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" "$directory/bootstrap-manifest"
  install -o chatops -g chatops -m 0600 "$contract_source" "$directory/staging-contract"
  printf '%s\n' "$directory" >"$recovery/private-credential-directory.path"
  chmod 0600 "$recovery/private-credential-directory.path"
  printf '%s\n' "$directory"
}

clear_private_credentials() {
  local directory="$1"
  rm -f -- "$directory/postgres-dsn" "$directory/subject-key" "$directory/allowlist" \
    "$directory/media-manifest" "$directory/bootstrap-manifest" "$directory/staging-contract"
  rmdir -- "$directory"
}

bootstrap_once() {
  require_root
  local recovery="$1"
  require_recovery "$recovery"
  require_stopped
  require_application_release
  [ ! -e "$recovery/bootstrap-result.json" ] || fail "BOOTSTRAP_ALREADY_RECORDED"
  local directory
  directory="$(private_credentials "$recovery" "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-staging.disabled.json")"
  set +e
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-bootstrap" \
    --reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
    --authorization "$directory/bootstrap-manifest" \
    --repository-root "$APPLICATION_ROOT" \
    --migration-directory "$APPLICATION_ROOT/migrations" \
    --dsn-file "$directory/postgres-dsn" >"$recovery/bootstrap-result.json"
  local status=$?
  set -e
  clear_private_credentials "$directory"
  chmod 0600 "$recovery/bootstrap-result.json"
  [ "$status" -eq 0 ] || fail "BOOTSTRAP_EXECUTION_FAILED"
  grep -q '"result":"CREATED"' "$recovery/bootstrap-result.json" || fail "BOOTSTRAP_NOT_CREATED"
  cat "$recovery/bootstrap-result.json"
}

verify_bootstrap() {
  require_root
  local recovery="$1"
  require_recovery "$recovery"
  require_stopped
  require_application_release
  local directory
  directory="$(private_credentials "$recovery" "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-staging.disabled.json")"
  set +e
  runuser -u chatops -- "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-bootstrap-verify" \
    --reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
    --authorization "$directory/bootstrap-manifest" \
    --repository-root "$APPLICATION_ROOT" \
    --migration-directory "$APPLICATION_ROOT/migrations" \
    --dsn-file "$directory/postgres-dsn" >"$recovery/bootstrap-verify.json"
  local status=$?
  set -e
  clear_private_credentials "$directory"
  chmod 0600 "$recovery/bootstrap-verify.json"
  [ "$status" -eq 0 ] || fail "BOOTSTRAP_VERIFY_FAILED"
  grep -q '"result":"S3_BOOTSTRAP_READY"' "$recovery/bootstrap-verify.json" || fail "BOOTSTRAP_NOT_READY"
  grep -q '"business_rows":0' "$recovery/bootstrap-verify.json" || fail "BUSINESS_ROWS_NONZERO"
  grep -q '"external_targets":0' "$recovery/bootstrap-verify.json" || fail "EXTERNAL_TARGETS_NONZERO"
  cat "$recovery/bootstrap-verify.json"
}

dry_prestart() {
  require_root
  local recovery="$1"
  require_recovery "$recovery"
  require_stopped
  require_application_release
  local directory
  directory="$(private_credentials "$recovery" "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-staging.disabled.json")"
  set +e
  runuser -u chatops -- env CREDENTIALS_DIRECTORY="$directory" \
    "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-prestart" \
    --contract "$directory/staging-contract" \
    --allowlist "$directory/allowlist" \
    --media-manifest "$directory/media-manifest" \
    --bootstrap-manifest "$directory/bootstrap-manifest" \
    --bootstrap-reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
    --migration-directory "$APPLICATION_ROOT/migrations" \
    --state-directory "$STATE_ROOT" >"$recovery/prestart-result.json" 2>"$recovery/prestart-error.json"
  local status=$?
  set -e
  clear_private_credentials "$directory"
  chmod 0600 "$recovery/prestart-result.json" "$recovery/prestart-error.json"
  [ "$status" -eq 0 ] || fail "PRESTART_FAILED"
  grep -q '"safe_code":"S3_PRESTART_READY"' "$recovery/prestart-result.json" || fail "PRESTART_NOT_READY"
  grep -q '"service_started":false' "$recovery/prestart-result.json" || fail "PRESTART_STARTED_SERVICE"
  cat "$recovery/prestart-result.json"
}

finalize_evidence() {
  require_root
  local recovery="$1"
  local control_sha="$2"
  local control_tree="$3"
  require_recovery "$recovery"
  require_stopped
  require_historical_evidence
  require_application_release
  require_control_release "$control_sha" "$control_tree"
  grep -q '"result":"CREATED"' "$recovery/bootstrap-result.json" || fail "FINAL_BOOTSTRAP_EVIDENCE_MISSING"
  grep -q '"result":"S3_BOOTSTRAP_READY"' "$recovery/bootstrap-verify.json" || fail "FINAL_VERIFY_EVIDENCE_MISSING"
  grep -q '"safe_code":"S3_PRESTART_READY"' "$recovery/prestart-result.json" || fail "FINAL_PRESTART_EVIDENCE_MISSING"
  [ "$(sha256sum /etc/systemd/system/tu1nz-adult-commercial-s3.service | awk '{print $1}')" = \
    "b9059cea568086796d1d5cbbe98a8599a5822ba7d4eaf9de9eb387d0bf9c41b5" ] || fail "FINAL_UNIT_DRIFT"
  [ "$(stat -c '%U:%G:%a' "$STATE_ROOT")" = "chatops:chatops:700" ] || fail "FINAL_STATE_ROOT_DRIFT"
  [ "$(stat -c '%U:%G:%a:%h' "$STATE_ROOT/telegram-offset.json")" = "chatops:chatops:600:1" ] || fail "FINAL_CURSOR_DRIFT"
  {
    printf 'finalized_at=%s\n' "$(date -u +%FT%TZ)"
    printf 'application_sha=%s\n' "$(git_value "$APPLICATION_ROOT" HEAD)"
    printf 'application_tree=%s\n' "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')"
    printf 'control_sha=%s\n' "$(git_value "$CONTROL_ROOT" HEAD)"
    printf 'control_tree=%s\n' "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')"
    systemctl show "$SERVICE" -p LoadState -p ActiveState -p SubState -p UnitFileState -p NRestarts -p ExecMainPID -p Restart
    find "$STATE_ROOT" -xdev -maxdepth 3 -printf '%y %U:%G %m %n %p\n' | sort
    runuser -u postgres -- psql -X -A -t -F '|' -v ON_ERROR_STOP=1 \
      -d tu1nz_adult_commercial_s3 \
      -c "SELECT (SELECT count(*) FROM creators),(SELECT count(*) FROM policy_versions),(SELECT count(*) FROM country_policy_rules),(SELECT count(*) FROM platform_policy_rules),(SELECT count(*) FROM integration_accounts),(SELECT count(*) FROM publication_destinations),(SELECT count(*) FROM submissions),(SELECT count(*) FROM payments),(SELECT count(*) FROM publications),(SELECT count(*) FROM platform_dispatches);"
  } >"$recovery/final-state.txt"
  chmod 0600 "$recovery/final-state.txt"
  (
    cd "$recovery"
    find . -type f ! -name FINAL-SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >FINAL-SHA256SUMS
  )
  chmod 0600 "$recovery/FINAL-SHA256SUMS"
  printf '{"ok":true,"safe_code":"S3_1_EVIDENCE_FINALIZED","service_started":false}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 1 ] || fail "ARGUMENT_COUNT"
    preflight
    ;;
  snapshot)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    snapshot "$2"
    ;;
  install)
    [ "$#" -eq 4 ] || fail "ARGUMENT_COUNT"
    install_delta "$2" "$3" "$4"
    ;;
  repair-state)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    repair_state "$2"
    ;;
  bootstrap-once)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    bootstrap_once "$2"
    ;;
  verify)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    verify_bootstrap "$2"
    ;;
  prestart)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    dry_prestart "$2"
    ;;
  finalize)
    [ "$#" -eq 4 ] || fail "ARGUMENT_COUNT"
    finalize_evidence "$2" "$3" "$4"
    ;;
  *)
    fail "UNKNOWN_ACTION"
    ;;
esac
