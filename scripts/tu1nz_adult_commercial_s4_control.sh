#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly PRESTART_SERVICE="tu1nz-adult-commercial-s4-prestart.service"
readonly PRESTART_CREDENTIAL_ROOT="/run/credentials/$PRESTART_SERVICE"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly CONFIG_ROOT="/etc/tu1nz"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-commercial-s3"
readonly APPLICATION_SHA="a745540b81a368b2e5f09d1fcdb49342b686ae0e"
readonly APPLICATION_TREE="6e7c869d1194b28baad67698a93ab2254b0d8739"
readonly DISABLED_CONTRACT_SHA="41e5682934cc632b8d00cd0afd542cd823ef3c99f1c9b418efcb01ccd1ad2f23"
readonly RUNTIME_AUTHORIZATION_SHA="d4e38b9d4d07d539eef49dd2095646e905f00ca214c45095c0cf97eb057d810f"
readonly PROVIDER_READINESS_SHA="8e3c4513315c5749ec01ec11a87c9adf057ad862631450a36a0319e6192b6bbc"
readonly BETA_READINESS_SHA="4e43c8cd44969228c2ee8baf1f00d0fb08ed4a2c69047f5eff2c411b9c55ee3c"
readonly UNIT_SHA="0a746cd03abc07e18e7193dbd00c246ead184717ea8bce83091a301279037cb9"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s4-extended-staging/"

fail() {
  printf 'S4_CONTROL_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_stopped() {
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "inactive" ] || fail "SERVICE_NOT_INACTIVE"
  [ "$(systemctl show "$SERVICE" -p SubState --value)" = "dead" ] || fail "SERVICE_NOT_DEAD"
  [ "$(systemctl show "$SERVICE" -p NRestarts --value)" = "0" ] || fail "SERVICE_RESTART_COUNT_NONZERO"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" = "0" ] || fail "SERVICE_PROCESS_PRESENT"
  [ "$(systemctl show "$SERVICE" -p Restart --value)" = "no" ] || fail "SERVICE_RESTART_POLICY_DRIFT"
  [ "$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)" = "static" ] || fail "SERVICE_ENABLEMENT_DRIFT"
  ! pgrep -f '[t]u1nz-commercial-s3-runtime' >/dev/null || fail "CANDIDATE_PROCESS_PRESENT"
}

require_active() {
  [ "$(systemctl show "$SERVICE" -p ActiveState --value)" = "active" ] || fail "SERVICE_NOT_ACTIVE"
  [ "$(systemctl show "$SERVICE" -p SubState --value)" = "running" ] || fail "SERVICE_NOT_RUNNING"
  [ "$(systemctl show "$SERVICE" -p MainPID --value)" -gt 0 ] || fail "SERVICE_PROCESS_MISSING"
  [ "$(systemctl show "$SERVICE" -p NRestarts --value)" = "0" ] || fail "SERVICE_RESTART_COUNT_NONZERO"
  [ "$(systemctl show "$SERVICE" -p Restart --value)" = "no" ] || fail "SERVICE_RESTART_POLICY_DRIFT"
}

require_release() {
  local control_sha="$1"
  local control_tree="$2"
  [[ "$control_sha" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
  [[ "$control_tree" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$APPLICATION_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$APPLICATION_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain)" ] || fail "APPLICATION_DIRTY"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$control_sha" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$control_tree" ] || fail "CONTROL_TREE_MISMATCH"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain)" ] || fail "CONTROL_DIRTY"
}

require_backup() {
  case "$1" in
    "${BACKUP_PREFIX}"*) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
  [ -d "$1" ] || fail "BACKUP_PATH_MISSING"
  [ ! -L "$1" ] || fail "BACKUP_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$1")" = "root:root" ] || fail "BACKUP_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$1")" in
    700|2700) ;;
    *) fail "BACKUP_MODE_DRIFT" ;;
  esac
  [ -f "$1/SHA256SUMS" ] || fail "BACKUP_HASH_INDEX_MISSING"
  (cd "$1" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "BACKUP_HASH_INVALID"
}

require_evidence() {
  case "$1" in
    "${BACKUP_PREFIX}"*) ;;
    *) fail "EVIDENCE_PATH_OUTSIDE_BOUNDARY" ;;
  esac
  [ -d "$1" ] || fail "EVIDENCE_PATH_MISSING"
  [ ! -L "$1" ] || fail "EVIDENCE_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$1")" = "root:root" ] || fail "EVIDENCE_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$1")" in
    700|2700) ;;
    *) fail "EVIDENCE_MODE_DRIFT" ;;
  esac
}

require_installed_static_files() {
  [ "$(sha256sum "/etc/systemd/system/$SERVICE" | awk '{print $1}')" = "$UNIT_SHA" ] || fail "UNIT_DRIFT"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" | awk '{print $1}')" = "$RUNTIME_AUTHORIZATION_SHA" ] || fail "RUNTIME_AUTHORIZATION_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s4-provider-readiness.disabled.json" | awk '{print $1}')" = "$PROVIDER_READINESS_SHA" ] || fail "PROVIDER_READINESS_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s4-beta-readiness.disabled.json" | awk '{print $1}')" = "$BETA_READINESS_SHA" ] || fail "BETA_READINESS_DRIFT"
}

require_installed_release_files() {
  require_installed_static_files
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.contract.json" | awk '{print $1}')" = "$DISABLED_CONTRACT_SHA" ] || fail "DISABLED_CONTRACT_DRIFT"
}

require_manifest_go() {
  python3 - "$CONTROL_ROOT/manifests/adult-publishing-commercial-s4-extended-staging.json" "$1" <<'PY' || return 1
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if not (
    value.get("decision") == "GO_FOR_BOUNDED_SERVER_STAGING"
    and value.get("backup_and_rollback", {}).get("path") == sys.argv[2]
    and value.get("authorization", {}).get("bounded_staging_authorized") is True
    and value.get("authorization", {}).get("continuous_staging_authorized") is False
    and value.get("product_boundary", {}).get("provider_calls_enabled") is False
    and value.get("product_boundary", {}).get("adult_media_enabled") is False
    and value.get("product_boundary", {}).get("production_enabled") is False
):
    raise SystemExit(2)
PY
}

require_active_contract() {
  local duration="$1"
  python3 - "$CONFIG_ROOT/adult-commercial-s3.contract.json" "$duration" <<'PY' || return 1
import json
import sys
from datetime import datetime
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
starts = datetime.fromisoformat(value["window_starts_at"].replace("Z", "+00:00"))
ends = datetime.fromisoformat(value["window_ends_at"].replace("Z", "+00:00"))
actual_duration = int((ends - starts).total_seconds())
duration_valid = (
    7200 <= actual_duration <= 21600
    if sys.argv[2] == "bounded"
    else actual_duration == int(sys.argv[2])
)
if not (
    value.get("active") is True
    and value.get("decision") == "GO_FOR_BOUNDED_SERVER_STAGING"
    and value.get("runtime_mode") == "BOUNDED_STAGING"
    and duration_valid
    and value.get("application_sha") == "a745540b81a368b2e5f09d1fcdb49342b686ae0e"
    and value.get("application_tree") == "6e7c869d1194b28baad67698a93ab2254b0d8739"
    and value.get("telegram_intake", {}).get("enabled") is True
    and value.get("telegram_intake", {}).get("expected_bot_id") == 8729546284
    and value.get("telegram_intake", {}).get("expected_bot_username") == "TU1NZ_Adult_Test_bot"
    and value.get("media", {}).get("adult_media_enabled") is False
    and value.get("avs", {}).get("real_provider_enabled") is False
    and value.get("payment", {}).get("real_payment_enabled") is False
    and value.get("publishing", {}).get("external_publish_enabled") is False
    and value.get("production_enabled") is False
):
    raise SystemExit(2)
PY
}

preflight() {
  require_root
  require_stopped
  require_release "$1" "$2"
  require_backup "$3"
  require_manifest_go "$3" || fail "MANIFEST_NOT_GO"
  require_installed_release_files
  printf '{"ok":true,"safe_code":"S4_EXTENDED_STAGING_PREFLIGHT_GREEN","service_started":false}\n'
}

open_window() {
  require_root
  require_stopped
  require_release "$1" "$2"
  require_backup "$3"
  require_manifest_go "$3" || fail "MANIFEST_NOT_GO"
  require_installed_release_files
  require_evidence "$4"
  local duration="$5"
  [ "$duration" -ge 7200 ] 2>/dev/null || fail "DURATION_TOO_SHORT"
  [ "$duration" -le 21600 ] 2>/dev/null || fail "DURATION_TOO_LONG"
  [ ! -e "$4/contract-before.json" ] || fail "WINDOW_ALREADY_PREPARED"
  install -o root -g root -m 0600 "$CONFIG_ROOT/adult-commercial-s3.contract.json" "$4/contract-before.json"
  install -o root -g root -m 0600 "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" "$4/bootstrap-authorization-before.json"
  install -o root -g root -m 0600 "$APPLICATION_ROOT/config/commercial-s4-provider-readiness.disabled.json" "$4/provider-readiness.json"
  install -o root -g root -m 0600 "$APPLICATION_ROOT/config/commercial-s4-beta-readiness.disabled.json" "$4/beta-readiness.json"
  local temporary
  temporary="$(mktemp "$CONFIG_ROOT/.adult-commercial-s3.s4.XXXXXX")"
  restore_failed_window() {
    local status=$?
    rm -f -- "$temporary"
    install -o root -g root -m 0600 "$4/contract-before.json" "$CONFIG_ROOT/adult-commercial-s3.contract.json"
    install -o root -g root -m 0600 "$4/bootstrap-authorization-before.json" "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
    exit "$status"
  }
  trap restore_failed_window EXIT
  python3 - "$APPLICATION_ROOT/config/commercial-s3-staging.disabled.json" "$temporary" "$(basename "$4")" "$duration" <<'PY'
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

source, target = Path(sys.argv[1]), Path(sys.argv[2])
identifier, duration = sys.argv[3], int(sys.argv[4])
value = json.loads(source.read_text(encoding="ascii"))
now = datetime.now(timezone.utc).replace(microsecond=0)
value["activation_id"] = "s4-" + identifier.lower()
value["active"] = True
value["application_sha"] = "a745540b81a368b2e5f09d1fcdb49342b686ae0e"
value["application_tree"] = "6e7c869d1194b28baad67698a93ab2254b0d8739"
value["decision"] = "GO_FOR_BOUNDED_SERVER_STAGING"
value["runtime_mode"] = "BOUNDED_STAGING"
value["telegram_intake"]["enabled"] = True
value["telegram_intake"]["expected_bot_id"] = 8729546284
value["telegram_intake"]["expected_bot_username"] = "TU1NZ_Adult_Test_bot"
value["window_starts_at"] = now.isoformat().replace("+00:00", "Z")
value["window_ends_at"] = (now + timedelta(seconds=duration)).isoformat().replace("+00:00", "Z")
material = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
with target.open("wb") as handle:
    handle.write(material)
    handle.flush()
    os.fsync(handle.fileno())
PY
  chmod 0600 "$temporary"
  chown root:root "$temporary"
  mv -T -- "$temporary" "$CONFIG_ROOT/adult-commercial-s3.contract.json"
  temporary=""
  install -o root -g root -m 0600 \
    "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s4-runtime-release-authorization.json" \
    "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
  require_active_contract "$duration" || fail "ACTIVE_CONTRACT_INVALID"
  trap - EXIT
  {
    printf 'opened_at=%s\n' "$(date -u +%FT%TZ)"
    printf 'duration_seconds=%s\n' "$duration"
    printf 'active_contract_sha256=%s\n' "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.contract.json" | awk '{print $1}')"
    printf 'runtime_release_authorization_sha256=%s\n' "$RUNTIME_AUTHORIZATION_SHA"
  } >"$4/window-open.txt"
  chmod 0600 "$4/window-open.txt"
  printf '{"ok":true,"safe_code":"S4_EXTENDED_STAGING_WINDOW_OPEN","service_started":false}\n'
}

close_window() {
  require_root
  require_stopped
  require_evidence "$1"
  [ -f "$1/contract-before.json" ] || fail "CONTRACT_RECOVERY_MISSING"
  [ -f "$1/bootstrap-authorization-before.json" ] || fail "BOOTSTRAP_RECOVERY_MISSING"
  [ "$(sha256sum "$1/contract-before.json" | awk '{print $1}')" = "$DISABLED_CONTRACT_SHA" ] || fail "CONTRACT_RECOVERY_DRIFT"
  [ "$(sha256sum "$1/bootstrap-authorization-before.json" | awk '{print $1}')" = "$RUNTIME_AUTHORIZATION_SHA" ] || fail "BOOTSTRAP_RECOVERY_DRIFT"
  install -o root -g root -m 0600 "$1/contract-before.json" "$CONFIG_ROOT/adult-commercial-s3.contract.json"
  install -o root -g root -m 0600 "$1/bootstrap-authorization-before.json" "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
  require_installed_release_files
  printf 'closed_at=%s\nrestored_contract_sha256=%s\nrestored_runtime_authorization_sha256=%s\n' \
    "$(date -u +%FT%TZ)" "$DISABLED_CONTRACT_SHA" "$RUNTIME_AUTHORIZATION_SHA" >"$1/window-close.txt"
  chmod 0600 "$1/window-close.txt"
  finalize_evidence "$1"
  printf '{"ok":true,"safe_code":"S4_EXTENDED_STAGING_WINDOW_CLOSED","service_started":false}\n'
}

finalize_evidence() {
  require_root
  require_stopped
  require_evidence "$1"
  [ -f "$1/window-close.txt" ] || fail "WINDOW_CLOSE_EVIDENCE_MISSING"
  local temporary
  temporary="$(mktemp /run/tu1nz-s4-evidence.XXXXXX)"
  (
    cd "$1"
    find . -maxdepth 1 -type f ! -name EVIDENCE-SHA256SUMS -print0 \
      | sort -z \
      | xargs -0 sha256sum >"$temporary"
  )
  install -o root -g root -m 0600 "$temporary" "$1/EVIDENCE-SHA256SUMS"
  rm -f -- "$temporary"
  (cd "$1" && sha256sum --check --strict EVIDENCE-SHA256SUMS >/dev/null) \
    || fail "EVIDENCE_HASH_INVALID"
}

await_readiness() {
  require_root
  require_release "$1" "$2"
  require_backup "$3"
  require_manifest_go "$3" || fail "MANIFEST_NOT_GO"
  require_installed_static_files
  require_active_contract bounded || fail "ACTIVE_CONTRACT_INVALID"
  require_evidence "$4"
  local maximum="$5"
  [ "$maximum" -ge 30 ] 2>/dev/null || fail "READINESS_WAIT_TOO_SHORT"
  [ "$maximum" -le 120 ] 2>/dev/null || fail "READINESS_WAIT_TOO_LONG"
  local deadline=$((SECONDS + maximum))
  local output status
  while [ "$SECONDS" -le "$deadline" ]; do
    require_active
    set +e
    output="$(python3 - "$STATE_ROOT/evidence" "$STATE_ROOT/status.json" "$4/window-open.txt" <<'PY'
import json
import sys
from pathlib import Path

startup_root, health_path, marker_path = map(Path, sys.argv[1:])
marker = marker_path.stat().st_mtime_ns
candidates = [
    path for path in startup_root.glob("startup-*.summary.json")
    if path.stat().st_mtime_ns >= marker
]
if not candidates:
    raise SystemExit(3)
summary_path = max(candidates, key=lambda path: path.stat().st_mtime_ns)
summary = json.loads(summary_path.read_text(encoding="ascii"))
if not (
    summary.get("state") == "READY"
    and summary.get("ready") is True
    and summary.get("last_completed_phase") == "18_READY"
    and summary.get("failed_phase") is None
):
    raise SystemExit(3)
health = json.loads(health_path.read_text(encoding="ascii"))
components = health.get("components", {})
if not (
    health.get("state") == "GREEN"
    and components.get("AVS_CONFIG") == "DISABLED_EXPECTED"
    and components.get("AVS_NETWORK") == "DISABLED_EXPECTED"
    and components.get("PAYMENT_CONFIG") == "DISABLED_EXPECTED"
    and components.get("PAYMENT_NETWORK") == "DISABLED_EXPECTED"
):
    raise SystemExit(3)
print('{"ok":true,"safe_code":"S4_RUNTIME_PHASE_18_READY","health":"GREEN"}')
PY
)"
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      printf '%s\n' "$output" | tee "$4/readiness.txt"
      chmod 0600 "$4/readiness.txt"
      return 0
    fi
    [ "$status" -eq 3 ] || fail "READINESS_EVIDENCE_INVALID"
    sleep 2
  done
  fail "READINESS_TIMEOUT"
}

fresh_prestart() {
  require_root
  require_stopped
  require_release "$1" "$2"
  require_backup "$3"
  require_manifest_go "$3" || fail "MANIFEST_NOT_GO"
  require_installed_static_files
  require_active_contract bounded || fail "ACTIVE_CONTRACT_INVALID"
  local output
  set +e
  output="$(systemd-run --quiet --wait --collect --pipe --unit="$PRESTART_SERVICE" \
    --property=Type=exec \
    --property=User=chatops --property=Group=chatops \
    --property=WorkingDirectory="$APPLICATION_ROOT" \
    --property=LoadCredential="postgres-dsn:$CONFIG_ROOT/adult-commercial-s3.postgres-dsn" \
    --property=LoadCredential="subject-key:$CONFIG_ROOT/adult-commercial-s3.subject-key" \
    --property=LoadCredential="staging-contract:$CONFIG_ROOT/adult-commercial-s3.contract.json" \
    --property=LoadCredential="allowlist:$CONFIG_ROOT/adult-commercial-s3.allowlist.json" \
    --property=LoadCredential="media-manifest:$CONFIG_ROOT/adult-commercial-s3.media-manifest.json" \
    --property=LoadCredential="bootstrap-manifest:$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" \
    --property=Restart=no --property=RuntimeMaxSec=120 \
    --property=TimeoutStartSec=60 --property=TimeoutStopSec=30 \
    --property=KillSignal=SIGTERM --property=UMask=0077 \
    --property=NoNewPrivileges=true --property=PrivateDevices=true \
    --property=PrivateTmp=true --property=ProtectHome=true \
    --property=ProtectSystem=strict --property=ProtectControlGroups=true \
    --property=ProtectKernelModules=true --property=ProtectKernelTunables=true \
    --property=ProtectKernelLogs=true --property=LockPersonality=true \
    --property=MemoryDenyWriteExecute=true --property=RestrictSUIDSGID=true \
    --property=RestrictRealtime=true --property=RestrictNamespaces=true \
    --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    --property=IPAddressDeny=any --property=IPAddressAllow=localhost \
    --property="ReadOnlyPaths=$APPLICATION_ROOT $CONFIG_ROOT" \
    --property="ReadWritePaths=/var/lib/tausendunde1nz/adult-commercial-s3 /var/log/tausendunde1nz" \
    "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-prestart" \
      --contract "$PRESTART_CREDENTIAL_ROOT/staging-contract" \
      --allowlist "$PRESTART_CREDENTIAL_ROOT/allowlist" \
      --media-manifest "$PRESTART_CREDENTIAL_ROOT/media-manifest" \
      --bootstrap-manifest "$PRESTART_CREDENTIAL_ROOT/bootstrap-manifest" \
      --bootstrap-reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
      --migration-directory "$APPLICATION_ROOT/migrations" \
      --state-directory /var/lib/tausendunde1nz/adult-commercial-s3 2>&1)"
  local status=$?
  set -e
  [ "$status" -eq 0 ] || { printf '%s\n' "$output" >&2; fail "FRESH_PRESTART_EXECUTION_FAILED"; }
  grep -q '"safe_code":"S3_PRESTART_READY"' <<<"$output" || fail "FRESH_PRESTART_NOT_READY"
  grep -q '"service_started":false' <<<"$output" || fail "FRESH_PRESTART_STARTED_SERVICE"
  require_stopped
  printf '%s\n' "$output"
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 4 ] || fail "USAGE_PREFLIGHT"
    preflight "$2" "$3" "$4"
    ;;
  open-window)
    [ "$#" -eq 6 ] || fail "USAGE_OPEN_WINDOW"
    open_window "$2" "$3" "$4" "$5" "$6"
    ;;
  close-window)
    [ "$#" -eq 2 ] || fail "USAGE_CLOSE_WINDOW"
    close_window "$2"
    ;;
  fresh-prestart)
    [ "$#" -eq 4 ] || fail "USAGE_FRESH_PRESTART"
    fresh_prestart "$2" "$3" "$4"
    ;;
  await-readiness)
    [ "$#" -eq 6 ] || fail "USAGE_AWAIT_READINESS"
    await_readiness "$2" "$3" "$4" "$5" "$6"
    ;;
  finalize-evidence)
    [ "$#" -eq 2 ] || fail "USAGE_FINALIZE_EVIDENCE"
    finalize_evidence "$2"
    printf '{"ok":true,"safe_code":"S4_EVIDENCE_FINALIZED"}\n'
    ;;
  *) fail "UNKNOWN_ACTION" ;;
esac
