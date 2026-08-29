#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly PROBE_SERVICE="tu1nz-adult-commercial-s3-probe.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-commercial-s3"
readonly CONFIG_ROOT="/etc/tu1nz"
readonly BASELINE="/opt/tu1nz_repos/backups/commercial-s3-1-fix/20260829T13-56-54Z"
readonly APPLICATION_SHA="9f82e3c682a0f59a4675cca568058a3779a4a4ed"
readonly APPLICATION_TREE="759cc536298901ae1ee57fa9de3e7ec177d357c3"
readonly PROBE_CREDENTIAL_ROOT="/run/credentials/$PROBE_SERVICE"

fail() {
  printf 'S3_2_PROBE_RED %s\n' "$1" >&2
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
  [ "$(systemctl show "$SERVICE" -p ExecMainPID --value)" = "0" ] || fail "SERVICE_PROCESS_PRESENT"
  [ "$(systemctl show "$SERVICE" -p Restart --value)" = "no" ] || fail "SERVICE_RESTART_POLICY_DRIFT"
  [ "$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)" = "static" ] || fail "SERVICE_ENABLEMENT_DRIFT"
  ! pgrep -f '[t]u1nz-commercial-s3-runtime' >/dev/null || fail "CANDIDATE_PROCESS_PRESENT"
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

require_baseline() {
  [ -d "$BASELINE" ] || fail "BASELINE_MISSING"
  [ -f "$BASELINE/SHA256SUMS" ] || fail "BASELINE_HASH_INDEX_MISSING"
  [ -f "$BASELINE/FINAL-SHA256SUMS" ] || fail "BASELINE_FINAL_INDEX_MISSING"
  (cd "$BASELINE" && sha256sum --check --strict SHA256SUMS >/dev/null) || fail "BASELINE_HASH_INVALID"
  (cd "$BASELINE" && sha256sum --check --strict FINAL-SHA256SUMS >/dev/null) || fail "BASELINE_FINAL_HASH_INVALID"
}

require_active_contract() {
  python3 - "$CONFIG_ROOT/adult-commercial-s3.contract.json" <<'PY' || return 1
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
if not (
    value.get("active") is True
    and value.get("decision") == "GO_FOR_BOUNDED_SERVER_STAGING"
    and value.get("application_sha") == "9f82e3c682a0f59a4675cca568058a3779a4a4ed"
    and value.get("application_tree") == "759cc536298901ae1ee57fa9de3e7ec177d357c3"
    and value.get("telegram_intake", {}).get("enabled") is True
    and value.get("telegram_intake", {}).get("expected_bot_id") == 8729546284
    and value.get("telegram_intake", {}).get("expected_bot_username") == "TU1NZ_Adult_Test_bot"
    and value.get("media", {}).get("adult_media_enabled") is False
    and value.get("payment", {}).get("provider") == "MOCK"
    and value.get("publishing", {}).get("external_publish_enabled") is False
    and value.get("production_enabled") is False
):
    raise SystemExit(2)
PY
}

preflight() {
  require_root
  require_stopped
  require_baseline
  require_release "$1" "$2"
  [ ! -e "/run/systemd/transient/$PROBE_SERVICE" ] || fail "STALE_TRANSIENT_PROBE"
  printf '{"ok":true,"safe_code":"S3_2_PROBE_PREFLIGHT_GREEN","service_started":false}\n'
}

probe() {
  require_root
  require_stopped
  require_baseline
  require_release "$1" "$2"
  require_active_contract || fail "ACTIVE_CONTRACT_INVALID"
  local marker
  marker="$(mktemp "$STATE_ROOT/evidence/.s3-2-probe-marker.XXXXXX")"
  chown chatops:chatops "$marker"
  chmod 0600 "$marker"
  set +e
  systemd-run --quiet --wait --collect --pipe --unit="$PROBE_SERVICE" \
    --property=Type=exec \
    --property=User=chatops --property=Group=chatops \
    --property=WorkingDirectory="$APPLICATION_ROOT" \
    --property=LoadCredential="telegram-token:$CONFIG_ROOT/adult-commercial-s3.telegram-token" \
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
    --property="ReadOnlyPaths=$APPLICATION_ROOT $CONFIG_ROOT" \
    --property="ReadWritePaths=$STATE_ROOT /var/log/tausendunde1nz" \
    "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-runtime" \
      --contract "$PROBE_CREDENTIAL_ROOT/staging-contract" \
      --allowlist "$PROBE_CREDENTIAL_ROOT/allowlist" \
      --media-manifest "$PROBE_CREDENTIAL_ROOT/media-manifest" \
      --bootstrap-manifest "$PROBE_CREDENTIAL_ROOT/bootstrap-manifest" \
      --bootstrap-reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
      --migration-directory "$APPLICATION_ROOT/migrations" \
      --state-directory "$STATE_ROOT" --startup-probe
  local status=$?
  set -e
  local summary
  summary="$(find "$STATE_ROOT/evidence" -maxdepth 1 -type f -name 'startup-*.summary.json' -newer "$marker" -print -quit)"
  rm -f -- "$marker"
  [ -n "$summary" ] || fail "PROBE_SUMMARY_MISSING"
  python3 - "$summary" "$status" <<'PY' || exit 2
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
status = int(sys.argv[2])
if not (
    status == 0
    and value.get("state") == "STARTING"
    and value.get("last_completed_phase") == "17_HEALTH_INITIALIZE"
    and value.get("failed_phase") is None
    and value.get("ready") is False
):
    raise SystemExit(2)
PY
  require_stopped
  printf '{"ok":true,"safe_code":"S3_2_STARTUP_PROBE_GREEN","product_polling":false,"ready":false}\n'
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 3 ] || fail "ARGUMENT_COUNT"
    preflight "$2" "$3"
    ;;
  probe)
    [ "$#" -eq 3 ] || fail "ARGUMENT_COUNT"
    probe "$2" "$3"
    ;;
  *)
    fail "UNKNOWN_ACTION"
    ;;
esac
