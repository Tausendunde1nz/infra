#!/usr/bin/env bash
set -euo pipefail

readonly SERVICE="tu1nz-adult-commercial-s3.service"
readonly PROBE_SERVICE="tu1nz-adult-commercial-s3-probe.service"
readonly PRESTART_SERVICE="tu1nz-adult-commercial-s3-prestart.service"
readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-commercial-s3"
readonly CONFIG_ROOT="/etc/tu1nz"
readonly BASELINE="/opt/tu1nz_repos/backups/commercial-s3-1-fix/20260829T13-56-54Z"
readonly APPLICATION_SHA="69c70b58814f19db5869bed458b180025060aeb3"
readonly APPLICATION_TREE="b5bb4cf55ede2dc14987bcfc362e8079ecc21302"
readonly PROBE_CREDENTIAL_ROOT="/run/credentials/$PROBE_SERVICE"
readonly PRESTART_CREDENTIAL_ROOT="/run/credentials/$PRESTART_SERVICE"
readonly DISABLED_CONTRACT_SHA="504cd844bba8fe733e2beb8c734f3757c22fea06e3958c8d5cb95f3f00672fef"
readonly S3_1_BOOTSTRAP_AUTHORIZATION_SHA="a7907f27a52c5992ac30af1c32929b1c3ed2a10f2ba0e74e07577ca835c68fc5"
readonly S3_2_RUNTIME_AUTHORIZATION_SHA="cdd6c7e7c977cfafceebf110a1460300f944c6f926fcf473da8d3d1e4f6c9591"
readonly EVIDENCE_PREFIX="/opt/tu1nz_repos/backups/commercial-s3-server-staging/"

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

require_evidence() {
  case "$1" in
    "${EVIDENCE_PREFIX}"*) ;;
    *) fail "EVIDENCE_PATH_OUTSIDE_BOUNDARY" ;;
  esac
  [ -d "$1" ] || fail "EVIDENCE_PATH_MISSING"
  [ ! -L "$1" ] || fail "EVIDENCE_PATH_SYMLINK"
  [ "$(stat -c '%U:%G' "$1")" = "root:root" ] || fail "EVIDENCE_PATH_OWNERSHIP_DRIFT"
  case "$(stat -c '%a' "$1")" in
    700|2700) ;;
    *) fail "EVIDENCE_PATH_MODE_DRIFT" ;;
  esac
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
    and value.get("application_sha") == "69c70b58814f19db5869bed458b180025060aeb3"
    and value.get("application_tree") == "b5bb4cf55ede2dc14987bcfc362e8079ecc21302"
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

open_window() {
  require_root
  require_stopped
  require_baseline
  require_release "$1" "$2"
  local evidence="$3"
  require_evidence "$evidence"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.contract.json" | awk '{print $1}')" = "$DISABLED_CONTRACT_SHA" ] || fail "DISABLED_CONTRACT_DRIFT"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" | awk '{print $1}')" = "$S3_1_BOOTSTRAP_AUTHORIZATION_SHA" ] || fail "BOOTSTRAP_AUTHORIZATION_DRIFT"
  [ "$(sha256sum "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-runtime-release-authorization.s3-2.json" | awk '{print $1}')" = "$S3_2_RUNTIME_AUTHORIZATION_SHA" ] || fail "RUNTIME_AUTHORIZATION_SOURCE_DRIFT"
  [ ! -e "$evidence/contract-before.json" ] || fail "WINDOW_ALREADY_PREPARED"
  install -o root -g root -m 0600 "$CONFIG_ROOT/adult-commercial-s3.contract.json" "$evidence/contract-before.json"
  install -o root -g root -m 0600 "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" "$evidence/bootstrap-authorization-before.json"
  local temporary
  temporary="$(mktemp "$CONFIG_ROOT/.adult-commercial-s3.s3-2.XXXXXX")"
  restore_failed_window() {
    local status=$?
    rm -f -- "$temporary"
    install -o root -g root -m 0600 "$evidence/contract-before.json" "$CONFIG_ROOT/adult-commercial-s3.contract.json"
    install -o root -g root -m 0600 "$evidence/bootstrap-authorization-before.json" "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
    exit "$status"
  }
  trap restore_failed_window EXIT
  python3 - "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-staging.disabled.json" "$temporary" "$(basename "$evidence")" <<'PY'
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

source, target, identifier = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
value = json.loads(source.read_text(encoding="ascii"))
now = datetime.now(timezone.utc).replace(microsecond=0)
value["activation_id"] = "s3-s32-" + identifier.lower()
value["active"] = True
value["application_sha"] = "69c70b58814f19db5869bed458b180025060aeb3"
value["application_tree"] = "b5bb4cf55ede2dc14987bcfc362e8079ecc21302"
value["decision"] = "GO_FOR_BOUNDED_SERVER_STAGING"
value["telegram_intake"]["enabled"] = True
value["telegram_intake"]["expected_bot_id"] = 8729546284
value["telegram_intake"]["expected_bot_username"] = "TU1NZ_Adult_Test_bot"
value["window_starts_at"] = now.isoformat().replace("+00:00", "Z")
value["window_ends_at"] = (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
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
    "$CONTROL_ROOT/config/adult-publishing/staging-s3/commercial-s3-runtime-release-authorization.s3-2.json" \
    "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" | awk '{print $1}')" = "$S3_2_RUNTIME_AUTHORIZATION_SHA" ] || fail "RUNTIME_AUTHORIZATION_INSTALL_DRIFT"
  require_active_contract || fail "ACTIVE_CONTRACT_INVALID"
  trap - EXIT
  {
    printf 'opened_at=%s\n' "$(date -u +%FT%TZ)"
    printf 'active_contract_sha256=%s\n' "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.contract.json" | awk '{print $1}')"
    printf 'disabled_contract_sha256=%s\n' "$DISABLED_CONTRACT_SHA"
    printf 'runtime_release_authorization_sha256=%s\n' "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" | awk '{print $1}')"
  } >"$evidence/window-open.txt"
  chmod 0600 "$evidence/window-open.txt"
  printf '{"ok":true,"safe_code":"S3_2_DIAGNOSTIC_WINDOW_OPEN","service_started":false}\n'
}

close_window() {
  require_root
  require_stopped
  local evidence="$1"
  require_evidence "$evidence"
  [ -f "$evidence/contract-before.json" ] || fail "CONTRACT_RECOVERY_MISSING"
  [ -f "$evidence/bootstrap-authorization-before.json" ] || fail "BOOTSTRAP_AUTHORIZATION_RECOVERY_MISSING"
  [ "$(sha256sum "$evidence/contract-before.json" | awk '{print $1}')" = "$DISABLED_CONTRACT_SHA" ] || fail "CONTRACT_RECOVERY_DRIFT"
  [ "$(sha256sum "$evidence/bootstrap-authorization-before.json" | awk '{print $1}')" = "$S3_1_BOOTSTRAP_AUTHORIZATION_SHA" ] || fail "BOOTSTRAP_AUTHORIZATION_RECOVERY_DRIFT"
  install -o root -g root -m 0600 "$evidence/contract-before.json" "$CONFIG_ROOT/adult-commercial-s3.contract.json"
  install -o root -g root -m 0600 "$evidence/bootstrap-authorization-before.json" "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.contract.json" | awk '{print $1}')" = "$DISABLED_CONTRACT_SHA" ] || fail "CONTRACT_RESTORE_FAILED"
  [ "$(sha256sum "$CONFIG_ROOT/adult-commercial-s3.bootstrap-manifest.json" | awk '{print $1}')" = "$S3_1_BOOTSTRAP_AUTHORIZATION_SHA" ] || fail "BOOTSTRAP_AUTHORIZATION_RESTORE_FAILED"
  printf 'closed_at=%s\nrestored_contract_sha256=%s\nrestored_bootstrap_authorization_sha256=%s\n' \
    "$(date -u +%FT%TZ)" "$DISABLED_CONTRACT_SHA" "$S3_1_BOOTSTRAP_AUTHORIZATION_SHA" >"$evidence/window-close.txt"
  chmod 0600 "$evidence/window-close.txt"
  printf '{"ok":true,"safe_code":"S3_2_DIAGNOSTIC_WINDOW_CLOSED","service_started":false}\n'
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

fresh_prestart() {
  require_root
  require_stopped
  require_baseline
  require_release "$1" "$2"
  require_active_contract || fail "ACTIVE_CONTRACT_INVALID"
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
    --property="ReadWritePaths=$STATE_ROOT /var/log/tausendunde1nz" \
    "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s3-prestart" \
      --contract "$PRESTART_CREDENTIAL_ROOT/staging-contract" \
      --allowlist "$PRESTART_CREDENTIAL_ROOT/allowlist" \
      --media-manifest "$PRESTART_CREDENTIAL_ROOT/media-manifest" \
      --bootstrap-manifest "$PRESTART_CREDENTIAL_ROOT/bootstrap-manifest" \
      --bootstrap-reference "$APPLICATION_ROOT/config/commercial-s3-bootstrap-reference.json" \
      --migration-directory "$APPLICATION_ROOT/migrations" \
      --state-directory "$STATE_ROOT" 2>&1)"
  local status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output" >&2
    fail "FRESH_PRESTART_EXECUTION_FAILED"
  fi
  grep -q '"safe_code":"S3_PRESTART_READY"' <<<"$output" || fail "FRESH_PRESTART_NOT_READY"
  grep -q '"service_started":false' <<<"$output" || fail "FRESH_PRESTART_STARTED_SERVICE"
  require_stopped
  printf '%s\n' "$output"
}

case "${1:-}" in
  preflight)
    [ "$#" -eq 3 ] || fail "ARGUMENT_COUNT"
    preflight "$2" "$3"
    ;;
  open-window)
    [ "$#" -eq 4 ] || fail "ARGUMENT_COUNT"
    open_window "$2" "$3" "$4"
    ;;
  close-window)
    [ "$#" -eq 2 ] || fail "ARGUMENT_COUNT"
    close_window "$2"
    ;;
  probe)
    [ "$#" -eq 3 ] || fail "ARGUMENT_COUNT"
    probe "$2" "$3"
    ;;
  fresh-prestart)
    [ "$#" -eq 3 ] || fail "ARGUMENT_COUNT"
    fresh_prestart "$2" "$3"
    ;;
  *)
    fail "UNKNOWN_ACTION"
    ;;
esac
