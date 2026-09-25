#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly AGGREGATE_STATE="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly QUALITY_STATE="/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json"
readonly SOURCE_APPLICATION_COMMIT="77f9079956a42ee411e17f5697da96f6810ba966"
readonly SOURCE_APPLICATION_TREE="370001f8ce0491ddf7709c2cee16d452d6098721"
readonly SOURCE_CONTROL_COMMIT="7c634d3b82572e8459d51c69f04dce82c624d766"
readonly SOURCE_CONTROL_TREE="1bfbd80d5478dd24f8f3e47d3654a8b7dea649e4"
readonly TARGET_APPLICATION_COMMIT="84619ea0204aeb4b133fe6491f3315beccd635ae"
readonly TARGET_APPLICATION_TREE="8f90cfc39b038e6438a6ee6bf2b96c029c4ebbab"
readonly FINAL_CONTROL_TAG="s11-2-r15-4-runtime-access-freeze-r1"
readonly CONTROLLER_UNIT_SHA="afa0ea4801404b34483adde8c63289b0b05f9b3392b2821fda0c1c52c1a22031"
readonly RETIRED_S8_HEALTH_TIMER_SHA="42f1d9ce275a84406ddc9501fa5431c65be0f01e65f4cc59d72d39a8ae700005"
readonly ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"
readonly RUNTIME_RELEASE_ID="s10-2d-r3-5"
readonly EXPERIENCE_RELEASE_ID="s11-2-canary-bootstrap-r1"
readonly EXPERIENCE_CONTRACT_SHA="faf4fe20887f7b9d7b31d8f35518db1dea2faa861c84acd791f9f0a739db425d"
readonly EXPERIENCE_COPY_SHA="bd842016355f7efd7dfdceedbe89e6e7ea0c7ada09dfe5587b37ad4e42abc972"
readonly SYNTHETIC_CONTRACT_SHA="2b9bffc4e485d825dd0e266183bd203fa5a31e876814d8ec2685ae4cc7544bfc"
readonly MIGRATION_UP_SHA="97cca3f1a59ec125ef621cdb79ce85931682011ec88ad0b5f164617767f68e77"
readonly MIGRATION_DOWN_SHA="4514d3b91dc3924b54116b216baa32896c7091ce4fd114dded62fbe6f1a1917b"
readonly MIGRATION_REARM_UP_SHA="8d2d293c1f382bb5f726624c5dbe24e85b8f5c47a037b0d1bb52726d3fc23621"
readonly MIGRATION_REARM_DOWN_SHA="ca1a286f042f685d7a48d6db1231d7a816973c5496da2702d9562958965f3d73"
readonly WMS_LANDING_COPY_SHA="86b07436a51fded974286f5a2fbbd60b93b5ae175fc9106c63136f5462da53b2"
readonly EXPERIENCE_CONTRACT="/etc/tu1nz/adult-commercial-s11-interactive-experience.json"
readonly EXPERIENCE_COPY="/etc/tu1nz/adult-commercial-s11-interactive-copy.json"
readonly WMS_CONTRACT="/etc/tu1nz/adult-commercial-s10-wms.json"
readonly WMS_LANDING_COPY="/etc/tu1nz/adult-commercial-s10-wms-copy.json"
readonly WMS_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly LOCAL_WMS_HEALTH="http://127.0.0.1:18110/health"
readonly WMS_BOT_CONTRACT="/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json"
readonly COMMUNITY_CONTRACT="/etc/tu1nz/adult-commercial-s10-2d-community.json"
readonly S8_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-telegram.service"
readonly S8_HEALTH_UNIT="/etc/systemd/system/tu1nz-adult-public-s8-health.service"
readonly S8_HEALTH_SCRIPT="/usr/local/bin/tu1nz_adult_public_s8_health.py"
readonly INSTALLED_CONTROLLER="/usr/local/bin/tu1nz_adult_public_s11_2_control.sh"
readonly INSTALLED_GATE="/usr/local/bin/tu1nz_adult_public_s11_2_gate.py"
readonly APPLICATION_RUNTIME_PYTHON="${APPLICATION_ROOT}/.venv/bin/python"
readonly RUNTIME_ACCESS_MANIFEST="/etc/tu1nz/adult-commercial-s11-2-runtime-access.json"
readonly CONTROLLER_UNIT="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service"
readonly CONTROLLER_TIMER="/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly RETIRED_S8_HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"
readonly RETIRED_S8_HEALTH_TIMER_PATH="/etc/systemd/system/${RETIRED_S8_HEALTH_TIMER}"
readonly SERVICES=(
  tu1nz-adult-public-s7.service
  tu1nz-adult-public-s8-landing.service
  tu1nz-adult-public-s8-telegram.service
  tu1nz-adult-public-s10-wms.service
  nginx.service
)
readonly TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
  tu1nz-adult-public-s9-health.timer
  tu1nz-adult-public-s10-health.timer
)

fail() {
  printf '{"ok":false,"safe_code":"%s"}\n' "$1" >&2
  return 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "S11_2_ROOT_REQUIRED"
}

acquire_lock() {
  exec 9> /run/tu1nz-adult-public-s11-2-control.lock
  flock -n 9 || fail "S11_2_CONTROL_ALREADY_RUNNING"
}

release_lock() {
  flock -u 9
  exec 9>&-
}

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "S11_2_SHA_INVALID"
}

require_backup_path() {
  [[ "$1" =~ ^/opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/[0-9]{8}T[0-9]{6}Z-predeploy$ ]] \
    || fail "S11_2_BACKUP_PATH_INVALID"
}

git_chatops() {
  local repository="$1"
  shift
  runuser -u chatops -- git -C "$repository" "$@"
}

remote_ref() {
  git_chatops "$1" ls-remote origin "$2" | awk 'NR == 1 {print $1}'
}

require_clean_commit() {
  local repository="$1" expected_commit="$2" expected_tree="$3" code="$4"
  [ "$(git_chatops "$repository" rev-parse HEAD)" = "$expected_commit" ] \
    || { fail "S11_2_${code}_COMMIT_DRIFT"; return 2; }
  [ "$(git_chatops "$repository" rev-parse 'HEAD^{tree}')" = "$expected_tree" ] \
    || { fail "S11_2_${code}_TREE_DRIFT"; return 2; }
  [ -z "$(git_chatops "$repository" status --porcelain)" ] \
    || { fail "S11_2_${code}_WORKTREE_DIRTY"; return 2; }
}

target_control_commit() {
  git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${FINAL_CONTROL_TAG}^{commit}"
}

target_control_tree() {
  git_chatops "$CONTROL_ROOT" rev-parse "refs/tags/${FINAL_CONTROL_TAG}^{commit}^{tree}"
}

require_remote_target() {
  local target_control="$1"
  [ "$(remote_ref "$APPLICATION_ROOT" refs/heads/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_2_REMOTE_APPLICATION_DRIFT"
  [ "$(remote_ref "$CONTROL_ROOT" "refs/tags/${FINAL_CONTROL_TAG}^{}")" = "$target_control" ] \
    || fail "S11_2_REMOTE_FREEZE_DRIFT"
}

require_local_freeze() {
  local target_control="$1" control_tree controller_sha gate_sha timer_sha
  [ "$(git_chatops "$CONTROL_ROOT" cat-file -t "refs/tags/${FINAL_CONTROL_TAG}")" = tag ] \
    || { fail "S11_2_FREEZE_NOT_ANNOTATED"; return 2; }
  [ "$(target_control_commit)" = "$target_control" ] \
    || { fail "S11_2_FREEZE_COMMIT_DRIFT"; return 2; }
  control_tree="$(target_control_tree)"
  controller_sha="$(git_chatops "$CONTROL_ROOT" show "${target_control}:scripts/tu1nz_adult_public_s11_2_control.sh" | sha256sum | awk '{print $1}')"
  gate_sha="$(git_chatops "$CONTROL_ROOT" show "${target_control}:scripts/tu1nz_adult_public_s11_2_gate.py" | sha256sum | awk '{print $1}')"
  timer_sha="$(git_chatops "$CONTROL_ROOT" show "${target_control}:systemd/tu1nz-adult-public-s11-canary-controller.timer" | sha256sum | awk '{print $1}')"
  [ "$(git_chatops "$CONTROL_ROOT" show "${target_control}:systemd/tu1nz-adult-public-s11-canary-controller.service" | sha256sum | awk '{print $1}')" = "$CONTROLLER_UNIT_SHA" ] \
    || { fail "S11_2_FREEZE_UNIT_HASH_RED"; return 2; }
  for binding in \
    "application_commit=${TARGET_APPLICATION_COMMIT}" \
    "application_tree=${TARGET_APPLICATION_TREE}" \
    "control_commit=${target_control}" \
    "control_tree=${control_tree}" \
    "runtime_controller_sha256=${controller_sha}" \
    "runtime_gate_sha256=${gate_sha}" \
    "controller_unit_sha256=${CONTROLLER_UNIT_SHA}" \
    "controller_timer_sha256=${timer_sha}" \
    "runtime_access_contract=SOURCE_CHATOPS_RUNTIME_INSTALLED_V1" \
    "umask_077_regression=GREEN" \
    "supplementary_groups=chatops" \
    "canary_contract=FIRST_10_24H_EPOCH_BOUND" \
    "promotion_contract=FIVE_REAL_AND_TECHNICAL_SLO_GREEN"
  do
    git_chatops "$CONTROL_ROOT" for-each-ref --format='%(contents)' "refs/tags/${FINAL_CONTROL_TAG}" \
      | grep -Fqx "$binding" \
      || { fail "S11_2_FREEZE_PROVENANCE_RED"; return 2; }
  done
}

source_access_check() {
  local source_controller="${CONTROL_ROOT}/scripts/tu1nz_adult_public_s11_2_control.sh"
  runuser -u chatops -- test -r "$source_controller" \
    || fail "S11_2_SOURCE_CONTROLLER_READ_RED"
  runuser -u chatops -- test -x "$source_controller" \
    || fail "S11_2_SOURCE_CONTROLLER_EXECUTE_RED"
  git_chatops "$APPLICATION_ROOT" rev-parse --verify HEAD >/dev/null \
    || fail "S11_2_SOURCE_APPLICATION_GIT_READ_RED"
  git_chatops "$CONTROL_ROOT" rev-parse --verify HEAD >/dev/null \
    || fail "S11_2_SOURCE_CONTROL_GIT_READ_RED"
  [ -z "$(git_chatops "$APPLICATION_ROOT" status --porcelain)" ] \
    || fail "S11_2_SOURCE_APPLICATION_DIRTY"
  [ -z "$(git_chatops "$CONTROL_ROOT" status --porcelain)" ] \
    || fail "S11_2_SOURCE_CONTROL_DIRTY"
  printf '{"ok":true,"safe_code":"S11_2_SOURCE_ACCESS_AS_CHATOPS_GREEN"}\n'
}

artifact_sha_from_git() {
  git_chatops "$1" show "${2}:${3}" | sha256sum | awk '{print $1}'
}

install_runtime_access_manifest() {
  local target_control="$1" control_tree controller_sha gate_sha unit_sha timer_sha retired_sha temporary
  control_tree="$(target_control_tree)"
  controller_sha="$(artifact_sha_from_git "$CONTROL_ROOT" "$target_control" scripts/tu1nz_adult_public_s11_2_control.sh)"
  gate_sha="$(artifact_sha_from_git "$CONTROL_ROOT" "$target_control" scripts/tu1nz_adult_public_s11_2_gate.py)"
  unit_sha="$(artifact_sha_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s11-canary-controller.service)"
  timer_sha="$(artifact_sha_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s11-canary-controller.timer)"
  retired_sha="$(artifact_sha_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s8-health.timer)"
  [ "$(sha256sum "$INSTALLED_CONTROLLER" | awk '{print $1}')" = "$controller_sha" ] \
    || fail "S11_2_RUNTIME_CONTROLLER_SOURCE_HASH_RED"
  [ "$(sha256sum "$INSTALLED_GATE" | awk '{print $1}')" = "$gate_sha" ] \
    || fail "S11_2_RUNTIME_GATE_SOURCE_HASH_RED"
  [ "$(sha256sum "$CONTROLLER_UNIT" | awk '{print $1}')" = "$unit_sha" ] \
    || fail "S11_2_RUNTIME_UNIT_SOURCE_HASH_RED"
  [ "$(sha256sum "$CONTROLLER_TIMER" | awk '{print $1}')" = "$timer_sha" ] \
    || fail "S11_2_RUNTIME_TIMER_SOURCE_HASH_RED"
  [ "$(sha256sum "$RETIRED_S8_HEALTH_TIMER_PATH" | awk '{print $1}')" = "$retired_sha" ] \
    || fail "S11_2_RETIRED_S8_HEALTH_TIMER_SOURCE_HASH_RED"
  temporary="$(mktemp /run/tu1nz-s11-2-runtime-access.XXXXXX)"
  S11_MANIFEST_DESTINATION="$temporary" \
  S11_TARGET_CONTROL="$target_control" \
  S11_TARGET_CONTROL_TREE="$control_tree" \
  S11_CONTROLLER_SHA="$controller_sha" \
  S11_GATE_SHA="$gate_sha" \
  S11_UNIT_SHA="$unit_sha" \
  S11_TIMER_SHA="$timer_sha" \
  S11_RETIRED_TIMER_SHA="$retired_sha" \
    /usr/bin/python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "schema": "TU1NZ_S11_2_RUNTIME_ACCESS_V1",
    "freeze_tag": "s11-2-r15-4-runtime-access-freeze-r1",
    "application_commit": "84619ea0204aeb4b133fe6491f3315beccd635ae",
    "application_tree": "8f90cfc39b038e6438a6ee6bf2b96c029c4ebbab",
    "control_commit": os.environ["S11_TARGET_CONTROL"],
    "control_tree": os.environ["S11_TARGET_CONTROL_TREE"],
    "source_access_identity": "chatops",
    "runtime_access_identity": "root:root+chatops",
    "runtime_interpreter": "/opt/tu1nz_repos/adult-publishing-core/.venv/bin/python",
    "artifacts": {
        "controller": {
            "path": "/usr/local/bin/tu1nz_adult_public_s11_2_control.sh",
            "sha256": os.environ["S11_CONTROLLER_SHA"], "owner": 0, "group": 0, "mode": "0755",
        },
        "gate": {
            "path": "/usr/local/bin/tu1nz_adult_public_s11_2_gate.py",
            "sha256": os.environ["S11_GATE_SHA"], "owner": 0, "group": 0, "mode": "0755",
        },
        "controller_unit": {
            "path": "/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service",
            "sha256": os.environ["S11_UNIT_SHA"], "owner": 0, "group": 0, "mode": "0644",
        },
        "controller_timer": {
            "path": "/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer",
            "sha256": os.environ["S11_TIMER_SHA"], "owner": 0, "group": 0, "mode": "0644",
        },
        "retired_s8_health_timer": {
            "path": "/etc/systemd/system/tu1nz-adult-public-s8-health.timer",
            "sha256": os.environ["S11_RETIRED_TIMER_SHA"], "owner": 0, "group": 0, "mode": "0644",
        },
    },
}
Path(os.environ["S11_MANIFEST_DESTINATION"]).write_text(
    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii"
)
PY
  install -o root -g root -m 0644 "$temporary" "$RUNTIME_ACCESS_MANIFEST"
  rm -f -- "$temporary"
}

verify_runtime_access_contract() {
  S11_RUNTIME_MANIFEST="$RUNTIME_ACCESS_MANIFEST" \
  S11_RUNTIME_PYTHON="$APPLICATION_RUNTIME_PYTHON" \
  S11_INSTALLED_CONTROLLER="$INSTALLED_CONTROLLER" \
  S11_INSTALLED_GATE="$INSTALLED_GATE" \
  S11_CONTROLLER_UNIT="$CONTROLLER_UNIT" \
  S11_CONTROLLER_TIMER="$CONTROLLER_TIMER" \
  S11_RETIRED_TIMER="$RETIRED_S8_HEALTH_TIMER_PATH" \
    /usr/bin/python3 - <<'PY' || { fail "S11_2_RUNTIME_ACCESS_CONTRACT_RED"; return 2; }
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

manifest_path = Path(os.environ["S11_RUNTIME_MANIFEST"])
metadata = manifest_path.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(2)
if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, 0o644):
    raise SystemExit(2)
payload = json.loads(manifest_path.read_text(encoding="ascii"))
if payload.get("schema") != "TU1NZ_S11_2_RUNTIME_ACCESS_V1":
    raise SystemExit(2)
if payload.get("freeze_tag") != "s11-2-r15-4-runtime-access-freeze-r1":
    raise SystemExit(2)
if payload.get("source_access_identity") != "chatops":
    raise SystemExit(2)
if payload.get("runtime_access_identity") != "root:root+chatops":
    raise SystemExit(2)
if payload.get("application_commit") != "84619ea0204aeb4b133fe6491f3315beccd635ae":
    raise SystemExit(2)
if payload.get("application_tree") != "8f90cfc39b038e6438a6ee6bf2b96c029c4ebbab":
    raise SystemExit(2)
runtime_python = Path(os.environ["S11_RUNTIME_PYTHON"])
if payload.get("runtime_interpreter") != str(runtime_python) or not os.access(runtime_python, os.X_OK):
    raise SystemExit(2)
if subprocess.run(
    [str(runtime_python), "-c", "import psycopg"],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    check=False,
).returncode != 0:
    raise SystemExit(2)
expected = {
    "controller": (Path(os.environ["S11_INSTALLED_CONTROLLER"]), 0o755),
    "gate": (Path(os.environ["S11_INSTALLED_GATE"]), 0o755),
    "controller_unit": (Path(os.environ["S11_CONTROLLER_UNIT"]), 0o644),
    "controller_timer": (Path(os.environ["S11_CONTROLLER_TIMER"]), 0o644),
    "retired_s8_health_timer": (Path(os.environ["S11_RETIRED_TIMER"]), 0o644),
}
artifacts = payload.get("artifacts")
if not isinstance(artifacts, dict) or set(artifacts) != set(expected):
    raise SystemExit(2)
for name, (path, mode) in expected.items():
    record = artifacts[name]
    if record.get("path") != str(path) or record.get("owner") != 0 or record.get("group") != 0:
        raise SystemExit(2)
    if record.get("mode") != f"0{mode:o}":
        raise SystemExit(2)
    current = path.lstat()
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
        raise SystemExit(2)
    if (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) != (0, 0, mode):
        raise SystemExit(2)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if record.get("sha256") != digest:
        raise SystemExit(2)
unit_text = Path(os.environ["S11_CONTROLLER_UNIT"]).read_text(encoding="ascii")
if "ExecStart=/usr/local/bin/tu1nz_adult_public_s11_2_control.sh observe" not in unit_text:
    raise SystemExit(2)
if any(line.startswith("WorkingDirectory=/opt/tu1nz_repos") for line in unit_text.splitlines()):
    raise SystemExit(2)
PY
  printf '{"ok":true,"safe_code":"S11_2_RUNTIME_INSTALLED_COPY_GREEN"}\n'
}

controller_access_check() {
  local chatops_gid groups
  require_root
  [ "$(id -u)" = 0 ] || fail "S11_2_CONTROLLER_EFFECTIVE_USER_RED"
  [ "$(id -g)" = 0 ] || fail "S11_2_CONTROLLER_EFFECTIVE_GROUP_RED"
  chatops_gid="$(getent group chatops | cut -d: -f3)"
  [[ "$chatops_gid" =~ ^[0-9]+$ ]] || fail "S11_2_CHATOPS_GROUP_RED"
  groups=" $(id -G) "
  [[ "$groups" == *" ${chatops_gid} "* ]] || fail "S11_2_CONTROLLER_SUPPLEMENTARY_GROUP_RED"
  verify_runtime_access_contract >/dev/null
  "$APPLICATION_RUNTIME_PYTHON" -c 'import psycopg' \
    || fail "S11_2_CONTROLLER_RUNTIME_PYTHON_RED"
  printf '{"ok":true,"safe_code":"S11_2_CONTROLLER_ACCESS_GREEN"}\n'
}

verify_controller_unit_contract() {
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p User --value)" = root ] \
    || fail "S11_2_CONTROLLER_UNIT_USER_RED"
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p Group --value)" = root ] \
    || fail "S11_2_CONTROLLER_UNIT_GROUP_RED"
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p SupplementaryGroups --value)" = chatops ] \
    || fail "S11_2_CONTROLLER_UNIT_SUPPLEMENTARY_GROUP_RED"
  [ "$(sha256sum "$CONTROLLER_UNIT" | awk '{print $1}')" = "$CONTROLLER_UNIT_SHA" ] \
    || fail "S11_2_CONTROLLER_UNIT_HASH_RED"
}

run_controller_access_check() {
  systemd-run --quiet --wait --collect --pipe \
    --unit=tu1nz-adult-public-s11-controller-access-preflight.service \
    --service-type=oneshot \
    --property=User=root \
    --property=Group=root \
    --property=SupplementaryGroups=chatops \
    --property=PrivateTmp=true \
    --property=PrivateDevices=true \
    --property=ProtectSystem=strict \
    --property=ProtectHome=true \
    --property=ProtectKernelTunables=true \
    --property=ProtectKernelModules=true \
    --property=ProtectKernelLogs=true \
    --property=ProtectControlGroups=true \
    --property=ProtectClock=true \
    --property=ProtectHostname=true \
    --property=RestrictSUIDSGID=true \
    --property=RestrictRealtime=true \
    --property=LockPersonality=true \
    --property=MemoryDenyWriteExecute=true \
    --property='SystemCallArchitectures=native' \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    --property='CapabilityBoundingSet=CAP_SETUID CAP_SETGID' \
    --property=ReadWritePaths=/run \
    --property=UMask=0077 \
    "$INSTALLED_CONTROLLER" access-preflight
}

wait_controller_natural_run() {
  local previous_trigger="$1" deadline trigger active result exit_status
  deadline=$((SECONDS + 390))
  while (( SECONDS < deadline )); do
    trigger="$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p LastTriggerUSec --value)"
    active="$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p ActiveState --value)"
    result="$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p Result --value)"
    exit_status="$(systemctl show tu1nz-adult-public-s11-canary-controller.service -p ExecMainStatus --value)"
    if [ -n "$trigger" ] && [ "$trigger" != "$previous_trigger" ] && [ "$active" = inactive ]; then
      [ "$result" = success ] && [ "$exit_status" = 0 ] \
        || fail "S11_2_FIRST_NATURAL_CONTROLLER_RUN_RED"
      printf '{"ok":true,"safe_code":"S11_2_FIRST_NATURAL_CONTROLLER_RUN_GREEN"}\n'
      return 0
    fi
    sleep 2
  done
  fail "S11_2_FIRST_NATURAL_CONTROLLER_RUN_TIMEOUT"
}

database_scalar() {
  local statement="$1"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_STATEMENT="$statement" \
    "$APPLICATION_RUNTIME_PYTHON" - <<'PY'
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
with psycopg.connect(dsn) as connection:
    row = connection.execute(os.environ["S11_STATEMENT"]).fetchone()
if row is None or len(row) != 1:
    raise SystemExit(2)
value = row[0]
print("true" if value is True else "false" if value is False else value)
PY
}

database_admin_history_count() {
  local value
  value="$(runuser -u postgres -- psql --no-psqlrc --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --dbname="$DATABASE" \
    --command="SELECT count(*) FROM commercial_s11_canary_epoch_history;")" \
    || fail "S11_2_EPOCH_HISTORY_ADMIN_READ_RED"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "S11_2_EPOCH_HISTORY_ADMIN_VALUE_RED"
  printf '%s\n' "$value"
}

database_transition() {
  local transition="$1" safe_code="$2"
  [[ "$transition" =~ ^(START_CANARY|CANARY_READY_FOR_PROMOTION|FULL_RELEASE|CANARY_RED|CANARY_INSUFFICIENT_REAL_VOLUME)$ ]] \
    || fail "S11_2_TRANSITION_INVALID"
  [[ "$safe_code" =~ ^S11_2_[A-Z0-9_]{1,96}$ ]] || fail "S11_2_SAFE_CODE_INVALID"
  runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" \
    --command="SELECT tu1nz_s11_2_transition_runtime_control('${RUNTIME_RELEASE_ID}','${transition}',clock_timestamp(),'${safe_code}');" \
    >/dev/null
}

database_rearm() {
  local safe_code="$1"
  [[ "$safe_code" =~ ^S11_2_[A-Z0-9_]{1,96}$ ]] || fail "S11_2_REARM_SAFE_CODE_INVALID"
  runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --dbname="$DATABASE" \
    --command="SELECT tu1nz_s11_2_rearm_runtime_control('${RUNTIME_RELEASE_ID}',clock_timestamp(),'${safe_code}');" \
    >/dev/null
}

release_state() {
  database_scalar "SELECT release_state||'|'||promotion_state FROM commercial_s11_runtime_control WHERE singleton;"
}

require_acquisition_state() {
  [ "$(database_scalar "SELECT wms_real_acquisition_ready::text||'|'||to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM commercial_s10_2d_runtime_control WHERE singleton;")" = "true|${ACQUISITION_BASELINE}" ]
}

require_product_boundaries() {
  [ "$(database_scalar "SELECT (NOT community_user_content_publishing_enabled AND NOT adult_media_enabled AND NOT real_avs_enabled AND NOT payments_enabled AND NOT external_publishing_enabled AND NOT controlled_beta_enabled AND NOT production_enabled)::text FROM commercial_s11_runtime_control WHERE singleton;")" = true ]
}

require_services_and_timers() {
  local unit next_realtime next_monotonic
  for unit in "${SERVICES[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_SERVICE_RED"; return 2; }
    [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ] \
      || { fail "S11_2_SERVICE_RESTART_RED"; return 2; }
  done
  for unit in "${TIMERS[@]}"; do
    [ "$(systemctl show "$unit" -p ActiveState --value)" = active ] \
      || { fail "S11_2_TIMER_RED"; return 2; }
    [ "$(systemctl is-enabled "$unit")" = enabled ] \
      || { fail "S11_2_TIMER_DISABLED"; return 2; }
    next_realtime="$(systemctl show "$unit" -p NextElapseUSecRealtime --value)"
    next_monotonic="$(systemctl show "$unit" -p NextElapseUSecMonotonic --value)"
    if { [ -z "$next_realtime" ] || [ "$next_realtime" = n/a ]; } \
      && { [ -z "$next_monotonic" ] || [ "$next_monotonic" = n/a ] || [ "$next_monotonic" = 0 ]; }; then
      fail "S11_2_TIMER_FUTURE_RUN_MISSING"
      return 2
    fi
  done
  [ "$(systemctl show "$RETIRED_S8_HEALTH_TIMER" -p LoadState --value)" = loaded ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_MISSING"; return 2; }
  [ "$(systemctl is-enabled "$RETIRED_S8_HEALTH_TIMER")" = disabled ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_ENABLED"; return 2; }
  [ "$(systemctl show "$RETIRED_S8_HEALTH_TIMER" -p ActiveState --value)" = inactive ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_ACTIVE"; return 2; }
  [ "$(systemctl show "$RETIRED_S8_HEALTH_TIMER" -p SubState --value)" = dead ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_SUBSTATE_RED"; return 2; }
  [ "$(systemctl show "$RETIRED_S8_HEALTH_TIMER" -p FragmentPath --value)" = "/etc/systemd/system/$RETIRED_S8_HEALTH_TIMER" ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_PATH_DRIFT"; return 2; }
  [ -z "$(systemctl show "$RETIRED_S8_HEALTH_TIMER" -p DropInPaths --value)" ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_DROPIN_PRESENT"; return 2; }
  [ "$(sha256sum "$RETIRED_S8_HEALTH_TIMER_PATH" | awk '{print $1}')" = "$RETIRED_S8_HEALTH_TIMER_SHA" ] \
    || { fail "S11_2_RETIRED_S8_HEALTH_TIMER_UNIT_DRIFT"; return 2; }
}

require_public_health() {
  local path code
  for path in / /privacy /terms /imprint; do
    code="$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' "https://wantmeseen.com${path}")"
    [ "$code" = 200 ] || { fail "S11_2_PUBLIC_ENDPOINT_RED"; return 2; }
  done
  [ "$(curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://wantmeseen.de/)" = 308 ] \
    || { fail "S11_2_LEGACY_REDIRECT_RED"; return 2; }
  curl -fsS --max-time 12 https://wantmeseen.com/health \
    | /usr/bin/python3 -c \
      'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities",{}).values()) else 1)' \
    >/dev/null || { fail "S11_2_PUBLIC_HEALTH_RED"; return 2; }
}

require_poller_and_rotation() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_bot_polling_state WHERE release_id='${RUNTIME_RELEASE_ID}' AND lease_owner_id IS NOT NULL AND lease_expires_at>CURRENT_TIMESTAMP AND last_successful_poll_at>=CURRENT_TIMESTAMP-INTERVAL '90 seconds' AND last_event_path_code IN ('BOT_EVENT_PATH_GREEN','BOT_UPDATE_NOT_RECEIVED');")" = 1 ] \
    || { fail "S11_2_POLLER_LEASE_RED"; return 2; }
  [ "$(systemctl show tu1nz-adult-public-s10-2d-rotate.service -p Result --value)" = success ] \
    || { fail "S11_2_PUBLICATION_ROTATION_RED"; return 2; }
}

require_hard_gates() {
  require_acquisition_state \
    || { fail "S11_2_ACQUISITION_STATE_RED"; return 2; }
  require_product_boundaries \
    || { fail "S11_2_PRODUCT_BOUNDARY_RED"; return 2; }
  require_services_and_timers || return $?
  require_poller_and_rotation || return $?
  require_public_health || return $?
}

require_wms_runtime_binding() {
  runuser -u chatops -- env PYTHONPATH="$APPLICATION_ROOT/src" \
    "$APPLICATION_RUNTIME_PYTHON" - <<'PY'
from pathlib import Path

from tu1nz_exposure_s10.contract import S10ExposureContract
from tu1nz_exposure_s10.copy import ExposureCopy
from tu1nz_exposure_s10.runtime import WMSLandingApplication
from tu1nz_exposure_s10.traffic import TrafficQualityCounter
from tu1nz_growth_s9.counter import AggregateCounter
from tu1nz_public_s8.community import CommunityContract
from tu1nz_public_s8.contract import S8Contract

contract = S10ExposureContract.load(Path("/etc/tu1nz/adult-commercial-s10-wms.json"))
copy = ExposureCopy.load(Path("/etc/tu1nz/adult-commercial-s10-wms-copy.json"))
bot = S8Contract.load(Path("/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json"))
community = CommunityContract.load(Path("/etc/tu1nz/adult-commercial-s10-2d-community.json"))
aggregate = AggregateCounter(Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"))
quality = TrafficQualityCounter(Path("/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json"))
WMSLandingApplication(
    contract,
    copy,
    bot,
    aggregate,
    community,
    "s10-2d-r3-5",
    quality,
)
PY
}

require_target_wms_compatibility() {
  local path
  for path in \
    src/tu1nz_exposure_s10 \
    src/tu1nz_growth_s9/counter.py \
    src/tu1nz_public_s8/community.py \
    src/tu1nz_public_s8/contract.py
  do
    git_chatops "$APPLICATION_ROOT" diff --quiet \
      "$SOURCE_APPLICATION_COMMIT" "$TARGET_APPLICATION_COMMIT" -- "$path" \
      || { fail "S11_2_TARGET_WMS_PARSER_DRIFT"; return 2; }
  done
  runuser -u chatops -- env PYTHONPATH="$APPLICATION_ROOT/src" \
    "$APPLICATION_RUNTIME_PYTHON" - \
    3< <(git_chatops "$APPLICATION_ROOT" show "${TARGET_APPLICATION_COMMIT}:config/commercial-s10-1-wms-copy.v1.json") <<'PY'
import json
import os
from pathlib import Path

from tu1nz_exposure_s10.contract import S10ExposureContract
from tu1nz_exposure_s10.copy import ExposureCopy
from tu1nz_exposure_s10.runtime import WMSLandingApplication
from tu1nz_exposure_s10.traffic import TrafficQualityCounter
from tu1nz_growth_s9.counter import AggregateCounter
from tu1nz_public_s8.community import CommunityContract
from tu1nz_public_s8.contract import S8Contract

raw = json.load(os.fdopen(3))
copy = ExposureCopy(
    raw["version"], raw["brand"], raw["design_tokens"], raw["public_copy"],
    raw["persona_modes"], raw["content_copy"], raw["nurture_copy"], raw["messages"],
)
copy.validate()
WMSLandingApplication(
    S10ExposureContract.load(Path("/etc/tu1nz/adult-commercial-s10-wms.json")),
    copy,
    S8Contract.load(Path("/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json")),
    AggregateCounter(Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json")),
    CommunityContract.load(Path("/etc/tu1nz/adult-commercial-s10-2d-community.json")),
    "s10-2d-r3-5",
    TrafficQualityCounter(Path("/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json")),
)
PY
}

require_source_state() {
  source_access_check >/dev/null
  require_clean_commit "$APPLICATION_ROOT" "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" SOURCE_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" SOURCE_CONTROL
  [ -f "$DATABASE_DSN" ] && [ ! -L "$DATABASE_DSN" ] || fail "S11_2_DATABASE_CREDENTIAL_RED"
  [ -f "$AGGREGATE_STATE" ] && [ ! -L "$AGGREGATE_STATE" ] || fail "S11_2_AGGREGATE_STATE_RED"
  [ -f "$QUALITY_STATE" ] && [ ! -L "$QUALITY_STATE" ] || fail "S11_2_QUALITY_STATE_RED"
  [ "$(database_scalar "SELECT enabled::text||'|'||(live_start IS NULL)::text FROM commercial_s11_runtime_control WHERE singleton;")" = "false|true" ] \
    || fail "S11_2_SOURCE_FEATURE_NOT_OFF"
  require_wms_runtime_binding \
    || { fail "S11_2_SOURCE_WMS_RUNTIME_BINDING_RED"; return 2; }
  require_hard_gates
}

preflight() {
  local target_control="$1" backup_path="$2"
  require_root
  require_sha "$target_control"
  require_backup_path "$backup_path"
  [ ! -e "$backup_path" ] || fail "S11_2_BACKUP_ALREADY_EXISTS"
  require_source_state
  require_remote_target "$target_control"
  printf '{"ok":true,"safe_code":"S11_2_PREFLIGHT_GREEN"}\n'
}

database_evidence() {
  local destination="$1"
  S11_DATABASE_DSN="$DATABASE_DSN" S11_DESTINATION="$destination" \
    "$APPLICATION_RUNTIME_PYTHON" - <<'PY'
import json
import os
from pathlib import Path
import psycopg

dsn = Path(os.environ["S11_DATABASE_DSN"]).read_text(encoding="utf-8").strip()
evidence = {}
with psycopg.connect(dsn) as connection:
    evidence["acquisition"] = connection.execute(
        "SELECT wms_real_acquisition_ready,real_acquisition_baseline_start "
        "FROM commercial_s10_2d_runtime_control WHERE singleton"
    ).fetchone()
    evidence["schema"] = connection.execute(
        "SELECT table_name,column_name,data_type,is_nullable FROM information_schema.columns "
        "WHERE table_schema='public' AND (table_name LIKE 'commercial_s8_%' "
        "OR table_name LIKE 'commercial_s10_2d_%' OR table_name LIKE 'commercial_s11_%') "
        "ORDER BY table_name,ordinal_position"
    ).fetchall()
    evidence["latency_counts"] = connection.execute(
        "SELECT evidence_class,sample_type,interaction_path,count(*) "
        "FROM commercial_s10_2d_latency_samples GROUP BY 1,2,3 ORDER BY 1,2,3"
    ).fetchall()
    s11_control_columns = {
        row[0] for row in connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='commercial_s11_runtime_control'"
        ).fetchall()
    }
    evidence["s11_control_schema"] = sorted(s11_control_columns)
    if "release_state" in s11_control_columns:
        evidence["s11_control"] = connection.execute(
            "SELECT enabled,live_start IS NOT NULL,release_state,canary_release_id,"
            "canary_evidence_start,canary_live_start,full_live_start,canary_horizon_at,"
            "canary_session_cap,promotion_state,community_user_content_publishing_enabled,"
            "adult_media_enabled,real_avs_enabled,payments_enabled,external_publishing_enabled,"
            "controlled_beta_enabled,production_enabled FROM commercial_s11_runtime_control "
            "WHERE singleton"
        ).fetchone()
    else:
        evidence["s11_control"] = connection.execute(
            "SELECT enabled,live_start IS NOT NULL,catalog_version,state_machine_version,"
            "community_user_content_publishing_enabled,adult_media_enabled,real_avs_enabled,"
            "payments_enabled,external_publishing_enabled,controlled_beta_enabled,"
            "production_enabled FROM commercial_s11_runtime_control WHERE singleton"
        ).fetchone()
    s11_session_columns = {
        row[0] for row in connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='commercial_s11_experience_sessions'"
        ).fetchall()
    }
    if "admission_state" in s11_session_columns:
        evidence["s11_sessions"] = connection.execute(
            "SELECT COALESCE(admission_state,'UNADMITTED'),count(*) "
            "FROM commercial_s11_experience_sessions GROUP BY 1 ORDER BY 1"
        ).fetchall()
    else:
        evidence["s11_sessions"] = [
            ["PRE_CANARY_SCHEMA", connection.execute(
                "SELECT count(*) FROM commercial_s11_experience_sessions"
            ).fetchone()[0]]
        ]
    evidence["s11_events"] = connection.execute(
        "SELECT evidence_class,event_type,count(*) FROM commercial_s11_product_events "
        "GROUP BY 1,2 ORDER BY 1,2"
    ).fetchall()
Path(os.environ["S11_DESTINATION"]).write_text(
    json.dumps(evidence, default=str, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
}

backup_optional() {
  local source="$1" destination="$2" absent="$3"
  if [ -f "$source" ] && [ ! -L "$source" ]; then
    install -m 0600 "$source" "$destination"
  else
    : > "$absent"
  fi
}

backup_runtime() {
  local backup_path="$1" target_control="$2" historical_unknown
  install -d -o root -g root -m 0700 "$backup_path"
  chmod 0700 "$backup_path"
  chmod g-s "$backup_path"
  git_chatops "$APPLICATION_ROOT" bundle create - HEAD > "$backup_path/application.bundle"
  git_chatops "$CONTROL_ROOT" bundle create - HEAD > "$backup_path/control.bundle"
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null
  runuser -u postgres -- pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE" \
    > "$backup_path/database.dump"
  pg_restore --list "$backup_path/database.dump" > "$backup_path/database.restore-list.txt"
  [ -s "$backup_path/database.restore-list.txt" ] || fail "S11_2_DATABASE_BACKUP_RED"
  backup_optional "$S8_UNIT" "$backup_path/s8-telegram.service" "$backup_path/S8_UNIT_ABSENT"
  backup_optional "$S8_HEALTH_UNIT" "$backup_path/s8-health.service" "$backup_path/S8_HEALTH_UNIT_ABSENT"
  backup_optional "$S8_HEALTH_SCRIPT" "$backup_path/s8-health.py" "$backup_path/S8_HEALTH_SCRIPT_ABSENT"
  backup_optional "$EXPERIENCE_CONTRACT" "$backup_path/experience-contract.json" "$backup_path/EXPERIENCE_CONTRACT_ABSENT"
  backup_optional "$EXPERIENCE_COPY" "$backup_path/experience-copy.json" "$backup_path/EXPERIENCE_COPY_ABSENT"
  backup_optional "$WMS_CONTRACT" "$backup_path/wms-contract.json" "$backup_path/WMS_CONTRACT_ABSENT"
  backup_optional "$WMS_LANDING_COPY" "$backup_path/wms-landing-copy.json" "$backup_path/WMS_LANDING_COPY_ABSENT"
  backup_optional "$WMS_BOT_CONTRACT" "$backup_path/wms-bot-contract.json" "$backup_path/WMS_BOT_CONTRACT_ABSENT"
  backup_optional "$COMMUNITY_CONTRACT" "$backup_path/community-contract.json" "$backup_path/COMMUNITY_CONTRACT_ABSENT"
  backup_optional "$INSTALLED_CONTROLLER" "$backup_path/s11-2-control.sh" "$backup_path/S11_2_CONTROLLER_ABSENT"
  backup_optional "$INSTALLED_GATE" "$backup_path/s11-2-gate.py" "$backup_path/S11_2_GATE_ABSENT"
  backup_optional "$RUNTIME_ACCESS_MANIFEST" "$backup_path/s11-2-runtime-access.json" "$backup_path/S11_2_RUNTIME_ACCESS_ABSENT"
  backup_optional "$CONTROLLER_UNIT" "$backup_path/s11-2-controller.service" "$backup_path/S11_2_SERVICE_ABSENT"
  backup_optional "$CONTROLLER_TIMER" "$backup_path/s11-2-controller.timer" "$backup_path/S11_2_TIMER_ABSENT"
  install -m 0600 "$AGGREGATE_STATE" "$backup_path/landing-aggregates.exact"
  install -m 0600 "$QUALITY_STATE" "$backup_path/wms-traffic-quality.exact"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" > "$backup_path/runtime-manifest.txt"
  database_evidence "$backup_path/database-aggregate-and-schema.json"
  historical_unknown="$(database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN';")"
  printf 'source_application_commit=%s\nsource_application_tree=%s\nsource_control_commit=%s\nsource_control_tree=%s\ntarget_application_commit=%s\ntarget_application_tree=%s\ntarget_control_commit=%s\nacquisition_baseline=%s\nhistorical_unknown_count=%s\nrestore_command=pg_restore --clean --if-exists --dbname=%s database.dump\n' \
    "$SOURCE_APPLICATION_COMMIT" "$SOURCE_APPLICATION_TREE" \
    "$SOURCE_CONTROL_COMMIT" "$SOURCE_CONTROL_TREE" \
    "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE" "$target_control" \
    "$ACQUISITION_BASELINE" "$historical_unknown" "$DATABASE" > "$backup_path/provenance.txt"
  : > "$backup_path/owners-and-modes.txt"
  chmod -R go-rwx "$backup_path"
  chmod 0700 "$backup_path"
  chmod g-s "$backup_path"
  find "$backup_path" -maxdepth 1 -type f -exec stat -c '%n|%U|%G|%a' {} + \
    | sort > "$backup_path/owners-and-modes.txt"
  (
    cd "$backup_path"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
  )
  printf '{"ok":true,"safe_code":"S11_2_RUNTIME_BACKUP_GREEN"}\n'
}

require_backup() {
  local backup_path="$1" target_control="$2"
  [ -d "$backup_path" ] && [ ! -L "$backup_path" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$backup_path")" = root:root:700 ] || return 1
  grep -Fqx "source_application_commit=${SOURCE_APPLICATION_COMMIT}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "source_control_commit=${SOURCE_CONTROL_COMMIT}" "$backup_path/provenance.txt" || return 1
  grep -Fqx "target_control_commit=${target_control}" "$backup_path/provenance.txt" || return 1
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  git -c safe.directory="$APPLICATION_ROOT" -C "$APPLICATION_ROOT" bundle verify "$backup_path/application.bundle" >/dev/null || return 1
  git -c safe.directory="$CONTROL_ROOT" -C "$CONTROL_ROOT" bundle verify "$backup_path/control.bundle" >/dev/null || return 1
  pg_restore --list "$backup_path/database.dump" >/dev/null || return 1
}

fetch_and_require_target() {
  local target_control="$1" path expected actual
  git_chatops "$APPLICATION_ROOT" fetch --quiet --no-tags origin main
  git_chatops "$CONTROL_ROOT" fetch --quiet --no-tags origin control-main \
    "refs/tags/${FINAL_CONTROL_TAG}:refs/tags/${FINAL_CONTROL_TAG}"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse origin/main)" = "$TARGET_APPLICATION_COMMIT" ] \
    || fail "S11_2_FETCHED_APPLICATION_DRIFT"
  [ "$(git_chatops "$APPLICATION_ROOT" rev-parse "${TARGET_APPLICATION_COMMIT}^{tree}")" = "$TARGET_APPLICATION_TREE" ] \
    || fail "S11_2_TARGET_APPLICATION_TREE_DRIFT"
  git_chatops "$CONTROL_ROOT" merge-base --is-ancestor "$target_control" origin/control-main \
    || fail "S11_2_CONTROL_NOT_CANONICAL"
  require_local_freeze "$target_control"
  while read -r path expected; do
    actual="$(git_chatops "$APPLICATION_ROOT" show "${TARGET_APPLICATION_COMMIT}:${path}" | sha256sum | awk '{print $1}')"
    [ "$actual" = "$expected" ] || fail "S11_2_APPLICATION_ARTIFACT_DRIFT"
  done <<EOF
config/commercial-s11-interactive-experience.sfw.json ${EXPERIENCE_CONTRACT_SHA}
config/commercial-s11-interactive-copy.v1.json ${EXPERIENCE_COPY_SHA}
config/commercial-s11-synthetic-experience.v1.json ${SYNTHETIC_CONTRACT_SHA}
migrations/0033_commercial_s11_2_canary_bootstrap.sql ${MIGRATION_UP_SHA}
migrations/0033_commercial_s11_2_canary_bootstrap.down.sql ${MIGRATION_DOWN_SHA}
migrations/0034_commercial_s11_2_canary_rearm.sql ${MIGRATION_REARM_UP_SHA}
migrations/0034_commercial_s11_2_canary_rearm.down.sql ${MIGRATION_REARM_DOWN_SHA}
config/commercial-s10-1-wms-copy.v1.json ${WMS_LANDING_COPY_SHA}
EOF
  require_target_wms_compatibility \
    || { fail "S11_2_TARGET_WMS_RUNTIME_BINDING_RED"; return 2; }
}

install_from_git() {
  local repository="$1" commit="$2" path="$3" mode="$4" destination="$5"
  git_chatops "$repository" show "${commit}:${path}" \
    | install -o root -g root -m "$mode" /dev/stdin "$destination"
}

apply_migration() {
  local bootstrap_installed rearm_installed current_state history_before history_after
  bootstrap_installed="$(database_scalar "SELECT count(*)=6 FROM information_schema.columns WHERE table_schema='public' AND table_name='commercial_s11_runtime_control' AND column_name IN ('release_state','canary_release_id','canary_evidence_start','canary_live_start','full_live_start','promotion_state');")"
  if [ "$bootstrap_installed" != true ]; then
    runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --dbname="$DATABASE" \
      < "$APPLICATION_ROOT/migrations/0033_commercial_s11_2_canary_bootstrap.sql" \
      >/dev/null
    [ "$(release_state)" = "S11_DISABLED|NOT_STARTED" ] \
      || fail "S11_2_MIGRATION_DEFAULT_NOT_OFF"
  fi

  rearm_installed="$(database_scalar "SELECT (to_regclass('public.commercial_s11_canary_epoch_history') IS NOT NULL AND to_regprocedure('public.tu1nz_s11_2_rearm_runtime_control(text,timestamp with time zone,text)') IS NOT NULL)::text;")"
  if [ "$rearm_installed" != true ]; then
    runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --dbname="$DATABASE" \
      < "$APPLICATION_ROOT/migrations/0034_commercial_s11_2_canary_rearm.sql" \
      >/dev/null
  fi

  current_state="$(release_state)"
  case "$current_state" in
    S11_DISABLED\|NOT_STARTED)
      return 0
      ;;
    S11_DISABLED\|CANARY_RED|S11_DISABLED\|CANARY_INSUFFICIENT_REAL_VOLUME)
      history_before="$(database_admin_history_count)"
      database_rearm S11_2_R15_TERMINAL_EPOCH_REARMED
      history_after="$(database_admin_history_count)"
      [ "$history_after" -eq $((history_before + 1)) ] \
        || fail "S11_2_TERMINAL_EPOCH_ARCHIVE_RED"
      [ "$(release_state)" = "S11_DISABLED|NOT_STARTED" ] \
        || fail "S11_2_TERMINAL_EPOCH_REARM_RED"
      ;;
    *)
      fail "S11_2_EXISTING_CANARY_STATE_RED"
      ;;
  esac
}

run_synthetic_journeys() {
  local destination="$1"
  "$APPLICATION_ROOT/.venv/bin/tu1nz-commercial-s11-experience-journey" \
    --contract "$EXPERIENCE_CONTRACT" --copy "$EXPERIENCE_COPY" \
    --release-id "$EXPERIENCE_RELEASE_ID" > "$destination"
  /usr/bin/python3 - "$destination" <<'PY'
import json
import sys
from pathlib import Path
payload=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected=["A_COMPLETE","B_SAFER_COMPLETE","C_BOLDEST_SFW","D_SKIP_ALL","E_STOP_RETURN","F_SECOND_SESSION","G_EXISTING_WAITLIST","H_AGE_REJECTION"]
if payload.get("ok") is not True or payload.get("journeys") != expected:
    raise SystemExit(2)
if any(payload.get(key) is not False for key in ("adult_media","real_avs","payments","publishing","community_user_content_publishing")):
    raise SystemExit(2)
PY
}

move_optional_synthetic_companions() {
  local backup_path="$1" postdeploy="$2" companion
  [ -d "$backup_path" ] || fail "S11_2_SYNTHETIC_SOURCE_DIRECTORY_RED"
  [ -d "$postdeploy" ] || fail "S11_2_SYNTHETIC_TARGET_DIRECTORY_RED"
  for companion in "$backup_path"/synthetic-journeys.json.*; do
    [ -e "$companion" ] || break
    [ -f "$companion" ] || fail "S11_2_SYNTHETIC_COMPANION_TYPE_RED"
    mv -- "$companion" "$postdeploy/"
  done
}

technical_latency_fixture() {
  local destination="$1" values_file="$2" iteration start_ns end_ns elapsed_ms
  : > "$values_file"
  for iteration in 1 2 3 4 5; do
    start_ns="$(date +%s%N)"
    run_synthetic_journeys "${destination}.${iteration}.json"
    end_ns="$(date +%s%N)"
    elapsed_ms=$(( (end_ns - start_ns + 999999) / 1000000 ))
    printf '%s\n' "$elapsed_ms" >> "$values_file"
  done
  /usr/bin/python3 - "$values_file" "$destination" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
values=[int(value) for value in Path(sys.argv[1]).read_text().splitlines()]
start=datetime.now(timezone.utc)-timedelta(seconds=1)
payload={
 "release_state":"S11_CANARY","promotion_state":"CANARY_COLLECTING_EVIDENCE",
 "now":datetime.now(timezone.utc).isoformat(),"evidence_start":start.isoformat(),
 "horizon_at":(start+timedelta(hours=24)).isoformat(),"session_cap":10,
 "admitted_count":0,"technical_values_ms":values,"real_values_ms":[],
 "new_unknown_count":0,"historical_unknown_count":0,"experience_sessions":0,
 "product_event_count":0,"hard_gates_green":True,
}
Path(sys.argv[2]).write_text(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n")
PY
  "$APPLICATION_RUNTIME_PYTHON" "$INSTALLED_GATE" --input "$destination" \
    | /usr/bin/python3 -c 'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p["technical_latency"]["state"]=="GREEN" else 2)' \
    || fail "S11_2_TECHNICAL_LATENCY_RED"
}

insert_technical_evidence() {
  local values_file="$1" value
  while read -r value; do
    [[ "$value" =~ ^[0-9]+$ ]] || fail "S11_2_TECHNICAL_LATENCY_VALUE_RED"
    runuser -u postgres -- psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --dbname="$DATABASE" --command="
        INSERT INTO commercial_s10_2d_latency_samples (
          sample_id,source,bot_response_latency_ms,poll_lag_ms,handler_duration_ms,
          send_ack_ms,occurred_at,release_id,run_id,evidence_class,
          cutover_started_at,sample_type,interaction_path
        )
        SELECT gen_random_uuid(),'DIRECT',${value},0,${value},0,clock_timestamp(),
               target_release_id,technical_evidence_run_id,'INTERNAL_TEST',
               cutover_started_at,'S11_CANARY_RESPONSE','INTERNAL_ACCEPTANCE'
        FROM commercial_s10_2d_runtime_control
        WHERE singleton AND target_release_id='${RUNTIME_RELEASE_ID}';" >/dev/null
  done < "$values_file"
}

wait_runtime() {
  local attempt
  for attempt in {1..60}; do
    if [ "$(systemctl show "$S8_SERVICE" -p ActiveState --value)" = active ] \
      && [ "$(systemctl show "$S8_SERVICE" -p NRestarts --value)" = 0 ] \
      && require_poller_and_rotation >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "S11_2_RUNTIME_READY_TIMEOUT"
}

wait_wms_ready() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if [ "$(systemctl show "$WMS_SERVICE" -p ActiveState --value)" = active ] \
      && curl --fail --silent --show-error --max-time 1 "$LOCAL_WMS_HEALTH" 2>/dev/null \
        | /usr/bin/python3 -c \
          'import json,sys;p=json.load(sys.stdin);raise SystemExit(0 if p.get("ok") is True and not any(p.get("forbidden_capabilities",{}).values()) else 1)' \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  fail "S11_2_WMS_LOCAL_HEALTH_TIMEOUT"
}

run_runtime_health() {
  local unit
  for unit in \
    tu1nz-adult-public-s8-health.service \
    tu1nz-adult-public-s9-health.service \
    tu1nz-adult-public-s10-health.service
  do
    systemctl start "$unit"
    [ "$(systemctl show "$unit" -p Result --value)" = success ] \
      || fail "S11_2_RUNTIME_HEALTH_RED"
  done
}

gate_json() {
  local hard="$1"
  if [ "$hard" = true ]; then
    "$APPLICATION_RUNTIME_PYTHON" "$INSTALLED_GATE" \
      --dsn-file "$DATABASE_DSN" --hard-gates-green
  else
    "$APPLICATION_RUNTIME_PYTHON" "$INSTALLED_GATE" --dsn-file "$DATABASE_DSN"
  fi
}

promote_under_barrier_json() {
  "$APPLICATION_RUNTIME_PYTHON" "$INSTALLED_GATE" --dsn-file "$DATABASE_DSN" \
    --promote-under-barrier --expected-release-id "$RUNTIME_RELEASE_ID"
}

gate_field() {
  /usr/bin/python3 -c 'import json,sys;value=json.load(sys.stdin).get(sys.argv[1]);sys.exit(2) if value is None else print(value)' "$1"
}

verify_target() {
  local target_control="$1" state technical historical_before historical_after next_realtime next_monotonic
  require_clean_commit "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE" TARGET_APPLICATION
  require_clean_commit "$CONTROL_ROOT" "$target_control" "$(target_control_tree)" TARGET_CONTROL
  require_local_freeze "$target_control"
  [ "$(sha256sum "$EXPERIENCE_CONTRACT" | awk '{print $1}')" = "$EXPERIENCE_CONTRACT_SHA" ] || fail "S11_2_INSTALLED_CONTRACT_DRIFT"
  [ "$(sha256sum "$EXPERIENCE_COPY" | awk '{print $1}')" = "$EXPERIENCE_COPY_SHA" ] || fail "S11_2_INSTALLED_COPY_DRIFT"
  [ "$(sha256sum "$WMS_LANDING_COPY" | awk '{print $1}')" = "$WMS_LANDING_COPY_SHA" ] || fail "S11_2_INSTALLED_LANDING_COPY_DRIFT"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s11_2_control.sh" "$INSTALLED_CONTROLLER" || fail "S11_2_INSTALLED_CONTROLLER_DRIFT"
  cmp -s "$CONTROL_ROOT/scripts/tu1nz_adult_public_s11_2_gate.py" "$INSTALLED_GATE" || fail "S11_2_INSTALLED_GATE_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s11-canary-controller.service" "$CONTROLLER_UNIT" || fail "S11_2_INSTALLED_SERVICE_DRIFT"
  cmp -s "$CONTROL_ROOT/systemd/tu1nz-adult-public-s11-canary-controller.timer" "$CONTROLLER_TIMER" || fail "S11_2_INSTALLED_TIMER_DRIFT"
  verify_runtime_access_contract >/dev/null
  state="$(release_state)"
  case "$state" in
    S11_CANARY\|CANARY_COLLECTING_EVIDENCE|S11_FULL\|FULL_RELEASE) ;;
    *) fail "S11_2_RUNTIME_STATE_RED" ;;
  esac
  require_hard_gates
  wait_runtime
  technical="$(gate_json true | /usr/bin/python3 -c 'import json,sys;print(json.load(sys.stdin)["technical_latency"]["state"])')"
  [ "$technical" = GREEN ] || fail "S11_2_TECHNICAL_LATENCY_RED"
  historical_before="$(grep '^historical_unknown_count=' "$S11_2_BACKUP_PATH/provenance.txt" | cut -d= -f2)"
  historical_after="$(database_scalar "SELECT count(*) FROM commercial_s10_2d_latency_samples WHERE evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN';")"
  [ "$historical_after" = "$historical_before" ] || fail "S11_2_HISTORICAL_UNKNOWN_MUTATED"
  [ "$(systemctl is-enabled tu1nz-adult-public-s11-canary-controller.timer)" = enabled ] || fail "S11_2_CONTROLLER_TIMER_DISABLED"
  [ "$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p ActiveState --value)" = active ] || fail "S11_2_CONTROLLER_TIMER_RED"
  next_realtime="$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p NextElapseUSecRealtime --value)"
  next_monotonic="$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p NextElapseUSecMonotonic --value)"
  if { [ -z "$next_realtime" ] || [ "$next_realtime" = n/a ]; } \
    && { [ -z "$next_monotonic" ] || [ "$next_monotonic" = n/a ] || [ "$next_monotonic" = 0 ]; }; then
    fail "S11_2_CONTROLLER_FUTURE_RUN_MISSING"
  fi
  printf '{"ok":true,"safe_code":"S11_2_CANARY_RUNTIME_GREEN","state":"%s"}\n' "$state"
}

restore_optional() {
  local backup_path="$1" stored="$2" absent="$3" destination="$4" mode="$5"
  if [ -f "$backup_path/$absent" ]; then
    rm -f -- "$destination"
  else
    install -o root -g root -m "$mode" "$backup_path/$stored" "$destination"
  fi
}

restore_source() {
  local backup_path="$1" target_control="$2" current_state
  require_backup "$backup_path" "$target_control" || return 1
  if ! current_state="$(release_state 2>/dev/null)"; then
    return 1
  fi
  case "$current_state" in
    S11_FULL\|*) return 1 ;;
    S11_CANARY\|*|S11_DISABLED\|*) ;;
    *) return 1 ;;
  esac
  systemctl disable --now tu1nz-adult-public-s11-canary-controller.timer >/dev/null 2>&1 || true
  if [[ "$current_state" == S11_CANARY\|* ]]; then
    database_transition CANARY_RED S11_2_DEPLOYMENT_ROLLBACK || return 1
  fi
  git_chatops "$APPLICATION_ROOT" switch --detach "$SOURCE_APPLICATION_COMMIT" >/dev/null || return 1
  git_chatops "$CONTROL_ROOT" switch --detach "$SOURCE_CONTROL_COMMIT" >/dev/null || return 1
  runuser -u chatops -- "$APPLICATION_RUNTIME_PYTHON" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null || return 1
  restore_optional "$backup_path" s8-telegram.service S8_UNIT_ABSENT "$S8_UNIT" 0644 || return 1
  restore_optional "$backup_path" s8-health.service S8_HEALTH_UNIT_ABSENT "$S8_HEALTH_UNIT" 0644 || return 1
  restore_optional "$backup_path" s8-health.py S8_HEALTH_SCRIPT_ABSENT "$S8_HEALTH_SCRIPT" 0755 || return 1
  restore_optional "$backup_path" experience-contract.json EXPERIENCE_CONTRACT_ABSENT "$EXPERIENCE_CONTRACT" 0644 || return 1
  restore_optional "$backup_path" experience-copy.json EXPERIENCE_COPY_ABSENT "$EXPERIENCE_COPY" 0644 || return 1
  restore_optional "$backup_path" wms-landing-copy.json WMS_LANDING_COPY_ABSENT "$WMS_LANDING_COPY" 0644 || return 1
  restore_optional "$backup_path" s11-2-control.sh S11_2_CONTROLLER_ABSENT "$INSTALLED_CONTROLLER" 0755 || return 1
  restore_optional "$backup_path" s11-2-gate.py S11_2_GATE_ABSENT "$INSTALLED_GATE" 0755 || return 1
  restore_optional "$backup_path" s11-2-runtime-access.json S11_2_RUNTIME_ACCESS_ABSENT "$RUNTIME_ACCESS_MANIFEST" 0644 || return 1
  restore_optional "$backup_path" s11-2-controller.service S11_2_SERVICE_ABSENT "$CONTROLLER_UNIT" 0644 || return 1
  restore_optional "$backup_path" s11-2-controller.timer S11_2_TIMER_ABSENT "$CONTROLLER_TIMER" 0644 || return 1
  require_wms_runtime_binding || return 1
  systemctl daemon-reload || return 1
  systemctl restart "$S8_SERVICE" || return 1
  systemctl restart "$WMS_SERVICE" || return 1
  wait_wms_ready || return 1
  require_public_health || return 1
  wait_runtime || return 1
  require_acquisition_state || return 1
  require_public_health || return 1
}

deploy() {
  local target_control="$1" backup_path="$2" current_state previous_trigger
  require_root
  acquire_lock
  preflight "$target_control" "$backup_path"
  backup_runtime "$backup_path" "$target_control"
  require_backup "$backup_path" "$target_control" || fail "S11_2_BACKUP_VERIFY_RED"
  S11_2_ROLLBACK_ARMED=true
  S11_2_BACKUP_PATH="$backup_path"
  S11_2_TARGET_CONTROL="$target_control"
  trap 'deployment_error' ERR

  fetch_and_require_target "$target_control"
  git_chatops "$APPLICATION_ROOT" switch --detach "$TARGET_APPLICATION_COMMIT" >/dev/null
  git_chatops "$CONTROL_ROOT" switch --detach "$target_control" >/dev/null
  runuser -u chatops -- "$APPLICATION_RUNTIME_PYTHON" -m pip install \
    --no-deps --no-build-isolation "$APPLICATION_ROOT" >/dev/null
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" config/commercial-s11-interactive-experience.sfw.json 0644 "$EXPERIENCE_CONTRACT"
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" config/commercial-s11-interactive-copy.v1.json 0644 "$EXPERIENCE_COPY"
  install_from_git "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" config/commercial-s10-1-wms-copy.v1.json 0644 "$WMS_LANDING_COPY"
  install_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s8-telegram.service 0644 "$S8_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s8-health.service 0644 "$S8_HEALTH_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" scripts/tu1nz_adult_public_s8_health.py 0755 "$S8_HEALTH_SCRIPT"
  install_from_git "$CONTROL_ROOT" "$target_control" scripts/tu1nz_adult_public_s11_2_control.sh 0755 "$INSTALLED_CONTROLLER"
  install_from_git "$CONTROL_ROOT" "$target_control" scripts/tu1nz_adult_public_s11_2_gate.py 0755 "$INSTALLED_GATE"
  install_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s11-canary-controller.service 0644 "$CONTROLLER_UNIT"
  install_from_git "$CONTROL_ROOT" "$target_control" systemd/tu1nz-adult-public-s11-canary-controller.timer 0644 "$CONTROLLER_TIMER"
  install_runtime_access_manifest "$target_control"
  apply_migration
  [ "$(release_state)" = "S11_DISABLED|NOT_STARTED" ] || fail "S11_2_CODE_OFF_RED"
  systemctl daemon-reload
  systemctl reset-failed tu1nz-adult-public-s11-canary-controller.service >/dev/null 2>&1 || true
  verify_controller_unit_contract
  run_controller_access_check
  systemctl restart "$S8_SERVICE"
  systemctl restart "$WMS_SERVICE"
  wait_wms_ready
  require_public_health
  wait_runtime
  run_runtime_health
  [ "$(release_state)" = "S11_DISABLED|NOT_STARTED" ] || fail "S11_2_FEATURE_OFF_FALLBACK_STATE_RED"
  printf '{"ok":true,"safe_code":"S11_2_FEATURE_OFF_FALLBACK_GREEN"}\n' \
    > "$backup_path/feature-off-fallback.json"
  run_synthetic_journeys "$backup_path/synthetic-journeys.json"
  technical_latency_fixture "$backup_path/technical-latency-input.json" "$backup_path/technical-latency-values.txt"
  require_hard_gates
  previous_trigger="$(systemctl show tu1nz-adult-public-s11-canary-controller.timer -p LastTriggerUSec --value 2>/dev/null || true)"
  database_transition START_CANARY S11_2_CANARY_BOOTSTRAP_LIVE
  insert_technical_evidence "$backup_path/technical-latency-values.txt"
  current_state="$(gate_json true | gate_field decision)"
  [ "$current_state" = CANARY_COLLECTING_EVIDENCE ] || fail "S11_2_INITIAL_CANARY_STATE_RED"
  release_lock
  systemctl enable --now tu1nz-adult-public-s11-canary-controller.timer
  wait_controller_natural_run "$previous_trigger"
  run_runtime_health
  verify_target "$target_control"
  install -d -o root -g root -m 0700 "$backup_path/postdeploy"
  mv "$backup_path/synthetic-journeys.json" "$backup_path/postdeploy/synthetic-journeys.json"
  move_optional_synthetic_companions "$backup_path" "$backup_path/postdeploy"
  mv "$backup_path/technical-latency-input.json" "$backup_path/postdeploy/technical-latency-input.json"
  mv "$backup_path/technical-latency-values.txt" "$backup_path/postdeploy/technical-latency-values.txt"
  mv "$backup_path/feature-off-fallback.json" "$backup_path/postdeploy/feature-off-fallback.json"
  database_evidence "$backup_path/postdeploy/database-aggregate.json"
  gate_json true > "$backup_path/postdeploy/canary-gate.json"
  systemctl show "${SERVICES[@]}" "${TIMERS[@]}" tu1nz-adult-public-s11-canary-controller.timer \
    > "$backup_path/postdeploy/runtime-manifest.txt"
  chmod -R go-rwx "$backup_path/postdeploy"
  (
    cd "$backup_path/postdeploy"
    find . -type f ! -name POSTDEPLOY_SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > POSTDEPLOY_SHA256SUMS
    sha256sum -c POSTDEPLOY_SHA256SUMS >/dev/null
  )
  (cd "$backup_path" && sha256sum -c SHA256SUMS >/dev/null)
  trap - ERR
  S11_2_ROLLBACK_ARMED=false
  printf '{"ok":true,"safe_code":"S11_2_DEPLOYMENT_GREEN","canary_state":"CANARY_COLLECTING_EVIDENCE","human_acceptance":"DEFERRED"}\n'
}

deployment_error() {
  local exit_status=$?
  trap - ERR
  if [ "${S11_2_ROLLBACK_ARMED:-false}" = true ] \
    && restore_source "$S11_2_BACKUP_PATH" "$S11_2_TARGET_CONTROL"; then
    printf '{"ok":false,"safe_code":"S11_2_DEPLOYMENT_ROLLED_BACK"}\n' >&2
  else
    printf '{"ok":false,"safe_code":"S11_2_DEPLOYMENT_ROLLBACK_RED"}\n' >&2
  fi
  exit "$exit_status"
}

observe() {
  local hard=true payload decision transition current_state
  require_root
  acquire_lock
  current_state="$(release_state)"
  if ! require_clean_commit \
      "$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE" TARGET_APPLICATION \
    || ! verify_runtime_access_contract >/dev/null; then
    if [[ "$current_state" == S11_CANARY\|* ]]; then
      database_transition CANARY_RED S11_2_RUNTIME_INTEGRITY_RED
      require_public_health
      printf '{"ok":false,"safe_code":"S11_2_CANARY_DISABLED_RUNTIME_INTEGRITY_RED"}\n' >&2
    else
      fail "S11_2_RUNTIME_INTEGRITY_RED"
    fi
    return 2
  fi
  if ! require_hard_gates; then
    hard=false
  fi
  if ! payload="$(gate_json "$hard")"; then
    if [[ "$current_state" == S11_CANARY\|* ]]; then
      database_transition CANARY_RED S11_2_GATE_READER_RED
      printf '{"ok":false,"safe_code":"S11_2_CANARY_DISABLED_GATE_READER_RED"}\n' >&2
    else
      fail "S11_2_GATE_READER_RED"
    fi
    return 2
  fi
  decision="$(printf '%s\n' "$payload" | gate_field decision)"
  transition="$(printf '%s\n' "$payload" | /usr/bin/python3 -c 'import json,sys;p=json.load(sys.stdin);print(p.get("transition") or "NONE")')"
  case "$transition" in
    NONE)
      if [ "$hard" != true ]; then
        fail "S11_2_TERMINAL_HARD_GATE_RED"
      fi
      printf '%s\n' "$payload"
      ;;
    CANARY_RED)
      database_transition CANARY_RED S11_2_CANARY_FAIL_CLOSED
      require_public_health
      printf '{"ok":false,"safe_code":"S11_2_CANARY_DISABLED_RED","decision":"%s"}\n' "$decision"
      ;;
    CANARY_INSUFFICIENT_REAL_VOLUME)
      database_transition CANARY_INSUFFICIENT_REAL_VOLUME S11_2_CANARY_INSUFFICIENT_REAL_VOLUME
      require_public_health
      printf '{"ok":true,"safe_code":"S11_2_CANARY_DISABLED_INSUFFICIENT_REAL_VOLUME"}\n'
      ;;
    PROMOTE_FULL)
      [ "$hard" = true ] || fail "S11_2_PROMOTION_HARD_GATE_RED"
      if ! require_hard_gates; then
        database_transition CANARY_RED S11_2_PROMOTION_HARD_GATE_RED
        require_public_health
        printf '{"ok":false,"safe_code":"S11_2_CANARY_DISABLED_PROMOTION_HARD_GATE_RED"}\n' >&2
        return 2
      fi
      if ! payload="$(promote_under_barrier_json)"; then
        database_transition CANARY_RED S11_2_PROMOTION_BARRIER_RED
        require_public_health
        printf '{"ok":false,"safe_code":"S11_2_CANARY_DISABLED_PROMOTION_BARRIER_RED"}\n' >&2
        return 2
      fi
      if ! require_hard_gates; then
        fail "S11_2_POST_PROMOTION_HARD_GATE_RED"
        return 2
      fi
      [ "$(release_state)" = "S11_FULL|FULL_RELEASE" ] || fail "S11_2_PROMOTION_STATE_RED"
      printf '%s\n' "$payload"
      ;;
    *) fail "S11_2_GATE_TRANSITION_RED" ;;
  esac
}

rollback() {
  local backup_path="$1" target_control="$2"
  require_root
  acquire_lock
  require_sha "$target_control"
  require_backup_path "$backup_path"
  restore_source "$backup_path" "$target_control" || fail "S11_2_ROLLBACK_RED"
  printf '{"ok":true,"safe_code":"S11_2_ROLLBACK_GREEN"}\n'
}

usage() {
  printf 'usage: %s access-preflight\n' "$0" >&2
  printf 'usage: %s preflight TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s deploy TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s observe\n' "$0" >&2
  printf '       %s verify TARGET_CONTROL BACKUP_PATH\n' "$0" >&2
  printf '       %s rollback BACKUP_PATH TARGET_CONTROL\n' "$0" >&2
  return 2
}

case "${1:-}" in
  access-preflight)
    [ "$#" -eq 1 ] || usage
    controller_access_check
    ;;
  hard-gates-read-only)
    [ "$#" -eq 1 ] || usage
    require_root
    require_hard_gates
    ;;
  preflight)
    [ "$#" -eq 3 ] || usage
    preflight "$2" "$3"
    ;;
  deploy)
    [ "$#" -eq 3 ] || usage
    deploy "$2" "$3"
    ;;
  observe)
    [ "$#" -eq 1 ] || usage
    observe
    ;;
  verify)
    [ "$#" -eq 3 ] || usage
    require_root
    acquire_lock
    S11_2_BACKUP_PATH="$3"
    verify_target "$2"
    ;;
  rollback)
    [ "$#" -eq 3 ] || usage
    rollback "$2" "$3"
    ;;
  *) usage ;;
esac
