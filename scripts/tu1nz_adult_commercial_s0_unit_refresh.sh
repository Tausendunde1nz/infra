#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-}"
[[ "$MODE" == preflight || "$MODE" == restore-test || "$MODE" == install || "$MODE" == resume-verify || "$MODE" == recover-bytecode-resume || "$MODE" == verify || "$MODE" == rollback ]] || {
  echo "usage: $0 preflight|restore-test|install|resume-verify|recover-bytecode-resume|verify|rollback --control-sha SHA [--archive PATH] [--manifest PATH] [--evidence-root PATH] [--restore-root PATH]" >&2
  exit 2
}
shift

CONTROL_SHA=""
ARCHIVE=""
MANIFEST=""
EVIDENCE_ROOT=""
RESTORE_ROOT=""
while (( $# > 0 )); do
  case "$1" in
    --control-sha) CONTROL_SHA="${2:-}"; shift 2 ;;
    --archive) ARCHIVE="${2:-}"; shift 2 ;;
    --manifest) MANIFEST="${2:-}"; shift 2 ;;
    --evidence-root) EVIDENCE_ROOT="${2:-}"; shift 2 ;;
    --restore-root) RESTORE_ROOT="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

readonly UNIT="tu1nz-adult-commercial-s0.service"
readonly APPLICATION_SHA="52494d6121660ead53774deb8616701f14bb7a8f"
readonly OLD_CONTROL_SHA="8c4e8992a60c215295cf9d0c400afcd9a931f883"
readonly OLD_UNIT_SHA256="ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3"
readonly OLD_MANIFEST_SHA256="2a3dc857205f9cff262edd686bc6db13d799c1e5de8aea954a8f50b9420cdc54"
readonly OLD_ARCHIVE="/opt/tu1nz_repos/backups/encrypted-system/tu1nz_system_backup_20260828T16-50-53Z.tar.gz"
readonly RELEASE_ROOT="/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial"
readonly CONTROL_RELEASE_ROOT="$RELEASE_ROOT/control"
readonly CONTROL_RELEASE="$CONTROL_RELEASE_ROOT/$CONTROL_SHA"
readonly CONFIG_ROOT="/etc/tu1nz/adult-publishing/staging-s0-commercial"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial"
readonly INSTALLED_UNIT="/etc/systemd/system/$UNIT"
readonly INSTALLED_MANIFEST="$CONFIG_ROOT/release-manifest.json"
readonly RUNTIME_USER="tu1nz-adult-commercial-s0"
readonly RUNTIME_GROUP="tu1nz-adult-commercial-s0"
readonly DATABASE="tu1nz_adult_commercial_s0"

fail() { echo "M4_25_STOPPED_UNIT_REFRESH_BLOCKED $*" >&2; exit 1; }
sha256() { /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'; }
git_read() { local repository="$1"; shift; /usr/bin/git -c "safe.directory=$repository" -C "$repository" "$@"; }
property() { /bin/systemctl show "$UNIT" --property="$1" --value; }
postgres() { /usr/sbin/runuser -u postgres -- /usr/bin/psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 "$@"; }
require_root() { [[ "$EUID" -eq 0 ]] || fail "root identity required"; }

runtime_max_microseconds() {
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$CONTROL_RELEASE/scripts" "$1" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from tu1nz_adult_commercial_s0_first_start import systemd_duration_microseconds

value = systemd_duration_microseconds(sys.argv[2])
if value is None:
    raise SystemExit("invalid finite systemd duration")
print(value)
PY
}

acquire_lock() {
  exec 9>>/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh.lock
  /usr/bin/chmod 0600 /opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh.lock
  /usr/bin/flock -n 9 || fail "another M4.25 transaction is active"
}

require_control_sha() {
  [[ "$CONTROL_SHA" =~ ^[0-9a-f]{40}$ && "$CONTROL_SHA" != "$OLD_CONTROL_SHA" ]] || fail "new exact Control SHA required"
}

require_safe_archive() {
  [[ "$ARCHIVE" == /opt/tu1nz_repos/backups/encrypted-system/tu1nz_system_backup_*.tar.gz ]] || fail "exact encrypted backup path required"
  [[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || fail "safe encrypted backup archive required"
}

require_safe_evidence_root() {
  [[ "$EVIDENCE_ROOT" =~ ^/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh/[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$ ]] || fail "exact M4.25 evidence root required"
}

verify_release() {
  [[ -d "$CONTROL_RELEASE/.git" && ! -L "$CONTROL_RELEASE" ]] || fail "immutable Control release missing"
  [[ "$(git_read "$CONTROL_RELEASE" rev-parse HEAD)" == "$CONTROL_SHA" ]] || fail "Control release SHA mismatch"
  [[ -z "$(git_read "$CONTROL_RELEASE" status --porcelain=v1)" ]] || fail "Control release is dirty"
  [[ -z "$(git_read "$CONTROL_RELEASE" clean -ndx)" ]] || fail "Control release has untracked or ignored files"
  git_read "$CONTROL_RELEASE" fsck --full >/dev/null
  [[ "$(stat -c '%a:%U:%G' "$CONTROL_RELEASE")" == "750:root:$RUNTIME_GROUP" ]] || fail "Control release metadata mismatch"
  [[ -f "$CONTROL_RELEASE/systemd/$UNIT" && ! -L "$CONTROL_RELEASE/systemd/$UNIT" ]] || fail "versioned unit missing"
  /usr/bin/systemd-analyze verify "$CONTROL_RELEASE/systemd/$UNIT"
  [[ "$(/usr/bin/grep -c '^Restart=no$' "$CONTROL_RELEASE/systemd/$UNIT")" == 1 ]] || fail "versioned unit must contain exact Restart=no"
  [[ "$(/usr/bin/grep -c '^RuntimeMaxSec=180$' "$CONTROL_RELEASE/systemd/$UNIT")" == 1 ]] || fail "versioned unit must contain exact RuntimeMaxSec=180"
  ! /usr/bin/grep -Eq '^\[Install\]$|^WantedBy=|^OnFailure=|^Restart=(always|on-failure)$' "$CONTROL_RELEASE/systemd/$UNIT" || fail "versioned unit contains activation or restart behavior"
}

verify_never_started() {
  [[ "$(property NRestarts)" == 0 ]] || fail "candidate restart count is non-zero"
  [[ "$(property ExecMainStartTimestampMonotonic)" == 0 ]] || fail "candidate has a main-process start timestamp"
  [[ "$(property ActiveEnterTimestampMonotonic)" == 0 ]] || fail "candidate has an active-enter timestamp"
  [[ -z "$(property ExecMainStartTimestamp)" && -z "$(property ActiveEnterTimestamp)" ]] || fail "candidate has textual start evidence"
  [[ "$(/usr/bin/journalctl -u "$UNIT" --no-pager --output=cat 2>/dev/null | /usr/bin/wc -l)" == 0 ]] || fail "candidate journal contains start evidence"
  [[ ! -e "$STATE_ROOT/runtime-status.json" && ! -L "$STATE_ROOT/runtime-status.json" ]] || fail "runtime status exists before first start"
  [[ ! -e "$STATE_ROOT/runtime.lock" && ! -L "$STATE_ROOT/runtime.lock" ]] || fail "runtime lock exists before first start"
}

verify_environment() {
  [[ "$(property LoadState)" == loaded ]] || fail "candidate is not loaded"
  [[ "$(property ActiveState)" == inactive ]] || fail "candidate is not inactive"
  [[ "$(property SubState)" == dead ]] || fail "candidate is not dead"
  [[ "$(property UnitFileState)" == static ]] || fail "candidate is not static"
  [[ -z "$(property Triggers)" && -z "$(property TriggeredBy)" ]] || fail "candidate has a trigger"
  [[ "$(/bin/systemctl list-timers --all --no-pager --plain | /usr/bin/grep -c 'adult-commercial-s0' || true)" == 0 ]] || fail "candidate timer exists"
  ! /usr/bin/pgrep -f 'tu1nz-commercial-runtime-candidate' >/dev/null || fail "candidate process exists"
  /bin/systemctl is-active --quiet postgresql.service || fail "PostgreSQL is not active"
  /bin/systemctl is-active --quiet tu1nz-adult-publishing-s1.service || fail "STAGING-S1 is not active"
  /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "encrypted-backup timer is not active"
  ! /bin/systemctl is-active --quiet tu1nz_encrypted_backup.service || fail "encrypted-backup service is active"
  [[ "$(postgres --dbname="$DATABASE" --command="SELECT (SELECT count(*) FROM creators) || '|' || (SELECT count(*) FROM policy_versions) || '|' || (SELECT count(*) FROM country_policy_rules) || '|' || (SELECT count(*) FROM platform_policy_rules) || '|' || (SELECT count(*) FROM integration_accounts) || '|' || (SELECT count(*) FROM publication_destinations)")" == "1|1|1|3|3|3" ]] || fail "synthetic database counts changed"
  [[ "$(postgres --dbname="$DATABASE" --command="SELECT (SELECT count(*) FROM pg_tables WHERE schemaname='public') || '|' || (SELECT count(*) FROM pg_proc WHERE proname LIKE 'tu1nz_%')")" == "39|21" ]] || fail "commercial schema changed"
  verify_never_started
}

verify_pre_refresh() {
  verify_environment
  verify_release
  [[ "$(sha256 "$INSTALLED_UNIT")" == "$OLD_UNIT_SHA256" ]] || fail "installed old unit boundary drift"
  [[ "$(sha256 "$INSTALLED_MANIFEST")" == "$OLD_MANIFEST_SHA256" ]] || fail "installed old manifest boundary drift"
  [[ "$(readlink "$RELEASE_ROOT/control-current")" == "control/$OLD_CONTROL_SHA" ]] || fail "old active Control link boundary drift"
  [[ "$(property Restart)" == on-failure ]] || fail "old effective Restart boundary drift"
  [[ "$(property RuntimeMaxUSec)" == infinity ]] || fail "old effective runtime maximum boundary drift"
}

verify_manifest_inputs() {
  require_safe_archive
  [[ "$MANIFEST" == "/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-input/release-manifest.$CONTROL_SHA.json" ]] || fail "exact prepared manifest path required"
  [[ -f "$MANIFEST" && ! -L "$MANIFEST" && "$(stat -c '%a:%U:%G:%h' "$MANIFEST")" == "600:root:root:1" ]] || fail "safe prepared manifest required"
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$CONTROL_RELEASE/scripts" "$MANIFEST" "$CONTROL_SHA" "$(sha256 "$CONTROL_RELEASE/systemd/$UNIT")" "$(basename "$ARCHIVE")" "$(sha256 "$ARCHIVE")" "$ARCHIVE" <<'PY'
import sys
from pathlib import Path

scripts, path, control_sha, unit_sha, archive_name, archive_sha, archive = sys.argv[1:]
sys.path.insert(0, scripts)
from tu1nz_adult_commercial_s0_release_gate import load_manifest, verify_archive

payload = load_manifest(Path(path))
verify_archive(Path(archive), payload)
expected = {
    "control_sha": control_sha, "unit_sha256": unit_sha,
    "archive_name": archive_name, "archive_sha256": archive_sha,
    "network_enabled": False, "external_providers_enabled": False,
    "real_media_enabled": False, "real_payment_enabled": False,
    "synthetic_data_only": True, "synthetic_publishers_only": True,
    "telegram_intake_enabled": False,
}
if any(payload.get(key) != value for key, value in expected.items()):
    raise SystemExit("prepared manifest boundary mismatch")
PY
}

verify_post_refresh() {
  verify_environment
  verify_release
  require_safe_archive
  [[ "$(readlink "$RELEASE_ROOT/control-current")" == "control/$CONTROL_SHA" ]] || fail "active Control link mismatch"
  /usr/bin/cmp --silent "$INSTALLED_UNIT" "$CONTROL_RELEASE/systemd/$UNIT" || fail "installed unit differs from SSOT"
  [[ "$(property Restart)" == no ]] || fail "effective Restart is not no"
  [[ "$(runtime_max_microseconds "$(property RuntimeMaxUSec)")" == 180000000 ]] || fail "effective runtime maximum is not 180 seconds"
  PYTHONDONTWRITEBYTECODE=1 "$CONTROL_RELEASE/scripts/tu1nz_adult_commercial_s0_release_gate.py" \
    --manifest "$INSTALLED_MANIFEST" --application-repository "$RELEASE_ROOT/application-current" \
    --control-repository "$RELEASE_ROOT/control-current" --application-release-root "$RELEASE_ROOT/application" \
    --control-release-root "$CONTROL_RELEASE_ROOT" --venv "$RELEASE_ROOT/venv-current" \
    --configuration-root "$CONFIG_ROOT" --state-root "$STATE_ROOT" --installed-unit "$INSTALLED_UNIT" \
    --archive "$ARCHIVE" --runtime-user "$RUNTIME_USER" --runtime-group "$RUNTIME_GROUP" \
    --release-user root --configuration-user root --unit-user root --unit-group root --require-active >/dev/null
}

# Rollback is never automatic.
restore_test() {
  require_root
  acquire_lock
  require_control_sha
  require_safe_archive
  [[ "$RESTORE_ROOT" =~ ^/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-restore/[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$ ]] || fail "exact isolated restore root required"
  [[ ! -e "$RESTORE_ROOT" && ! -L "$RESTORE_ROOT" ]] || fail "isolated restore root already exists"
  /usr/bin/python3 - "$ARCHIVE" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

with tarfile.open(sys.argv[1], mode="r:gz") as handle:
    members = handle.getmembers()
names = set()
for member in members:
    name = member.name.rstrip("/")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise SystemExit("unsafe archive member")
    if name in names or member.islnk() or member.isdev() or member.isfifo():
        raise SystemExit("unsafe archive member type")
    names.add(name)
symlinks = {member.name.rstrip("/") for member in members if member.issym()}
if any(other.startswith(link + "/") for link in symlinks for other in names if other != link):
    raise SystemExit("archive writes through symlink member")
PY
  /usr/bin/install -d -o root -g root -m 0700 "$RESTORE_ROOT"
  /usr/bin/tar -xzf "$ARCHIVE" -C "$RESTORE_ROOT" --no-same-owner --no-same-permissions \
    "releases/adult-publishing/staging-s0-commercial/application/$APPLICATION_SHA" \
    "releases/adult-publishing/staging-s0-commercial/control/$CONTROL_SHA" \
    "releases/adult-publishing/staging-s0-commercial/venv/$APPLICATION_SHA" \
    "tu1nz/adult-publishing/staging-s0-commercial" \
    "tausendunde1nz/adult-publishing/staging-s0-commercial" \
    commercial-s0-database.dump staging-s1-database.dump
  [[ "$(sha256 "$RESTORE_ROOT/releases/adult-publishing/staging-s0-commercial/control/$CONTROL_SHA/systemd/$UNIT")" == "$(sha256 "$CONTROL_RELEASE/systemd/$UNIT")" ]] || fail "restored unit digest mismatch"
  /usr/bin/pg_restore --list "$RESTORE_ROOT/commercial-s0-database.dump" >/dev/null
  /usr/bin/pg_restore --list "$RESTORE_ROOT/staging-s1-database.dump" >/dev/null
  [[ "$(sha256 "$RESTORE_ROOT/tausendunde1nz/adult-publishing/staging-s0-commercial/state.json")" == "$(sha256 "$STATE_ROOT/state.json")" ]] || fail "restored commercial state mismatch"
  printf 'archive_sha256=%s\ncontrol_sha=%s\nunit_sha256=%s\nstate_sha256=%s\nrestore_completed_at=%s\n' \
    "$(sha256 "$ARCHIVE")" "$CONTROL_SHA" "$(sha256 "$CONTROL_RELEASE/systemd/$UNIT")" \
    "$(sha256 "$STATE_ROOT/state.json")" "$(/usr/bin/date -u -Is)" >"$RESTORE_ROOT/restore-evidence.txt"
  /usr/bin/chmod 0600 "$RESTORE_ROOT/restore-evidence.txt"
  echo "M4_25_ISOLATED_RESTORE_OK root=$RESTORE_ROOT"
}

install_refresh() {
  require_root
  acquire_lock
  require_control_sha
  require_safe_evidence_root
  verify_pre_refresh
  verify_manifest_inputs
  [[ ! -e "$EVIDENCE_ROOT" && ! -L "$EVIDENCE_ROOT" ]] || fail "M4.25 evidence root already exists"
  /usr/bin/install -d -o root -g root -m 0700 "$EVIDENCE_ROOT"
  /usr/bin/install -o root -g root -m 0600 "$INSTALLED_UNIT" "$EVIDENCE_ROOT/$UNIT.before"
  /usr/bin/install -o root -g root -m 0600 "$INSTALLED_MANIFEST" "$EVIDENCE_ROOT/release-manifest.json.before"
  printf '%s\n' "$(readlink "$RELEASE_ROOT/control-current")" >"$EVIDENCE_ROOT/control-current.before"
  /usr/bin/chmod 0600 "$EVIDENCE_ROOT/control-current.before"
  printf 'phase=evidence-preserved\n' >"$EVIDENCE_ROOT/phase.txt"
  /usr/bin/chmod 0600 "$EVIDENCE_ROOT/phase.txt"
  /usr/bin/install -o root -g "$RUNTIME_GROUP" -m 0640 "$MANIFEST" "$INSTALLED_MANIFEST"
  printf 'phase=manifest-installed\n' >"$EVIDENCE_ROOT/phase.txt"
  verify_never_started
  /usr/bin/install -o root -g root -m 0644 "$CONTROL_RELEASE/systemd/$UNIT" "$INSTALLED_UNIT"
  printf 'phase=unit-installed\n' >"$EVIDENCE_ROOT/phase.txt"
  verify_never_started
  local next_link="$RELEASE_ROOT/control-current.m4-25-$CONTROL_SHA"
  [[ ! -e "$next_link" && ! -L "$next_link" ]] || fail "temporary Control link already exists"
  /usr/bin/ln -s "control/$CONTROL_SHA" "$next_link"
  /usr/bin/mv -T -- "$next_link" "$RELEASE_ROOT/control-current"
  printf 'phase=control-advanced\n' >"$EVIDENCE_ROOT/phase.txt"
  verify_never_started
  /bin/systemctl daemon-reload
  printf 'phase=daemon-reloaded\n' >"$EVIDENCE_ROOT/phase.txt"
  verify_post_refresh
  printf 'phase=verified-stopped\n' >"$EVIDENCE_ROOT/phase.txt"
  echo "M4_25_STOPPED_UNIT_REFRESH_OK evidence=$EVIDENCE_ROOT"
}

resume_verify() {
  require_root
  acquire_lock
  require_control_sha
  require_safe_evidence_root
  require_safe_archive
  [[ -f "$EVIDENCE_ROOT/phase.txt" && ! -L "$EVIDENCE_ROOT/phase.txt" ]] || fail "resume evidence phase missing"
  [[ "$(cat "$EVIDENCE_ROOT/phase.txt")" == phase=daemon-reloaded ]] || fail "exact daemon-reloaded resume phase required"
  [[ "$(sha256 "$EVIDENCE_ROOT/$UNIT.before")" == "$OLD_UNIT_SHA256" ]] || fail "resume rollback unit evidence mismatch"
  [[ "$(sha256 "$EVIDENCE_ROOT/release-manifest.json.before")" == "$OLD_MANIFEST_SHA256" ]] || fail "resume rollback manifest evidence mismatch"
  [[ "$(cat "$EVIDENCE_ROOT/control-current.before")" == "control/$OLD_CONTROL_SHA" ]] || fail "resume rollback Control evidence mismatch"
  verify_post_refresh
  printf 'phase=verified-stopped\n' >"$EVIDENCE_ROOT/phase.txt"
  echo "M4_25_STOPPED_UNIT_RESUME_VERIFY_OK evidence=$EVIDENCE_ROOT"
}

recover_bytecode_resume() {
  require_root
  acquire_lock
  require_control_sha
  require_safe_evidence_root
  require_safe_archive
  local bytecode="$CONTROL_RELEASE/scripts/__pycache__"
  local manifest_pyc="$bytecode/tu1nz_adult_commercial_s0_manifest.cpython-312.pyc"
  local staging_pyc="$bytecode/tu1nz_adult_staging_manifest.cpython-312.pyc"
  local preserved="$EVIDENCE_ROOT/rejected-python-bytecode-$CONTROL_SHA"
  [[ "$(cat "$EVIDENCE_ROOT/phase.txt")" == phase=daemon-reloaded ]] || fail "exact daemon-reloaded recovery phase required"
  verify_never_started
  [[ -d "$bytecode" && ! -L "$bytecode" && ! -e "$preserved" && ! -L "$preserved" ]] || fail "exact bytecode recovery boundary required"
  [[ "$(/usr/bin/find "$bytecode" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | /usr/bin/sort)" == $'tu1nz_adult_commercial_s0_manifest.cpython-312.pyc\ntu1nz_adult_staging_manifest.cpython-312.pyc' ]] || fail "unexpected bytecode recovery content"
  [[ "$(sha256 "$manifest_pyc")" == 788207a92807a9cd5437da6966a5d0f3cd947fc991154af56b49654fdb3282cf ]] || fail "commercial manifest bytecode digest mismatch"
  [[ "$(sha256 "$staging_pyc")" == c18c5c923d075ac94e3d1ddd859e8c33a5dbbe4944ef5464dd3d639d0bc55093 ]] || fail "staging manifest bytecode digest mismatch"
  [[ -z "$(git_read "$CONTROL_RELEASE" status --porcelain=v1)" ]] || fail "tracked Control release drift during bytecode recovery"
  [[ "$(git_read "$CONTROL_RELEASE" clean -ndx)" == "Would remove scripts/__pycache__/" ]] || fail "unexpected ignored Control release material"
  /usr/bin/mv -- "$bytecode" "$preserved"
  /usr/bin/chown -R root:root "$preserved"
  /usr/bin/chmod 0700 "$preserved"
  /usr/bin/chmod 0600 "$preserved"/*.pyc
  [[ -z "$(git_read "$CONTROL_RELEASE" status --porcelain=v1)" ]] || fail "tracked Control release drift after bytecode preservation"
  [[ -z "$(git_read "$CONTROL_RELEASE" clean -ndx)" ]] || fail "Control release remains unclean after bytecode preservation"
  verify_post_refresh
  printf 'phase=verified-stopped\n' >"$EVIDENCE_ROOT/phase.txt"
  echo "M4_25_STOPPED_UNIT_BYTECODE_RECOVERY_OK evidence=$EVIDENCE_ROOT"
}

rollback_refresh() {
  require_root
  acquire_lock
  require_control_sha
  require_safe_evidence_root
  require_safe_archive
  verify_never_started
  [[ -f "$EVIDENCE_ROOT/$UNIT.before" && ! -L "$EVIDENCE_ROOT/$UNIT.before" ]] || fail "rollback unit evidence missing"
  [[ -f "$EVIDENCE_ROOT/release-manifest.json.before" && ! -L "$EVIDENCE_ROOT/release-manifest.json.before" ]] || fail "rollback manifest evidence missing"
  [[ "$(sha256 "$EVIDENCE_ROOT/$UNIT.before")" == "$OLD_UNIT_SHA256" ]] || fail "rollback unit digest mismatch"
  [[ "$(sha256 "$EVIDENCE_ROOT/release-manifest.json.before")" == "$OLD_MANIFEST_SHA256" ]] || fail "rollback manifest digest mismatch"
  [[ "$(cat "$EVIDENCE_ROOT/control-current.before")" == "control/$OLD_CONTROL_SHA" ]] || fail "rollback Control link mismatch"
  [[ -f "$OLD_ARCHIVE" && ! -L "$OLD_ARCHIVE" ]] || fail "old release archive missing"
  [[ "$(git_read "$CONTROL_RELEASE_ROOT/$OLD_CONTROL_SHA" rev-parse HEAD)" == "$OLD_CONTROL_SHA" ]] || fail "old Control release SHA mismatch"
  [[ -z "$(git_read "$CONTROL_RELEASE_ROOT/$OLD_CONTROL_SHA" status --porcelain=v1)" ]] || fail "old Control release is dirty"
  [[ "$(sha256 "$CONTROL_RELEASE_ROOT/$OLD_CONTROL_SHA/systemd/$UNIT")" == "$OLD_UNIT_SHA256" ]] || fail "old Control unit digest mismatch"
  /usr/bin/install -o root -g "$RUNTIME_GROUP" -m 0640 "$EVIDENCE_ROOT/release-manifest.json.before" "$INSTALLED_MANIFEST"
  /usr/bin/install -o root -g root -m 0644 "$EVIDENCE_ROOT/$UNIT.before" "$INSTALLED_UNIT"
  local prior_link="$RELEASE_ROOT/control-current.m4-25-rollback-$CONTROL_SHA"
  [[ ! -e "$prior_link" && ! -L "$prior_link" ]] || fail "rollback Control link already exists"
  /usr/bin/ln -s "control/$OLD_CONTROL_SHA" "$prior_link"
  /usr/bin/mv -T -- "$prior_link" "$RELEASE_ROOT/control-current"
  /bin/systemctl daemon-reload
  verify_environment
  [[ "$(sha256 "$INSTALLED_UNIT")" == "$OLD_UNIT_SHA256" ]] || fail "old unit was not restored"
  [[ "$(sha256 "$INSTALLED_MANIFEST")" == "$OLD_MANIFEST_SHA256" ]] || fail "old manifest was not restored"
  [[ "$(readlink "$RELEASE_ROOT/control-current")" == "control/$OLD_CONTROL_SHA" ]] || fail "old Control link was not restored"
  [[ "$(property Restart)" == on-failure && "$(property RuntimeMaxUSec)" == infinity ]] || fail "old effective unit boundary was not restored"
  PYTHONDONTWRITEBYTECODE=1 "$CONTROL_RELEASE_ROOT/$OLD_CONTROL_SHA/scripts/tu1nz_adult_commercial_s0_release_gate.py" \
    --manifest "$INSTALLED_MANIFEST" --application-repository "$RELEASE_ROOT/application-current" \
    --control-repository "$RELEASE_ROOT/control-current" --application-release-root "$RELEASE_ROOT/application" \
    --control-release-root "$CONTROL_RELEASE_ROOT" --venv "$RELEASE_ROOT/venv-current" \
    --configuration-root "$CONFIG_ROOT" --state-root "$STATE_ROOT" --installed-unit "$INSTALLED_UNIT" \
    --archive "$OLD_ARCHIVE" --runtime-user "$RUNTIME_USER" --runtime-group "$RUNTIME_GROUP" \
    --release-user root --configuration-user root --unit-user root --unit-group root --require-active >/dev/null
  printf 'phase=rolled-back-stopped\n' >"$EVIDENCE_ROOT/phase.txt"
  echo "M4_25_STOPPED_UNIT_ROLLBACK_OK"
}

case "$MODE" in
  preflight)
    require_root
    acquire_lock
    require_control_sha
    verify_pre_refresh
    echo "M4_25_STOPPED_UNIT_PREFLIGHT_OK"
    ;;
  restore-test) restore_test ;;
  install) install_refresh ;;
  resume-verify) resume_verify ;;
  recover-bytecode-resume) recover_bytecode_resume ;;
  verify)
    require_root
    acquire_lock
    require_control_sha
    verify_post_refresh
    echo "M4_25_STOPPED_UNIT_VERIFY_OK"
    ;;
  rollback) rollback_refresh ;;
esac
