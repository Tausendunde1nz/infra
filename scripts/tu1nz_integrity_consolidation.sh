#!/usr/bin/env bash
set -euo pipefail
umask 0027

CONTROL_DIR="${TU1NZ_CONTROL_DIR:-/opt/tu1nz_repos/control}"
DOCS_DIR="${TU1NZ_DOCS_DIR:-/opt/tu1nz_repos/docs}"
STATE_ROOT="${TU1NZ_STATE_DIR:-/var/lib/tausendunde1nz/agentmode}"
INTEGRITY_DIR="${TU1NZ_INTEGRITY_DIR:-$STATE_ROOT/integrity}"
LOG_DIR="${TU1NZ_LOG_DIR:-/var/log/tausendunde1nz/health}"
LOCK_FILE="${TU1NZ_INTEGRITY_LOCK_FILE:-/run/tu1nz-agentmode/integrity.lock}"
REQUIRE_SYNC="${TU1NZ_REQUIRE_SYNC:-/usr/local/bin/tu1nz_require_sync.sh}"
GIT_BIN="${TU1NZ_GIT_BIN:-git}"
FLOCK_BIN="${TU1NZ_FLOCK_BIN:-flock}"

install -d -m 0750 "$STATE_ROOT" "$INTEGRITY_DIR" "$LOG_DIR" "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
"$FLOCK_BIN" -n 9 || exit 0

# shellcheck disable=SC1090
source "$REQUIRE_SYNC"
tu1nz_require_sync 12h

head_sha="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" rev-parse --verify 'HEAD^{commit}')"
tree_sha="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" rev-parse --verify 'HEAD^{tree}')"
branch="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" branch --show-current)"
tracked_status="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" status --porcelain=v1 --untracked-files=no)"
refs_sha256="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" for-each-ref --format='%(refname) %(objectname)' | LC_ALL=C sort | sha256sum | awk '{print $1}')"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ && "$tree_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$branch" == "control-main" ]]
[[ -z "$tracked_status" ]]

control_tmp="$(mktemp "$INTEGRITY_DIR/control-checksums.txt.tmp.XXXXXX")"
docs_tmp="$(mktemp "$INTEGRITY_DIR/docs-checksums.txt.tmp.XXXXXX")"
state_tmp="$(mktemp "$INTEGRITY_DIR/integrity_state.json.tmp.XXXXXX")"
cleanup() {
  rm -f "$control_tmp" "$docs_tmp" "$state_tmp"
}
trap cleanup EXIT

(
  cd "$CONTROL_DIR"
  env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" ls-files -z | xargs -0 sha256sum
) >"$control_tmp"
find -L "$DOCS_DIR" -maxdepth 1 -type f -name '*.pdf' -print 2>/dev/null | \
  LC_ALL=C sort | while IFS= read -r pdf; do sha256sum "$pdf"; done >"$docs_tmp"

control_manifest_sha256="$(sha256sum "$control_tmp" | awk '{print $1}')"
docs_manifest_sha256="$(sha256sum "$docs_tmp" | awk '{print $1}')"
observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '{\n  "status": "INTEGRITY_OK",\n  "control_head": "%s",\n  "control_tree": "%s",\n  "control_refs_sha256": "%s",\n  "control_manifest_sha256": "%s",\n  "docs_manifest_sha256": "%s",\n  "observed_at": "%s"\n}\n' \
  "$head_sha" "$tree_sha" "$refs_sha256" "$control_manifest_sha256" \
  "$docs_manifest_sha256" "$observed_at" >"$state_tmp"

chmod 0640 "$control_tmp" "$docs_tmp" "$state_tmp"
mv -f "$control_tmp" "$INTEGRITY_DIR/control-checksums.txt"
mv -f "$docs_tmp" "$INTEGRITY_DIR/docs-checksums.txt"
mv -f "$state_tmp" "$INTEGRITY_DIR/integrity_state.json"
trap - EXIT

transition_key="INTEGRITY_OK|$head_sha|$tree_sha|$control_manifest_sha256|$docs_manifest_sha256"
previous=""
if [[ -r "$INTEGRITY_DIR/notification_state" ]]; then
  previous="$(head -n 1 "$INTEGRITY_DIR/notification_state" 2>/dev/null || true)"
fi
if [[ "$transition_key" != "$previous" ]]; then
  transition_tmp="$(mktemp "$INTEGRITY_DIR/notification_state.tmp.XXXXXX")"
  printf '%s\n' "$transition_key" >"$transition_tmp"
  chmod 0640 "$transition_tmp"
  mv -f "$transition_tmp" "$INTEGRITY_DIR/notification_state"
  printf '[%s] INTEGRITY_OK head=%s tree=%s manifest=%s\n' \
    "$observed_at" "$head_sha" "$tree_sha" "$control_manifest_sha256" \
    >>"$LOG_DIR/integrity-transitions.log"
fi
