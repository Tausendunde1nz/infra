#!/usr/bin/env bash
# TU1NZ Agentmode observer. Canonical Control is always read-only.
set -euo pipefail
umask 0027

CONTROL_DIR="${TU1NZ_CONTROL_DIR:-/opt/tu1nz_repos/control}"
DOCS_DIR="${TU1NZ_DOCS_DIR:-/opt/tu1nz_repos/docs}"
STATE_DIR="${TU1NZ_STATE_DIR:-/var/lib/tausendunde1nz/agentmode}"
LOG_DIR="${TU1NZ_LOG_DIR:-/var/log/tausendunde1nz/health}"
LOCK_FILE="${TU1NZ_LOCK_FILE:-/run/tu1nz-agentmode/control-observer.lock}"
NOTIFY_CONFIG="${TU1NZ_NOTIFY_CONFIG:-/etc/tu1nz/notify.conf}"
CONTROL_BRANCH="${TU1NZ_CONTROL_BRANCH:-control-main}"
INTERVAL_SECONDS="${TU1NZ_INTERVAL_SECONDS:-300}"
REMOTE_TIMEOUT_SECONDS="${TU1NZ_REMOTE_TIMEOUT_SECONDS:-30}"
GIT_BIN="${TU1NZ_GIT_BIN:-git}"
CURL_BIN="${TU1NZ_CURL_BIN:-curl}"
FLOCK_BIN="${TU1NZ_FLOCK_BIN:-flock}"

CONTROL_STATUS="CONTROL_CHECK_NOT_RUN"
LOCAL_SHA="-"
LOCAL_TREE="-"
REMOTE_SHA="-"
REFS_SHA256="-"
OBSERVED_AT="-"
DOCS_STATUS="DOCS_NOT_CHECKED"

usage() {
  printf 'Usage: %s [--check|--observe-once|--loop]\n' "$0" >&2
}

sha256_stream() {
  sha256sum | awk '{print $1}'
}

control_snapshot() {
  local head tree branch tracked refs
  head="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || return 1
  tree="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" rev-parse --verify 'HEAD^{tree}' 2>/dev/null)" || return 1
  branch="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" branch --show-current 2>/dev/null)" || return 1
  tracked="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" status --porcelain=v1 --untracked-files=no 2>/dev/null)" || return 1
  refs="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" for-each-ref --format='%(refname) %(objectname)' 2>/dev/null | LC_ALL=C sort | sha256_stream)" || return 1

  [[ "$head" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$tree" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$branch" == "$CONTROL_BRANCH" ]] || return 1
  [[ -z "$tracked" ]] || return 1
  [[ "$refs" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s|%s|%s|%s\n' "$head" "$tree" "$branch" "$refs"
}

probe_control() {
  local before after remote_url remote_output remote_ref extra

  OBSERVED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  CONTROL_STATUS="CONTROL_LOCAL_STATE_INVALID"
  LOCAL_SHA="-"
  LOCAL_TREE="-"
  REMOTE_SHA="-"
  REFS_SHA256="-"

  before="$(control_snapshot)" || return 20
  IFS='|' read -r LOCAL_SHA LOCAL_TREE _ REFS_SHA256 <<<"$before"

  remote_url="$(env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$CONTROL_DIR" remote get-url origin 2>/dev/null)" || {
    CONTROL_STATUS="CONTROL_REMOTE_CONFIGURATION_INVALID"
    return 21
  }
  [[ -n "$remote_url" ]] || {
    CONTROL_STATUS="CONTROL_REMOTE_CONFIGURATION_INVALID"
    return 21
  }

  local -a remote_command
  remote_command=(
    "$GIT_BIN" -c credential.interactive=never ls-remote --exit-code
    "$remote_url" "refs/heads/$CONTROL_BRANCH"
  )
  if command -v timeout >/dev/null 2>&1; then
    remote_command=(timeout "$REMOTE_TIMEOUT_SECONDS" "${remote_command[@]}")
  fi
  if ! remote_output="$(GIT_TERMINAL_PROMPT=0 "${remote_command[@]}" 2>/dev/null)"; then
    CONTROL_STATUS="CONTROL_REMOTE_CHECK_FAILED"
    return 22
  fi

  if [[ -z "$remote_output" || "$remote_output" == *$'\n'* ]]; then
    CONTROL_STATUS="CONTROL_REMOTE_RESPONSE_INVALID"
    return 23
  fi
  read -r REMOTE_SHA remote_ref extra <<<"$remote_output"
  if [[ ! "$REMOTE_SHA" =~ ^[0-9a-f]{40}$ ]] || \
     [[ "$remote_ref" != "refs/heads/$CONTROL_BRANCH" ]] || \
     [[ -n "${extra:-}" ]]; then
    CONTROL_STATUS="CONTROL_REMOTE_RESPONSE_INVALID"
    REMOTE_SHA="-"
    return 23
  fi

  after="$(control_snapshot)" || {
    CONTROL_STATUS="CONTROL_POSTCHECK_FAILED"
    return 24
  }
  if [[ "$after" != "$before" ]]; then
    CONTROL_STATUS="CONTROL_MUTATION_DETECTED"
    return 25
  fi

  if [[ "$LOCAL_SHA" == "$REMOTE_SHA" ]]; then
    CONTROL_STATUS="CONTROL_CURRENT"
  else
    CONTROL_STATUS="CONTROL_UPDATE_AVAILABLE"
  fi
  return 0
}

sync_docs_repository() {
  DOCS_STATUS="DOCS_NOT_PRESENT"
  [[ -d "$DOCS_DIR/.git" ]] || return 0

  if env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$DOCS_DIR" fetch --all -q >/dev/null 2>&1 && \
     env GIT_OPTIONAL_LOCKS=0 "$GIT_BIN" -C "$DOCS_DIR" reset --hard '@{u}' -q >/dev/null 2>&1; then
    DOCS_STATUS="DOCS_SYNCED"
    return 0
  fi
  DOCS_STATUS="DOCS_SYNC_FAILED"
  return 1
}

atomic_write() {
  local destination="$1"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  cat >"$temporary"
  chmod 0640 "$temporary"
  mv -f "$temporary" "$destination"
}

write_observation_state() {
  printf '{\n  "status": "%s",\n  "local_sha": "%s",\n  "local_tree": "%s",\n  "remote_sha": "%s",\n  "refs_sha256": "%s",\n  "docs_status": "%s",\n  "observed_at": "%s"\n}\n' \
    "$CONTROL_STATUS" "$LOCAL_SHA" "$LOCAL_TREE" "$REMOTE_SHA" \
    "$REFS_SHA256" "$DOCS_STATUS" "$OBSERVED_AT" | \
    atomic_write "$STATE_DIR/control_update_state.json"
}

write_success_marker() {
  printf 'status=%s local_sha=%s remote_sha=%s observed_at=%s\n' \
    "$CONTROL_STATUS" "$LOCAL_SHA" "$REMOTE_SHA" "$OBSERVED_AT" | \
    atomic_write "$STATE_DIR/last_sync.ok"
}

send_transition_notification() {
  local message="$1"
  local BOT_TOKEN="" ALERT_CHAT_ID=""
  [[ -r "$NOTIFY_CONFIG" ]] || return 0
  # shellcheck disable=SC1090
  source "$NOTIFY_CONFIG" || return 0
  [[ -n "${BOT_TOKEN:-}" && -n "${ALERT_CHAT_ID:-}" ]] || return 0

  {
    printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$BOT_TOKEN"
    printf 'request = "POST"\n'
  } | "$CURL_BIN" -fsS --config - \
        --data-urlencode "chat_id=$ALERT_CHAT_ID" \
        --data-urlencode "text=$message" >/dev/null 2>&1 || true
}

record_transition() {
  local transition_key previous="" message
  transition_key="${CONTROL_STATUS}|${LOCAL_SHA}|${REMOTE_SHA}|${DOCS_STATUS}"
  if [[ -r "$STATE_DIR/notification_state" ]]; then
    previous="$(head -n 1 "$STATE_DIR/notification_state" 2>/dev/null || true)"
  fi
  [[ "$transition_key" != "$previous" ]] || return 0

  printf '%s\n' "$transition_key" | atomic_write "$STATE_DIR/notification_state"
  printf '[%s] status=%s local=%s remote=%s docs=%s\n' \
    "$OBSERVED_AT" "$CONTROL_STATUS" "$LOCAL_SHA" "$REMOTE_SHA" "$DOCS_STATUS" \
    >>"$LOG_DIR/control-transitions.log"

  message="TU1NZ Control: $CONTROL_STATUS
Local: $LOCAL_SHA
Remote: $REMOTE_SHA
Docs: $DOCS_STATUS
Time: $OBSERVED_AT"
  send_transition_notification "$message"
}

write_docs_checksums() {
  local temporary
  temporary="$(mktemp "$STATE_DIR/docs-checksums.txt.tmp.XXXXXX")"
  if find -L "$DOCS_DIR" -maxdepth 1 -type f -name '*.pdf' -print 2>/dev/null | \
      LC_ALL=C sort | while IFS= read -r pdf; do sha256sum "$pdf"; done >"$temporary"; then
    chmod 0640 "$temporary"
    mv -f "$temporary" "$STATE_DIR/docs-checksums.txt"
  else
    rm -f "$temporary"
    return 1
  fi
}

observe_once() {
  local probe_rc=0 docs_rc=0
  mkdir -p "$STATE_DIR" "$LOG_DIR" "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  if ! "$FLOCK_BIN" -n 9; then
    return 0
  fi

  sync_docs_repository || docs_rc=$?
  write_docs_checksums || docs_rc=$?
  if probe_control; then
    probe_rc=0
  else
    probe_rc=$?
  fi
  write_observation_state
  if [[ "$probe_rc" -eq 0 ]]; then
    write_success_marker
  fi
  record_transition

  if [[ "$probe_rc" -ne 0 ]]; then
    return "$probe_rc"
  fi
  return "$docs_rc"
}

run_check() {
  local probe_rc=0
  if probe_control; then
    probe_rc=0
  else
    probe_rc=$?
  fi
  printf '%s local=%s tree=%s remote=%s refs=%s observed_at=%s\n' \
    "$CONTROL_STATUS" "$LOCAL_SHA" "$LOCAL_TREE" "$REMOTE_SHA" \
    "$REFS_SHA256" "$OBSERVED_AT"
  return "$probe_rc"
}

mode="${1:---observe-once}"
case "$mode" in
  --check)
    [[ "$#" -eq 1 ]] || { usage; exit 64; }
    run_check
    ;;
  --observe-once)
    [[ "$#" -eq 1 ]] || { usage; exit 64; }
    observe_once
    ;;
  --loop)
    [[ "$#" -eq 1 ]] || { usage; exit 64; }
    [[ "$INTERVAL_SECONDS" =~ ^[1-9][0-9]*$ ]] || {
      printf 'Invalid TU1NZ_INTERVAL_SECONDS\n' >&2
      exit 64
    }
    while :; do
      observe_once || true
      sleep "$INTERVAL_SECONDS"
    done
    ;;
  *)
    usage
    exit 64
    ;;
esac
