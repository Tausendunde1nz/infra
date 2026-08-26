#!/usr/bin/env bash
set -Eeuo pipefail

LOG_DIR="/var/log/tausendunde1nz"
LOG_FILE="$LOG_DIR/git_sync.log"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE"

REPOS=(
  "/opt/spicymila_bot"
  "/opt/telegram_chatbot"
  "/opt/trendwatch_bot"
)

timestamp() { date -Is; }

sync_repo() {
  local repo="$1"
  echo "[$(timestamp)] repo=$repo state=start" | tee -a "$LOG_FILE"

  if [[ ! -d "$repo/.git" ]]; then
    echo "[$(timestamp)] repo=$repo state=skip reason=not-a-git-repository" | tee -a "$LOG_FILE"
    return 0
  fi

  git -C "$repo" status --porcelain | sed 's/^/    WS: /' | tee -a "$LOG_FILE" || true

  if ! git -C "$repo" pull --rebase --autostash --ff-only 2>&1 | sed 's/^/    PULL: /' | tee -a "$LOG_FILE"; then
    git -C "$repo" pull --rebase --autostash 2>&1 | sed 's/^/    PULL(RB): /' | tee -a "$LOG_FILE" || true
  fi

  if [[ -n "$(git -C "$repo" status --porcelain)" ]]; then
    git -C "$repo" add -A
    git -C "$repo" commit -m "auto backup: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
      2>&1 | sed 's/^/    COMMIT: /' | tee -a "$LOG_FILE"
  fi

  local upstream current_branch ahead
  upstream="$(git -C "$repo" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  if [[ -z "$upstream" ]]; then
    current_branch="$(git -C "$repo" branch --show-current)"
    git -C "$repo" branch --set-upstream-to "origin/$current_branch" "$current_branch" 2>/dev/null || true
    upstream="$(git -C "$repo" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  fi

  ahead="$(git -C "$repo" rev-list --left-right --count HEAD..."${upstream:-HEAD}" 2>/dev/null | awk '{print $1}' || echo 0)"
  if [[ "${ahead:-0}" -gt 0 ]]; then
    git -C "$repo" push --force-with-lease 2>&1 | sed 's/^/    PUSH: /' | tee -a "$LOG_FILE" || true
  else
    echo "[$(timestamp)] repo=$repo state=clean" | tee -a "$LOG_FILE"
  fi

  echo "[$(timestamp)] repo=$repo state=done" | tee -a "$LOG_FILE"
}

for repo in "${REPOS[@]}"; do
  sync_repo "$repo"
done
