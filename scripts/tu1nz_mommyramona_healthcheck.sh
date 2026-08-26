#!/usr/bin/env bash
set -Eeuo pipefail

URL="https://api.mychatbuddy.dev/mommyramona/health"
STATE_FILE="/var/log/tausendunde1nz/mommyramona-health.state"
NOW="$(date -Is)"

previous="unknown"
[[ -r "$STATE_FILE" ]] && previous="$(<"$STATE_FILE")"

if /usr/bin/curl --fail --silent --show-error --max-time 20 "$URL" >/dev/null; then
  current="ok"
  rc=0
else
  current="failed"
  rc=1
fi

if [[ "$current" != "$previous" ]]; then
  printf '%s service=mommyramona status=%s previous=%s\n' "$NOW" "$current" "$previous"
fi

printf '%s\n' "$current" > "$STATE_FILE"
exit "$rc"
