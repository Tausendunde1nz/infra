#!/usr/bin/env bash
# Source this file and call tu1nz_require_sync <maximum-age>.

__tu1nz_parse_duration() {
  local duration="${1:-12h}"
  case "$duration" in
    *s) printf '%s\n' "${duration%s}" ;;
    *m) printf '%s\n' "$(( ${duration%m} * 60 ))" ;;
    *h) printf '%s\n' "$(( ${duration%h} * 3600 ))" ;;
    *d) printf '%s\n' "$(( ${duration%d} * 86400 ))" ;;
    *)  printf '%s\n' "$(( duration * 3600 ))" ;;
  esac
}

tu1nz_require_sync() {
  local maximum_age_raw="${1:-12h}"
  local maximum_age_seconds marker modification_time now age marker_status
  maximum_age_seconds="$(__tu1nz_parse_duration "$maximum_age_raw")" || return 1
  [[ "$maximum_age_seconds" =~ ^[0-9]+$ ]] || return 1

  marker="${TU1NZ_LAST_SYNC_FILE:-/var/lib/tausendunde1nz/agentmode/last_sync.ok}"
  if [[ ! -f "$marker" ]]; then
    printf 'ERROR: no fresh TU1NZ Control observation at %s\n' "$marker" >&2
    return 1
  fi

  marker_status="$(sed -n 's/^status=\([^ ]*\).*$/\1/p' "$marker" | head -n 1)"
  case "$marker_status" in
    CONTROL_CURRENT|CONTROL_UPDATE_AVAILABLE) ;;
    *)
      printf 'ERROR: invalid TU1NZ Control observation status\n' >&2
      return 1
      ;;
  esac

  if modification_time="$(stat -c %Y "$marker" 2>/dev/null)"; then
    :
  else
    modification_time="$(stat -f %m "$marker" 2>/dev/null)" || return 1
  fi
  now="$(date -u +%s)"
  age=$(( now - modification_time ))
  if [[ "$age" -lt 0 || "$age" -gt "$maximum_age_seconds" ]]; then
    printf 'ERROR: TU1NZ Control observation older than %s (age: %ss)\n' \
      "$maximum_age_raw" "$age" >&2
    return 1
  fi
  return 0
}
