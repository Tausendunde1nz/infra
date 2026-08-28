#!/usr/bin/env bash
set -u

SYNC_COMMAND="${TU1NZ_SYNC_COMMAND:-/usr/local/bin/tu1nz_sync_all.sh}"
SYSTEMCTL_BIN="${TU1NZ_SYSTEMCTL_BIN:-systemctl}"
AGENT_MODE_MARKER="${TU1NZ_AGENT_MODE_MARKER:-/etc/tu1nz/AGENT_MODE_ACTIVE.marker}"
SSOT_CHECKSUM="${TU1NZ_SSOT_CHECKSUM:-/etc/tu1nz/ssot.checksum}"
exit_status=0

printf '%s\n' '=== TU1NZ Agent Health Check ==='

if [[ -f "$AGENT_MODE_MARKER" ]]; then
  printf '%s\n' 'AGENTMODE: OK'
else
  printf '%s\n' 'AGENTMODE: MISSING'
  exit_status=1
fi

doc_status="$($SYSTEMCTL_BIN is-active tu1nz-docagent.service 2>/dev/null || true)"
if [[ "$doc_status" == "active" || "$doc_status" == "inactive" ]]; then
  printf 'DOCAGENT: OK (%s)\n' "$doc_status"
else
  printf 'DOCAGENT: ERROR (%s)\n' "${doc_status:-unknown}"
  exit_status=1
fi

if control_result="$($SYNC_COMMAND --check 2>&1)"; then
  case "$control_result" in
    CONTROL_CURRENT\ *|CONTROL_UPDATE_AVAILABLE\ *)
      printf 'CONTROL: %s\n' "$control_result"
      ;;
    *)
      printf 'CONTROL: INVALID_RESPONSE\n' >&2
      exit_status=1
      ;;
  esac
else
  printf 'CONTROL: %s\n' "${control_result:-CHECK_FAILED}" >&2
  exit_status=1
fi

if [[ -f "$SSOT_CHECKSUM" ]]; then
  if sha256sum -c "$SSOT_CHECKSUM" >/dev/null 2>&1; then
    printf '%s\n' 'CHECKSUM: OK'
  else
    printf '%s\n' 'CHECKSUM: MISMATCH'
    exit_status=1
  fi
else
  printf '%s\n' 'CHECKSUM: NO_REFERENCE'
fi

printf '%s\n' '=== END ==='
exit "$exit_status"
