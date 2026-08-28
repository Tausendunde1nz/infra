#!/usr/bin/env bash
set -euo pipefail
umask 0027

STATE_DIR="${TU1NZ_STATE_DIR:-/var/lib/tausendunde1nz/agentmode}"
MONITOR_COMMAND="${TU1NZ_MONITOR_COMMAND:-/usr/local/bin/tu1nz_monitor.sh}"
ALERT_COMMAND="${TU1NZ_ALERT_COMMAND:-/usr/local/bin/tu1nz_alert_if_fail.sh}"
output_file="$STATE_DIR/monitor_last.txt"

mkdir -p "$STATE_DIR"
set +e
"$MONITOR_COMMAND" | tee "$output_file"
monitor_status=${PIPESTATUS[0]}
set -e
chmod 0640 "$output_file"
"$ALERT_COMMAND" || true
exit "$monitor_status"
