#!/usr/bin/env bash
set -Eeuo pipefail

CONTROL_DIR="/opt/tu1nz_repos/control"
SYSTEMD_DIR="${CONTROL_DIR}/systemd"
CRONTAB_FILE="${CONTROL_DIR}/docs/post-migration-chatops.crontab"

usage() {
  printf 'Usage: %s {syntax|verify|units|reload|health|git|gitlog|timers|backup|backuptimer|crontab|status}\n' "$0" >&2
  exit 64
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    printf 'ERROR: root privileges required\n' >&2
    exit 77
  fi
}

case "${1:-}" in
  syntax)
    bash -n \
      /usr/local/bin/tu1nz_mommyramona_healthcheck.sh \
      /usr/local/bin/tausendunde1nz-git-sync.sh \
      /usr/local/bin/tu1nz_encrypted_backup.sh
    printf 'SCRIPT_SYNTAX=PASS\n'
    ;;
  verify)
    systemd-analyze verify \
      "${SYSTEMD_DIR}/tu1nz-mommyramona-health.service" \
      "${SYSTEMD_DIR}/tu1nz-mommyramona-health.timer" \
      "${SYSTEMD_DIR}/tu1nz-legacy-git-sync.service" \
      "${SYSTEMD_DIR}/tu1nz-legacy-git-sync.timer" \
      "${SYSTEMD_DIR}/tu1nz_encrypted_backup.service" \
      "${SYSTEMD_DIR}/tu1nz_encrypted_backup.timer"
    printf 'SYSTEMD_VERIFY=PASS\n'
    ;;
  units)
    require_root
    install -o root -g root -m 0644 \
      "${SYSTEMD_DIR}/tu1nz-mommyramona-health.service" \
      "${SYSTEMD_DIR}/tu1nz-mommyramona-health.timer" \
      "${SYSTEMD_DIR}/tu1nz-legacy-git-sync.service" \
      "${SYSTEMD_DIR}/tu1nz-legacy-git-sync.timer" \
      "${SYSTEMD_DIR}/tu1nz_encrypted_backup.service" \
      "${SYSTEMD_DIR}/tu1nz_encrypted_backup.timer" \
      /etc/systemd/system/
    printf 'SYSTEMD_UNITS=STAGED\n'
    ;;
  reload)
    require_root
    systemctl daemon-reload
    printf 'DAEMON_RELOAD=PASS\n'
    ;;
  health)
    require_root
    systemctl start tu1nz-mommyramona-health.service
    systemctl --no-pager --full status tu1nz-mommyramona-health.service
    ;;
  git)
    require_root
    systemctl start tu1nz-legacy-git-sync.service
    systemctl --no-pager --full status tu1nz-legacy-git-sync.service
    ;;
  gitlog)
    systemctl --no-pager --full status tu1nz-legacy-git-sync.service || true
    journalctl --no-pager -u tu1nz-legacy-git-sync.service -n 120
    ;;
  timers)
    require_root
    systemctl enable --now \
      tu1nz-mommyramona-health.timer \
      tu1nz-legacy-git-sync.timer
    systemctl --no-pager list-timers \
      tu1nz-mommyramona-health.timer \
      tu1nz-legacy-git-sync.timer
    ;;
  backup)
    require_root
    systemctl start tu1nz_encrypted_backup.service
    systemctl --no-pager --full status tu1nz_encrypted_backup.service
    ;;
  backuptimer)
    require_root
    systemctl enable --now tu1nz_encrypted_backup.timer
    systemctl --no-pager list-timers tu1nz_encrypted_backup.timer
    ;;
  crontab)
    require_root
    crontab -u chatops "${CRONTAB_FILE}"
    crontab -u chatops -l
    ;;
  status)
    systemctl --no-pager --full status \
      tu1nz-mommyramona-health.timer \
      tu1nz-legacy-git-sync.timer \
      tu1nz_encrypted_backup.timer
    ;;
  *)
    usage
    ;;
esac
