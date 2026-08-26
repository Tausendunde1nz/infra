#!/usr/bin/env bash
set -Eeuo pipefail

CONTROL_DIR="/opt/tu1nz_repos/control"
SYSTEMD_DIR="${CONTROL_DIR}/systemd"
CRONTAB_FILE="${CONTROL_DIR}/docs/post-migration-chatops.crontab"

usage() {
  printf 'Usage: %s {syntax|verify|units|reload|health|git|gitlog|timers|backup|restore|backuptimer|crontab|status}\n' "$0" >&2
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
  restore)
    require_root
    run_id="$(date -u +%Y%m%dT%H%M%SZ)"
    run_dir="/opt/tu1nz_repos/backups/restore-tests/${run_id}"
    extract_dir="${run_dir}/extracted"
    remote_root="gcrypt01:backups"
    latest="$(rclone lsf "${remote_root}" --files-only --include 'tu1nz_system_backup_*.tar.gz' | sort | tail -n 1)"
    [[ -n "${latest}" ]] || {
      printf 'ERROR: no encrypted system backup found\n' >&2
      exit 1
    }
    mkdir -p "${extract_dir}"
    downloaded="${run_dir}/${latest}"
    local_archive="/opt/tu1nz_repos/backups/encrypted-system/${latest}"
    rclone copyto "${remote_root}/${latest}" "${downloaded}"
    if [[ ! -f "${local_archive}" ]]; then
      printf 'ERROR: local source archive missing: %s\n' "${local_archive}" >&2
      exit 1
    fi
    if ! cmp --silent "${local_archive}" "${downloaded}"; then
      printf 'ERROR: remote download differs from local source archive\n' >&2
      exit 1
    fi
    printf 'RESTORE_ARCHIVE_COMPARE=PASS sha256=%s\n' \
      "$(sha256sum "${downloaded}" | awk '{print $1}')"
    if ! tar -tzf "${downloaded}" >/dev/null; then
      printf 'ERROR: downloaded archive integrity check failed\n' >&2
      exit 1
    fi
    tar -xzf "${downloaded}" -C "${extract_dir}"
    for repo in control adult-publishing-core; do
      if [[ ! -d "${extract_dir}/${repo}/.git" ]]; then
        printf 'ERROR: restored Git repository missing: %s\n' "${repo}" >&2
        exit 1
      fi
      if ! git -C "${extract_dir}/${repo}" fsck --full; then
        printf 'ERROR: git fsck failed: %s\n' "${repo}" >&2
        exit 1
      fi
      repo_status="$(git -C "${extract_dir}/${repo}" status --porcelain)"
      if [[ -n "${repo_status}" ]]; then
        printf 'ERROR: restored Git repository is not clean: %s\n%s\n' \
          "${repo}" "${repo_status}" >&2
        exit 1
      fi
      printf 'RESTORE_REPOSITORY=PASS repo=%s head=%s\n' \
        "${repo}" "$(git -C "${extract_dir}/${repo}" rev-parse HEAD)"
    done
    printf 'RESTORE_VERIFY=PASS remote=%s local=%s extracted=%s\n' \
      "${remote_root}/${latest}" "${downloaded}" "${extract_dir}"
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
