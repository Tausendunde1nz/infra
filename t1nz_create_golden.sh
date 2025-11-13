#!/usr/bin/env bash
set -euo pipefail

echo "[t1nz-golden] Starting Golden Snapshot (dry-run optional)..."

DRY_RUN="0"
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="1"
  echo "[t1nz-golden] DRY RUN MODE ENABLED"
fi

TARGET_DIR="/opt/tu1nz_golden"
TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
SNAPSHOT_DIR="${TARGET_DIR}/${TIMESTAMP}"

echo "[t1nz-golden] Creating snapshot directory: ${SNAPSHOT_DIR}"
[[ "$DRY_RUN" == "0" ]] && sudo mkdir -p "${SNAPSHOT_DIR}"

echo "[t1nz-golden] Copying critical system files..."
COPY_LIST=(
  "/etc"
  "/opt/tu1nz_repos"
  "/opt/tu1nz_services"
  "/opt/n8n"
  "/var/spool/cron"
)

for item in "${COPY_LIST[@]}"; do
  echo "[t1nz-golden] → ${item}"
  [[ "$DRY_RUN" == "0" ]] && sudo rsync -a --delete "${item}" "${SNAPSHOT_DIR}/"
done

echo "[t1nz-golden] Creating checksum file..."
[[ "$DRY_RUN" == "0" ]] && (cd "${SNAPSHOT_DIR}" && sudo find . -type f -exec sha256sum {} \; | sudo tee checksums.txt)

echo "[t1nz-golden] Golden Snapshot finished."
