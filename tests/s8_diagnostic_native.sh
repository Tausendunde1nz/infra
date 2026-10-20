#!/usr/bin/env bash
# Same native image/PID1/filesystem configuration as s8_anchor_native.sh.
# One finite synthetic sequence, no private inputs, retry or guard waiver.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_RUN_ATTEMPT:?}" = 1
test "$(uname -m)" = x86_64
image="tu1nz-s8-diagnostic:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT}"
docker build --file tests/s8-native.Dockerfile --tag "$image" .
docker image inspect --format 'S8_DIAG_IMAGE {{.Id}}' "$image"
docker info --format 'S8_DIAG_DOCKER {{.ServerVersion}} {{.Driver}} {{.KernelVersion}}'
native="$(docker create --network none --privileged --cgroupns=private \
  --env container=docker --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --mount "type=bind,src=$PWD,dst=/source,readonly" --workdir /source "$image")"
[[ "$native" =~ ^[0-9a-f]{64}$ ]]
cleanup() {
  docker stop --time 20 "$native" >/dev/null || true
  docker rm "$native" >/dev/null
}
trap cleanup EXIT
docker start "$native" >/dev/null
ready=false
# Unchanged finite PID1 startup readiness, not a repair sleep or test retry.
for _ in $(seq 1 30); do
  if docker exec "$native" systemctl is-system-running --quiet; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
docker exec "$native" findmnt --noheadings --output TARGET,FSTYPE,OPTIONS --target /etc
timeout --signal=TERM --kill-after=10s 90s \
  docker exec "$native" python3 -B tests/s8_diagnostic_once.py
