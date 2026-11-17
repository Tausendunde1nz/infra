#!/usr/bin/env bash
# Existing isolated CI method, public synthetic input only. No private token,
# Environment, host socket, provider access, artifact upload or persistent VM.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -m)" = x86_64
image="tu1nz-startlimit-ci:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
docker build --file tests/public-operator-native.Dockerfile --tag "$image" .
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
for _ in $(seq 1 40); do
  if docker exec "$native" systemctl is-system-running --quiet; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
timeout 1200 docker exec "$native" python3 -I -B /source/tests/mainserver_startlimit_native.py
