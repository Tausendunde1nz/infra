#!/usr/bin/env bash
# Disposable native CI fixture only. No production sockets/data or provider I/O.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -m)" = x86_64
image="tu1nz-public-isolation-ci:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
docker build --file tests/s8-native.Dockerfile --tag "$image" .
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
for _ in $(seq 1 30); do
  if docker exec "$native" systemctl is-system-running --quiet; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
docker exec "$native" python3 -B -m unittest -v tests.test_public_web_isolation
docker exec "$native" python3 -B /source/tests/public_web_isolation_native.py
