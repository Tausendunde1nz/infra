#!/usr/bin/env bash
# Disposable offline native kernel/PID-1 gate. No host targets or provider I/O.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -m)" = x86_64
image="tu1nz-s8-anchor-ci:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
docker build --file tests/s8-native.Dockerfile --tag "$image" .
docker run --rm --network none --cap-drop ALL --cap-add LINUX_IMMUTABLE \
  --cap-add CHOWN --cap-add SETGID --env container=docker \
  --mount "type=bind,src=$PWD,dst=/source,readonly" --workdir /source \
  "$image" python3 -B tests/s8_parent_rebind_counterexample.py
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
docker exec "$native" python3 -B -m unittest -v \
  tests.test_s8_anchor tests.test_s8_path_policy tests.test_s8_execution_contract \
  tests.test_s8_new_stock tests.test_s8_protected_journal tests.test_s8_journal_kernel_barrier \
  tests.test_s8_admission_channel tests.test_s8_frozen_entry tests.test_s8_execution_observer
docker exec "$native" bash tests/s8_historical_kernel_native.sh
