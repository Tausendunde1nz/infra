#!/usr/bin/env bash
# Existing privileged offline PID1 profile; only a fresh synthetic bind is added.
# No private input, retry, guard exception, image reuse or persistent resource.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_RUN_ATTEMPT:?}" = 1
test "$(uname -m)" = x86_64
image="tu1nz-s8-profile:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT}"
docker build --file tests/s8-native.Dockerfile --tag "$image" .
docker image inspect --format 'S8_PROFILE_IMAGE {{.Id}}' "$image"
docker info --format 'S8_PROFILE_DOCKER {{.ServerVersion}} {{.Driver}} {{.KernelVersion}}'
profile_dir="$(mktemp -d "$RUNNER_TEMP/s8-fileattr-profile.XXXXXXXX")"
native="$(docker create --network none --privileged --cgroupns=private \
  --env container=docker --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --mount "type=bind,src=$PWD,dst=/source,readonly" \
  --mount "type=bind,src=$profile_dir,dst=/s8-native-profile" \
  --workdir /source "$image")"
[[ "$native" =~ ^[0-9a-f]{64}$ ]]
cleanup() {
  docker stop --time 20 "$native" >/dev/null || true
  docker rm "$native" >/dev/null
}
trap cleanup EXIT
docker start "$native" >/dev/null
ready=false
# Existing finite PID1 readiness, not a seal repair or test repetition.
for _ in $(seq 1 30); do
  if docker exec "$native" systemctl is-system-running --quiet; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
# Change only this newly created synthetic directory, not its host parents.
docker exec "$native" chown 0:0 /s8-native-profile
docker exec "$native" findmnt --noheadings --output TARGET,FSTYPE --target /var/tmp
docker exec "$native" findmnt --noheadings --output TARGET,FSTYPE --target /s8-native-profile
timeout --signal=TERM --kill-after=10s 100s \
  docker exec "$native" python3 -B tests/s8_fileattr_profile_probe.py
