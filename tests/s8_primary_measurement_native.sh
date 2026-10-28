#!/usr/bin/env bash
# PREPARED ONLY. One disposable GitHub-hosted substitute, not historic replay.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_RUN_ATTEMPT:?}" = 1
test "${GITHUB_REF:?}" = refs/heads/codex/s8-primary-synthetic-20261028
test "$(uname -m)" = x86_64
test "$(git rev-parse HEAD)" = "${GITHUB_SHA:?}"
test -z "$(git status --porcelain=v1 --untracked-files=normal)"
test "$(git rev-parse HEAD^)" = cb7e8a7fcd098089c7d9e2c8d3b696d4d5d01313
test "$(git log -1 --format=%B)" = 'S8: prepare primary observation 20261028'
expected=(.github/workflows/s8-primary-measurement.yml tests/s8_primary_measurement.py tests/s8_primary_measurement_native.sh tests/test_s8_primary_measurement.py)
mapfile -t actual < <(git diff --name-only HEAD^ HEAD | LC_ALL=C sort)
test "${actual[*]}" = "${expected[*]}"
printf 'S8_PRIMARY_BINDING source=%s base=%s diff=' "$GITHUB_SHA" "$(git rev-parse HEAD^)"
git diff --binary --full-index HEAD^ HEAD | sha256sum
printf 'S8_PRIMARY_SUBSTITUTE image=%s version=%s os=%s arch=%s\n' "${ImageOS:-UNKNOWN}" "${ImageVersion:-UNKNOWN}" "${RUNNER_OS:-UNKNOWN}" "${RUNNER_ARCH:-UNKNOWN}"
image="tu1nz-s8-primary:${GITHUB_RUN_ID:?}-1"
scratch="$(mktemp -d "${RUNNER_TEMP:?}/s8-primary.XXXXXXXX")"
test "$(findmnt --noheadings --output FSTYPE --target "$scratch")" = ext4
native=''
cleanup() {
  if [[ "$native" =~ ^[0-9a-f]{64}$ ]]; then
    docker stop --time 20 "$native" >/dev/null || true
    docker rm "$native" >/dev/null
  fi
  # Exact fresh scratch remains recoverable on this disposable runner; no rm -rf.
}
trap cleanup EXIT
timeout --signal=TERM --kill-after=10s 300s docker build --file tests/s8-native.Dockerfile --tag "$image" .
docker image inspect --format 'S8_PRIMARY_IMAGE {{.Id}}' "$image"
docker info --format 'S8_PRIMARY_DOCKER {{.ServerVersion}} {{.Driver}} {{.KernelVersion}}'
native="$(docker create --network none --privileged --cgroupns=private \
  --env container=docker --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --mount "type=bind,src=$PWD,dst=/source,readonly" \
  --mount "type=bind,src=$scratch,dst=/s8-native-profile" \
  --workdir /source "$image")"
[[ "$native" =~ ^[0-9a-f]{64}$ ]]
docker start "$native" >/dev/null
ready=false
for _ in $(seq 1 30); do
  if docker exec "$native" systemctl is-system-running --quiet; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
docker exec "$native" chown 0:0 /s8-native-profile
docker exec "$native" findmnt --noheadings --output TARGET,FSTYPE,OPTIONS --target /etc
docker exec "$native" findmnt --noheadings --output TARGET,FSTYPE,OPTIONS --target /s8-native-profile
docker exec "$native" dpkg-query --show --showformat='S8_PRIMARY_PACKAGE ${binary:Package}=${Version}\n' python3 python3.12 systemd systemd-sysv acl dbus util-linux e2fsprogs
set +e
timeout --signal=TERM --kill-after=10s 100s \
  docker exec "$native" python3 -B tests/s8_primary_measurement.py
status=$?
set -e
# Only synthetic measurement bytes, bounded by the recorder, not any host log.
docker cp "$native:/var/tmp/s8-primary-observation.jsonl" "$scratch/observation.jsonl"
test "$(stat --format=%s "$scratch/observation.jsonl")" -le 16777216
printf 'S8_PRIMARY_RAW_BEGIN\n'
sudo -n head --bytes=16777216 "$scratch/observation.jsonl"
printf 'S8_PRIMARY_RAW_END\n'
exit "$status"
