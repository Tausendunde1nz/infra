#!/usr/bin/env bash
# PREPARED ONLY. One disposable GitHub-hosted substitute, not historic replay.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_RUN_ATTEMPT:?}" = 1
test "${GITHUB_REF:?}" = refs/heads/codex/s8-evidence-export-fix-20261028
test "$(uname -m)" = x86_64
test "$(git rev-parse HEAD)" = "${GITHUB_SHA:?}"
test -z "$(git status --porcelain=v1 --untracked-files=normal)"
test "$(git rev-parse HEAD^)" = c3ca4cb8589226b326dcd4db999b50a11f607b4d
test "$(git log -1 --format=%B)" = 'S8: prepare evidence export 20261028'
expected=(.github/workflows/s8-primary-measurement.yml tests/s8_evidence_export.py tests/s8_primary_measurement.py tests/s8_primary_measurement_native.sh tests/test_s8_evidence_export.py tests/test_s8_evidence_export_native.py tests/test_s8_primary_measurement.py)
mapfile -t actual < <(git diff --name-only HEAD^ HEAD | LC_ALL=C sort)
test "${actual[*]}" = "${expected[*]}"
printf 'S8_PRIMARY_BINDING source=%s base=%s diff=' "$GITHUB_SHA" "$(git rev-parse HEAD^)"
git diff --binary --full-index HEAD^ HEAD | sha256sum
printf 'S8_PRIMARY_SUBSTITUTE image=%s version=%s os=%s arch=%s\n' "${ImageOS:-UNKNOWN}" "${ImageVersion:-UNKNOWN}" "${RUNNER_OS:-UNKNOWN}" "${RUNNER_ARCH:-UNKNOWN}"
image="tu1nz-s8-primary:${GITHUB_RUN_ID:?}-1"
scratch="$(mktemp -d "${RUNNER_TEMP:?}/s8-primary.XXXXXXXX")"
export_dir="$(mktemp -d "${RUNNER_TEMP:?}/s8-export.XXXXXXXX")"
test "$(findmnt --noheadings --output FSTYPE --target "$scratch")" = ext4
native=''
measurement_status=''
measurement_started=false
finalize() {
  entry=$?
  trap - EXIT
  set +e
  final=$entry
  if [[ "$native" =~ ^[0-9a-f]{64}$ ]]; then
    args=(--container "$native" --export-dir "$export_dir" --launcher-exit "$entry")
    if [[ "$measurement_started" = true ]]; then
      measurement_status="${measurement_status:-$entry}"
      args+=(--measurement-exit "$measurement_status")
    fi
    # Read-only stream BEFORE guest destruction, even after RED/timeout/signal.
    python3 -B tests/s8_evidence_export.py "${args[@]}"
    export_status=$?
    docker stop --time 20 "$native" >/dev/null
    stop_status=$?
    docker rm "$native" >/dev/null
    remove_status=$?
    if [[ "$measurement_started" = true && "$measurement_status" -ne 0 ]]; then final=$measurement_status
    elif [[ "$entry" -ne 0 ]]; then final=$entry
    elif [[ "$export_status" -ne 0 ]]; then final=$export_status
    elif [[ "$stop_status" -ne 0 ]]; then final=$stop_status
    elif [[ "$remove_status" -ne 0 ]]; then final=$remove_status
    else final=0; fi
    printf 'S8_PRIMARY_LAUNCHER measurement_started=%s measurement_exit=%s export_aggregate_exit=%s stop_exit=%s remove_exit=%s final_exit=%s\n' "$measurement_started" "${measurement_status:-NOT_STARTED}" "$export_status" "$stop_status" "$remove_status" "$final"
  fi
  # Both exact fresh directories remain recoverable. Export was NEVER mounted.
  exit "$final"
}
trap finalize EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
timeout --signal=TERM --kill-after=10s 300s docker build --file tests/s8-native.Dockerfile --tag "$image" .
docker image inspect --format 'S8_PRIMARY_IMAGE {{.Id}}' "$image"
docker info --format 'S8_PRIMARY_DOCKER {{.ServerVersion}} {{.Driver}} {{.KernelVersion}}'
# Required future native transport proof, separate disposable fixture guest.
S8_EVIDENCE_NATIVE_IMAGE="$image" python3 -B tests/test_s8_evidence_export_native.py
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
measurement_started=true
timeout --signal=TERM --kill-after=10s 100s \
  docker exec "$native" python3 -B tests/s8_primary_measurement.py
measurement_status=$?
set -e
exit "$measurement_status"
