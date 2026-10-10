#!/bin/bash
# Native chain fixtures on real ext4, never a mocked kernel admission result.
set -euo pipefail
test -f /.dockerenv
test "$(id -u)" = 0
test "${container:-}" = docker
test ! -e /s8-provision-historical.img
test ! -e /s8-provision-historical
test ! -e /opt/tu1nz_repos
test ! -e /etc/tu1nz
truncate -s 128M /s8-provision-historical.img
device=$(losetup --find --show /s8-provision-historical.img)
case "$device" in /dev/loop[0-9]*) ;; *) exit 71;; esac
test "$(losetup -n -O BACK-FILE "$device")" = /s8-provision-historical.img
mkfs.ext4 -q /s8-provision-historical.img
mkdir /s8-provision-historical
mount -o nodev,nosuid,noexec "$device" /s8-provision-historical
test "$(findmnt -n -o SOURCE -T /s8-provision-historical)" = "$device"
mkdir /s8-provision-historical/repositories /s8-provision-historical/history
mkdir /opt/tu1nz_repos
mkdir -p /etc/tu1nz/adult-commercial-s12-1-private/state
mount --bind /s8-provision-historical/repositories /opt/tu1nz_repos
mount --bind /s8-provision-historical/history /etc/tu1nz/adult-commercial-s12-1-private/state
for target in /opt/tu1nz_repos /etc/tu1nz/adult-commercial-s12-1-private/state; do
  test "$(findmnt -n -o FSTYPE -T "$target")" = ext4
  test "$(findmnt -n -o MAJ:MIN -T "$target")" = "$(findmnt -n -o MAJ:MIN -T /s8-provision-historical)"
done
python3 -B tests/s8_historical_fixture_mounts.py capture
status=0
python3 -B tests/s8_provision_native_chain.py "${1:?synthetic chain mode required}" || status=$?
# Release only this case's validated synthetic binds/loop. No existing host or
# historical mounts are reachable. Preserve test failure as the primary code.
cleanup_status=0
# The test deliberately relocates /etc/tu1nz. Resolve the captured mount ID,
# object and two prescribed synthetic names, never adopt the old pathname.
python3 -B tests/s8_historical_fixture_mounts.py release "$status" || cleanup_status=$?
if test "$(losetup -n -O BACK-FILE "$device")" = /s8-provision-historical.img; then
  losetup --detach "$device" || { test "$cleanup_status" != 0 || cleanup_status=2; }
else
  test "$cleanup_status" != 0 || cleanup_status=2
fi
test "$status" = 0 || exit "$status"
exit "$cleanup_status"
