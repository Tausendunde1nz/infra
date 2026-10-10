#!/bin/bash
# Only a newly allocated private loop backing file; no host/historical paths.
set -euo pipefail
test -f /.dockerenv
test "$(id -u)" = 0
test ! -e /proof
test ! -e /s8-historical-native.img
truncate -s 128M /s8-historical-native.img
device=$(losetup --find --show /s8-historical-native.img)
case "$device" in /dev/loop[0-9]*) ;; *) exit 71;; esac
test "$(losetup -n -O BACK-FILE "$device")" = /s8-historical-native.img
mkfs.ext4 -q /s8-historical-native.img
mkdir /proof
mount -o nodev,nosuid,noexec "$device" /proof
test "$(findmnt -n -o FSTYPE -T /proof)" = ext4
test "$(findmnt -n -o SOURCE -T /proof)" = "$device"
status=0
TU1NZ_S8_NATIVE_EXT4_ROOT=/proof python3 -B -m unittest -v tests.test_s8_historical_read tests.test_s8_historical_objects || status=$?
test "$(findmnt -n -o SOURCE -T /proof)" = "$device"
umount /proof
test "$(losetup -n -O BACK-FILE "$device")" = /s8-historical-native.img
losetup --detach "$device"
exit "$status"
