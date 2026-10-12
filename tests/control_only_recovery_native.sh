#!/bin/bash
# New private ext4 backing file only; no production/historical mounts or PID1.
set -euo pipefail
test -f /.dockerenv
test "$(id -u)" = 0
test -r "${TU1NZ_CONTROL_POLICY_CAPSULE:?authentic public target capsule required}"
# Numeric consumer needs a real NSS entry for unchanged Path.home() default
# evaluation. Isolated container only; no HOME rewrite or global policy file.
if ! getent passwd 1001 >/dev/null; then useradd --uid 1001 --home-dir /home/chatops --no-create-home chatops; fi
test ! -e /home/chatops/.codex
test ! -e /control-only-native.img
test ! -e /control-proof
truncate -s 512M /control-only-native.img
device=$(losetup --find --show /control-only-native.img)
case "$device" in /dev/loop[0-9]*) ;; *) exit 71;; esac
test "$(losetup -n -O BACK-FILE "$device")" = /control-only-native.img
mkfs.ext4 -q /control-only-native.img
mkdir /control-proof
mount -o nodev,nosuid,noexec "$device" /control-proof
test "$(findmnt -n -o FSTYPE -T /control-proof)" = ext4
test "$(findmnt -n -o SOURCE -T /control-proof)" = "$device"
status=0
TU1NZ_CONTROL_NATIVE_ROOT=/control-proof python3 -B -m unittest -v tests.test_control_only_recovery || status=$?
test "$(findmnt -n -o SOURCE -T /control-proof)" = "$device"
umount /control-proof
test "$(losetup -n -O BACK-FILE "$device")" = /control-only-native.img
losetup --detach "$device"
exit "$status"
