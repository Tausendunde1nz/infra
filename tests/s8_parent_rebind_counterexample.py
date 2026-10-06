"""Disposable local Linux proof only; NOT a server script or recovery path.

Run with this file and Control scripts read-only mounted in a fresh netless
container. Exact synthetic /etc/tu1nz fixture must be absent initially. The
container runtime removes its own disposable layer; this probe deletes nothing.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, "/source/scripts")
from tu1nz_s8_journal_fence import APPEND, IMMUTABLE, add_inode_protection, inode_flags
from tu1nz_s8_path_policy import ACCESS, CONFIG_ACCESS, acl_bytes, parent_metadata


def flag(path, flags):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        for value in flags: add_inode_protection(fd, value)
    finally:
        os.close(fd)


assert sys.platform == "linux" and os.geteuid() == 0
assert os.environ.get("container") == "docker" and Path("/.dockerenv").is_file()
parent = Path("/etc/tu1nz")
retained = Path("/etc/tu1nz-synthetic-retained-parent")
assert not os.path.lexists(parent) and not os.path.lexists(retained)
os.umask(0o077)
parent.mkdir(mode=0o750)
os.chown(parent, 0, 1001)
os.setxattr(parent, ACCESS, acl_bytes(CONFIG_ACCESS))
os.chmod(parent, 0o750)
parent_metadata(parent, creation=True)
root = parent / "s8-atomic-admission-r1"
root.mkdir(mode=0o700)
state = root / "state"
state.mkdir(mode=0o700)
record = state / "synthetic-consumed.json"
record.write_bytes(b'{"synthetic":true,"consumed":true}\n')
flag(record, [IMMUTABLE])
flag(state, [APPEND])
flag(root, [APPEND, IMMUTABLE])
original = root.stat().st_dev, root.stat().st_ino

# Provisioner has ended: no userspace witness can survive its death. The
# attacker is uid 0 but has NO capability, including no immutable/ptrace/admin
# capability. The group membership only permits reproducing the known gid.
os.setgroups([1001])
pid = os.fork()
if pid == 0:
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.capset(ctypes.byref(Header(0x20080522, 0)), (Data * 2)()) == 0
    caps = {k: v.strip() for k, v in (line.split(":", 1) for line in
            Path("/proc/self/status").read_text().splitlines() if line.startswith("Cap"))}
    assert all(int(caps[name], 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
    try:
        root.rename(parent / "forbidden-direct-rename")
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError("DIRECT_INODE_PROTECTION_MISSING")
    parent.rename(retained)
    missing_consumed_name = not os.path.lexists(root)
    parent.mkdir(mode=0o750)
    os.chown(parent, -1, 1001)
    os.setxattr(parent, ACCESS, acl_bytes(CONFIG_ACCESS))
    os.chmod(parent, 0o750)
    parent_metadata(parent, creation=True)
    # Only the filesystem new-name boundary is tested, NOT an S8 start or a
    # full admission bypass. Unchanged other mandatory gates may still deny.
    root.mkdir(mode=0o700)
    old_root = retained / root.name
    old_fd = os.open(old_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        assert inode_flags(old_fd) & (APPEND | IMMUTABLE) == APPEND | IMMUTABLE
    finally:
        os.close(old_fd)
    assert (old_root.stat().st_dev, old_root.stat().st_ino) == original
    assert (old_root / "state/synthetic-consumed.json").read_bytes() == b'{"synthetic":true,"consumed":true}\n'
    print(json.dumps(dict(schema="TU1NZ_S8_PARENT_REBIND_PROBE_V1", synthetic=True,
        current_parent_acl_matches_exact_profile=True, direct_root_rename_denied=True,
        writer_uid=0, writer_effective_capabilities=0, writer_permitted_capabilities=0,
        parent_rename_succeeded=True, consumed_name_appeared_absent=missing_consumed_name,
        new_same_named_directory_created=True, old_inode_flags_and_consumption_retained=True,
        full_admission_bypass_tested=False, live_host_tested=False, historical_cause="UNKNOWN"),
        sort_keys=True), flush=True)
    os._exit(0)
status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
assert status == 0, status
