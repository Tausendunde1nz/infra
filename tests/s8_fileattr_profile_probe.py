"""Finite synthetic fileattr comparison, NOT a guard or admission result.

Separate listeners belong only to these probes. The original guard suite uses
its unchanged observer and original reads afterwards. No queue is shared/drained.
Logging/fstat/clock calls affect timing; inotify does NOT identify an event actor.
"""
import ctypes
import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.s8_diagnostic_once import Trace, decode_events, main as guard_measurement
from tests.s8_fork_child import child_failure_boundary
from tu1nz_s8_journal_fence import APPEND, IMMUTABLE, add_inode_protection

MEASUREMENT = "s8-fileattr-profile-20261024-1"


def watch(path, mask):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "probe inotify init")
    if libc.inotify_add_watch(fd, os.fsencode(path), mask) < 0:
        error = ctypes.get_errno(); os.close(fd)
        raise OSError(error, "probe inotify watch")
    return fd


def sample(trace, fd, phase):
    # One predetermined read of our OWN listener, no polling or retries.
    try:
        raw = os.read(fd, 65536)
    except BlockingIOError:
        trace.note("probe_events", phase=phase, events=[], eagain=True)
        return []
    else:
        events = decode_events(raw)
        trace.note("probe_events", phase=phase, events=events, eagain=False)
        return events


def require_control_events(events):
    if not events or any(e.get("mask") != "0x4" or e.get("name") != "control.json"
                         or e.get("malformed") for e in events):
        raise RuntimeError("S8_PROFILE_CONTROL_NOT_OBSERVED")


def probe(base, trace):
    parent = base / MEASUREMENT
    parent.mkdir(mode=0o700)  # create-only; no adoption, deletion or cleanup writes
    root = parent / "stock"
    listener = watch(parent, 0xfc4)
    try:
        root.mkdir(mode=0o700)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        sample(trace, listener, "mkdir")
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            trace.note("probe_seal_begin", target=Trace.identity(fd), flag=hex(APPEND))
            add_inode_protection(fd, APPEND)
            trace.note("probe_seal_end", target=Trace.identity(fd), flag=hex(APPEND))
        finally: os.close(fd)
        sample(trace, listener, "append_directory")
    finally: os.close(listener)

    listener = watch(root, 0xec4)
    try:
        record = root / "record.json"
        fd = os.open(record, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, b'{"synthetic":true}\n'); os.fsync(fd)
        finally: os.close(fd)
        sample(trace, listener, "before_record_seal")
        fd = os.open(record, os.O_RDONLY)
        try:
            trace.note("probe_seal_begin", target=Trace.identity(fd), flag=hex(IMMUTABLE))
            add_inode_protection(fd, IMMUTABLE)
            trace.note("probe_seal_end", target=Trace.identity(fd), flag=hex(IMMUTABLE))
        finally: os.close(fd)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        sample(trace, listener, "immutable_record")

        control = root / "control.json"
        fd = os.open(control, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try: os.fsync(fd)
        finally: os.close(fd)
        sample(trace, listener, "before_control")
        pid = os.fork()
        if pid == 0:
            with child_failure_boundary():
                os.chmod(control, 0o640); os.chmod(control, 0o600); os._exit(0)
        if os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) != 0:
            raise RuntimeError("synthetic control child failed")
        events = sample(trace, listener, "controlled_foreign_chmod_restored")
        require_control_events(events)
        if control.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError("S8_PROFILE_CONTROL_MODE_RED")
    finally: os.close(listener)
    # Fixtures stay sealed on the disposable hosted VM. No original is altered.


def main():
    if not (sys.platform == "linux" and os.geteuid() == 0
            and os.environ.get("container") == "docker"
            and Path("/.dockerenv").is_file()
            and Path("/proc/1/comm").read_text().strip() == "systemd"):
        raise SystemExit("S8_PROFILE_ISOLATED_PID1_REQUIRED")
    signal.alarm(90)
    trace = Trace()
    for label, base in (("container_root", Path("/var/tmp")),
                        ("runner_bind", Path("/s8-native-profile"))):
        trace.case = label
        probe(base, trace)
    if trace.errors:
        raise SystemExit("S8_PROFILE_OBSERVER_RED")
    return guard_measurement(MEASUREMENT)


if __name__ == "__main__": raise SystemExit(main())
