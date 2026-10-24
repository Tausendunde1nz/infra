"""One finite synthetic native measurement; never a production entry point.

Observe only reads/ioctls/fsyncs already requested by the original tests/guards.
Return their original bytes/results/exceptions unchanged. Extra fstat/readlink,
clock and stdout operations perturb timing; no historical-cause claim follows.
Inotify has no actor identity. A logged caller is NOT an event-origin claim.
"""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import platform
import select
import signal
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tests.s8_fork_child import child_failure_boundary
import tu1nz_s8_journal_fence as fence
from tu1nz_s8_new_stock import ParentCreationWitness


def decode_events(raw):
    events, offset = [], 0
    while offset < len(raw):
        if len(raw) - offset < 16:
            events.append(dict(malformed=True, remaining=len(raw)-offset)); break
        wd, mask, cookie, size = struct.unpack_from("iIII", raw, offset)
        offset += 16
        if size > len(raw) - offset:
            events.append(dict(malformed=True, name_length=size)); break
        name = raw[offset:offset+size].split(b"\0", 1)[0]
        events.append(dict(wd=wd, mask=hex(mask), cookie=cookie,
                           name=os.fsdecode(name), event_actor="not_in_inotify"))
        offset += size
    return events


class Trace:
    def __init__(self):
        self.read, self.ioctl, self.fsync, self.close = os.read, fcntl.ioctl, os.fsync, os.close
        self.errors = []
        self.sequence = 0
        self.watches = {}
        self.lock = threading.Lock()
        self.case = "setup"

    def note(self, operation, **fields):
        try:
            with self.lock:
                self.sequence += 1
                print("S8_DIAG " + json.dumps(dict(sequence=self.sequence,
                    monotonic_ns=time.monotonic_ns(), caller_pid=os.getpid(),
                    caller_tid=threading.get_native_id(), case=self.case,
                    operation=operation, **fields), sort_keys=True), flush=True)
        except Exception as error:
            self.errors.append(type(error).__name__)

    @staticmethod
    def identity(fd):
        try:
            value = os.fstat(fd)
            return dict(fd=fd, dev=value.st_dev, ino=value.st_ino,
                        mode=oct(value.st_mode), uid=value.st_uid, gid=value.st_gid,
                        object=os.readlink("/proc/self/fd/" + str(fd)))
        except OSError as error:
            return dict(fd=fd, identity_errno=error.errno)

    @staticmethod
    def is_inotify(fd):
        try: return "inotify" in os.readlink("/proc/self/fd/" + str(fd))
        except OSError: return False

    def observed_read(self, fd, count):
        # Exactly one original read, never a preview, drain or replacement.
        try: raw = self.read(fd, count)
        except BlockingIOError:
            if self.is_inotify(fd):
                self.note("inotify_read_EAGAIN", fd=fd, watch=self.watches.get(fd))
            raise
        if self.is_inotify(fd):
            self.note("inotify_read", fd=fd, watch=self.watches.get(fd),
                      byte_count=len(raw), events=decode_events(raw))
        return raw

    def observed_ioctl(self, fd, request, *args):
        selected = request in (fence.GET_FLAGS, fence.SET_FLAGS)
        if selected:
            self.note("ioctl_begin", request=hex(request), target=self.identity(fd),
                      flag_value=int(args[0][0]))
        try: result = self.ioctl(fd, request, *args)
        except OSError as error:
            if selected: self.note("ioctl_error", request=hex(request), errno=error.errno)
            raise
        if selected:
            self.note("ioctl_end", request=hex(request), target=self.identity(fd),
                      flag_value=int(args[0][0]))
        return result

    def observed_fsync(self, fd):
        self.note("fsync_begin", target=self.identity(fd))
        result = self.fsync(fd)
        self.note("fsync_end", target=self.identity(fd))
        return result

    def observed_close(self, fd):
        result = self.close(fd)
        self.watches.pop(fd, None)  # A reused fd must not inherit an old label.
        return result

    def checked(self, original, kind):
        def observe(instance, *args, **kwargs):
            fd = instance.events if kind == "journal" else instance.fd
            root = instance.root if kind == "journal" else instance.parent
            self.watches[fd] = dict(kind=kind, root=str(root),
                target_name=None if kind == "journal" else os.fsdecode(instance.name))
            self.note("check_begin", kind=kind, root=str(root))
            try: result = original(instance, *args, **kwargs)
            except BaseException as error:
                code = str(error) if type(error).__name__ == "ContractError" else type(error).__name__
                self.note("check_error", kind=kind, code=code)
                raise
            self.note("check_end", kind=kind)
            return result
        return observe

    def install(self, stack):
        stack.enter_context(patch.object(os, "read", self.observed_read))
        stack.enter_context(patch.object(fcntl, "ioctl", self.observed_ioctl))
        stack.enter_context(patch.object(os, "fsync", self.observed_fsync))
        stack.enter_context(patch.object(os, "close", self.observed_close))
        stack.enter_context(patch.object(fence.NewJournalFence, "check",
            self.checked(fence.NewJournalFence.check, "journal")))
        stack.enter_context(patch.object(ParentCreationWitness, "check",
            self.checked(ParentCreationWitness.check, "parent")))


class ForeignMetadataControl(unittest.TestCase):
    """Known synthetic action; no claim that inotify encodes its PID."""
    def runTest(self):
        with tempfile.TemporaryDirectory(prefix="s8-diag-foreign-", dir="/var/tmp") as temporary:
            root = Path(temporary)
            record = root / "record.json"
            record.write_bytes(b'{"synthetic":true}\n'); record.chmod(0o600)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            listener = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            self.assertGreaterEqual(listener, 0)
            pid = None
            try:
                self.assertGreaterEqual(libc.inotify_add_watch(listener, os.fsencode(root), 0x4), 0)
                reader, writer = os.pipe()
                pid = os.fork()
                if pid == 0:
                    with child_failure_boundary():
                        os.close(reader)
                        self.trace.note("controlled_foreign_chmod_begin", object=str(record))
                        os.chmod(record, 0o640); os.chmod(record, 0o600)
                        self.trace.note("controlled_foreign_chmod_end", object=str(record))
                        os.close(writer); os._exit(0)
                os.close(writer)
                try:
                    self.assertTrue(select.select([reader], [], [], 5)[0], "foreign child deadline")
                    self.assertEqual(os.read(reader, 1), b"")
                finally: os.close(reader)
                status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]); pid = None
                self.assertEqual(status, 0)
                self.assertEqual(record.stat().st_mode & 0o777, 0o600)
                raw = os.read(listener, 65536)  # This control owns its only read.
                self.assertTrue(any(int(e.get("mask", "0"), 16) & 0x4
                                    for e in decode_events(raw)))
            finally:
                if pid is not None:
                    try: os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.waitpid(pid, 0)
                os.close(listener)


def main(measurement="s8-measure-20261019-1"):
    if not (sys.platform == "linux" and os.geteuid() == 0
            and os.environ.get("container") == "docker" and Path("/.dockerenv").is_file()
            and Path("/proc/1/comm").read_text().strip() == "systemd"):
        raise SystemExit("S8_DIAGNOSTIC_ISOLATED_PID1_REQUIRED")
    trace = Trace()
    trace.note("profile", kernel=platform.release(), architecture=platform.machine(),
               measurement=measurement, synthetic=True)
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            trace.case = test.id(); trace.note("case_begin"); super().startTest(test)
        def stopTest(self, test):
            trace.note("case_end"); super().stopTest(test)
    names = [
        "tests.test_s8_new_stock.NewStockTests.test_wrong_input_and_acl_drift_do_not_publish_authority",
        "tests.test_s8_protected_journal.ProtectedJournalTests.test_successful_records_remain_sealed_after_fence_handoff",
        "tests.test_s8_journal_kernel_barrier.KernelJournalBarrierTests.test_kernel_flag_seal_does_not_hide_a_chmod_in_the_event_allowlist",
        "tests.test_s8_journal_kernel_barrier.KernelJournalBarrierTests.test_single_writer_fence_before_creation_and_immutable_handoff",
    ]
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromNames(names))
    foreign = ForeignMetadataControl(); foreign.trace = trace
    suite.addTest(foreign)
    with ExitStack() as stack:
        trace.install(stack)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    trace.note("measurement_end", tests=result.testsRun, failures=len(result.failures),
               errors=len(result.errors), skipped=len(result.skipped), observer_errors=trace.errors)
    # A diagnostic HOLD is not reclassified as PASS. No failed test is skipped.
    return 0 if result.wasSuccessful() and not result.skipped and not trace.errors else 1


if __name__ == "__main__": raise SystemExit(main())
