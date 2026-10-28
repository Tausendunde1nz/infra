"""One synthetic SUBSTITUTE-profile observation, never acceptance or a repair.

The production guards and original assertions remain unchanged. No kernel
actor trace is claimed: inotify cannot identify a metadata-event originator.
No tracefs/BPF/audit hooks, extra permission listeners, queue peeks or drains.
"""
from contextlib import ExitStack, contextmanager
import json
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import re
import signal
import select
import struct
import sys
import time
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.s8_diagnostic_once import Trace, fence
from tests.s8_fork_child import child_failure_boundary

MAX_LOG = 16 * 1024 * 1024
MAX_RECORD = 3 * 1024 * 1024


def exception_fields(error):
    """Public source locations only; never locals, source lines or free text."""
    frames, frame = [], error.__traceback__
    root = Path(__file__).resolve().parents[1]
    while frame is not None:
        filename = Path(frame.tb_frame.f_code.co_filename)
        try:
            relative = str(filename.relative_to(root))
        except ValueError:
            relative = "external_python_frame"
        frames.append(dict(file=relative, line=frame.tb_lineno))
        frame = frame.tb_next
    code = str(error) if type(error).__name__ == "ContractError" else "UNKNOWN"
    if not re.fullmatch(r"S8_EXECUTION_[A-Z0-9_]{1,128}", code):
        code = "UNKNOWN"
    return dict(exception_type=type(error).__name__, code=code, frames=frames)


def decode_raw(raw):
    """Keep every byte even when decoding is incomplete or watch is lost."""
    events, offset, invalid = [], 0, False
    while offset < len(raw):
        if len(raw) - offset < 16:
            invalid = True
            events.append(dict(offset=offset, malformed=True))
            break
        wd, mask, cookie, size = struct.unpack_from("iIII", raw, offset)
        start = offset
        offset += 16
        if size > len(raw) - offset:
            invalid = True
            events.append(dict(offset=start, wd=wd, mask=mask, cookie=cookie,
                               name_length=size, malformed=True))
            break
        name = raw[offset:offset + size]
        if size and (size % 4 or b"\0" not in name or any(name[name.index(0):])):
            invalid = True
        events.append(dict(offset=start, wd=wd, mask=mask, cookie=cookie,
                           name_raw_hex=name.hex(), actor="UNKNOWN"))
        invalid |= bool(mask & (0x4000 | 0x8000 | 0x2000))
        offset += size
    return dict(raw_hex=raw.hex(), byte_count=len(raw), events=events,
                observation_invalid=invalid, actor="UNKNOWN")


class Recorder:
    """One append write/record, no Python locks inherited across fork.

    A short/failed write invalidates evidence, never replaces a guard result.
    Native output must be on a local filesystem supporting atomic O_APPEND.
    Exit records + parent fork records permit detection of lost child reports.
    """
    def __init__(self, fd):
        self.fd = fd
        self.write = os.write
        self.errors = []
        self.phase = "setup"

    def note(self, operation, **fields):
        try:
            payload = (json.dumps(dict(operation=operation, phase=self.phase,
                observed_monotonic_ns=time.monotonic_ns(), caller_pid=os.getpid(),
                caller_tid=__import__("threading").get_native_id(), **fields),
                sort_keys=True) + "\n").encode()
            if len(payload) > MAX_RECORD or os.fstat(self.fd).st_size + len(payload) > MAX_LOG:
                raise ValueError("bounded observer capacity")
            if self.write(self.fd, payload) != len(payload):
                raise OSError("short observer write")
        except BaseException as error:
            self.errors.append(type(error).__name__)


class PrimaryTrace(Trace):
    def __init__(self, recorder):
        super().__init__()
        self.recorder = recorder
        self.bindings = {}

    def note(self, operation, **fields):
        self.recorder.note(operation, case=self.case, **fields)

    @staticmethod
    def identity(fd):
        identity = Trace.identity(fd)
        try:
            value = os.fstat(fd)
            identity.update(ctime_ns=value.st_ctime_ns, mtime_ns=value.st_mtime_ns)
            try:
                identity["acl_sha256"] = hashlib.sha256(os.getxattr(fd, "system.posix_acl_access")).hexdigest()
            except OSError as error:
                identity["acl"] = "NONE" if error.errno in (errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)) else "UNAVAILABLE"
                identity["acl_errno"] = error.errno
        except OSError as error:
            identity["metadata_errno"] = error.errno
        return identity

    def observed_read(self, fd, count):
        begin = time.monotonic_ns()
        try:
            raw = self.read(fd, count)  # exactly the original read, once
        except BaseException as error:
            if self.is_inotify(fd):
                self.note("original_inotify_read_exception", fd=fd,
                    watch=self.watches.get(fd), begin_monotonic_ns=begin,
                    **exception_fields(error), errno=getattr(error, "errno", None))
            raise
        if self.is_inotify(fd):
            observation = decode_raw(raw)
            watch = self.watches.get(fd) or {}
            binding = self.bindings.get(fd) or {}
            wds = binding.get("wds", [watch["wd"]] if "wd" in watch else [])
            if watch.get("kind", "").startswith("primitive"):
                stage = self.recorder.phase.rsplit(":", 1)[-1]
                allowed = {"mkdir": {b"journal", b""}, "own_APPEND": {b"journal", b""},
                    "record_created": {b"record.json", b""}, "own_IMMUTABLE": {b"record.json", b""},
                    "control_created": {b"control.json", b""}, "known_foreign_chmod": {b"control.json"}}.get(stage, set())
            elif watch.get("kind") == "parent":
                allowed = {os.fsencode(watch["target_name"]), b""}
            else:
                # Exact public filenames of this one original synthetic fixture.
                allowed = {b"", b"stock-plan.json", b"anchor.json", b"state", b"intent.json", b"objects.json"}
            for event in observation["events"]:
                name = bytes.fromhex(event.get("name_raw_hex", "")).split(b"\0", 1)[0]
                if event.get("wd") not in wds or name not in allowed:
                    observation["observation_invalid"] = True
            observation["watch_binding"] = binding or watch
            self.note("original_inotify_read", fd=fd, watch=self.watches.get(fd),
                      begin_monotonic_ns=begin, **observation)
        else:
            try: fanotify = "fanotify" in os.readlink(f"/proc/self/fd/{fd}")
            except OSError: fanotify = False
            if fanotify:
                # These are kernel OPEN_PERM requests, NOT metadata-origin proof.
                self.note("original_fanotify_read", fd=fd, raw_hex=raw.hex(),
                    byte_count=len(raw), begin_monotonic_ns=begin,
                    metadata_event_actor="UNKNOWN")
        return raw

    def checked(self, original, kind):
        observed = super().checked(original, kind)
        def check(instance, *args, **kwargs):
            fd = instance.events if kind == "journal" else instance.fd
            # Own descriptor metadata, not another read from an event queue.
            try:
                table = Path(f"/proc/self/fdinfo/{fd}").read_text()
                watches = [line for line in table.splitlines() if line.startswith("inotify ")]
                wds = [int(re.search(r"\bwd:([0-9a-f]+)\b", line)[1], 16) for line in watches]
                self.bindings[fd] = dict(wds=wds, watch_metadata=watches)
                self.note("watch_binding", kind=kind, fd=fd, watch_metadata=watches,
                    observation_invalid=not bool(watches))
            except (OSError, TypeError, ValueError) as error:
                self.bindings.pop(fd, None)
                self.note("watch_binding_unavailable", fd=fd, errno=getattr(error, "errno", None),
                          observation_invalid=True)
            return observed(instance, *args, **kwargs)
        return check

    def observed_close(self, fd):
        result = super().observed_close(fd)
        self.bindings.pop(fd, None)
        return result

    @contextmanager
    def child_boundary(self):
        with child_failure_boundary():  # retains the real 99/98 exit behavior
            try:
                yield
            except BaseException as error:
                self.note("child_first_unexpected_exception", **exception_fields(error))
                raise

    def install_primary(self, stack):
        self.install(stack)
        import tests.test_s8_anchor as anchor_tests
        original_exit, original_fork = os._exit, os.fork
        original_subtest = unittest.TestCase.subTest

        def observed_exit(code):
            self.note("child_exit", code=code, observer_errors=list(self.recorder.errors))
            original_exit(code)

        def observed_fork():
            pid = original_fork()
            if pid > 0:
                self.note("fork_parent", child_pid=pid)
            return pid

        @contextmanager
        def observed_subtest(instance, *args, **params):
            old = self.recorder.phase
            self.recorder.phase = params.get("phase", old)
            try:
                with original_subtest(instance, *args, **params):
                    yield
            finally:
                self.recorder.phase = old

        stack.enter_context(patch.object(anchor_tests, "child_failure_boundary", self.child_boundary))
        stack.enter_context(patch.object(os, "_exit", observed_exit))
        stack.enter_context(patch.object(os, "fork", observed_fork))
        stack.enter_context(patch.object(unittest.TestCase, "subTest", observed_subtest))


def validate_log(raw, recorder_errors=()):
    """No event removal. Missing/invalid evidence can never produce GREEN."""
    if recorder_errors or len(raw) > MAX_LOG or not raw.endswith(b"\n"):
        return False
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
        end = [r for r in rows if r["operation"] == "measurement_end"]
        begins = [r["case"] for r in rows if r["operation"] == "case_begin"]
        ends = [r["case"] for r in rows if r["operation"] == "case_end"]
        if (len(end) != 1 or rows[-1] != end[0] or end[0]["tests"] != 3
                or len(begins) != 3 or len(set(begins)) != 3 or begins != ends):
            return False
        forks = [r for r in rows if r["operation"] == "fork_parent"]
        exits = [r for r in rows if r["operation"] == "child_exit"]
        expected = {"root-created", "root-sealed", "slot-created", "intent-sealed", "objects-sealed",
                    "/var/tmp:known_foreign_chmod", "/s8-native-profile:known_foreign_chmod"}
        if (len(forks) != 7 or len(exits) != 7 or len({r["child_pid"] for r in forks}) != 7
                or {r["phase"] for r in forks} != expected
                or {r["child_pid"] for r in forks} != {r["caller_pid"] for r in exits}):
            return False
        for fork in forks:
            ended = [r for r in exits if r["caller_pid"] == fork["child_pid"]]
            if len(ended) != 1 or ended[0]["phase"] != fork["phase"]:
                return False
        for row in rows:
            if row.get("observation_invalid") or row.get("observer_errors"):
                return False
            if row["operation"] == "child_exit" and row["code"] == 99:
                errors = [r for r in rows if r.get("caller_pid") == row["caller_pid"]
                          and r["operation"] == "child_first_unexpected_exception"]
                if len(errors) != 1:
                    return False
                if rows.index(errors[0]) > rows.index(row) or errors[0]["phase"] != row["phase"]:
                    return False
        return bool(rows)
    except (KeyError, ValueError, TypeError):
        return False


class PrimitivePair(unittest.TestCase):
    """Separate synthetic queues; never consume any original guard queue."""
    def id(self):
        return super().id() + ":" + self.parent

    def runTest(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        # Guest destruction is the cleanup. Sealed inodes are not reset here.
        temporary = Path(tempfile.mkdtemp(prefix="s8-primary-", dir=self.parent))
        listener = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        self.assertGreaterEqual(listener, 0)
        child = None
        try:
            wd = libc.inotify_add_watch(listener, os.fsencode(temporary), 0xfc4)
            self.assertGreaterEqual(wd, 0)
            self.trace.watches[listener] = dict(kind="primitive_parent", root=str(temporary), wd=wd)
            root = temporary / "journal"
            self.trace.recorder.phase = str(self.parent) + ":mkdir"
            root.mkdir(mode=0o700)
            def snapshot(phase):
                self.trace.recorder.phase = str(self.parent) + ":" + phase
                try: os.read(listener, 65536)
                except BlockingIOError: pass  # observed, never a guard decision
            snapshot("mkdir")
            self.trace.recorder.phase = str(self.parent) + ":own_APPEND"
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: fence.add_inode_protection(fd, fence.APPEND)
            finally: os.close(fd)
            snapshot("own_APPEND")
            os.close(listener)
            listener = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            self.assertGreaterEqual(listener, 0)
            wd = libc.inotify_add_watch(listener, os.fsencode(root), 0xec4)
            self.assertGreaterEqual(wd, 0)
            self.trace.watches[listener] = dict(kind="primitive_journal", root=str(root), wd=wd)
            record = root / "record.json"
            self.trace.recorder.phase = str(self.parent) + ":record_created"
            fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                self.assertEqual(os.write(fd, b'{"synthetic":true}\n'), 19)
                os.fsync(fd)
            finally: os.close(fd)
            snapshot("record_created")
            self.trace.recorder.phase = str(self.parent) + ":own_IMMUTABLE"
            fd = os.open(record, os.O_RDONLY)
            try: fence.add_inode_protection(fd, fence.IMMUTABLE)
            finally: os.close(fd)
            snapshot("own_IMMUTABLE")
            self.trace.recorder.phase = str(self.parent) + ":control_created"
            control = root / "control.json"
            fd = os.open(control, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            snapshot("control_created")  # preserve own baseline; not a guard queue
            self.trace.recorder.phase = str(self.parent) + ":known_foreign_chmod"
            reader, writer = os.pipe()
            child = os.fork()
            if child == 0:
                with self.trace.child_boundary():
                    os.close(reader)
                    self.trace.note("known_fixture_action_begin", target=str(control), actor_claim=False)
                    os.chmod(control, 0o640); os.chmod(control, 0o600)
                    self.trace.note("known_fixture_action_end", target=str(control), actor_claim=False)
                    os.close(writer); os._exit(0)
            os.close(writer)
            try:
                self.assertTrue(select.select([reader], [], [], 5)[0], "control child deadline")
                self.assertEqual(os.read(reader, 1), b"")
            finally: os.close(reader)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 0)
            child = None
            self.trace.recorder.phase = str(self.parent) + ":known_foreign_chmod"
            raw = os.read(listener, 65536)
            events = decode_raw(raw)["events"]
            self.assertTrue(events and all(e.get("mask", 0) == 4 and
                bytes.fromhex(e.get("name_raw_hex", "")).split(b"\0", 1)[0] == b"control.json"
                for e in events), "positive metadata control not observed")
        finally:
            if child is not None:
                try: os.kill(child, signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(child, 0)
            os.close(listener)


def main():
    # No live-host path: the existing native fixture is an additional gate.
    if not (sys.platform == "linux" and os.geteuid() == 0
            and os.environ.get("container") == "docker" and Path("/.dockerenv").is_file()
            and Path("/proc/1/comm").read_text().strip() == "systemd"):
        raise SystemExit("S8_MEASUREMENT_DISPOSABLE_PID1_REQUIRED")
    signal.alarm(90)
    output = Path("/var/tmp/s8-primary-observation.jsonl")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o600)
    recorder = Recorder(fd)
    trace = PrimaryTrace(recorder)
    name = "tests.test_s8_anchor.AnchorNativeTests.test_interruption_after_each_anchor_mutation_leaves_no_new_admission"
    suite = unittest.defaultTestLoader.loadTestsFromName(name)
    for parent in ("/var/tmp", "/s8-native-profile"):
        primitive = PrimitivePair(); primitive.parent = parent; primitive.trace = trace
        suite.addTest(primitive)
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            trace.case = test.id()
            recorder.phase = "fixture_setup"
            recorder.note("case_begin", case=test.id())
            super().startTest(test)
        def stopTest(self, test):
            recorder.note("case_end", case=test.id())
            super().stopTest(test)
    try:
        with ExitStack() as stack:
            trace.install_primary(stack)
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        recorder.note("measurement_end", tests=result.testsRun, skipped=len(result.skipped),
            failures=len(result.failures), errors=len(result.errors),
            observer_errors=recorder.errors, substitute_only=True, actor="UNKNOWN")
    finally:
        os.close(fd)
    valid = validate_log(output.read_bytes(), recorder.errors)
    red = [test.id() for test, _ in result.failures + result.errors]
    skipped = [test.id() for test, _ in result.skipped]
    original_success = not any(value.startswith(name) for value in red + skipped)
    primitive_success = not any("PrimitivePair.runTest:" in value for value in red + skipped)
    print("S8_PRIMARY_SUMMARY " + json.dumps(dict(evidence_complete=valid,
        sequence_success=result.wasSuccessful(), original_case_success=original_success,
        primitive_cases_success=primitive_success, skipped=len(result.skipped),
        substitute_only=True, historical_cause="UNPROVEN", metadata_actor="UNKNOWN")))
    return 0 if valid and result.wasSuccessful() and not result.skipped and not recorder.errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
