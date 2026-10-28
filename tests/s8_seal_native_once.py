"""One synthetic targeted acceptance. No private input or production entry.

Uses the existing PID1 image/init/isolation and byte-exact evidence transport.
The legacy three-case validator is unchanged; this report has its own schema.
No guard decision, syscall result, event queue or selected test is replaced.
"""
from contextlib import ExitStack
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import re
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.s8_primary_measurement import Recorder, PrimaryTrace, decode_raw, exception_fields
from tests.s8_evidence_export import MAX_LOG, REPORT, docker_export, final_exit
from tests.s8_diagnostic_once import fence

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "tests/s8_seal_native_binding.json"
BRANCH = "codex/s8-seal-native-once-20261028"
MESSAGE = "S8: prepare seal native once 20261028"
CANDIDATE = "bb0aa241f96f2552da808fa4a3d2d9688e1bdf48"
BASE = "1eb70824d016e06b36b972b569790f3ce2446b5b"
CANDIDATE_DIFF = "7a234703f34a84419cabb6631d43a9d71383ec794b3fb13f620d6176b41b4aa6"
SUPPLEMENT = sorted([".github/workflows/s8-seal-native-once.yml", "tests/s8_anchor_native.sh",
    "tests/s8_evidence_export.py", "tests/s8_seal_native_binding.json",
    "tests/s8_seal_native_once.py", "tests/test_s8_seal_native_once.py", "tests/test_s8_evidence_export_native.py"])
SELECTION = ["tests.test_s8_seal_metadata.NativeSealMetadataTests",
    "tests.test_s8_new_stock.NewStockTests", "tests.test_s8_protected_journal.ProtectedJournalTests",
    "tests.test_s8_journal_kernel_barrier.KernelJournalBarrierTests", "tests.test_s8_path_policy.PathPolicyTests",
    "tests.test_s8_anchor.AnchorNativeTests", "tests.test_s8_admission_channel.AdmissionChannelTests",
    "tests.test_s8_frozen_entry.FrozenEntryTests.test_pid1_loaded_entry_ignores_mutable_control_path"]
SCHEMA = "TU1NZ_S8_SEAL_NATIVE_REPORT_V1"


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite): yield from cases(item)
        else: yield item


def selected_suite():
    suite = unittest.defaultTestLoader.loadTestsFromNames(SELECTION)
    rows = list(cases(suite)); ids = [test.id() for test in rows]
    if len(ids) != 46 or len(set(ids)) != 46 or any(type(test).__name__ == "_FailedTest" for test in rows):
        raise ValueError("SELECTION_BINDING_RED")
    return suite, ids


def verify_files(root=ROOT, binding_path=BINDING):
    value = json.loads(binding_path.read_text())
    if value["candidate"] != CANDIDATE or value["base"] != BASE or value["candidate_diff"] != CANDIDATE_DIFF:
        raise ValueError("CANDIDATE_BINDING_RED")
    expected = set(SUPPLEMENT) - {"tests/s8_seal_native_binding.json"}
    if set(value["files"]) != expected or value["selection"] != SELECTION:
        raise ValueError("PACKAGE_BINDING_RED")
    for name, digest in value["files"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError("PACKAGE_BYTE_BINDING_RED")
    return value


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def verify_source(env=os.environ):
    if (env.get("GITHUB_ACTIONS") != "true" or env.get("GITHUB_RUN_ATTEMPT") != "1"
            or env.get("GITHUB_EVENT_NAME") != "push" or env.get("GITHUB_REPOSITORY") != "Tausendunde1nz/infra"
            or env.get("GITHUB_REF") != "refs/heads/" + BRANCH
            or not re.fullmatch("[0-9a-f]{40}", env.get("GITHUB_SHA", ""))
            or not re.fullmatch("[0-9]+", env.get("GITHUB_RUN_ID", ""))):
        raise ValueError("RUN_BINDING_RED")
    verify_files()
    if (git("rev-parse", "HEAD").decode().strip() != env["GITHUB_SHA"]
            or git("rev-parse", "HEAD^").decode().strip() != CANDIDATE
            or git("log", "-1", "--format=%B").decode().rstrip("\n") != MESSAGE
            or git("status", "--porcelain=v1", "--untracked-files=normal")
            or git("diff", "--name-only", CANDIDATE, "HEAD").decode().splitlines() != SUPPLEMENT
            or hashlib.sha256(git("diff", "--full-index", "--binary", BASE, CANDIDATE)).hexdigest() != CANDIDATE_DIFF):
        raise ValueError("SOURCE_BINDING_RED")
    return dict(head=env["GITHUB_SHA"], candidate=CANDIDATE, base=BASE,
        cumulative_diff_sha256=hashlib.sha256(git("diff", "--full-index", "--binary", BASE, "HEAD")).hexdigest())


class SealTrace(PrimaryTrace):
    """Observer only: original calls once, raw bytes intact, no queue preview."""
    def __init__(self, recorder):
        super().__init__(recorder)
        self.groups = {}
        self.exceptions = set()

    def first_child_exception(self, error):
        if os.getpid() not in self.exceptions:
            self.exceptions.add(os.getpid())
            self.note("child_first_unexpected_exception", **exception_fields(error))

    def bind_inotify(self, fd, kind, wds):
        if fd is None: return
        if fd not in self.groups:
            # Parent ctor binds BEFORE the deliberate rmwatch negative case.
            # A lost watch is recorded as a guard outcome, never as live cover.
            try:
                table = Path(f"/proc/self/fdinfo/{fd}").read_text()
                actual = {int(re.search(r"\bwd:([0-9a-f]+)\b", line)[1], 16)
                          for line in table.splitlines() if line.startswith("inotify ")}
                if not set(wds) <= actual: raise ValueError()
                self.groups[fd] = dict(kind=kind, wds=list(wds))
                self.note("inotify_bound", fd=fd, kind=kind, wds=list(wds), fdinfo=table)
            except (OSError, TypeError, ValueError):
                self.note("binding_unavailable", fd=fd, kind=kind)
        else:
            self.groups[fd]["wds"] = list(wds)

    def observed_read(self, fd, count):
        raw = self.read(fd, count)  # Exactly once, including original exceptions.
        group = self.groups.get(fd)
        try: link = os.readlink(f"/proc/self/fd/{fd}")
        except OSError: link = ""
        if "inotify" in link:
            decoded = decode_raw(raw)
            codes = list(decoded["observation_codes"])
            if not raw: codes.append("INOTIFY_QUEUE_EOF")
            if group and group["kind"] == "ancestry" and not self.bindings.get(fd):
                codes.append("ANCESTRY_NODE_BINDING_UNAVAILABLE")
            for event in decoded["events"]:
                if group is None or event.get("wd") not in group.get("wds", []): codes.append("INOTIFY_WD_UNBOUND")
            # The raw decoder's loss flag is retained unchanged. Only N07 has
            # an intentionally removed, previously bound watch; it MUST still
            # produce its original guard rejection and a successful test.
            expected_loss = self.case.endswith(".test_N07_parent_namespace_watch_removal_is_red")
            integrity = [code for code in codes if not (expected_loss and code == "INOTIFY_WATCH_LOST")]
            self.note("kernel_inotify", fd=fd, group=group, decoded=decoded,
                      observer_codes=sorted(set(integrity)))
        elif "fanotify" in link:
            decoded = []
            codes = [] if group else ["FANOTIFY_GROUP_UNBOUND"]
            if group and group["kind"] == "metadata":
                try:
                    decoded = [dict(tid=tid, fsid=fid[0].hex(), handle_type=fid[1], handle=fid[2].hex())
                               for tid, fid in fence.metadata_events(raw)]
                except Exception: codes.append("FANOTIFY_METADATA_DECODE_RED")
            self.note("kernel_fanotify", fd=fd, group=group, raw_hex=raw.hex(), byte_count=len(raw),
                      events=decoded, observer_codes=codes)
        return raw

    def observed_close(self, fd):
        known = fd in self.groups
        result = super().observed_close(fd)
        self.groups.pop(fd, None)
        if known: self.note("observer_fd_closed", fd=fd)
        return result

    def checked(self, original, kind):
        def check(instance, *args, **kwargs):
            if kind == "parent": self.bind_inotify(instance.fd, kind, [instance.wd])
            else:
                self.bind_inotify(instance.events, kind, self.watch_ids(instance.events))
                if instance.fd is not None:
                    self.groups[instance.fd] = dict(kind="permission", owner_tid=instance.owner_tid)
            self.note("guard_check_begin", kind=kind)
            try: return original(instance, *args, **kwargs)
            except BaseException as error:
                self.note("guard_check_exception", kind=kind, **exception_fields(error)); raise
        return check

    @staticmethod
    def watch_ids(fd):
        try:
            return [int(re.search(r"\bwd:([0-9a-f]+)\b", line)[1], 16)
                    for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines() if line.startswith("inotify ")]
        except (OSError, TypeError, ValueError): return []

    def checked_chain(self, original):
        observed = super().checked_chain(original)
        def check(instance, *args, **kwargs):
            self.bind_inotify(instance.events, "ancestry", [row[0] for row in instance.nodes])
            # Reuse the already reviewed per-node inode/device/fdinfo binding,
            # including its invalid records, without another original check.
            return observed(instance, *args, **kwargs)
        return check

    def install_seal(self, stack):
        super().install_primary(stack)
        from tu1nz_s8_new_stock import ParentCreationWitness
        import tests.test_s8_journal_kernel_barrier as barrier_tests
        original_parent = ParentCreationWitness.__init__
        original_metadata = fence.MetadataWitness.check
        original_serve = fence.NewJournalFence._serve
        original_cdll = barrier_tests.ctypes.CDLL
        original_exit, original_wait = os._exit, os.waitpid
        def parent(instance, *args, **kwargs):
            original_parent(instance, *args, **kwargs)
            self.bind_inotify(instance.fd, "parent", [instance.wd])
        def metadata(instance, *args, **kwargs):
            if instance.fd is not None:
                self.groups[instance.fd] = dict(kind="metadata", owner_tid=instance.owner[1],
                    targets=[dict(fsid=f[0].hex(), handle_type=f[1], handle=f[2].hex()) for f in sorted(instance.targets)])
            self.note("metadata_check_begin", fd=instance.fd, bound=instance.bound)
            try: return original_metadata(instance, *args, **kwargs)
            except BaseException as error:
                self.note("guard_check_exception", kind="metadata", **exception_fields(error)); raise
        def serve(instance):
            # The constructor's liveness open precedes its first check().
            # Bind the exact permission FD before the unchanged server reads it.
            if instance.fd is not None:
                self.groups[instance.fd] = dict(kind="permission", owner_tid=instance.owner_tid)
                self.note("permission_group_bound", fd=instance.fd, owner_tid=instance.owner_tid)
            return original_serve(instance)
        def control_libc(*args, **kwargs):
            libc = original_cdll(*args, **kwargs)
            if not self.case.endswith(".test_kernel_flag_seal_does_not_hide_a_chmod_in_the_event_allowlist"):
                return libc
            # Only this existing synthetic test's local ctypes reference is
            # proxied. The real add_watch runs once; its result is unchanged.
            def add_watch(fd, path, mask):
                wd = libc.inotify_add_watch(fd, path, mask)
                if wd >= 0:
                    try:
                        stat = os.stat(path, follow_symlinks=False)
                        table = Path(f"/proc/self/fdinfo/{fd}").read_text()
                        lines = [line for line in table.splitlines() if line.startswith("inotify ")]
                        encoded = (os.major(stat.st_dev) << 8) | (os.minor(stat.st_dev) & 255) | ((os.minor(stat.st_dev) & ~255) << 12)
                        valid = len(lines) == 1 and mask == 4
                        valid = valid and int(re.search(r"\bwd:([0-9a-f]+)\b", lines[0])[1], 16) == wd
                        valid = valid and int(re.search(r"\bino:([0-9a-f]+)\b", lines[0])[1], 16) == stat.st_ino
                        valid = valid and int(re.search(r"\bsdev:([0-9a-f]+)\b", lines[0])[1], 16) == encoded
                        if not valid: raise ValueError()
                        self.bind_inotify(fd, "kernel_barrier_control", [wd])
                        self.note("control_listener_bound", fd=fd, wd=wd, mask=mask, path=os.fsdecode(path),
                                  dev=stat.st_dev, ino=stat.st_ino, fdinfo=table)
                    except (OSError, TypeError, ValueError, IndexError):
                        self.note("binding_unavailable", fd=fd, kind="kernel_barrier_control")
                return wd
            class ControlLibc:
                def __getattr__(self, name):
                    return add_watch if name == "inotify_add_watch" else getattr(libc, name)
            return ControlLibc()
        def exiting(code):
            if code == 99 and sys.exception() is not None: self.first_child_exception(sys.exception())
            original_exit(code)
        def waited(*args, **kwargs):
            result = original_wait(*args, **kwargs)
            if result[0] > 0: self.note("child_waited", child_pid=result[0], exit_code=os.waitstatus_to_exitcode(result[1]))
            return result
        stack.enter_context(patch.object(ParentCreationWitness, "__init__", parent))
        stack.enter_context(patch.object(fence.MetadataWitness, "check", metadata))
        stack.enter_context(patch.object(fence.NewJournalFence, "_serve", serve))
        stack.enter_context(patch.object(barrier_tests, "ctypes", SimpleNamespace(CDLL=control_libc)))
        stack.enter_context(patch.object(os, "_exit", exiting))
        stack.enter_context(patch.object(os, "waitpid", waited))

    def child_boundary(self):
        # Keep the existing helper, with one first-exception record per child.
        from contextlib import contextmanager
        from tests.s8_fork_child import child_failure_boundary
        @contextmanager
        def boundary():
            with child_failure_boundary():
                try: yield
                except BaseException as error: self.first_child_exception(error); raise
        return boundary()


class SealResult(unittest.TestResult):
    def __init__(self, trace):
        super().__init__(); self.trace = trace; self.status = {}; self.failfast = True
    def startTest(self, test):
        super().startTest(test); self.trace.case = test.id(); self.trace.recorder.phase = "test"
        self.trace.note("case_begin")
    def addSuccess(self, test):
        super().addSuccess(test); self.status[test.id()] = "PASS"
    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.status[test.id()] = "SKIP"; self.stop()
    def addFailure(self, test, err):
        super().addFailure(test, err); self.status[test.id()] = "FAIL"
        self.trace.note("case_first_unexpected_exception", **exception_fields(err[1]))
    def addError(self, test, err):
        super().addError(test, err); self.status[test.id()] = "ERROR"
        self.trace.note("case_first_unexpected_exception", **exception_fields(err[1]))
    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err:
            self.status[test.id()] = "FAIL"
            self.trace.note("case_first_unexpected_exception", **exception_fields(err[1]))
    def stopTest(self, test):
        self.trace.note("case_end", status=self.status.get(test.id(), "UNKNOWN"))
        super().stopTest(test)


def evidence_diagnostics(raw, source_sha=None):
    codes = []
    def fail(code):
        if code not in codes: codes.append(code)
    if not raw or len(raw) > MAX_LOG: return dict(evidence_complete=False, codes=["REPORT_EMPTY_OR_SIZE_LIMIT"])
    if not raw.endswith(b"\n"): fail("REPORT_NO_FINAL_NEWLINE")
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
        starts = [r for r in rows if r["operation"] == "suite_begin"]
        ends = [r for r in rows if r["operation"] == "suite_end"]
        if len(starts) != 1 or starts[0]["schema"] != SCHEMA: fail("SUITE_SCHEMA_RED")
        if len(ends) != 1 or rows[-1] != ends[0]: fail("SUITE_END_MISSING_OR_NOT_LAST")
        expected = starts[0]["expected_ids"]
        if expected != selected_suite()[1]: fail("EXPECTED_CASES_RED")
        actual_sha = starts[0]["source_sha"]
        if not re.fullmatch("[0-9a-f]{40}", actual_sha) or source_sha is not None and actual_sha != source_sha:
            fail("REPORT_SOURCE_BINDING_RED")
        begin = [r["case"] for r in rows if r["operation"] == "case_begin"]
        end = [r["case"] for r in rows if r["operation"] == "case_end"]
        if begin != expected or end != expected: fail("CASE_COVERAGE_PARTIAL")
        if len(ends) == 1 and (ends[0]["tests"] != 46 or ends[0]["skipped"]): fail("NATIVE_COUNT_OR_SKIP")
        if (len(ends) == 1 and (ends[0]["failures"] or ends[0]["errors"])
                or any(r.get("status") != "PASS" for r in rows if r["operation"] == "case_end")):
            fail("SUITE_RESULT_RED")
        for row in rows:
            if row.get("observer_codes") or row.get("observer_errors"): fail("OBSERVER_INTEGRITY_RED")
            if (row.get("observation_invalid") or row.get("observation_codes")
                    or row["operation"] in ("binding_unavailable", "watch_binding_unavailable")):
                fail("OBSERVER_BINDING_RED")
            if row["operation"] == "kernel_fanotify":
                payload = bytes.fromhex(row["raw_hex"])
                if len(payload) != row["byte_count"]: fail("KERNEL_BYTE_COUNT_RED")
                if row["group"] and row["group"]["kind"] == "metadata":
                    decoded = [dict(tid=tid, fsid=fid[0].hex(), handle_type=fid[1], handle=fid[2].hex())
                               for tid, fid in fence.metadata_events(payload)]
                    if decoded != row["events"]: fail("KERNEL_RAW_DECODE_MISMATCH")
            if row["operation"] == "kernel_inotify":
                if decode_raw(bytes.fromhex(row["decoded"]["raw_hex"])) != row["decoded"]:
                    fail("KERNEL_RAW_DECODE_MISMATCH")
        for fork in [r for r in rows if r["operation"] == "fork_parent"]:
            if not any(r["operation"] == "child_waited" and r["child_pid"] == fork["child_pid"]
                       and r["caller_pid"] == fork["caller_pid"] for r in rows): fail("CHILD_WAIT_MISSING")
        for exited in [r for r in rows if r["operation"] == "child_exit" and r["code"] == 99]:
            if not any(r["operation"] == "child_first_unexpected_exception" and r["caller_pid"] == exited["caller_pid"]
                       and rows.index(r) < rows.index(exited) for r in rows): fail("CHILD99_EXCEPTION_MISSING")
        # Direct kernel evidence, not masks/time/final stat as attribution.
        for marker in ("test_N03_", "test_N04_"):
            events = [(r, ev) for r in rows if r["operation"] == "kernel_fanotify" and marker in r["case"]
                      for ev in r["events"]]
            own = {json.dumps({k:e[k] for k in ("fsid", "handle_type", "handle")}, sort_keys=True)
                   for r,e in events if e["tid"] == r["group"]["owner_tid"]}
            foreign = {json.dumps({k:e[k] for k in ("fsid", "handle_type", "handle")}, sort_keys=True)
                       for r,e in events if e["tid"] > 0 and e["tid"] != r["group"]["owner_tid"]}
            if not own & foreign: fail("COALESCING_PAIR_EVIDENCE_MISSING")
        n01 = [(r,e) for r in rows if r["operation"] == "kernel_fanotify" and "test_N01_" in r["case"] for e in r["events"]]
        if not any(e["tid"] > 0 and e["tid"] != r["group"]["owner_tid"] for r,e in n01):
            fail("PREBIND_FOREIGN_EVIDENCE_MISSING")
        n02 = [e for r in rows if r["operation"] == "kernel_fanotify" and "test_N02_" in r["case"]
               for e in r["events"] if e["tid"] == r["group"]["owner_tid"]]
        if len(n02) < 3 or len({(e["fsid"],e["handle_type"],e["handle"]) for e in n02}) < 2:
            fail("OWN_FLAG_TRANSITION_EVIDENCE_MISSING")
        n07 = [r for r in rows if "test_N07_" in r.get("case", "")]
        if not any(r["operation"] == "kernel_inotify" and "INOTIFY_WATCH_LOST" in r["decoded"]["observation_codes"] for r in n07):
            fail("WATCH_LOSS_EVIDENCE_MISSING")
        if not any(r["operation"] == "guard_check_exception" and r["code"] == "S8_EXECUTION_STOCK_PARENT_EVENT_RED" for r in n07):
            fail("WATCH_LOSS_GUARD_REJECTION_MISSING")
    except (KeyError, TypeError, ValueError, IndexError, fence.ContractError): fail("REPORT_SCHEMA_INVALID")
    return dict(evidence_complete=not codes, codes=codes)


def guest(source_sha):
    if not (sys.platform == "linux" and os.geteuid() == 0 and os.environ.get("container") == "docker"
            and Path("/.dockerenv").is_file() and Path("/proc/1/comm").read_text().strip() == "systemd"
            and re.fullmatch("[0-9a-f]{40}", source_sha or "")): return 74
    verify_files()
    suite, ids = selected_suite()
    fd = os.open(REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o600)
    recorder = Recorder(fd); trace = SealTrace(recorder); result = SealResult(trace)
    signal.alarm(180)
    try:
        trace.note("suite_begin", schema=SCHEMA, source_sha=source_sha, expected_ids=ids)
        with ExitStack() as stack:
            trace.install_seal(stack); suite.run(result)
        trace.note("suite_end", tests=result.testsRun, skipped=len(result.skipped), failures=len(result.failures),
                   errors=len(result.errors), observer_errors=recorder.errors)
    finally:
        os.close(fd); signal.alarm(0)
    diagnostic = evidence_diagnostics(Path(REPORT).read_bytes(), source_sha)
    return 0 if result.wasSuccessful() and not result.skipped and diagnostic["evidence_complete"] else 1


def command(args, seconds, *, capture=False):
    return subprocess.run(args, timeout=seconds, check=True, capture_output=capture, text=capture)


def cleanup(container):
    codes = []
    for args, seconds, code in [(["docker", "stop", "--time", "20", container], 30, "STOP_RED"),
                                (["docker", "rm", container], 10, "REMOVE_RED")]:
        try: command(args, seconds, capture=True)
        except (OSError, subprocess.SubprocessError): codes.append(code)
    try:
        result = command(["docker", "container", "ls", "--all", "--quiet", "--filter", "id=" + container], 10, capture=True)
        if result.stdout.strip(): codes.append("CONTAINER_REMAINS")
    except (OSError, subprocess.SubprocessError): codes.append("CLEANUP_UNVERIFIED")
    return codes


def owned(label):
    result = command(["docker", "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=" + label], 10, capture=True)
    ids = result.stdout.splitlines()
    if len(ids) > 1 or any(not re.fullmatch("[0-9a-f]{64}", cid) for cid in ids):
        raise ValueError("OWNED_CONTAINER_BINDING_RED")
    return ids


class LaunchAbort(Exception):
    def __init__(self, code): self.code = code


def emit(result, raw):
    if result.get("bytes_saved") != len(raw) or result.get("raw_sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("EXPORT_READBACK_RED")
    print("S8_SEAL_TRANSPORT " + json.dumps(result, sort_keys=True), flush=True)
    print("S8_SEAL_RAW_B64_BEGIN", flush=True)
    encoded = base64.b64encode(raw).decode()
    for offset in range(0, len(encoded), 4096): print("S8_SEAL_RAW_B64 " + encoded[offset:offset + 4096], flush=True)
    print("S8_SEAL_RAW_B64_END", flush=True)


def launch():
    binding = verify_source()
    if sys.platform != "linux" or os.geteuid() == 0 or os.uname().machine != "x86_64":
        raise ValueError("HOSTED_NONROOT_X86_64_REQUIRED")
    print("S8_SEAL_BINDING " + json.dumps(binding, sort_keys=True), flush=True)
    print("S8_SEAL_HOSTED " + json.dumps({k:os.environ.get(k, "UNKNOWN") for k in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")}), flush=True)
    image = "tu1nz-s8-primary:" + os.environ["GITHUB_RUN_ID"] + "-1"
    export = Path(tempfile.mkdtemp(prefix="s8-seal-export-", dir=os.environ["RUNNER_TEMP"]))
    container = None; measurement = None; entry = 0; exported = None; cleanup_codes = []; launcher_codes = []
    transport_started = main_started = measurement_started = transport_green = False
    transport_label = "tu1nz.s8-seal-transport=" + os.environ["GITHUB_RUN_ID"]
    main_label = "tu1nz.s8-seal-main=" + os.environ["GITHUB_RUN_ID"]
    handlers = {signum:signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
    def abort(signum, frame): raise LaunchAbort(128 + signum)
    for signum in handlers: signal.signal(signum, abort)
    try:
        if owned(transport_label) or owned(main_label): raise ValueError("PREEXISTING_LABEL_NO_ADOPTION")
        driver = command(["docker", "info", "--format", "{{.Driver}}"], 10, capture=True).stdout.strip()
        if driver != "overlay2": raise ValueError("OVERLAY2_PROFILE_REQUIRED")
        command(["timeout", "--signal=TERM", "--kill-after=10s", "300s", "docker", "build", "--file",
                 "tests/s8-native.Dockerfile", "--tag", image, "."], 315)
        command(["docker", "image", "inspect", "--format", "S8_SEAL_IMAGE {{.Id}}", image], 10)
        command(["docker", "info", "--format", "S8_SEAL_DOCKER {{.ServerVersion}} {{.Driver}} {{.KernelVersion}}"], 10)
        env = dict(os.environ, S8_EVIDENCE_NATIVE_IMAGE=image, S8_SEAL_TRANSPORT_OWNER=os.environ["GITHUB_RUN_ID"])
        transport_started = True
        subprocess.run([sys.executable, "-B", "tests/test_s8_evidence_export_native.py"], env=env, check=True, timeout=120)
        if owned(transport_label): raise ValueError("TRANSPORT_FIXTURE_CLEANUP_RED")
        transport_green = True
        # Same image/init/isolated PID1 construction as the default launcher.
        main_started = True
        container = command(["docker", "create", "--label", main_label, "--network", "none", "--privileged", "--cgroupns=private",
            "--env", "container=docker", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp",
            "--mount", "type=bind,src=" + str(ROOT) + ",dst=/source,readonly", "--workdir", "/source", image], 10, capture=True).stdout.strip()
        if not re.fullmatch("[0-9a-f]{64}", container): container = None; raise ValueError("CONTAINER_ID_RED")
        command(["docker", "start", container], 10, capture=True)
        command(["timeout", "35s", "docker", "exec", container, "bash", "-c",
                 "for i in {1..30}; do systemctl is-system-running --quiet && exit 0; sleep 1; done; exit 1"], 40)
        command(["docker", "exec", container, "findmnt", "--noheadings", "--output", "TARGET,FSTYPE,OPTIONS", "--target", "/etc"], 10)
        command(["docker", "exec", container, "dpkg-query", "--show", "--showformat=S8_SEAL_PACKAGE ${binary:Package}=${Version}\\n",
                 "python3", "python3.12", "systemd", "systemd-sysv", "acl", "dbus", "util-linux", "e2fsprogs"], 10)
        measurement_started = True
        result = subprocess.run(["timeout", "--signal=TERM", "--kill-after=10s", "190s", "docker", "exec", container,
                  "python3", "-B", "tests/s8_seal_native_once.py", "--guest", "--source-sha", binding["head"]], timeout=205)
        measurement = result.returncode
    except LaunchAbort as error:
        entry = error.code; launcher_codes.append("LAUNCH_CANCELLED")
        if measurement_started and measurement is None: measurement = error.code
    except subprocess.TimeoutExpired:
        entry = 124; launcher_codes.append("LAUNCH_DEADLINE")
        if measurement_started and measurement is None: measurement = 124
    except subprocess.CalledProcessError as error:
        entry = error.returncode if 0 < error.returncode <= 255 else 74; launcher_codes.append("LAUNCH_COMMAND_RED")
    except (OSError, ValueError, subprocess.SubprocessError):
        entry = 74; launcher_codes.append("LAUNCH_OR_PROFILE_RED")
    finally:
        # Bounded export/owned cleanup grace only. A hard VM kill may still
        # leave PARTIAL evidence; it is never a successful acceptance.
        for signum in handlers: signal.signal(signum, signal.SIG_IGN)
        if transport_started:
            try:
                for cid in owned(transport_label):
                    cleanup_codes.extend(cleanup(cid)); launcher_codes.append("TRANSPORT_FIXTURE_REMAINED")
            except (OSError, ValueError, subprocess.SubprocessError): cleanup_codes.append("TRANSPORT_CLEANUP_UNVERIFIED")
        if main_started and container is None:
            try:
                ids = owned(main_label)
                if ids: container = ids[0]
            except (OSError, ValueError, subprocess.SubprocessError): cleanup_codes.append("MAIN_CLEANUP_UNVERIFIED")
        if container is not None:
            try:
                exported, raw = docker_export(container, export, measurement, launcher_exit=entry,
                    diagnostics=lambda raw:evidence_diagnostics(raw, binding["head"]))
                saved = (export / "observation.jsonl").read_bytes()
                if saved != raw: raise ValueError("EXPORT_READBACK_RED")
                emit(exported, raw)
            except (OSError, ValueError, TypeError): launcher_codes.append("EXPORT_OR_FRAMING_RED")
            finally: cleanup_codes.extend(cleanup(container))
        else: launcher_codes.append("GUEST_NOT_CREATED_NO_REPORT")
    export_exit = 74 if exported is None else exported["export_exit"]
    complete = exported is not None and exported["evidence_complete"]
    status = final_exit(measurement, export_exit, complete, entry)
    if not status and (cleanup_codes or launcher_codes): status = 74
    final = dict(binding=binding, measurement_exit=measurement, launcher_exit=entry, export_exit=export_exit,
        evidence_complete=complete, cleanup_codes=cleanup_codes, launcher_codes=launcher_codes,
        native_transport_7_zero_skip_cleanup=transport_green,
        final_exit=status, full_required_CI=False, historical_cause="UNPROVEN")
    fd = os.open(export / "final.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(final, stream, sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    print("S8_SEAL_FINAL " + json.dumps(final, sort_keys=True), flush=True)
    for signum, handler in handlers.items(): signal.signal(signum, handler)
    return status


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--launch", action="store_true")
    parser.add_argument("--guest", action="store_true"); parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
        if args.launch and not args.guest: return launch()
        if args.guest and not args.launch: return guest(args.source_sha)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("S8_SEAL_HOLD BINDING_OR_RUNTIME_ERROR", flush=True)
    return 74


if __name__ == "__main__": raise SystemExit(main())
