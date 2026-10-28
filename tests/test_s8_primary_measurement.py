"""Portable observation contracts; no Docker, native guards or host reads."""
import errno
import json
import os
import struct
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch
from tests.s8_primary_measurement import PrimaryTrace, Recorder, decode_raw, exception_fields, validate_log


class PrimaryObservationTests(unittest.TestCase):
    def trace(self):
        return PrimaryTrace(Mock(phase="synthetic", errors=[]))

    @staticmethod
    def complete_rows():
        rows = [dict(operation="case_begin", case=str(i)) for i in range(3)]
        for i, phase in enumerate(("root-created", "root-sealed", "slot-created", "intent-sealed", "objects-sealed",
                                   "/var/tmp:known_foreign_chmod", "/s8-native-profile:known_foreign_chmod")):
            rows.append(dict(operation="fork_parent", child_pid=i + 40, phase=phase))
            rows.append(dict(operation="child_exit", caller_pid=i + 40, phase=phase, code=77 if i < 5 else 0))
        rows.extend(dict(operation="case_end", case=str(i)) for i in range(3))
        rows.append(dict(operation="measurement_end", tests=3))
        return rows

    @staticmethod
    def encode(rows):
        return b"".join(json.dumps(r).encode() + b"\n" for r in rows)

    def test_exact_raw_byte_identity_and_single_original_read(self):
        raw = struct.pack("iIII", 7, 0x4, 91, 4) + b"x\0\0\0"
        trace = self.trace(); trace.read = Mock(return_value=raw)
        trace.watches[9] = dict(kind="primitive_journal", wd=7)
        trace.recorder.phase = "/synthetic:own_IMMUTABLE"
        raw = struct.pack("iIII", 7, 0x4, 91, 16) + b"record.json\0\0\0\0\0"
        trace.read.return_value = raw
        with patch.object(trace, "is_inotify", return_value=True):
            self.assertIs(trace.observed_read(9, 65536), raw)
        trace.read.assert_called_once_with(9, 65536)
        fields = trace.recorder.note.call_args.kwargs
        self.assertEqual(bytes.fromhex(fields["raw_hex"]), raw)
        self.assertEqual(fields["events"][0]["cookie"], 91)
        self.assertEqual(fields["actor"], "UNKNOWN")

    def test_eagain_and_other_exception_not_replaced_or_retried(self):
        for error in (BlockingIOError(errno.EAGAIN, "synthetic"), OSError(errno.EIO, "synthetic")):
            trace = self.trace(); trace.read = Mock(side_effect=error)
            with patch.object(trace, "is_inotify", return_value=True):
                with self.assertRaises(type(error)) as caught: trace.observed_read(8, 65536)
            self.assertIs(caught.exception, error)
            trace.read.assert_called_once_with(8, 65536)

    def test_empty_read_retained_not_replaced_by_eagain(self):
        trace = self.trace(); raw = b""; trace.read = Mock(return_value=raw)
        with patch.object(trace, "is_inotify", return_value=True):
            self.assertIs(trace.observed_read(8, 1), raw)
        self.assertEqual(trace.recorder.note.call_args.kwargs["byte_count"], 0)

    def test_malformed_overflow_ignored_unmount_kept_and_invalidate(self):
        for raw in (b"x", struct.pack("iIII", 7, 4, 0, 9),
                    struct.pack("iIII", 7, 4, 0, 4) + b"xxxx",
                    struct.pack("iIII", 7, 4, 0, 3) + b"x\0\0",
                    *(struct.pack("iIII", -1, m, 0, 0) for m in (0x4000, 0x8000, 0x2000))):
            parsed = decode_raw(raw)
            self.assertTrue(parsed["observation_invalid"])
            self.assertTrue(parsed["observation_codes"])
            self.assertEqual(bytes.fromhex(parsed["raw_hex"]), raw)

    def test_wrong_watch_or_phase_object_invalidate_without_changing_bytes(self):
        for wd, name in ((7, b"other.json"), (8, b"record.json")):
            raw = struct.pack("iIII", wd, 4, 0, 16) + (name + b"\0").ljust(16, b"\0")
            trace = self.trace(); trace.read = Mock(return_value=raw)
            trace.watches[9] = dict(kind="primitive_journal", wd=7)
            trace.recorder.phase = "/synthetic:own_IMMUTABLE"
            with patch.object(trace, "is_inotify", return_value=True):
                self.assertIs(trace.observed_read(9, 65536), raw)
            self.assertTrue(trace.recorder.note.call_args.kwargs["observation_invalid"])
            trace.read.assert_called_once()

    def test_original_guard_result_and_same_exception_survive(self):
        target = Mock(events=3, root="/synthetic")
        for error in (None, ValueError("synthetic")):
            trace = self.trace(); original = Mock(return_value=object(), side_effect=error)
            if error is None:
                self.assertIs(trace.checked(original, "journal")(target), original.return_value)
            else:
                with self.assertRaises(ValueError) as caught: trace.checked(original, "journal")(target)
                self.assertIs(caught.exception, error)
            original.assert_called_once_with(target)

    def test_ioctl_fsync_close_and_fd_reuse_preserved(self):
        from tests.s8_diagnostic_once import fence
        trace = self.trace(); trace.ioctl = Mock(return_value=17)
        trace.fsync = Mock(return_value=None); trace.close = Mock(return_value=None)
        trace.watches[5] = dict(root="/synthetic")
        trace.bindings[5] = dict(wds=[1])
        with patch.object(trace, "identity", return_value=dict(fd=5)):
            self.assertEqual(trace.observed_ioctl(5, fence.SET_FLAGS, [16]), 17)
            self.assertIsNone(trace.observed_fsync(5)); self.assertIsNone(trace.observed_close(5))
        trace.ioctl.assert_called_once_with(5, fence.SET_FLAGS, [16])
        trace.fsync.assert_called_once_with(5); trace.close.assert_called_once_with(5)
        self.assertNotIn(5, trace.watches)
        self.assertNotIn(5, trace.bindings)

    def test_exception_fields_do_not_include_message_locals_or_source_lines(self):
        try: raise ValueError("must-not-leak")
        except ValueError as error: fields = exception_fields(error)
        self.assertNotIn("must-not-leak", json.dumps(fields))
        self.assertEqual(fields["code"], "UNKNOWN")
        self.assertTrue(fields["frames"])

    def test_child_error_record_precedes_unchanged_real_99_boundary(self):
        # Local fork/pipe only, no native test or protected object.
        for kind in (RuntimeError, AssertionError, SystemExit, KeyboardInterrupt):
            with self.subTest(kind=kind.__name__), tempfile.TemporaryFile() as stream:
                recorder = Recorder(stream.fileno()); trace = PrimaryTrace(recorder)
                pid = os.fork()
                if pid == 0:
                    with trace.child_boundary(): raise kind("synthetic")
                self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 99)
                stream.seek(0); rows = [json.loads(x) for x in stream.read().splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["operation"], "child_first_unexpected_exception")
                self.assertEqual(rows[0]["exception_type"], kind.__name__)

    def test_normal_fallthrough_remains_98_and_explicit_exit_remains_77(self):
        for code in (None, 77):
            trace = self.trace(); pid = os.fork()
            if pid == 0:
                with trace.child_boundary():
                    if code is not None: os._exit(code)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 98 if code is None else code)

    def test_report_failure_does_not_replace_99(self):
        recorder = Recorder(-1); trace = PrimaryTrace(recorder); pid = os.fork()
        if pid == 0:
            with trace.child_boundary(): raise RuntimeError("synthetic")
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 99)

    def test_log_requires_child_exception_for_99_and_all_child_exits(self):
        rows = self.complete_rows(); rows[4]["code"] = 99
        self.assertFalse(validate_log(self.encode(rows)))
        rows.insert(4, dict(operation="child_first_unexpected_exception", caller_pid=40, phase="root-created"))
        self.assertTrue(validate_log(self.encode(rows)))
        self.assertFalse(validate_log(self.encode(rows[:-1])))
        self.assertFalse(validate_log(self.encode(rows)[:-1]))
        rows.insert(1, dict(operation="read", observation_invalid=True))
        self.assertFalse(validate_log(self.encode(rows)))

    def test_log_rejects_complete_prefix_missing_case_wrong_phase_and_report_errors(self):
        rows = self.complete_rows()
        self.assertTrue(validate_log(self.encode(rows)))
        self.assertFalse(validate_log(self.encode(rows[:-1])))
        self.assertFalse(validate_log(self.encode(rows), ["OSError"]))
        rows[4]["phase"] = "wrong"
        self.assertFalse(validate_log(self.encode(rows)))
        rows = self.complete_rows(); rows.pop(0)
        self.assertFalse(validate_log(self.encode(rows)))

    def test_installed_boundary_alias_records_phase_error_then_unchanged_exit(self):
        import tests.test_s8_anchor as target
        with tempfile.TemporaryFile() as stream:
            recorder = Recorder(stream.fileno()); trace = PrimaryTrace(recorder)
            with ExitStack() as stack:
                trace.install_primary(stack)
                with self.subTest(phase="root-sealed"):
                    pid = os.fork()
                    if pid == 0:
                        with target.child_failure_boundary(): raise RuntimeError("synthetic")
                    self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 99)
            stream.seek(0); rows = [json.loads(x) for x in stream.read().splitlines()]
            failure = next(r for r in rows if r["operation"] == "child_first_unexpected_exception")
            ended = next(r for r in rows if r["operation"] == "child_exit")
            self.assertEqual(failure["phase"], "root-sealed")
            self.assertEqual(ended["code"], 99)
            self.assertLess(rows.index(failure), rows.index(ended))

    def test_short_or_failed_record_marks_observer_failure(self):
        with tempfile.TemporaryFile() as stream:
            recorder = Recorder(stream.fileno()); recorder.write = Mock(return_value=0)
            recorder.note("synthetic")
            self.assertEqual(recorder.errors, ["OSError"])
            recorder.write.assert_called_once()

    def test_chain_incremental_binding_and_original_result_once(self):
        trace = self.trace(); sentinel = object(); original = Mock(return_value=sentinel)
        chain = SimpleNamespace(events=9, nodes=[(7, Path("/synthetic"), 12, (1, 2), None, True)])
        with patch.object(Path, "read_text", return_value="inotify wd:7 ino:2 sdev:1 mask:fce\n"), \
             patch.object(trace, "identity", return_value=dict(dev=1, ino=2)):
            self.assertIs(trace.checked_chain(original)(chain), sentinel)
        original.assert_called_once_with(chain)
        self.assertEqual(trace.bindings[9]["wds"], [7])
        self.assertEqual(trace.bindings[9]["nodes"][0]["path"], "/synthetic")
        self.assertFalse(trace.recorder.note.call_args.kwargs["observation_invalid"])

    def test_chain_sibling_and_selected_names_stay_byte_exact_not_guard_exceptions(self):
        for name in (b"sibling", b"selected", b""):
            raw = struct.pack("iIII", 7, 4, 0, 16) + (name + b"\0").ljust(16, b"\0")
            trace = self.trace(); trace.read = Mock(return_value=raw)
            trace.watches[9] = dict(kind="ancestry")
            trace.bindings[9] = dict(wds=[7], nodes=[dict(wd=7, path="/synthetic", target_raw_hex=b"selected".hex())])
            with patch.object(trace, "is_inotify", return_value=True):
                self.assertIs(trace.observed_read(9, 65536), raw)
            fields = trace.recorder.note.call_args.kwargs
            self.assertFalse(fields["observation_invalid"])
            self.assertEqual(bytes.fromhex(fields["raw_hex"]), raw)
            trace.read.assert_called_once_with(9, 65536)

    def test_chain_missing_or_wrong_metadata_keeps_original_exception(self):
        error = RuntimeError("not copied"); original = Mock(side_effect=error)
        chain = SimpleNamespace(events=9, nodes=[(7, Path("/synthetic"), 12, (1, 2), None, True)])
        for text in ("", "inotify wd:8 ino:2 sdev:1 mask:fce\n"):
            trace = self.trace()
            with patch.object(Path, "read_text", return_value=text), \
                 patch.object(trace, "identity", return_value=dict(dev=1, ino=2)):
                with self.assertRaises(RuntimeError) as caught: trace.checked_chain(original)(chain)
            self.assertIs(caught.exception, error)
            self.assertEqual(trace.bindings[9], {})
            self.assertTrue(trace.recorder.note.call_args.kwargs["observation_invalid"])

    def test_chain_unbound_wd_and_fd_reuse_still_invalidate(self):
        trace = self.trace(); trace.close = Mock()
        trace.watches[9] = dict(kind="ancestry")
        trace.bindings[9] = dict(wds=[7], nodes=[dict(wd=7, path="/synthetic")])
        raw = struct.pack("iIII", 8, 4, 0, 0); trace.read = Mock(return_value=raw)
        with patch.object(trace, "is_inotify", return_value=True): trace.observed_read(9, 65536)
        self.assertTrue(trace.recorder.note.call_args.kwargs["observation_invalid"])
        trace.observed_close(9)
        self.assertNotIn(9, trace.watches); self.assertNotIn(9, trace.bindings)

    def test_chain_wd_alone_never_binds_wrong_inode_or_device(self):
        chain = SimpleNamespace(events=9, nodes=[(7, Path("/synthetic"), 12, (1, 2), None, True)])
        for text, observed in (("inotify wd:7 ino:3 sdev:1 mask:fce\n", dict(dev=1, ino=2)),
                               ("inotify wd:7 ino:2 sdev:2 mask:fce\n", dict(dev=1, ino=2)),
                               ("inotify wd:7 ino:3 sdev:1 mask:fce\n", dict(dev=1, ino=3))):
            trace = self.trace(); original = Mock(return_value=17)
            with patch.object(Path, "read_text", return_value=text), patch.object(trace, "identity", return_value=observed):
                self.assertEqual(trace.checked_chain(original)(chain), 17)
            original.assert_called_once_with(chain)
            self.assertEqual(trace.bindings[9], {})
            self.assertTrue(trace.recorder.note.call_args.kwargs["observation_invalid"])


if __name__ == "__main__": unittest.main()
