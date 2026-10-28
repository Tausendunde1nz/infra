"""Portable bytes/files/pipe tests, NOT Docker or different-UID evidence."""
import ast
import base64
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from tests.s8_evidence_export import MAX_LOG, evidence_diagnostics, final_exit, receive_report, send_report
from tests import test_s8_primary_measurement as baseline_cases
from tests import s8_evidence_export as exporter

PIPE_WRITE = os.write


def complete_report():
    return baseline_cases.PrimaryObservationTests.encode(baseline_cases.PrimaryObservationTests.complete_rows())


class Producer:
    def __init__(self, raw, code="STREAM_COMPLETE", exitcode=0, status=None):
        value = dict(code=code, bytes_sent=len(raw), source_size=len(raw)) if status is None else status
        reader, writer = os.pipe(); error_reader, error_writer = os.pipe()
        self.stdout = os.fdopen(reader, "rb", buffering=0)
        self.stderr = os.fdopen(error_reader, "rb", buffering=0)
        self.returncode = exitcode; self.terminated = False
        def feed():
            try:
                PIPE_WRITE(error_writer, json.dumps(value).encode())
                view = memoryview(raw)
                while view:
                    count = PIPE_WRITE(writer, view); view = view[count:]
            except BrokenPipeError: pass
            finally: os.close(writer); os.close(error_writer)
        self.thread = threading.Thread(target=feed, daemon=True); self.thread.start()
    def wait(self, timeout=None):
        self.thread.join(timeout)
        if self.thread.is_alive(): raise subprocess.TimeoutExpired("synthetic-producer", timeout)
        return self.returncode
    def terminate(self): self.terminated = True
    def kill(self): self.terminated = True


class EvidenceTransportPortableTests(unittest.TestCase):
    def test_complete_report_survives_negative_measurement_exactly(self):
        raw = complete_report()
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(Producer(raw), target, 1)
            self.assertEqual(saved, raw)
            self.assertEqual(Path(target, "observation.jsonl").read_bytes(), raw)
            self.assertEqual(result["measurement_exit"], 1)
            self.assertEqual(result["export_exit"], 0)
            self.assertEqual(result["final_exit"], 1)
            self.assertEqual(result["report_state"], "COMPLETE")
            self.assertEqual(stat.S_IMODE(Path(target, "observation.jsonl").stat().st_mode), 0o600)
            self.assertEqual(Path(target, "observation.jsonl").stat().st_uid, os.geteuid())

    def test_partial_child_exception_bytes_survive_validator_false(self):
        raw = b'{"operation":"child_first_unexpected_exception","code":"UNKNOWN"}\n{"partial"'
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(Producer(raw), target, 99)
            self.assertEqual(saved, raw)
            self.assertEqual(result["export_exit"], 0)
            self.assertEqual(result["report_state"], "PARTIAL")
            self.assertIn("REPORT_JSON_INVALID", result["evidence_codes"])
            self.assertEqual(result["final_exit"], 99)

    def test_missing_report_is_not_success_and_keeps_measurement_status(self):
        producer = Producer(b"", "REPORT_UNAVAILABLE", 74,
                            dict(code="REPORT_UNAVAILABLE", bytes_sent=0, source_size=None))
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(producer, target, 1)
            self.assertEqual(saved, b""); self.assertEqual(result["final_exit"], 1)
            self.assertIn("REPORT_UNAVAILABLE", result["transport_codes"])
            self.assertEqual(result["report_state"], "PARTIAL")

    def test_sender_reads_only_regular_no_follow_single_link_and_limits_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report = root / "report"
            report.write_bytes(b"abcdefgh"); report.chmod(0o600)
            sink = io.BytesIO(); result = send_report(report, sink, 4)
            self.assertEqual(sink.getvalue(), b"abcd")
            self.assertEqual(result["code"], "REPORT_SIZE_LIMIT")
            link = root / "link"; link.symlink_to(report)
            self.assertEqual(send_report(link, io.BytesIO())["code"], "REPORT_OBJECT_INVALID")
            self.assertEqual(send_report(root, io.BytesIO())["code"], "REPORT_OBJECT_INVALID")
            self.assertEqual(send_report(root / "absent", io.BytesIO())["code"], "REPORT_MISSING")

    def test_receiver_size_limit_is_explicit_and_retains_bounded_prefix(self):
        producer = Producer(b"abcdefgh")
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(producer, target, 0, limit=4)
            self.assertEqual(saved, b"abcd"); self.assertTrue(producer.terminated)
            self.assertIn("EXPORT_SIZE_LIMIT", result["transport_codes"])
            self.assertEqual(result["report_state"], "PARTIAL")
            self.assertNotEqual(result["final_exit"], 0)

    def test_export_failure_cannot_overwrite_original_exit_and_does_not_follow_directory_link(self):
        with tempfile.TemporaryDirectory() as parent:
            actual = Path(parent, "actual"); actual.mkdir(mode=0o700)
            link = Path(parent, "link"); link.symlink_to(actual, target_is_directory=True)
            result, saved = receive_report(Producer(complete_report()), link, 124)
            self.assertEqual(saved, b""); self.assertEqual(result["final_exit"], 124)
            self.assertIn("EXPORT_IO_ERROR", result["transport_codes"])
            self.assertEqual(list(actual.iterdir()), [])

    def test_existing_destination_is_preserved_create_only(self):
        with tempfile.TemporaryDirectory() as target:
            path = Path(target, "observation.jsonl"); path.write_bytes(b"keep")
            result, _ = receive_report(Producer(complete_report()), target, 0)
            self.assertEqual(path.read_bytes(), b"keep")
            self.assertNotEqual(result["export_exit"], 0)

    def test_invalid_directory_mode_never_receives_raw_or_status(self):
        with tempfile.TemporaryDirectory() as target:
            Path(target).chmod(0o750)
            result, _ = receive_report(Producer(complete_report()), target, 1)
            self.assertEqual(list(Path(target).iterdir()), [])
            self.assertNotEqual(result["export_exit"], 0)
            self.assertEqual(result["final_exit"], 1)

    def test_status_sync_failure_retains_raw_and_cannot_be_success(self):
        original = os.fsync; calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError("do not export this message")
            return original(fd)
        with tempfile.TemporaryDirectory() as target, patch("os.fsync", side_effect=sync):
            result, saved = receive_report(Producer(complete_report()), target, 99)
            self.assertEqual(saved, complete_report())
            self.assertEqual(Path(target, "observation.jsonl").read_bytes(), saved)
            self.assertIn("EXPORT_STATUS_IO_ERROR", result["transport_codes"])
            self.assertFalse(result["evidence_complete"])
            self.assertEqual(result["final_exit"], 99)
            self.assertNotIn("do not export", json.dumps(result))

    def test_cli_frames_partial_binary_bytes_without_changing_red_exit(self):
        raw = b'{"partial":\xff'
        value = dict(final_exit=99, evidence_complete=False, export_exit=0, report_state="PARTIAL")
        output = io.StringIO()
        with patch.dict(os.environ, GITHUB_ACTIONS="true", GITHUB_RUN_ATTEMPT="1"), \
             patch.object(os.sys, "argv", ["exporter", "--container", "a" * 64, "--export-dir", "/synthetic", "--measurement-exit", "99"]), \
             patch.object(exporter, "docker_export", return_value=(value, raw)), redirect_stdout(output):
            self.assertEqual(exporter.main(), 99)
        lines = output.getvalue().splitlines()
        self.assertIn("S8_PRIMARY_RAW_B64_BEGIN", lines)
        self.assertIn("S8_PRIMARY_RAW_B64_END", lines)
        encoded = "".join(line.removeprefix("S8_PRIMARY_RAW_B64 ") for line in lines if line.startswith("S8_PRIMARY_RAW_B64 "))
        self.assertEqual(base64.b64decode(encoded, validate=True), raw)

    def test_write_error_preserves_already_saved_prefix_and_original_exit(self):
        original = os.write; calls = []
        def write(fd, data):
            if not calls:
                calls.append(True); return original(fd, data[:5])
            raise OSError("private text must not enter status")
        with tempfile.TemporaryDirectory() as target, patch("os.write", side_effect=write):
            result, raw = receive_report(Producer(complete_report()), target, 77)
            self.assertEqual(raw, complete_report()[:5])
            self.assertEqual(result["final_exit"], 77)
            self.assertNotIn("private text", json.dumps(result))

    def test_sender_status_corruption_and_size_mismatch_are_hold(self):
        for value in ({"secret": "do-not-copy"}, dict(code="STREAM_COMPLETE", bytes_sent=2, source_size=3)):
            with tempfile.TemporaryDirectory() as target:
                result, _ = receive_report(Producer(complete_report(), status=value), target, 0)
                self.assertNotEqual(result["final_exit"], 0)
                self.assertNotIn("do-not-copy", json.dumps(result))

    def test_exit_propagation_is_unchanged_for_all_original_nonzero_results(self):
        for measurement in (1, 2, 77, 98, 99, 124, 130, 137, 143, 255):
            for exported, complete in ((0, True), (0, False), (74, False)):
                self.assertEqual(final_exit(measurement, exported, complete), measurement)
        self.assertEqual(final_exit(None, 0, True, 2), 2)
        self.assertNotEqual(final_exit(None, 0, True), 0)
        self.assertNotEqual(final_exit(0, 0, False), 0)
        self.assertEqual(final_exit(0, 0, True), 0)

    def test_real_subprocess_stream_is_retained_with_nonzero_sender(self):
        # Real local pipes/process, no Docker/UID/native-kernel claim.
        command = [os.sys.executable, "-B", "-c", "import sys;sys.stdout.buffer.write(b'prefix');sys.stderr.write('{}');sys.exit(1)"]
        producer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(producer, target, 99)
            self.assertEqual(saved, b"prefix"); self.assertEqual(result["final_exit"], 99)
            self.assertIn("SENDER_NONZERO", result["transport_codes"])

    def test_hung_sender_is_bounded_killed_reaped_and_keeps_prefix(self):
        command = [os.sys.executable, "-I", "-B", "-c",
                   "import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(1,b'partial');time.sleep(30)"]
        producer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as target:
            result, saved = receive_report(producer, target, 99, timeout=0.2)
            self.assertEqual(saved, b"partial")
            self.assertIn("EXPORT_DEADLINE", result["transport_codes"])
            self.assertIn("SENDER_REAP_DEADLINE", result["transport_codes"])
            self.assertIsNotNone(producer.poll())
            self.assertEqual(result["final_exit"], 99)
            self.assertLess(time.monotonic() - started, 6)

    def test_closed_pipes_but_hung_sender_is_not_a_success(self):
        command = [os.sys.executable, "-I", "-B", "-c", "import os,time;os.close(1);os.close(2);time.sleep(30)"]
        producer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        with tempfile.TemporaryDirectory() as target:
            result, _ = receive_report(producer, target, 0, timeout=0.2)
            self.assertIn("SENDER_REAP_DEADLINE", result["transport_codes"])
            self.assertNotEqual(result["final_exit"], 0)
            self.assertIsNotNone(producer.poll())

    def test_finite_diagnostics_and_exact_legacy_acceptance_parity(self):
        # Only the replaced validator is compared, not historical S8 closures.
        source = subprocess.check_output(["git", "show", "c3ca4cb8589226b326dcd4db999b50a11f607b4d:tests/s8_primary_measurement.py"]).decode()
        old = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "validate_log")
        namespace = dict(json=json, MAX_LOG=MAX_LOG)
        exec(compile(ast.Module(body=[old], type_ignores=[]), "legacy-validator", "exec"), namespace)
        legacy = namespace["validate_log"]
        cases = [b"", b"not json", complete_report(), complete_report()[:-1]]
        rows = baseline_cases.PrimaryObservationTests.complete_rows()
        for index in range(len(rows)):
            changed = copy.deepcopy(rows); changed.pop(index)
            cases.append(baseline_cases.PrimaryObservationTests.encode(changed))
        for raw in cases:
            self.assertEqual(evidence_diagnostics(raw)["evidence_complete"], legacy(raw))
        self.assertIn("END_RECORD_COUNT", evidence_diagnostics(baseline_cases.PrimaryObservationTests.encode(rows[:-1]))["codes"])
        bad = copy.deepcopy(rows); bad[4]["code"] = 99
        self.assertIn("CHILD99_EXCEPTION_COUNT", evidence_diagnostics(baseline_cases.PrimaryObservationTests.encode(bad))["codes"])
        self.assertIn("RECORDER_ERROR", evidence_diagnostics(complete_report(), ["secret"])["codes"])

    def test_actual_bash_exit_trap_preserves_measurement_and_export_status_separately(self):
        source = Path("tests/s8_primary_measurement_native.sh").read_text()
        function = source[source.index("finalize() {"):source.index("\ntrap finalize EXIT")]
        for measured, exported, entry, stopped, removed, expected in ((1, 74, 1, 2, 3, 1), (99, 0, 99, 2, 3, 99),
                (0, 74, 0, 2, 3, 74), (0, 0, 0, 2, 0, 2), (0, 0, 0, 0, 3, 3), (0, 0, 0, 0, 0, 0)):
            script = ("set -euo pipefail\nnative=" + "a" * 64 + "\nexport_dir=/synthetic\nmeasurement_started=true\nmeasurement_status=" + str(measured) +
                "\npython3() { return " + str(exported) + "; }\ndocker() { if [[ $1 = stop ]]; then return " + str(stopped) +
                "; else return " + str(removed) + "; fi; }\n" + function + "\ntrap finalize EXIT\nexit " + str(entry))
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected)
            self.assertIn("measurement_exit=" + str(measured), result.stdout)
            self.assertIn("export_aggregate_exit=" + str(exported), result.stdout)

    def test_bash_term_still_runs_read_only_export_before_cleanup(self):
        source = Path("tests/s8_primary_measurement_native.sh").read_text()
        function = source[source.index("finalize() {"):source.index("\ntrap finalize EXIT")]
        script = ("set -euo pipefail\nnative=" + "a" * 64 + "\nexport_dir=/synthetic\nmeasurement_started=true\nmeasurement_status=''\n" +
            "python3() { echo EXPORT_ATTEMPT >&2; return 0; }\ndocker() { echo CLEANUP_ATTEMPT >&2; return 0; }\n" + function +
            "\ntrap finalize EXIT\ntrap 'exit 143' TERM\nkill -TERM $$")
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 143)
        self.assertLess(result.stderr.index("EXPORT_ATTEMPT"), result.stderr.index("CLEANUP_ATTEMPT"))


if __name__ == "__main__": unittest.main()
