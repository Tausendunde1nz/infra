"""Prepared genuine Docker/UID transport acceptance. Never a portable PASS."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.s8_evidence_export import MAX_LOG, docker_export
from tests.test_s8_evidence_export import complete_report

IMAGE = os.environ.get("S8_EVIDENCE_NATIVE_IMAGE", "")


@unittest.skipUnless(sys.platform == "linux" and IMAGE, "native Linux Docker transport not locally available")
class NativeEvidenceTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        assert os.geteuid() != 0 and shutil.which("docker")
        assert IMAGE == "tu1nz-s8-primary:" + os.environ["GITHUB_RUN_ID"] + "-1"
        cls.scratch = tempfile.mkdtemp(prefix="s8-native-transport-", dir=os.environ["RUNNER_TEMP"])
        cls.container = subprocess.check_output(["docker", "create", "--network", "none", "--user", "0:0",
            "--env", "container=docker", "--mount", "type=bind,src=" + os.getcwd() + ",dst=/source,readonly",
            "--mount", "type=bind,src=" + cls.scratch + ",dst=/s8-native-profile", "--workdir", "/source",
            "--entrypoint", "/usr/bin/python3", IMAGE, "-I", "-B", "-c", "import time;time.sleep(300)"]).decode().strip()
        assert re.fullmatch("[0-9a-f]{64}", cls.container)
        cls.addClassCleanup(cls.cleanup)
        subprocess.run(["docker", "start", cls.container], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", cls.container, "chown", "0:0", "/s8-native-profile"], check=True)

    @classmethod
    def cleanup(cls):
        try:
            subprocess.run(["docker", "stop", "--time", "20", cls.container], check=True, stdout=subprocess.DEVNULL)
        finally:
            subprocess.run(["docker", "rm", cls.container], check=True, stdout=subprocess.DEVNULL)
        # Preserve exact scratch/export directories until this disposable VM ends.

    def setUp(self):
        subprocess.run(["docker", "exec", self.container, "python3", "-I", "-B", "-c",
            "from pathlib import Path;Path('/s8-native-profile/s8-primary-observation.jsonl').unlink(missing_ok=True)"], check=True)
        self.export = tempfile.mkdtemp(prefix="s8-native-export-", dir=os.environ["RUNNER_TEMP"])

    def write(self, raw):
        subprocess.run(["docker", "exec", "-i", self.container, "python3", "-I", "-B", "-c",
            "import os,sys;f=os.open('/s8-native-profile/s8-primary-observation.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);s=os.fdopen(f,'wb');s.write(sys.stdin.buffer.read());s.close()"], input=raw, check=True)

    def test_root0700_different_uid_stream_succeeds_without_opening_measurement_rights(self):
        self.write(complete_report())
        root = Path(self.scratch).stat(); self.assertEqual(root.st_uid, 0)
        self.assertEqual(stat.S_IMODE(root.st_mode), 0o700)
        with self.assertRaises(PermissionError): Path(self.scratch, "s8-primary-observation.jsonl").read_bytes()
        result, saved = docker_export(self.container, self.export, 1, fixture=True)
        self.assertEqual(saved, complete_report()); self.assertEqual(result["export_exit"], 0)
        self.assertEqual(result["final_exit"], 1)
        self.assertEqual(Path(self.export, "observation.jsonl").stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(Path(self.scratch).stat().st_mode), 0o700)

    def test_old_direct_copy_is_denied_but_separate_export_is_not(self):
        self.write(complete_report())
        old = subprocess.run(["docker", "cp", self.container + ":/s8-native-profile/s8-primary-observation.jsonl",
                              self.scratch + "/old-destination.jsonl"], capture_output=True)
        self.assertNotEqual(old.returncode, 0)
        result, saved = docker_export(self.container, self.export, 0, fixture=True)
        self.assertEqual(saved, complete_report()); self.assertEqual(result["final_exit"], 0)

    def test_missing_report_is_partial_and_does_not_mask_measurement(self):
        result, saved = docker_export(self.container, self.export, 99, fixture=True)
        self.assertEqual(saved, b""); self.assertEqual(result["final_exit"], 99)
        self.assertEqual(result["report_state"], "PARTIAL")

    def test_partial_report_retains_first_exception_and_raw_prefix(self):
        raw = b'{"operation":"child_first_unexpected_exception","code":"UNKNOWN"}\n{"partial"'
        self.write(raw)
        result, saved = docker_export(self.container, self.export, 1, fixture=True)
        self.assertEqual(saved, raw); self.assertEqual(result["export_exit"], 0)
        self.assertFalse(result["evidence_complete"]); self.assertEqual(result["final_exit"], 1)

    def test_export_permission_failure_stays_separate(self):
        self.write(complete_report()); Path(self.export).chmod(0o500)
        result, _ = docker_export(self.container, self.export, 77, fixture=True)
        self.assertNotEqual(result["export_exit"], 0); self.assertEqual(result["final_exit"], 77)

    def test_size_limit_retains_only_explicit_partial_prefix(self):
        self.write(b"x" * (MAX_LOG + 1))
        result, saved = docker_export(self.container, self.export, 0, fixture=True)
        self.assertEqual(len(saved), MAX_LOG); self.assertEqual(result["report_state"], "PARTIAL")
        self.assertIn("REPORT_SIZE_LIMIT", result["transport_codes"])
        self.assertNotEqual(result["final_exit"], 0)

    def test_docker_channel_failure_does_not_become_success(self):
        result, _ = docker_export("0" * 64, self.export, 124, fixture=True)
        self.assertNotEqual(result["export_exit"], 0); self.assertEqual(result["final_exit"], 124)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeEvidenceTransportTests))
    # Required future native proof: an omitted/skipped test is never success.
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 7 and not result.skipped else 1)
