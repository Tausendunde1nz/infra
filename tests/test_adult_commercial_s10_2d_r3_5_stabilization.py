import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tu1nz_adult_public_s10_2d_release_simulator.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-community-instant.json"


class CommercialS102DR35StabilizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        application = ROOT.parent / "application"
        cls.application = application
        cls.python = application / ".venv/bin/python"
        if not cls.python.exists():
            cls.python = Path(sys.executable)

    def test_full_release_simulator_runs_all_eight_paths(self):
        if not self.application.exists():
            self.skipTest("paired application source checkout is unavailable")
        completed = subprocess.run(
            [
                str(self.python),
                str(SCRIPT),
                "--application-root",
                str(self.application),
                "--control-root",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["scenarios"]), 8)
        self.assertTrue(all(item["ok"] for item in report["scenarios"]))
        self.assertEqual(report["bot"]["interactions"], 100)
        self.assertLess(report["bot"]["p95_ms"], 2000)
        self.assertTrue(report["target_pid1_community"])
        self.assertFalse(report["source_pid1_community"])
        self.assertFalse(report["acquisition_active"])

    def test_controller_uses_scalar_cte_and_scoped_evidence_reconciliation(self):
        source = (ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh").read_text()
        self.assertIn("WITH updated AS (UPDATE commercial_s10_2d_runtime_control", source)
        self.assertNotIn('database_scalar "UPDATE commercial_s10_2d_runtime_control', source)
        self.assertIn("reconcile_failed_cutover_evidence", source)
        self.assertIn("R3_ROLLBACK_EVIDENCE_OWNERSHIP_RED", source)
        self.assertIn("commercial_s10_2d_latency_append_only", source)
        self.assertIn("MIGRATION_0030_RED", source)

    def test_target_and_source_pid1_contracts_are_distinct(self):
        target = (ROOT / "systemd/tu1nz-adult-public-s8-telegram.service").read_text()
        source = (ROOT / "systemd/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf").read_text()
        self.assertIn("--runtime-release-id s10-2d-r3-5", target)
        self.assertIn("--community-contract", target)
        self.assertNotIn("--runtime-release-id", source)
        self.assertNotIn("--community-contract", source)

    def test_release_contract_binds_final_application_and_source_boundaries(self):
        manifest = json.loads(MANIFEST.read_text())
        release = manifest["source_stabilization_r3_5"]
        self.assertEqual(release["application_commit"], "d4ec676b3422d1dce111fe9ec1b855910580fcf0")
        self.assertEqual(release["application_tree"], "2dfa39732aca27e6ff12afd85c199576d427faa0")
        self.assertEqual(release["application_post_merge_ci"], 34030838080)
        self.assertEqual(release["application_tests_green"], 1005)
        self.assertEqual(release["control_tests_green"], 425)
        self.assertEqual(release["release_simulator"]["scenarios_green"], 8)
        self.assertTrue(release["exactly_one_active_poller_per_bot"])
        self.assertTrue(release["active_acquisition_hard_blocked"])
        self.assertTrue(release["s10_2d_next_runtime_cutover_ready"])
        self.assertFalse(release["server_mutation"])
        self.assertFalse(release["runtime_cutover"])


if __name__ == "__main__":
    unittest.main()
