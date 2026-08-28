from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_installation_authorization_gate.py"
SOURCE = ROOT / "manifests" / "adult-publishing-commercial-installation-authorization.m4-22.json"


class CommercialInstallationAuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.contract = json.loads(SOURCE.read_text(encoding="ascii"))
        self.path = Path(self.temporary.name) / "authorization.json"
        self.write_contract()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_contract(self) -> None:
        self.path.write_text(
            json.dumps(self.contract, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )

    def gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(GATE), "--contract", str(self.path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_rejected(self) -> None:
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_accepts_technical_go_with_execution_blocked(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_22_TECHNICAL_GO_EXECUTION_NO_GO_CONFIRMED", result.stdout)

    def test_rejects_installation_execution_claim(self) -> None:
        self.contract["installation_gates"]["commercial_installation_executed"] = True
        self.assert_rejected()

    def test_rejects_activation(self) -> None:
        self.contract["activation_decision"] = "GO"
        self.assert_rejected()

    def test_rejects_network_enablement(self) -> None:
        self.contract["network_enabled"] = True
        self.assert_rejected()

    def test_rejects_unrecorded_server_change(self) -> None:
        self.contract["server_changed"] = True
        self.assert_rejected()

    def test_rejects_invented_operator_approval(self) -> None:
        self.contract["authorization"]["operator_approved"] = True
        self.assert_rejected()

    def test_rejects_invented_selected_profile(self) -> None:
        self.contract["authorization"]["selected_profile"]["retention_days"] = 7
        self.assert_rejected()

    def test_rejects_invented_failed_unit_acceptance(self) -> None:
        self.contract["authorization"]["known_unrelated_failed_unit_accepted"] = True
        self.assert_rejected()

    def test_rejects_false_fresh_backup_claim(self) -> None:
        self.contract["backup_restore"]["fresh_preinstall_archive_created"] = True
        self.assert_rejected()

    def test_rejects_false_backup_script_match(self) -> None:
        self.contract["backup_restore"]["installed_backup_script_matches_versioned"] = True
        self.assert_rejected()

    def test_rejects_path_collision(self) -> None:
        self.contract["host_observation"]["commercial_process_reference_detected"] = True
        self.assert_rejected()

    def test_rejects_nonlocal_postgres(self) -> None:
        self.contract["host_observation"]["postgres_listen_addresses"] = "*"
        self.assert_rejected()

    def test_rejects_stale_control_baseline(self) -> None:
        self.contract["repository_baselines"]["control_main_sha"] = "0" * 40
        self.assert_rejected()

    def test_rejects_missing_m4_21_merge(self) -> None:
        self.contract["host_access_contract"]["m4_21_merged"] = False
        self.assert_rejected()

    def test_rejects_real_payment(self) -> None:
        self.contract["product_boundary"]["real_payment_enabled"] = True
        self.assert_rejected()

    def test_rejects_extra_top_level_key(self) -> None:
        self.contract["unexpected"] = False
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
