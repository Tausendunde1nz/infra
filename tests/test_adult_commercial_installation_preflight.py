from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_installation_preflight_gate.py"
SOURCE = ROOT / "manifests" / "adult-publishing-commercial-installation-preflight.m4-20.json"


class CommercialInstallationPreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.contract = json.loads(SOURCE.read_text(encoding="ascii"))
        self.path = Path(self.temporary.name) / "preflight.json"
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

    def test_accepts_exact_read_only_no_go_evidence(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_20_INSTALLATION_PREFLIGHT_NO_GO_CONFIRMED", result.stdout)

    def test_rejects_installation_go(self) -> None:
        self.contract["installation_decision"] = "GO"
        self.assert_rejected()

    def test_rejects_activation_go(self) -> None:
        self.contract["activation_decision"] = "GO"
        self.assert_rejected()

    def test_rejects_active_runtime(self) -> None:
        self.contract["active"] = True
        self.assert_rejected()

    def test_rejects_server_change_claim(self) -> None:
        self.contract["server_changed"] = True
        self.assert_rejected()

    def test_rejects_missing_acl_blocker(self) -> None:
        self.contract["blockers"].remove("RUNTIME_PARENT_TRAVERSAL_ACL_NOT_VERSIONED")
        self.assert_rejected()

    def test_rejects_unproven_runtime_traversal(self) -> None:
        self.contract["path_and_identity"]["runtime_parent_traversal_ready"] = True
        self.assert_rejected()

    def test_rejects_unproven_postgres_identity_mapping(self) -> None:
        self.contract["postgresql"]["runtime_dsn_authentication_ready"] = True
        self.assert_rejected()

    def test_rejects_path_collision(self) -> None:
        self.contract["interference"]["path_collision_detected"] = True
        self.assert_rejected()

    def test_rejects_missing_remote_backup(self) -> None:
        self.contract["backup_restore"]["exact_archive_remote_present"] = False
        self.assert_rejected()

    def test_rejects_commercial_backup_claim(self) -> None:
        self.contract["backup_restore"]["commercial_release_bound"] = True
        self.assert_rejected()

    def test_rejects_unit_installation_claim(self) -> None:
        self.contract["unit"]["installed"] = True
        self.assert_rejected()

    def test_rejects_real_payment(self) -> None:
        self.contract["product_boundary"]["real_payment_enabled"] = True
        self.assert_rejected()

    def test_rejects_completed_next_gate(self) -> None:
        self.contract["required_next_gates"]["first_start_separately_approved"] = True
        self.assert_rejected()

    def test_rejects_extra_top_level_key(self) -> None:
        self.contract["unexpected"] = False
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
