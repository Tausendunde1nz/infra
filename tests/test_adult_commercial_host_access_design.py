from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_host_access_gate.py"
SOURCE = ROOT / "manifests" / "adult-publishing-commercial-host-access.m4-21.json"
ARTIFACTS = (
    "config/postgresql/adult-publishing-commercial-s0.pg_hba.rule",
    "config/postgresql/adult-publishing-commercial-s0.pg_ident.map",
    "scripts/tu1nz_adult_commercial_path_access.sh",
)
HBA_RULE = (
    "local tu1nz_adult_commercial_s0 "
    "tu1nz_adult_commercial_s0_runtime peer map=tu1nz_adult_commercial_s0"
)
IDENT_MAP = (
    "tu1nz_adult_commercial_s0 tu1nz-adult-commercial-s0 "
    "tu1nz_adult_commercial_s0_runtime"
)


class CommercialHostAccessDesignTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.control.mkdir()
        self.contract = json.loads(SOURCE.read_text(encoding="ascii"))
        for name in ARTIFACTS:
            source = ROOT / name
            target = self.control / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if name.endswith(".sh") else 0o644)
            self.contract["artifact_sha256"][name] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
        self.contract_path = self.root / "contract.json"
        self.hba = self.root / "pg_hba.conf"
        self.ident = self.root / "pg_ident.conf"
        self.hba.write_text(
            "local all postgres peer\n"
            + HBA_RULE
            + "\nlocal all all peer\n"
            + "host all all 127.0.0.1/32 scram-sha-256\n",
            encoding="ascii",
        )
        self.ident.write_text(IDENT_MAP + "\n", encoding="ascii")
        self.write_contract()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_contract(self) -> None:
        self.contract_path.write_text(
            json.dumps(self.contract, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )

    def gate(self, phase: str = "design", include_configs: bool = False) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(GATE),
            "--contract",
            str(self.contract_path),
            "--control-repository",
            str(self.control),
            "--phase",
            phase,
        ]
        if include_configs:
            arguments.extend(["--pg-hba", str(self.hba), "--pg-ident", str(self.ident)])
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_design_rejected(self) -> None:
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_positive_design_contract(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_21_HOST_ACCESS_DESIGN_OK", result.stdout)

    def test_positive_installed_postgres_fixture(self) -> None:
        result = self.gate(phase="installed", include_configs=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_21_POSTGRES_PEER_AUTH_OK", result.stdout)

    def test_rejects_activation(self) -> None:
        self.contract["active"] = True
        self.assert_design_rejected()

    def test_rejects_installation_go(self) -> None:
        self.contract["installation_decision"] = "GO"
        self.assert_design_rejected()

    def test_rejects_server_change(self) -> None:
        self.contract["server_changed"] = True
        self.assert_design_rejected()

    def test_rejects_wrong_control_parent(self) -> None:
        self.contract["control_parent_sha"] = "0" * 40
        self.assert_design_rejected()

    def test_rejects_chatops_membership(self) -> None:
        self.contract["path_access"]["forbidden_supplementary_group"] = "wheel"
        self.assert_design_rejected()

    def test_rejects_recursive_acl(self) -> None:
        self.contract["path_access"]["recursive"] = True
        self.assert_design_rejected()

    def test_rejects_acl_mask_drift(self) -> None:
        self.contract["path_access"]["paths"][1]["acl_mask"] = "rwx"
        self.assert_design_rejected()

    def test_rejects_extra_acl_path(self) -> None:
        self.contract["path_access"]["paths"].append(
            {
                "acl_mask": "r-x",
                "expected_metadata": "755:root:root",
                "path": "/tmp",
            }
        )
        self.assert_design_rejected()

    def test_rejects_migrator_mapping(self) -> None:
        self.contract["postgres_peer"]["migrator_mapping_present"] = True
        self.assert_design_rejected()

    def test_rejects_password_authentication(self) -> None:
        self.contract["postgres_peer"]["authentication_method"] = "scram-sha-256"
        self.assert_design_rejected()

    def test_rejects_hba_rule_after_generic_anchor(self) -> None:
        self.hba.write_text(
            "local all postgres peer\nlocal all all peer\n" + HBA_RULE + "\n",
            encoding="ascii",
        )
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_duplicate_hba_rule(self) -> None:
        self.hba.write_text(
            HBA_RULE + "\n" + HBA_RULE + "\nlocal all all peer\n",
            encoding="ascii",
        )
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_nonadjacent_hba_rule(self) -> None:
        self.hba.write_text(
            HBA_RULE
            + "\nlocal other other peer\nlocal all all peer\n",
            encoding="ascii",
        )
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_trust_authentication(self) -> None:
        self.hba.write_text(
            HBA_RULE + "\nlocal all all peer\nlocal other other trust\n",
            encoding="ascii",
        )
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_missing_ident_mapping(self) -> None:
        self.ident.write_text("# empty\n", encoding="ascii")
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_extra_runtime_ident_mapping(self) -> None:
        self.ident.write_text(
            IDENT_MAP
            + "\nother-map other-user tu1nz_adult_commercial_s0_runtime\n",
            encoding="ascii",
        )
        self.assertNotEqual(self.gate(phase="installed", include_configs=True).returncode, 0)

    def test_rejects_artifact_drift(self) -> None:
        path = self.control / "config/postgresql/adult-publishing-commercial-s0.pg_ident.map"
        path.write_text("drift\n", encoding="ascii")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_completed_installation_gate(self) -> None:
        self.contract["required_installation_gates"]["acl_apply_and_verify_complete"] = True
        self.assert_design_rejected()

    def test_rejects_real_payment(self) -> None:
        self.contract["product_boundary"]["real_payment_enabled"] = True
        self.assert_design_rejected()

    def test_rejects_installed_phase_without_configs(self) -> None:
        self.assertNotEqual(self.gate(phase="installed").returncode, 0)

    def test_rejects_design_phase_with_installed_configs(self) -> None:
        self.assertNotEqual(self.gate(include_configs=True).returncode, 0)

    def test_path_tool_is_exact_nonrecursive_and_has_rollback(self) -> None:
        source = (self.control / "scripts/tu1nz_adult_commercial_path_access.sh").read_text(
            encoding="ascii"
        )
        self.assertEqual(source.count("/opt/tu1nz_repos\n"), 1)
        self.assertEqual(source.count("/etc/tu1nz\n"), 1)
        self.assertNotIn("setfacl -R", source)
        self.assertNotIn("setfacl --recursive", source)
        self.assertIn("setfacl --no-mask -m", source)
        self.assertIn("setfacl --no-mask -x", source)
        self.assertIn('MODE" == rollback', source)
        self.assertNotIn("systemctl", source)
        self.assertNotIn("docker", source)


if __name__ == "__main__":
    unittest.main()
