from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_readiness_gate.py"
SOURCE_CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-readiness.m4-18.json"


def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, check=False, timeout=30)


def git(repository: Path, *arguments: str) -> str:
    result = run(["/usr/bin/git", "-C", str(repository), *arguments])
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class CommercialReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.application = self.root / "application"
        self.application.mkdir()
        git(self.application, "init", "-q")
        git(self.application, "config", "user.email", "m4.18@tu1nz.invalid")
        git(self.application, "config", "user.name", "M4.18 Test")
        git(
            self.application,
            "remote",
            "add",
            "origin",
            "https://github.com/Tausendunde1nz/adult-publishing-core.git",
        )
        self.contract = json.loads(SOURCE_CONTRACT.read_text(encoding="ascii"))
        candidate = {
            "active": False,
            "commercial_composition_enabled": True,
            "commercial_contract_version": "tu1nz-commercial-persistence-m4.15-v1",
            "database_scope": "LOCAL_ONLY",
            "environment": "STAGING-S0-COMMERCIAL-CANDIDATE",
            "external_providers_enabled": False,
            "installed": False,
            "network_enabled": False,
            "persistence_schema_version": "0014_m4_15_durable_commercial_persistence",
            "real_media_enabled": False,
            "repository_entrypoint_available": True,
            "runtime_version": "tu1nz-commercial-runtime-candidate-m4.17-v1",
            "server_enabled": False,
            "synthetic_data_only": True,
            "synthetic_publishers_only": True,
        }
        artifacts = self.contract["artifact_sha256"]
        for name in artifacts:
            path = self.application / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name == "config/commercial-runtime-candidate.disabled.json":
                path.write_text(json.dumps(candidate, sort_keys=True), encoding="ascii")
            else:
                path.write_text("m4.18 fixture: " + name + "\n", encoding="ascii")
            artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.application / "pyproject.toml").write_text(
            '[project.scripts]\n'
            'tu1nz-commercial-runtime-candidate = "tu1nz_sandbox.commercial_candidate:runtime_entrypoint"\n'
            'tu1nz-commercial-candidate-health = "tu1nz_sandbox.commercial_candidate:health_entrypoint"\n',
            encoding="ascii",
        )
        git(self.application, "add", ".")
        git(self.application, "commit", "-qm", "fixture")
        self.contract["application_sha"] = git(self.application, "rev-parse", "HEAD")
        self.contract_path = self.root / "contract.json"
        self.write_contract()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_contract(self) -> None:
        self.contract_path.write_text(
            json.dumps(self.contract, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )

    def gate(self) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(GATE),
                "--contract",
                str(self.contract_path),
                "--application-repository",
                str(self.application),
            ]
        )

    def test_positive_inactive_exact_candidate_contract(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_18_COMMERCIAL_READINESS_OK", result.stdout)

    def test_rejects_activation(self) -> None:
        self.contract["active"] = True
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_external_provider(self) -> None:
        self.contract["external_providers_enabled"] = True
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_real_payment(self) -> None:
        self.contract["real_payment_enabled"] = True
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_x_as_paid_target(self) -> None:
        self.contract["paid_targets"].append("X")
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_missing_activation_blocker(self) -> None:
        self.contract["required_activation_gates"] = {
            key: True for key in self.contract["required_activation_gates"]
        }
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_server_path_collision(self) -> None:
        self.contract["server_observation"]["path_collision_detected"] = True
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_backup_claim_for_unbound_candidate(self) -> None:
        self.contract["server_observation"]["exact_candidate_sha_in_backup"] = True
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_artifact_drift(self) -> None:
        path = self.application / "src/tu1nz_sandbox/commercial_candidate.py"
        path.write_text("drift\n", encoding="ascii")
        git(self.application, "add", str(path))
        git(self.application, "commit", "-qm", "drift")
        self.contract["application_sha"] = git(self.application, "rev-parse", "HEAD")
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_dirty_application(self) -> None:
        (self.application / "dirty.txt").write_text("dirty\n", encoding="ascii")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_wrong_origin(self) -> None:
        git(self.application, "remote", "set-url", "origin", "https://example.invalid/repo.git")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_rejects_extra_contract_key(self) -> None:
        self.contract["unexpected"] = False
        self.write_contract()
        self.assertNotEqual(self.gate().returncode, 0)


if __name__ == "__main__":
    unittest.main()
