from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_community_compatibility as compatibility


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
APPLICATION = Path("/private/tmp/tu1nz-r15-6.sbD4cQ/application")
APPLICATION_CONTRACT = APPLICATION / "src/tu1nz_public_s8/community_health.py"
FIXTURE = ROOT / "tests/fixtures/s11_2_r15_12_application_event_path_red.json"


class R1512CompatibilityTests(unittest.TestCase):
    def test_manifest_binds_joint_writer_reader_and_source_only_gate(self):
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["r15_12_artifact_bindings"]
        control_artifacts = {
            "control_community_reader_sha256": ROOT / "scripts/tu1nz_adult_public_community_health_contract.py",
            "compatibility_gate_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_community_compatibility.py",
            "r15_13_simulator_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_r15_13_simulator.py",
            "focused_envelope_suite_sha256": ROOT / "tests/test_adult_commercial_s11_2_r15_12_community_envelope.py",
            "focused_compatibility_suite_sha256": Path(__file__),
            "controller_sha256": CONTROLLER,
            "ssot_sha256": ROOT / "docs/COMMERCIAL_S11_2_R15_12_COMMUNITY_HEALTH_ENVELOPE.md",
        }
        for key, path in control_artifacts.items():
            with self.subTest(binding=key):
                self.assertEqual(bindings[key], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(
            bindings["application_community_health_contract_sha256"],
            "c4c3605233ed33c1c7e3d2004f412fc28cf476081999914e48a221a00d9a65dc",
        )
        self.assertEqual(
            bindings["application_integration_fixture_sha256"],
            "0900d979c8029bc8b998476fe326e01b84ee149167296ac482d14daca7486728",
        )

    def test_canonical_application_writer_matches_control_reader(self):
        if not APPLICATION_CONTRACT.is_file():
            self.skipTest("joint source checkout is not present")
        report = compatibility.verify(APPLICATION_CONTRACT, FIXTURE)
        self.assertTrue(report["ok"])
        self.assertEqual(report["control_reader_version"], "CONTROL_COMMUNITY_READER_V2")

    def test_application_writer_output_flows_through_real_control_reader(self):
        if not APPLICATION_CONTRACT.is_file():
            self.skipTest("joint source checkout is not present")
        specification = importlib.util.spec_from_file_location(
            "r1512_application_community_health", APPLICATION_CONTRACT
        )
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        community = {
            "provider": {"ok": True, "safe_code": "S10_2D_COMMUNITY_GREEN"},
            "bot_event_path": {"ok": False, "safe_code": "BOT_EVENT_PATH_WAITING"},
            "pending_moderation": 0,
            "stuck_restrictions": 0,
        }
        payload = {
            "health_schema_version": module.APPLICATION_HEALTH_SCHEMA_VERSION,
            "community_failure": module.community_failure_from_health(community),
            "community": community,
            "ok": False,
            "safe_code": "S8_DIAGNOSTIC_RED",
            "state": "RED",
        }
        failure = compatibility.reader.failure_from_payload(payload, 2)
        self.assertEqual(failure.child_code, "BOT_EVENT_PATH_WAITING")
        self.assertEqual(failure.component, "POLLING")

    def test_controller_runs_schema_gate_before_dependent_health_or_mutation(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        fetch = source[source.index("fetch_and_require_target() {"):source.index("install_from_git() {")]
        self.assertLess(
            fetch.index("require_target_community_health_compatibility"),
            fetch.index("require_target_wms_compatibility"),
        )
        self.assertIn("S11_2_COMMUNITY_HEALTH_COMPATIBILITY_RED", fetch)
        self.assertIn("APPLICATION_COMMUNITY_HEALTH_CONTRACT_SHA", fetch)
        self.assertIn("APPLICATION_COMMUNITY_HEALTH_FIXTURE_SHA", fetch)

    def test_schema_drift_fails_closed(self):
        if not APPLICATION_CONTRACT.is_file():
            self.skipTest("joint source checkout is not present")
        with tempfile.TemporaryDirectory() as directory:
            drifted = Path(directory) / "community_health.py"
            shutil.copyfile(APPLICATION_CONTRACT, drifted)
            source = drifted.read_text(encoding="utf-8").replace(
                'APPLICATION_HEALTH_SCHEMA_VERSION = "S8_HEALTH_V2"',
                'APPLICATION_HEALTH_SCHEMA_VERSION = "S8_HEALTH_V3"',
            )
            drifted.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "S11_2_COMMUNITY_HEALTH_SCHEMA_MISMATCH"):
                compatibility.verify(drifted, FIXTURE)


if __name__ == "__main__":
    unittest.main()
