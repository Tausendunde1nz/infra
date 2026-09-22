from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-r14-technical-runtime-latency.json"
UNIT = ROOT / "systemd/tu1nz-adult-public-s8-technical-latency-probe.service"
DOC = ROOT / "docs/COMMERCIAL_S11_2_R14_TECHNICAL_RUNTIME_LATENCY.md"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_r14_control.sh"


class CommercialS112R14TechnicalLatencyTests(unittest.TestCase):
    def test_manifest_pins_the_canonical_technical_profile(self) -> None:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["application_release"]["commit"],
            "77f9079956a42ee411e17f5697da96f6810ba966",
        )
        self.assertEqual(payload["application_release"]["post_merge_ci"], 35777850947)
        contract = payload["technical_runtime_contract"]
        self.assertEqual(contract["window_hours"], 24)
        self.assertEqual(contract["minimum_samples"], 5)
        self.assertEqual(contract["evidence_class"], "INTERNAL_TEST")
        self.assertEqual(contract["source"], "DIRECT")
        self.assertEqual(contract["sample_type"], "DIRECT_BOT_RESPONSE")
        self.assertEqual(contract["interaction_path"], "INTERNAL_ACCEPTANCE")
        self.assertEqual(contract["metric"], "handler_duration_ms")
        self.assertTrue(contract["unknown_provenance_fails_closed"])

    def test_manifest_hash_binds_every_runtime_artifact(self) -> None:
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["artifact_bindings"]
        expected = {
            "control_controller_sha256": CONTROLLER,
            "systemd_probe_unit_sha256": UNIT,
            "control_document_sha256": DOC,
        }
        self.assertEqual(set(bindings), {*expected, "application_probe_sha256"})
        self.assertRegex(bindings["application_probe_sha256"], r"^[0-9a-f]{64}$")
        for field, path in expected.items():
            with self.subTest(field=field):
                self.assertEqual(
                    bindings[field],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

    def test_probe_unit_is_manual_bounded_and_has_no_provider_credential(self) -> None:
        source = UNIT.read_text(encoding="utf-8")
        self.assertIn("technical_latency_probe", source)
        self.assertIn("LoadCredential=s8_database_dsn:", source)
        self.assertNotIn("telegram_token", source)
        self.assertNotIn("[Install]", source)
        self.assertNotIn("Restart=", source)
        self.assertIn("ExecCondition=/usr/bin/systemctl is-active --quiet", source)
        self.assertIn("NoNewPrivileges=true", source)
        self.assertIn("ProtectSystem=strict", source)

    def test_contract_forbids_restart_real_evidence_and_s11_activation(self) -> None:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertFalse(payload["probe"]["real_evidence_allowed"])
        self.assertFalse(payload["probe"]["unknown_evidence_allowed"])
        self.assertFalse(payload["probe"]["manual_database_insert"])
        self.assertEqual(payload["probe"]["samples_per_invocation"], 1)
        self.assertEqual(payload["probe"]["telegram_messages"], 0)
        self.assertFalse(payload["runtime_boundaries"]["s8_restart_allowed"])
        self.assertFalse(payload["runtime_boundaries"]["s11_canary_allowed"])
        self.assertTrue(payload["completion"]["s11_remains_disabled"])

    def test_documentation_requires_append_only_serial_provenance_validation(self) -> None:
        source = DOC.read_text(encoding="utf-8")
        self.assertIn("append-only", source)
        self.assertIn("serially", source)
        self.assertIn("never deleted", source)
        self.assertIn("S11 remains", source)

    def test_controller_is_backup_first_serial_and_never_restarts_s8(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        main = source[source.index("main() {"):]
        self.assertLess(main.index("r14_backup"), main.index("r14_install_probe_unit"))
        self.assertLess(main.index("r14_install_probe_unit"), main.index("r14_finalize"))
        self.assertIn("for r14_iteration in 1 2 3 4 5", source)
        self.assertIn("r14_run_one_probe", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("systemctl stop", source)
        self.assertNotIn("DELETE FROM commercial_s10_2d_latency_samples", source)
        self.assertNotIn("UPDATE commercial_s10_2d_latency_samples", source)
        self.assertIn("S11_2_R14_STARTING_SAMPLE_DRIFT", source)
        self.assertIn('after["r14_new_real"] != 0', source)
        self.assertIn('"p0_recovery": "CLOSED"', source)
        self.assertIn('"next_s11_canary_runtime_ready": True', source)


if __name__ == "__main__":
    unittest.main()
