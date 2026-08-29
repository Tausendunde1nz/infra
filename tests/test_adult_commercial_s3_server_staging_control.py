from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts/tu1nz_adult_commercial_s3_control_gate.py"
SPEC = importlib.util.spec_from_file_location("s3_control_gate", GATE_PATH)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s3-server-staging.json"


class CommercialS3ServerStagingControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_gate_accepts_exact_ssot(self) -> None:
        result = GATE.validate(ROOT)
        self.assertTrue(result["ok"])
        self.assertFalse(result["production_enabled"])
        self.assertFalse(result["service_enabled"])

    def test_application_and_database_are_exactly_bound(self) -> None:
        self.assertEqual(self.payload["application"]["sha"], GATE.EXPECTED_APPLICATION_SHA)
        self.assertEqual(self.payload["application"]["tree"], GATE.EXPECTED_APPLICATION_TREE)
        self.assertEqual(
            self.payload["database"]["migration_chain_sha256"],
            GATE.EXPECTED_MIGRATION_DIGEST,
        )
        self.assertEqual(self.payload["database"]["business_rows_before_acceptance"], 0)
        self.assertTrue(self.payload["database"]["isolated"])

    def test_authorization_is_single_bounded_and_requires_stop(self) -> None:
        authorization = self.payload["authorization"]
        self.assertTrue(authorization["single_bounded_start_authorized"])
        self.assertTrue(authorization["single_product_acceptance_authorized"])
        self.assertTrue(authorization["stop_required"])
        self.assertEqual(authorization["maximum_window_seconds"], 1800)
        self.assertFalse(authorization["enable_authorized"])
        self.assertFalse(authorization["restart_authorized"])

    def test_product_boundary_remains_non_production(self) -> None:
        boundary = self.payload["product_boundary"]
        self.assertEqual(boundary["avs_provider"], "MOCK")
        self.assertEqual(boundary["payment_provider"], "MOCK")
        self.assertFalse(boundary["external_publish_enabled"])
        self.assertFalse(boundary["adult_media_enabled"])
        self.assertFalse(boundary["production_enabled"])
        self.assertEqual(set(boundary["publishers"].values()), {"SYNTHETIC"})

    def test_token_value_is_absent_and_unit_is_static(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                MANIFEST,
                ROOT / "systemd/tu1nz-adult-commercial-s3.service",
                GATE_PATH,
            )
        )
        self.assertNotRegex(source, r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}")
        unit = (ROOT / "systemd/tu1nz-adult-commercial-s3.service").read_text(encoding="ascii")
        sections = [line for line in unit.splitlines() if line.startswith("[")]
        self.assertNotIn("[Install]", sections)
        self.assertIn("Restart=no", unit.splitlines())
        self.assertNotIn("WantedBy=", unit)

    def test_existing_s0_is_protected(self) -> None:
        protected = self.payload["protected_existing_state"]
        self.assertEqual(protected["commercial_s0_unit"], "tu1nz-adult-commercial-s0.service")
        self.assertTrue(protected["commercial_s0_unit_unchanged"])
        self.assertTrue(protected["commercial_s0_evidence_unchanged"])
        self.assertTrue(protected["existing_databases_unchanged"])


if __name__ == "__main__":
    unittest.main()
