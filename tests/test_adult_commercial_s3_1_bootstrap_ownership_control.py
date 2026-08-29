from __future__ import annotations

import importlib.util
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts/tu1nz_adult_commercial_s3_1_control_gate.py"
SPEC = importlib.util.spec_from_file_location("s3_1_control_gate", GATE_PATH)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s3-1-bootstrap-ownership.json"


class CommercialS31BootstrapOwnershipControlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_gate_accepts_exact_fail_closed_ssot(self) -> None:
        result = GATE.validate(ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["expected_reference_rows"], 12)
        self.assertFalse(result["service_start_authorized"])

    def test_bootstrap_authorization_binds_release_database_and_closed_boundary(self) -> None:
        path = ROOT / self.payload["artifacts"]["bootstrap_authorization"]["path"]
        authorization = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(authorization["application_sha"], GATE.APPLICATION_SHA)
        self.assertEqual(authorization["application_tree"], GATE.APPLICATION_TREE)
        self.assertEqual(authorization["bootstrap_reference_sha256"], GATE.REFERENCE_CANONICAL_SHA256)
        self.assertEqual(authorization["migration_chain_sha256"], GATE.MIGRATION_SHA256)
        self.assertEqual(authorization["database_name"], "tu1nz_adult_commercial_s3")
        self.assertEqual(authorization["database_role"], "tu1nz_adult_commercial_s3_runtime")
        self.assertTrue(authorization["single_bootstrap_authorized"])
        self.assertFalse(authorization["boundaries"]["service_start_authorized"])
        self.assertFalse(authorization["boundaries"]["production_enabled"])
        self.assertFalse(authorization["boundaries"]["external_publish_enabled"])

    def test_exact_reference_rows_are_separate_from_business_rows(self) -> None:
        bootstrap = self.payload["bootstrap"]
        counts = bootstrap["expected_reference_rows"]
        self.assertEqual(sum(value for key, value in counts.items() if key != "total"), 12)
        self.assertEqual(counts["total"], 12)
        self.assertEqual(bootstrap["business_rows_after"], 0)
        self.assertEqual(bootstrap["external_targets_after"], 0)
        self.assertEqual(
            [item["name"] for item in bootstrap["destinations"]],
            ["REDDIT_TEST", "TELEGRAM_TEST", "X_TEST"],
        )

    def test_cursor_recovery_preserves_evidence_without_takeover(self) -> None:
        state = self.payload["state_recovery"]
        self.assertTrue(state["legacy_cursor_preserved_in_recovery_delta"])
        self.assertFalse(state["legacy_cursor_takeover"])
        self.assertTrue(state["cursor_created_by_runtime_user"])
        self.assertEqual(state["runtime_user"], "chatops")
        self.assertEqual(state["runtime_group"], "chatops")
        self.assertEqual(state["expected_directory_mode"], "0700")
        self.assertEqual(state["expected_file_mode"], "0600")

    def test_prestart_dependency_contract_matches_application(self) -> None:
        self.assertEqual(
            set(self.payload["prestart"]["required_dependencies"]),
            {
                "allowlist",
                "application_release",
                "bootstrap_manifest",
                "bootstrap_reference_data",
                "business_rows_zero",
                "cursor_ownership",
                "database_read_write",
                "database_schema",
                "harmless_media_manifest",
                "policy",
                "runtime_state",
                "synthetic_creator",
                "synthetic_destinations",
            },
        )
        self.assertFalse(self.payload["prestart"]["external_network"])
        self.assertFalse(self.payload["prestart"]["service_started"])

    def test_controller_has_no_service_activation_or_secret(self) -> None:
        path = ROOT / self.payload["artifacts"]["server_fix_controller"]["path"]
        source = path.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"systemctl\s+(start|restart|enable)\b", source))
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("chown", source)
        self.assertIsNone(re.search(r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}", source))
        self.assertIn("systemctl daemon-reload", source)
        self.assertIn("BOOTSTRAP_ALREADY_RECORDED", source)
        self.assertIn("S3_1_EVIDENCE_FINALIZED", source)
        self.assertIn("FINAL-SHA256SUMS", source)
        self.assertIn("tar -C / --compare", source)

    def test_historical_failure_evidence_is_immutable_input(self) -> None:
        evidence = self.payload["historical_evidence"]
        self.assertTrue(evidence["failure_evidence_immutable"])
        self.assertEqual(
            evidence["final_evidence_index_sha256"],
            "6d5606ebc293fef86f79a592930808a4ec324da6a615c631e9f5e72e233c2e27",
        )
        self.assertEqual(
            evidence["recovery_archive_sha256"],
            "04421c79b292472b0f5a792cfd716d32044d31236693237cce0a498566b78888",
        )


if __name__ == "__main__":
    unittest.main()
