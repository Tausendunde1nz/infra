from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s5-s6-offline-staging.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_commercial_s5_s6_offline_stage.sh"


class CommercialS5S6OfflineStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_release_is_exactly_bound(self) -> None:
        app = self.value["application"]
        self.assertEqual(app["merge_commit"], "99a179990ae67aeab420eccef984915ae2aebfbd")
        self.assertEqual(app["tree"], "ecd67fa84fbd1248dd2b7b29a6cafba7bdc0d527")
        self.assertEqual(app["schema"], "0020_commercial_s6_payment_readiness")
        self.assertEqual(
            app["migration_chain_sha256"],
            "84fe9df14d3e37b45fde96bf541f8cdcc7cb8947a0ed3765699abdf4bdb2cf5b",
        )
        self.assertEqual(self.value["decision"], "GO_FOR_OFFLINE_STAGING_ONLY")

    def test_provider_and_product_boundaries_are_closed(self) -> None:
        for enabled in self.value["product_boundary"].values():
            self.assertFalse(enabled)
        authorization = self.value["authorization"]
        self.assertTrue(authorization["application_fast_forward_authorized"])
        self.assertTrue(authorization["database_migration_0020_authorized"])
        self.assertFalse(authorization["provider_call_authorized"])
        self.assertFalse(authorization["service_start_authorized"])
        self.assertFalse(authorization["systemd_change_authorized"])
        self.assertEqual(
            self.value["providers"]["yoti"]["live_sandbox"],
            "WAITING_EXTERNAL_ORGANISATION_VERIFICATION",
        )
        self.assertEqual(
            self.value["providers"]["segpay"]["demo_or_sandbox"],
            "WAITING_HUMAN_PROVIDER_GATE",
        )

    def test_health_contract_matches_offline_staging(self) -> None:
        self.assertEqual(
            self.value["health"],
            {
                "AVS_ADAPTER": "GREEN",
                "AVS_AUTH": "DISABLED_EXPECTED",
                "AVS_CONFIG": "GREEN",
                "AVS_NETWORK": "DISABLED_EXPECTED",
                "PAYMENT_CONFIG": "DISABLED_EXPECTED",
                "PAYMENT_NETWORK": "DISABLED_EXPECTED",
            },
        )

    def test_completed_execution_evidence_is_exact_and_provider_free(self) -> None:
        execution = self.value["execution"]
        self.assertEqual(execution["status"], "GREEN_OFFLINE_STAGING_COMPLETE")
        self.assertEqual(execution["application_sha"], self.value["application"]["merge_commit"])
        self.assertEqual(execution["application_tree"], self.value["application"]["tree"])
        self.assertEqual(
            execution["control_execution_sha"],
            "de8342b9fb977f1a863bda7f87130068a68a9241",
        )
        self.assertEqual(
            execution["backup_index_sha256"],
            "b621f1c526559fea45a0f9fbc41d7d2564f5285c9f61b2b71bc0e41c290ba75c",
        )
        self.assertTrue(execution["application_clean"])
        self.assertTrue(execution["control_clean"])
        self.assertFalse(execution["service_started"])
        self.assertFalse(execution["provider_called"])
        for key in (
            "provider_ledger_entries",
            "s4_beta_metrics",
            "s4_provider_receipts",
            "s6_events",
            "s6_grants",
            "s6_reversals",
        ):
            self.assertEqual(execution[key], 0)
        self.assertEqual(execution["server_tests"], "27/27")

    def test_controller_is_syntax_valid_and_fail_closed(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", CONTROLLER],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("require_backup", source)
        self.assertIn("require_stopped", source)
        self.assertIn("merge --ff-only", source)
        self.assertIn("--require-hashes", source)
        self.assertIn("0020_commercial_s6_payment_readiness.sql", source)
        self.assertIn("avs_active=False", source)
        self.assertIn("avs_offline_staged=True", source)
        self.assertIn("payment_active=False", source)
        self.assertIn("provider_called\":false", source)
        self.assertNotIn("systemctl start", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("systemctl enable", source)
        self.assertNotIn("daemon-reload", source)
        self.assertNotIn("yoti.com/", source)
        self.assertNotIn("segpay.com/", source)
        self.assertNotIn("rm -rf", source)
        self.assertIsNone(re.search(r"[0-9]{7,12}:[A-Za-z0-9_-]{30,}", source))

    def test_manifest_hash_is_stable_material(self) -> None:
        digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
