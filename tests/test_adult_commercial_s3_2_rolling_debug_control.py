from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s3-2-rolling-debug.json"
SCRIPT = ROOT / "scripts/tu1nz_adult_commercial_s3_2_probe.sh"


class CommercialS32RollingDebugControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_release_and_authorization_are_exactly_rolling_and_fail_closed(self) -> None:
        self.assertEqual(self.value["version"], "tu1nz-commercial-s3-2-rolling-debug-control-v1")
        self.assertEqual(
            self.value["decision"],
            "GO_ROLLING_SERVER_STAGING_DEBUG_BEFORE_PRODUCT_ACCEPTANCE",
        )
        self.assertEqual(
            self.value["application"]["sha"],
            "d7e78201f06ec493e7ecabcb4b624e5f92c9abf9",
        )
        self.assertEqual(
            self.value["application"]["tree"],
            "81f28d53b2595b88ad1a48cba68378e680b8abbd",
        )
        self.assertEqual(self.value["application"]["branch"], "fix/commercial-s3-staging-recovery")
        self.assertEqual(self.value["control"]["branch"], "fix/commercial-s3-staging-recovery")
        authorization = self.value["authorization"]
        self.assertTrue(authorization["rolling_server_debug_authorized"])
        self.assertEqual(authorization["maximum_product_acceptance_runs"], 1)
        self.assertFalse(authorization["restart_authorized"])
        self.assertFalse(authorization["enable_authorized"])
        runtime_authorization = self.value["runtime_release_authorization"]
        self.assertFalse(runtime_authorization["single_bootstrap_authorized"])
        self.assertFalse(runtime_authorization["service_start_authorized"])
        self.assertEqual(
            runtime_authorization["decision"],
            "GO_FOR_RUNTIME_RELEASE_VERIFY_ONLY",
        )
        payload = json.loads((ROOT / runtime_authorization["path"]).read_text(encoding="ascii"))
        self.assertEqual(
            hashlib.sha256((ROOT / runtime_authorization["path"]).read_bytes()).hexdigest(),
            runtime_authorization["sha256"],
        )
        self.assertFalse(payload["single_bootstrap_authorized"])
        self.assertFalse(payload["boundaries"]["service_start_authorized"])
        self.assertEqual(payload["application_sha"], self.value["application"]["sha"])
        self.assertEqual(payload["application_tree"], self.value["application"]["tree"])

    def test_all_eighteen_phases_are_exact_and_ordered(self) -> None:
        self.assertEqual(
            self.value["startup_phases"],
            [
                "01_CONTRACT_LOAD", "02_CREDENTIAL_LOAD", "03_PATH_VALIDATE",
                "04_DATABASE_CONNECT", "05_MIGRATION_VALIDATE", "06_BOOTSTRAP_VERIFY",
                "07_ALLOWLIST_LOAD", "08_STATE_VALIDATE", "09_STATE_INITIALIZE",
                "10_LOCK_ACQUIRE", "11_TELEGRAM_ASSEMBLY", "12_TELEGRAM_AUTH_VALIDATE",
                "13_POLLING_STATE_LOAD", "14_WORKER_ASSEMBLY", "15_OUTBOX_VALIDATE",
                "16_AUDIT_VALIDATE", "17_HEALTH_INITIALIZE", "18_READY",
            ],
        )

    def test_product_and_service_boundaries_remain_closed(self) -> None:
        boundary = self.value["product_boundary"]
        self.assertFalse(boundary["adult_media_enabled"])
        self.assertFalse(boundary["external_publish_enabled"])
        self.assertFalse(boundary["production_enabled"])
        self.assertFalse(boundary["controlled_beta_enabled"])
        self.assertEqual(boundary["avs_provider"], "MOCK")
        self.assertEqual(boundary["payment_provider"], "MOCK")
        self.assertTrue(all(value == "SYNTHETIC" for value in boundary["publishers"].values()))
        service = self.value["service"]
        self.assertEqual(service["restart"], "no")
        self.assertFalse(service["unit_enablement"])
        self.assertTrue(service["probe_is_transient"])
        self.assertFalse(service["probe_product_polling"])

    def test_probe_reuses_runtime_systemd_credentials_and_has_no_product_action(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("systemd-run", source)
        self.assertIn("--startup-probe", source)
        self.assertIn("fresh-prestart", source)
        self.assertIn("tu1nz-commercial-s3-prestart", source)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", source)
        self.assertIn("LoadCredential=", source)
        self.assertIn("ProtectSystem=strict", source)
        self.assertIn("Restart=no", source)
        self.assertIn("700|2700", source)
        self.assertIn("open-window", source)
        self.assertIn("close-window", source)
        self.assertIn("DISABLED_CONTRACT_SHA", source)
        self.assertIn("GO_FOR_BOUNDED_SERVER_STAGING", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("systemctl enable", source)
        self.assertNotIn("daemon-reload", source)
        self.assertNotIn("rm -rf", source)
        self.assertIsNone(re.search(r"[0-9]{7,12}:[A-Za-z0-9_-]{30,}", source))
        for forbidden in ("sendMessage", "getUpdates", "systemctl start", "takedown"):
            self.assertNotIn(forbidden, source)

    def test_baseline_is_reused_only_for_code_delta(self) -> None:
        baseline = self.value["baseline_recovery"]
        self.assertTrue(baseline["required"])
        self.assertTrue(baseline["restore_proof_required"])
        self.assertFalse(baseline["full_backup_repetition_required_for_code_only_delta"])
        self.assertEqual(
            baseline["path"],
            "/opt/tu1nz_repos/backups/commercial-s3-1-fix/20260829T13-56-54Z",
        )


if __name__ == "__main__":
    unittest.main()
