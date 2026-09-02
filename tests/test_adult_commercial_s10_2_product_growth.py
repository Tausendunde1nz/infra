from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2-product-growth.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2_control.sh"


class CommercialS102ProductGrowthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.controller = CONTROLLER.read_text(encoding="utf-8")

    def test_manifest_binds_the_canonical_application_release(self) -> None:
        application = self.value["application"]
        self.assertEqual(application["source_commit"], "cdeab77c17c28f4ade46c27975f1c20e74cb8737")
        self.assertEqual(application["source_tree"], "88d8869fbbb9931b16451f7bb1483e1fa6d483df")
        self.assertEqual(application["target_commit"], "deeb38c30427066989eb85e1c115d2aeccf140cf")
        self.assertEqual(application["target_tree"], "3619e7dc557b49c632efa713bb0bc4214fd83fca")
        self.assertEqual(application["post_merge_ci"], 33686246719)
        self.assertEqual(self.value["control"]["expected_base_commit"], "0a13ee2e4d05f4d3d1a1d4d3ff91f4859415c067")
        self.assertTrue(self.value["control"]["exact_post_merge_commit_and_tree_required"])

    def test_product_scope_is_conversion_focused_and_privacy_safe(self) -> None:
        journey = self.value["product_journey"]
        self.assertEqual(journey["public_name"], "Want Me Seen")
        self.assertEqual(journey["landing_to_private_telegram_seconds_target"], 30)
        self.assertEqual(
            journey["funnel_events"],
            ["LANDING_VIEW", "TELEGRAM_CTA", "BOT_START", "INTRO_COMPLETED", "WAITLIST_JOINED", "OPT_IN", "OPT_OUT"],
        )
        self.assertEqual(journey["referral_mode"], "COHORT_ONLY_NO_PERSONAL_CODE")
        self.assertFalse(journey["referral_reward"])
        self.assertTrue(journey["nurture_opt_in_only"])
        self.assertEqual(
            set(self.value["content_engine"]["purposes"]),
            {"AWARENESS", "CURIOSITY", "TRUST", "CONVERSION", "RETENTION"},
        )
        self.assertTrue(self.value["analytics"]["aggregate_only"])
        self.assertFalse(self.value["analytics"]["personal_referral_codes"])
        self.assertFalse(self.value["analytics"]["sensitive_preferences"])

    def test_all_new_risk_boundaries_remain_closed(self) -> None:
        self.assertTrue(all(value is False for value in self.value["product_boundary"].values()))
        deployment = self.value["deployment"]
        self.assertFalse(deployment["database_migration"])
        self.assertFalse(deployment["enable_or_disable_units"])
        self.assertFalse(deployment["two_hour_observation_required"])
        self.assertTrue(deployment["automatic_rollback_to_source_on_failure"])
        self.assertEqual(
            deployment["restart_services"],
            ["tu1nz-adult-public-s8-telegram.service", "tu1nz-adult-public-s10-wms.service"],
        )

    def test_controller_is_hash_bound_syntax_valid_and_fail_closed(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONTROLLER.read_bytes()).hexdigest(),
            self.value["control"]["controller_sha256"],
        )
        subprocess.run(["bash", "-n", str(CONTROLLER)], check=True)
        for value in (
            self.value["application"]["source_commit"],
            self.value["application"]["source_tree"],
            self.value["application"]["target_commit"],
            self.value["application"]["target_tree"],
            "CONTROL_SHA_MISMATCH",
            "REMOTE_TARGET_SHA_MISMATCH",
            "BACKUP_APPLICATION_SHA_MISMATCH",
            "PRODUCT_BOUNDARY_RED",
            "DEPLOY_ROLLED_BACK",
            "schema_migration\":false",
            "COHORT_ONLY",
        ):
            self.assertIn(str(value), self.controller)
        self.assertIn("fetch --no-tags origin main", self.controller)
        self.assertIn("switch --detach", self.controller)
        self.assertNotIn("systemctl enable", self.controller)
        self.assertNotIn("systemctl disable", self.controller)
        self.assertNotIn("psql ", self.controller)
        self.assertNotIn("pg_restore", self.controller)
        self.assertNotIn("adult-commercial-s8-telegram.token", self.controller)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.controller))


if __name__ == "__main__":
    unittest.main()
