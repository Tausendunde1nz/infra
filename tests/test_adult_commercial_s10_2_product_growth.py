from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
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
            "SOURCE_S10_CONTRACT_SHA",
            "TARGET_S10_CONTRACT_SHA",
            'required_events.add("INTRO_COMPLETED")',
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

    def test_product_boundary_accepts_source_and_requires_target_intro(self) -> None:
        match = re.search(
            r'<<\'PY\' \|\| fail "PRODUCT_BOUNDARY_RED"\n(.*?)\nPY\n}',
            self.controller,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        program = match.group(1)
        s8 = {name: False for name in (
            "invite_automation_enabled", "adult_content", "media_intake",
            "real_submissions", "real_avs", "payments", "publishing",
            "controlled_beta", "production_adult_workflow",
        )}
        s9 = {name: False for name in (
            "x_enabled", "reddit_enabled", "invite_automation_enabled",
            "controlled_beta", "adult_content", "media_intake", "real_avs",
            "payments", "external_adult_publishing", "production_adult_workflow",
        )}
        s10 = {name: False for name in (
            "adult_content", "media_intake", "identity_documents", "real_avs",
            "payments", "external_publishing", "creator_activation",
            "controlled_beta", "production",
        )}
        common_events = [
            "LANDING_VIEW", "TELEGRAM_CTA", "BOT_START", "WAITLIST_JOINED",
            "OPT_IN", "OPT_OUT",
        ]
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("s8.json", "s9.json", "s10.json")]
            paths[0].write_text(json.dumps(s8), encoding="utf-8")
            paths[1].write_text(json.dumps(s9), encoding="utf-8")

            def run(events: list[str], source: bool) -> subprocess.CompletedProcess[str]:
                s10["allowed_events"] = events
                paths[2].write_text(json.dumps(s10), encoding="utf-8")
                digest = hashlib.sha256(paths[2].read_bytes()).hexdigest()
                source_hash, target_hash = (digest, "0" * 64) if source else ("0" * 64, digest)
                return subprocess.run(
                    ["python3", "-", *(str(path) for path in paths), source_hash, target_hash],
                    input=program,
                    text=True,
                    check=False,
                )

            self.assertEqual(run(common_events, source=True).returncode, 0)
            self.assertEqual(run(common_events + ["INTRO_COMPLETED"], source=False).returncode, 0)
            self.assertNotEqual(run(common_events, source=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
