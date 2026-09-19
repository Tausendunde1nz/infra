from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-interactive-experience.json"
DOC = ROOT / "docs/COMMERCIAL_S11_INTERACTIVE_EXPERIENCE_MVP.md"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_control.sh"
S8_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-telegram.service"
HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-health.service"
HEALTH_SCRIPT = ROOT / "scripts/tu1nz_adult_public_s8_health.py"


class CommercialS11InteractiveExperienceControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.doc = DOC.read_text(encoding="utf-8")
        self.controller = CONTROLLER.read_text(encoding="utf-8")

    def test_manifest_binds_canonical_source_and_reviewed_application(self) -> None:
        self.assertEqual(
            self.manifest["source"]["application_commit"],
            "1d0dbb88603be49ea172178b77d86451036035a1",
        )
        self.assertEqual(
            self.manifest["source"]["control_commit"],
            "5f0b5878888a5d48317e28ce75a6f0f552d6a419",
        )
        release = self.manifest["application_release"]
        self.assertEqual(release["commit"], "65707b079183151cfe7ea508f9270c31389f2334")
        self.assertEqual(release["tree"], "79d60a5b8d791f65c0de06d0ae7861fb0d032ed4")
        self.assertEqual(release["pull_request"], 114)
        self.assertEqual(release["post_merge_ci"], 35443107077)
        self.assertEqual(release["tests"], "1028_GREEN")

    def test_manifest_binds_all_application_artifacts(self) -> None:
        expected = {
            "experience_contract": "faf4fe20887f7b9d7b31d8f35518db1dea2faa861c84acd791f9f0a739db425d",
            "experience_copy": "bd842016355f7efd7dfdceedbe89e6e7ea0c7ada09dfe5587b37ad4e42abc972",
            "migration_up": "5792180ca628740d6a3b644958b3ba0c4f82d68bc93bd17673f3445d02429606",
            "migration_down": "bf4d3ce5e082d813a4f637ac010babb0c4835b94f204167b287657de90aaa157",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.manifest["artifacts"][name]["sha256"], digest)
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertIn(digest, self.controller)

    def test_product_contract_is_exactly_sfw_mvp(self) -> None:
        product = self.manifest["product"]
        self.assertEqual(product["challenge_count"], 36)
        self.assertEqual(product["challenges_per_mode"], 12)
        self.assertEqual(product["session_challenge_count"], 3)
        self.assertEqual(product["modes"], ["PLAYFUL", "BOLD", "DARING"])
        self.assertFalse(product["feature_source_default"])
        self.assertEqual(product["human_acceptance"], "DEFERRED")
        self.assertEqual(product["catalog_version"], "s11-curated-sfw-challenges-v1")
        self.assertEqual(product["state_machine_version"], "s11-experience-state-v1")
        self.assertTrue(all(value is False for value in self.manifest["boundaries"].values()))

    def test_analytics_classes_are_separate_and_content_free(self) -> None:
        analytics = self.manifest["analytics"]
        self.assertEqual(
            analytics["evidence_classes"],
            ["REAL_ACQUISITION", "SYNTHETIC", "INTERNAL_TEST"],
        )
        self.assertFalse(analytics["message_bodies_recorded"])
        self.assertFalse(analytics["challenge_response_text_recorded"])
        self.assertFalse(analytics["synthetic_in_real_kpis"])
        for event in (
            "EXPERIENCE_STARTED", "AGE_SELF_ATTESTED", "MODE_SELECTED",
            "DARE_PRESENTED", "DARE_ACCEPTED", "DARE_COMPLETED", "DARE_SKIPPED",
            "SAFER_REQUESTED", "BOLDER_REQUESTED", "SESSION_COMPLETED",
            "NEXT_SESSION_STARTED", "EARLY_ACCESS_CTA", "EARLY_ACCESS_JOINED",
            "COMMUNITY_CTA",
        ):
            self.assertIn(event, self.doc)

    def test_units_preserve_community_and_add_experience(self) -> None:
        for path in (S8_UNIT, HEALTH_UNIT):
            source = path.read_text(encoding="utf-8")
            self.assertIn(
                "--community-contract /etc/tu1nz/adult-commercial-s10-2d-community.json",
                source,
            )
            self.assertIn(
                "--community-copy /etc/tu1nz/adult-commercial-s10-2d-community-copy.json",
                source,
            )
            self.assertIn(
                "--experience-contract /etc/tu1nz/adult-commercial-s11-interactive-experience.json",
                source,
            )
            self.assertIn(
                "--experience-copy /etc/tu1nz/adult-commercial-s11-interactive-copy.json",
                source,
            )
            self.assertIn("--runtime-release-id s10-2d-r3-5", source)
            self.assertIn("adult-commercial-s10-2b-telegram.token", source)

    def test_health_runner_requires_complete_experience_pair(self) -> None:
        source = HEALTH_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--experience-contract", type=Path)', source)
        self.assertIn('parser.add_argument("--experience-copy", type=Path)', source)
        self.assertIn("S8_EXPERIENCE_ARGUMENTS_INCOMPLETE", source)
        self.assertIn('"--experience-contract", str(arguments.experience_contract)', source)
        self.assertIn('"--experience-copy", str(arguments.experience_copy)', source)

    def test_backup_precedes_every_deploy_mutation(self) -> None:
        body = self.controller[
            self.controller.index("deploy() {"):self.controller.index("deployment_error() {")
        ]
        backup = body.index("backup_runtime")
        for mutation in (
            "fetch_and_require_target", "switch --detach", "pip install",
            "install_from_git", "apply_migration", "systemctl daemon-reload",
            "systemctl restart", "set_feature true",
        ):
            self.assertGreater(body.index(mutation), backup, mutation)
        self.assertLess(body.index("require_feature_state off"), body.index("set_feature true"))
        self.assertLess(body.index("run_synthetic_journeys"), body.index("set_feature true"))

    def test_backup_is_private_complete_and_verified(self) -> None:
        for token in (
            "application.bundle", "control.bundle", "bundle verify",
            "landing-aggregates.exact", "database-aggregate-and-schema.json",
            "runtime-manifest.txt", "owners-and-modes.txt", "provenance.txt",
            "SHA256SUMS", "chmod -R go-rwx", "EXPERIENCE_CONTRACT_ABSENT",
            "EXPERIENCE_COPY_ABSENT",
        ):
            self.assertIn(token, self.controller)
        self.assertNotIn("adult-commercial-s7-database.dsn\" \"$backup_path", self.controller)
        self.assertNotIn("telegram.token\" \"$backup_path", self.controller)

    def test_failure_is_fail_closed_and_rollback_is_nondestructive(self) -> None:
        self.assertIn("trap 'deployment_error' ERR", self.controller)
        self.assertIn("S11_DEPLOYMENT_ROLLED_BACK", self.controller)
        self.assertIn("set_feature false S11_ROLLBACK_DISABLED", self.controller)
        self.assertNotIn("0031_commercial_s11_interactive_experience.down.sql\"", self.controller)
        self.assertNotIn("git reset --hard", self.controller)
        restore = self.controller[
            self.controller.index("restore_source() {"):self.controller.index("deploy() {")
        ]
        self.assertIn("pip install", restore)
        self.assertIn("s8-telegram.service", restore)
        self.assertIn("require_acquisition_state", restore)

    def test_runtime_validation_covers_required_system(self) -> None:
        for token in (
            "tu1nz-adult-public-s7.service", "tu1nz-adult-public-s8-landing.service",
            "tu1nz-adult-public-s8-telegram.service", "tu1nz-adult-public-s10-wms.service",
            "nginx.service", "tu1nz-adult-public-s9-audience.timer",
            "tu1nz-adult-public-s9-nurture.timer", "tu1nz-adult-public-s9-report.timer",
            "tu1nz-adult-public-s9-health.timer", "tu1nz-adult-public-s10-health.timer",
            "NextElapseUSecRealtime", "commercial_s10_2d_bot_polling_state",
            "lease_expires_at>CURRENT_TIMESTAMP", "BOT_EVENT_PATH_GREEN",
            "tu1nz-adult-public-s10-2d-rotate.service", "https://wantmeseen.com/health",
            "https://wantmeseen.de/", "/privacy", "/terms", "/imprint",
        ):
            self.assertIn(token, self.controller)

    def test_acquisition_baseline_is_immutable(self) -> None:
        expected = "2026-09-18T00:41:06.710027Z"
        self.assertTrue(self.manifest["source"]["real_acquisition_active"])
        self.assertEqual(self.manifest["source"]["acquisition_baseline_start"], expected)
        self.assertIn(expected, self.controller)
        self.assertNotIn("real_acquisition_baseline_start=", self.controller)
        self.assertNotIn("wms_real_acquisition_ready=", self.controller)

    def test_controller_and_health_script_have_valid_syntax(self) -> None:
        subprocess.run(["bash", "-n", str(CONTROLLER)], check=True)
        subprocess.run(["python3", "-m", "py_compile", str(HEALTH_SCRIPT)], check=True)

    def test_final_report_contract_has_all_requested_topics(self) -> None:
        self.assertIn("## Final report contract", self.doc)
        self.assertIn("all 56 requested items in order", self.doc)
        self.assertIn("full GO/NO-GO matrix", self.doc)
        self.assertNotRegex(self.doc, re.compile(r"27 people|everyone is watching", re.I))


if __name__ == "__main__":
    unittest.main()
