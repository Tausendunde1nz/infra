from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-community-instant.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh"
S8_HEALTH = ROOT / "scripts/tu1nz_adult_public_s8_health.py"
S10_HEALTH = ROOT / "scripts/tu1nz_adult_public_s10_1_health.py"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s10_1_backup.sh"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2D_COMMUNITY_INSTANT_CONTROL.md"
S8_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-telegram.service"
S8_HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-health.service"
S10_UNIT = ROOT / "systemd/tu1nz-adult-public-s10-wms.service"
S10_HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s10-health.service"
S9_HEALTH_DROPIN = ROOT / "systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf"
ROTATE_UNIT = ROOT / "systemd/tu1nz-adult-public-s10-2d-rotate.service"


class CommercialS102DCommunityInstantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.controller = CONTROLLER.read_text(encoding="utf-8")
        self.control = CONTROL.read_text(encoding="utf-8")

    def test_manifest_binds_reviewed_application_release_and_migration(self) -> None:
        self.assertEqual(self.manifest["version"], "tu1nz-commercial-s10-2d-community-instant-v1")
        self.assertEqual(self.manifest["decision"], "GO_BACKUP_FIRST_PENDING_OPERATOR_CHECKPOINT")
        self.assertFalse(self.manifest["active"])
        app = self.manifest["application"]
        self.assertEqual(app["source_commit"], "f9747088a31ec6c671e82de24e293ebdec99f717")
        self.assertEqual(app["source_tree"], "7defedef032f6af38bbce0165eb6c2bdec327df7")
        self.assertEqual(app["target_commit"], "963d80f626a197b564201f92d5164090cf49d102")
        self.assertEqual(app["target_tree"], "03e25deaba0ec3c3250310f8a4c1bf1cadae87c5")
        self.assertEqual(app["post_merge_ci"], 33962072767)
        self.assertEqual(app["unit_tests_green"], 989)
        self.assertEqual(app["postgresql_acceptance"], [17, 18])
        self.assertEqual(app["migration"], "0029_commercial_s10_2d_community")

    def test_all_new_control_material_is_hash_bound_and_syntax_valid(self) -> None:
        control = self.manifest["control"]
        self.assertEqual(hashlib.sha256(CONTROLLER.read_bytes()).hexdigest(), control["controller_sha256"])
        self.assertEqual(hashlib.sha256(S8_HEALTH.read_bytes()).hexdigest(), control["s8_health_sha256"])
        self.assertEqual(hashlib.sha256(S10_HEALTH.read_bytes()).hexdigest(), control["s10_health_sha256"])
        subprocess.run(["bash", "-n", str(CONTROLLER)], check=True)
        subprocess.run(["python3", "-m", "py_compile", str(S8_HEALTH), str(S10_HEALTH)], check=True)

    def test_controller_is_backup_first_version_bound_and_fail_closed(self) -> None:
        for value in (
            self.manifest["application"]["source_commit"],
            self.manifest["application"]["source_tree"],
            self.manifest["application"]["target_commit"],
            self.manifest["application"]["target_tree"],
            self.manifest["application"]["migration_sha256"],
            self.manifest["application"]["migration_down_sha256"],
            "BACKUP_APPLICATION_SHA_MISMATCH",
            "BACKUP_CONTROL_SHA_MISMATCH",
            "REMOTE_TARGET_SHA_MISMATCH",
            "TARGET_BOT_GROUP_CAPABILITY_RED",
            "TARGET_BOT_PROFILE_CONFIGURE_RED",
            "COMMUNITY_OPERATOR_PREFLIGHT_RED",
            "MIGRATION_0029_RED",
            "DEPLOY_AND_ROLLBACK_RED",
            "SOURCE_BOTFATHER_GROUPS_OPERATOR_REQUIRED",
            "PRODUCT_SURFACE_CHANGED_BEFORE_ACTIVE_ACQUISITION",
            "OBSERVATION_WINDOW_INCOMPLETE",
            "LATENCY_SAMPLE_FLOOR_MISSING",
            "WMS_REAL_ACQUISITION_READY",
        ):
            self.assertIn(str(value), self.controller)
        deploy = self.controller.split("deploy() {", 1)[1].split("observation_snapshot() {", 1)[0]
        self.assertLess(deploy.index("preflight"), deploy.index("quiesce"))
        preflight = self.controller.split("preflight() {", 1)[1].split("rollback() {", 1)[0]
        self.assertIn("require_backup", preflight)
        self.assertLess(preflight.index("target_group_capability_verify"), preflight.index("target_community_verify"))
        self.assertLess(deploy.index("configure_current_bot_profile"), deploy.index("apply_migration"))
        self.assertLess(deploy.index("apply_migration"), deploy.index("start_target"))
        self.assertLess(deploy.index("verify_target"), deploy.index("run_rotation"))
        self.assertIn("run_bound_migration migrations/0029", self.controller)
        self.assertIn("rollback_migration_if_unused", self.controller)
        self.assertNotIn("pg_restore", self.controller)
        self.assertNotIn("telegram_user_id", self.controller)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.controller))

    def test_bot_profile_transition_is_symmetric_and_fail_closed(self) -> None:
        self.assertIn("-m tu1nz_public_s8.brand_migration", self.controller)
        self.assertIn("--configure-bot", self.controller)
        self.assertIn("--verify-bot", self.controller)
        self.assertIn('client._call("getMe", {}, 20)', self.controller)
        self.assertNotIn('client.call_profile("getMe"', self.controller)
        rollback = self.controller.split("rollback() {", 1)[1].split("deploy() {", 1)[0]
        self.assertLess(rollback.index("restore_technical_state"), rollback.index("restore_source_bot_profile"))
        self.assertLess(rollback.index("restore_source_bot_profile"), rollback.index("systemctl start"))
        restore = self.controller.split("restore_source_bot_profile() {", 1)[1].split("require_target_control() {", 1)[0]
        self.assertLess(restore.index("verify_current_bot_profile"), restore.index("configure_bound_bot_profile"))
        self.assertIn("configure_bound_bot_profile", restore)
        self.assertIn("S8_TELEGRAM_GROUP_CAPABILITY_MISMATCH", restore)
        self.assertIn("S8_TELEGRAM_GROUPS_ENABLED", self.controller)

        bound = self.controller.split("configure_bound_bot_profile() {", 1)[1].split(
            "verify_current_bot_profile() {", 1
        )[0]
        self.assertIn('git -C "$APPLICATION_ROOT" archive "$TARGET_SHA"', bound)
        self.assertIn("-m tu1nz_public_s8.brand_migration", bound)

    def test_public_community_contract_uses_the_live_redirect_not_page_copy(self) -> None:
        verify = self.controller.split("verify_target() {", 1)[1].split("preflight() {", 1)[0]
        self.assertIn("https://wantmeseen.com/go/community?campaign=s10_wms_launch&source=organic_search", verify)
        self.assertIn("302|https://t.me/WantMeSeenCommunity", verify)
        self.assertNotIn("grep -Fq 'Want Me Seen Community'", verify)

    def test_landing_is_quiesced_and_restarted_with_the_version_switch(self) -> None:
        quiesce = self.controller.split("quiesce() {", 1)[1].split("run_health_gates() {", 1)[0]
        start = self.controller.split("start_target() {", 1)[1].split("run_rotation() {", 1)[0]
        rollback = self.controller.split("rollback() {", 1)[1].split("deploy() {", 1)[0]
        self.assertIn('systemctl stop "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE"', quiesce)
        self.assertIn('systemctl start "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE"', start)
        self.assertIn('systemctl start "$S8_LANDING_SERVICE" "$S8_SERVICE" "$S10_SERVICE"', rollback)

    def test_timer_verification_waits_only_for_bounded_transient_settling(self) -> None:
        check = self.controller.split("require_timers_green() {", 1)[1].split(
            "require_adult_runtime_closed() {", 1
        )[0]
        self.assertIn("for attempt in {1..90}", check)
        self.assertIn('fail "TIMER_NOT_ENABLED"', check)
        self.assertIn('fail "TIMER_NOT_ACTIVE"', check)
        self.assertIn('fail "TIMER_NOT_SETTLED"', check)
        self.assertNotIn("TIMER_NOT_WAITING", check)

    def test_community_identity_rights_permissions_and_privacy_are_exact(self) -> None:
        identity = self.manifest["public_identity"]
        community = self.manifest["community"]
        self.assertEqual(identity["community"], "@WantMeSeenCommunity")
        self.assertEqual(identity["community_type"], "supergroup")
        self.assertEqual(identity["bot"], "@wantmeseenbot")
        self.assertEqual(identity["bot_id"], 8861935205)
        self.assertEqual(community["steady_state_bot_rights"], ["delete_messages", "restrict_members"])
        self.assertEqual(community["botfather_privacy_mode"], "ENABLED")
        self.assertTrue(community["text_only_default_permissions"])
        self.assertFalse(community["media_publishing_enabled"])
        self.assertTrue(community["adult_self_attestation_required"])
        self.assertFalse(community["self_attestation_is_avs"])
        for value in ("change_info", "pin_messages", "promote_members", "anonymous_admin"):
            self.assertIn(value, community["forbidden_bot_rights"])

    def test_navigation_waitlist_and_business_priority_are_product_bound(self) -> None:
        navigation = self.manifest["navigation"]
        self.assertEqual(navigation["website_primary"], "BOT")
        self.assertEqual(navigation["website_secondary"], "COMMUNITY")
        self.assertEqual(navigation["channel"], ["BOT", "COMMUNITY"])
        self.assertEqual(navigation["community"], ["BOT", "FULL_WMS_EARLY_ACCESS"])
        self.assertEqual(navigation["bot"], ["CHANNEL", "COMMUNITY", "FULL_WMS_EARLY_ACCESS"])
        self.assertEqual(navigation["waitlist_meaning"], "FULL_WMS_EARLY_ACCESS")
        loop = self.manifest["business_loop"]
        self.assertEqual(loop["priorities"][:5], [
            "BOT_LATENCY", "REACH", "COMMUNITY_JOINS", "CONVERSION", "COMMUNITY_ENGAGEMENT",
        ])
        self.assertFalse(loop["autonomous_task_generation"])
        self.assertFalse(loop["fake_users_or_content"])

    def test_health_units_bind_community_and_reuse_existing_runtime(self) -> None:
        s8 = S8_UNIT.read_text(encoding="utf-8")
        s8_health_unit = S8_HEALTH_UNIT.read_text(encoding="utf-8")
        s10 = S10_UNIT.read_text(encoding="utf-8")
        s10_health_unit = S10_HEALTH_UNIT.read_text(encoding="utf-8")
        dropin = S9_HEALTH_DROPIN.read_text(encoding="utf-8")
        for source in (s8, s8_health_unit, s10, s10_health_unit, dropin):
            self.assertIn("--community-contract /etc/tu1nz/adult-commercial-s10-2d-community.json", source)
            self.assertIn("NoNewPrivileges=true", source if source is not dropin else s10_health_unit)
        self.assertIn("--community-copy /etc/tu1nz/adult-commercial-s10-2d-community-copy.json", s8)
        self.assertIn("--community-copy /etc/tu1nz/adult-commercial-s10-2d-community-copy.json", s8_health_unit)
        self.assertIn("--s8-copy /etc/tu1nz/adult-commercial-s8-copy.json", s10_health_unit)
        self.assertIn("--s8-copy /etc/tu1nz/adult-commercial-s8-copy.json", dropin)
        self.assertIn("tu1nz-public-s8-telegram", s8)
        self.assertIn("tu1nz_exposure_s10.runtime", s10)

    def test_rotation_is_one_shot_hardened_and_uses_reviewed_queue_path(self) -> None:
        unit = ROTATE_UNIT.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("--rotate-content", unit)
        self.assertIn("--s10-copy /etc/tu1nz/adult-commercial-s10-wms-copy.json", unit)
        self.assertIn("--public-origin https://wantmeseen.com", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertNotIn("[Install]", unit)
        rotation = self.manifest["content_rotation"]
        self.assertEqual(rotation["items_en"], 36)
        self.assertTrue(rotation["in_flight_lease_forbidden"])
        self.assertTrue(rotation["published_and_failed_evidence_preserved"])

    def test_backup_surface_includes_community_and_migration_0029(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        self.assertIn("0029_commercial_s10_2d_community", source)
        self.assertIn("adult-commercial-s10-*.json", source)
        self.assertIn("tu1nz_adult_public_s8_health.py", source)
        self.assertIn("tu1nz_adult_public_s10_1_health.py", source)
        self.assertIn("s10-runtime-executables-before.tar", source)

    def test_latency_and_readiness_are_strictly_separate(self) -> None:
        latency = self.manifest["latency"]
        baseline = self.manifest["baseline"]
        self.assertEqual(latency["minimum_samples"], 5)
        self.assertEqual(latency["p50_strictly_less_than_ms"], 1000)
        self.assertEqual(latency["p95_strictly_less_than_ms"], 2000)
        self.assertEqual(latency["p99_strictly_less_than_ms"], 5000)
        self.assertEqual(baseline["minimum_green_observation_seconds"], 1800)
        self.assertEqual(baseline["pre_acquisition_readiness"], "PENDING")
        self.assertFalse(baseline["wms_real_acquisition_ready"])
        self.assertIn("mark-ready)", self.controller)
        self.assertIn("observe)", self.controller)

    def test_future_media_and_all_real_risk_boundaries_remain_closed(self) -> None:
        future = self.manifest["future_media_contract"]
        self.assertTrue(future["test_only"])
        self.assertTrue(future["synthetic_only"])
        self.assertTrue(all(future[key] for key in (
            "avs_required", "identity_binding_required", "all_depicted_consent_required",
            "destination_consent_required", "moderation_required", "final_confirmation_required",
            "withdrawal_queues_takedown",
        )))
        self.assertTrue(all(value is False for value in self.manifest["product_boundary"].values()))

    def test_control_doc_records_single_checkpoint_and_exact_report_contract(self) -> None:
        for value in (
            "Single bundled operator checkpoint",
            "@WantMeSeenCommunity",
            "delete-messages and restrict/ban-members",
            "at least 1,800 seconds",
            "exactly 41 numbered points",
            "No acquisition campaign is launched",
        ):
            self.assertIn(value, self.control)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.control))


if __name__ == "__main__":
    unittest.main()
