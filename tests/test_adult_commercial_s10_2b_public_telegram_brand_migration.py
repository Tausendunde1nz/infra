from __future__ import annotations

import json
import hashlib
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2b-public-telegram-brand-migration.json"
INSTALLER = ROOT / "scripts/tu1nz_adult_public_s10_2b_secret_install.sh"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2b_control.sh"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2B_PUBLIC_TELEGRAM_BRAND_MIGRATION.md"


class CommercialS102BPublicTelegramBrandMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.installer = INSTALLER.read_text(encoding="utf-8")
        self.controller = CONTROLLER.read_text(encoding="utf-8")
        self.control = CONTROL.read_text(encoding="utf-8")

    def test_cutover_state_binds_the_reviewed_application_and_identity(self) -> None:
        self.assertEqual(
            self.manifest["decision"],
            "WAITING_REPLACEMENT_BACKUP_AFTER_GUARD_RECOVERY",
        )
        self.assertFalse(self.manifest["active"])
        application = self.manifest["application"]
        self.assertEqual(application["source_commit"], "deeb38c30427066989eb85e1c115d2aeccf140cf")
        self.assertEqual(application["source_tree"], "3619e7dc557b49c632efa713bb0bc4214fd83fca")
        self.assertEqual(application["target_commit"], "f9747088a31ec6c671e82de24e293ebdec99f717")
        self.assertEqual(application["target_tree"], "7defedef032f6af38bbce0165eb6c2bdec327df7")
        self.assertEqual(application["post_merge_ci"], 33809025595)
        self.assertTrue(application["identity_binding_complete"])
        identity = self.manifest["public_identity"]
        self.assertEqual(identity["channel"], "@WantMeSeen")
        self.assertEqual(identity["bot"], "@wantmeseenbot")
        self.assertEqual(identity["bot_id"], 8861935205)

    def test_secret_installer_is_tty_only_root_only_and_does_not_accept_arguments(self) -> None:
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)
        for value in (
            "ROOT_REQUIRED",
            "INTERACTIVE_TTY_REQUIRED",
            'read -r -s -p',
            '"$#" -eq 0',
            "TARGET_ALREADY_EXISTS",
            "BOT_IDENTITY_VALIDATION_FAILED",
            "can_join_groups",
            ".casefold() == expected_username.casefold()",
            "ProxyHandler({})",
            "RejectRedirect",
            "install -o root -g root -m 0600",
        ):
            self.assertIn(value, self.installer)
        self.assertNotRegex(self.installer, r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}")

    def test_controller_is_hash_bound_backup_first_and_fail_closed(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONTROLLER.read_bytes()).hexdigest(),
            self.manifest["control"]["controller_sha256"],
        )
        subprocess.run(["bash", "-n", str(CONTROLLER)], check=True)
        for value in (
            self.manifest["application"]["source_commit"],
            self.manifest["application"]["source_tree"],
            self.manifest["application"]["target_commit"],
            self.manifest["application"]["target_tree"],
            "BACKUP_APPLICATION_SHA_MISMATCH",
            "REMOTE_TARGET_SHA_MISMATCH",
            "NEW_BOT_CHANNEL_PERMISSION_MISSING",
            "OLD_BOT_FALLBACK_PERMISSION_MISSING",
            'member.get("can_change_info") is True',
            'chat.get("type") == "channel"',
            'type(member.get("can_restrict_members")) is bool',
            '"can_promote_members"',
            "PRODUCT_BOUNDARY_RED",
            "DATABASE_CONTINUITY_RED",
            "DEPLOY_ROLLED_BACK",
            "restore_fallback_channel",
            "--configure-bot",
            "--configure-channel",
            "--verify-bot",
            "--verify-channel",
            self.manifest["recovery_baseline"]["s7_contract_sha256"],
            '"S7_PROTECTED_CONTRACT"',
            "S8_HEALTH_TIMER_NOT_RETIRED",
            "S8_HEALTH_TIMER_UNIT_DRIFT",
            "require_s8_health_timer_retired",
        ):
            self.assertIn(str(value), self.controller)
        self.assertIn("fetch --no-tags origin main", self.controller)
        self.assertIn("switch --detach", self.controller)
        self.assertNotIn("systemctl enable", self.controller)
        self.assertNotIn("systemctl disable", self.controller)
        self.assertNotIn("pg_restore", self.controller)
        self.assertNotIn(
            'install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s7-public-launch.sfw.json"',
            self.controller,
        )
        self.assertNotIn("telegram_user_id", self.controller)
        self.assertNotIn("private_chat_id", self.controller)
        self.assertNotIn(
            '"can_restrict_members", "can_manage_video_chats"',
            self.controller,
        )
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.controller))

    def test_secret_policy_is_outside_git_and_preserves_legacy_fallback(self) -> None:
        secret = self.manifest["secret_handling"]
        self.assertEqual(secret["target"], "/etc/tu1nz/adult-commercial-s10-2b-telegram.token")
        self.assertEqual(secret["mode"], "0600")
        self.assertEqual(secret["owner"], "root:root")
        self.assertTrue(secret["legacy_secret_preserved_for_fallback"])
        self.assertTrue(secret["installed"])
        for key in ("chat_forbidden", "git_forbidden", "logs_forbidden", "history_forbidden"):
            self.assertTrue(secret[key])

    def test_backup_is_verified_and_contains_no_secret_material(self) -> None:
        backup = self.manifest["backup"]
        self.assertEqual(
            backup["path"],
            "/opt/tu1nz_repos/backups/commercial-s8-public-telegram/20260904T110654Z-pre-s10-2b-public-telegram",
        )
        self.assertTrue(backup["verified"])
        self.assertFalse(backup["contains_secret_material"])
        self.assertFalse(backup["reusable_by_current_controller"])
        self.assertTrue(backup["replacement_required"])
        self.assertEqual(
            backup["replacement_reason"],
            "S10_RUNTIME_EXECUTABLES_BACKUP_MISSING",
        )
        self.assertRegex(backup["index_sha256"], r"^[0-9a-f]{64}$")

    def test_continuity_and_rollback_preserve_the_existing_product_state(self) -> None:
        continuity = self.manifest["continuity"]
        self.assertTrue(continuity["existing_channel_preserved"])
        self.assertTrue(continuity["existing_channel_id_preserved"])
        self.assertTrue(continuity["postgres_waitlist_ssot_preserved"])
        self.assertFalse(continuity["database_schema_change"])
        self.assertEqual(continuity["old_bot_mode"], "FALLBACK_ONLY")
        self.assertIn("without a", self.control)
        self.assertIn("database restore", self.control)
        self.assertIn("channel, subscribers and history", self.control)
        self.assertIn("legacy bot restores the channel CTA", self.control)

    def test_all_new_risk_boundaries_remain_closed(self) -> None:
        self.assertTrue(all(value is False for value in self.manifest["product_boundary"].values()))
        self.assertFalse(self.manifest["application"]["database_migration"])
        self.assertTrue(self.manifest["cutover"]["automatic_rollback_on_failure"])
        self.assertFalse(self.manifest["cutover"]["two_hour_observation_required"])
        self.assertTrue(self.manifest["cutover"]["risk_based_transport_observation_required"])
        self.assertEqual(
            self.manifest["cutover"]["required_channel_admin_rights"],
            ["change_channel_info", "post_messages", "edit_messages"],
        )
        self.assertIn("add_administrators", self.manifest["cutover"]["forbidden_channel_admin_rights"])
        semantics = self.manifest["cutover"]["channel_admin_rights_semantics"]
        self.assertEqual(semantics["chat_type"], "channel")
        self.assertEqual(
            semantics["can_restrict_members"],
            "TELEGRAM_CHANNEL_PROMOTION_BACKWARD_COMPATIBILITY_BOOLEAN",
        )
        self.assertFalse(semantics["independent_desktop_toggle_available"])
        self.assertTrue(semantics["subscriber_invites_forbidden"])
        self.assertTrue(semantics["administrator_promotion_forbidden"])
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.control))

    def test_recovery_baseline_preserves_s7_and_retires_duplicate_s8_monitoring(self) -> None:
        recovery = self.manifest["recovery_baseline"]
        self.assertEqual(recovery["s7_classification"], "INTENTIONAL_HISTORICAL_PROTECTED_FALLBACK")
        self.assertEqual(
            recovery["s7_contract_origin_commit"],
            "3613970c29af20351e09b157f0484f42d2525d3e",
        )
        self.assertTrue(recovery["s7_contract_preserved_during_cutover"])
        self.assertEqual(recovery["s8_health_timer_state"], "RETIRED_DISABLED_INACTIVE")
        self.assertTrue(recovery["s8_one_shot_health_gate_retained"])
        self.assertEqual(recovery["recurring_health_authority"], ["S9", "S10"])
        timer_block = re.search(r"readonly TIMERS=\((.*?)\n\)", self.controller, re.DOTALL)
        self.assertIsNotNone(timer_block)
        self.assertNotIn("tu1nz-adult-public-s8-health.timer", timer_block.group(1))

    def test_cutover_binds_source_and_target_copy_separately_and_restores_the_health_executable(self) -> None:
        for value in (
            'SOURCE_S8_COPY_SHA="6da055fa206ae3705c07051901cdc6e5d7ff3c83e0afe1568e2f24cc00f70e09"',
            'TARGET_S8_COPY_SHA="35050d02636630c23b7c97ae0184945b4587695f9a121e908f5f638bd668bd01"',
            'SOURCE_S10_COPY_SHA="7b0f8e286894a3ad1b5f014cb140db4a672564277bd66ad456965baf4b22b9c2"',
            'TARGET_S10_COPY_SHA="f995929dd9fe037fcc469e2c0573607f1d90fc757a76df89ef51d0f59c899fdc"',
            's10-runtime-executables-before.tar',
            'INSTALLED_HEALTH_SCRIPT_DRIFT',
            'install -o root -g root -m 0755',
        ):
            self.assertIn(value, self.controller)
        backup = (ROOT / "scripts/tu1nz_adult_public_s10_1_backup.sh").read_text(encoding="utf-8")
        self.assertIn("S10_RUNTIME_EXECUTABLES_BACKUP_MISSING", backup)
        self.assertIn("S10_RUNTIME_EXECUTABLE_UNSAFE", backup)
        self.assertIn("./tu1nz_adult_public_s8_health.py", backup)


if __name__ == "__main__":
    unittest.main()
