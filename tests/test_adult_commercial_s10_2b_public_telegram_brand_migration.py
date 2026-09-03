from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2b-public-telegram-brand-migration.json"
INSTALLER = ROOT / "scripts/tu1nz_adult_public_s10_2b_secret_install.sh"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2B_PUBLIC_TELEGRAM_BRAND_MIGRATION.md"


class CommercialS102BPublicTelegramBrandMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.installer = INSTALLER.read_text(encoding="utf-8")
        self.control = CONTROL.read_text(encoding="utf-8")

    def test_prepared_state_requires_identity_binding_before_activation(self) -> None:
        self.assertEqual(self.manifest["decision"], "GO_PREPARE_WAITING_BOTFATHER")
        self.assertFalse(self.manifest["active"])
        self.assertTrue(self.manifest["application"]["identity_binding_required_after_bot_creation"])
        self.assertEqual(self.manifest["public_identity"]["preferred_channel"], "@WantMeSeen")
        self.assertEqual(self.manifest["public_identity"]["preferred_bot"], "@wantmeseenbot")

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

    def test_secret_policy_is_outside_git_and_preserves_legacy_fallback(self) -> None:
        secret = self.manifest["secret_handling"]
        self.assertEqual(secret["target"], "/etc/tu1nz/adult-commercial-s10-2b-telegram.token")
        self.assertEqual(secret["mode"], "0600")
        self.assertEqual(secret["owner"], "root:root")
        self.assertTrue(secret["legacy_secret_preserved_for_fallback"])
        for key in ("chat_forbidden", "git_forbidden", "logs_forbidden", "history_forbidden"):
            self.assertTrue(secret[key])

    def test_continuity_and_rollback_preserve_the_existing_product_state(self) -> None:
        continuity = self.manifest["continuity"]
        self.assertTrue(continuity["existing_channel_preserved"])
        self.assertTrue(continuity["existing_channel_id_preserved"])
        self.assertTrue(continuity["postgres_waitlist_ssot_preserved"])
        self.assertFalse(continuity["database_schema_change"])
        self.assertEqual(continuity["old_bot_mode"], "FALLBACK_ONLY")
        self.assertIn("without a database restore", self.control)
        self.assertIn("The renamed channel may", self.control)

    def test_all_new_risk_boundaries_remain_closed(self) -> None:
        self.assertTrue(all(value is False for value in self.manifest["product_boundary"].values()))
        self.assertFalse(self.manifest["application"]["database_migration"])
        self.assertTrue(self.manifest["cutover"]["automatic_rollback_on_failure"])
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.control))


if __name__ == "__main__":
    unittest.main()
