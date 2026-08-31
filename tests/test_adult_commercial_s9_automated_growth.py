from __future__ import annotations

import json
import py_compile
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s9-automated-growth.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s9_control.sh"
HEALTH = ROOT / "scripts/tu1nz_adult_public_s9_health.py"
LANDING = ROOT / "systemd/tu1nz-adult-public-s8-landing.service"
LANDING_DROP_IN = ROOT / "systemd/tu1nz-adult-public-s8-landing.service.d/s9-growth.conf"
UNITS = tuple(sorted((ROOT / "systemd").glob("tu1nz-adult-public-s9-*")))


class CommercialS9ControlTests(unittest.TestCase):
    def test_manifest_is_exactly_bound_and_fail_closed(self) -> None:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(value["application"]["commit"], "d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79")
        self.assertEqual(value["application"]["tree"], "c9fa052bceb1e7ec3b84a5254d399acde9ff0989")
        self.assertEqual(value["decision"], "GO_S9_PUBLIC_SFW_ORGANIC_ONLY")
        self.assertEqual(value["audience"]["organic_search"], "AUTOMATED_SUPPORTED")
        self.assertFalse(value["audience"]["audience_seeding_enabled"])
        self.assertFalse(value["invite_readiness"]["invite_automation_enabled"])
        self.assertEqual(value["invite_readiness"]["maximum_automated_state"], "ELIGIBLE")
        self.assertEqual(value["invite_readiness"]["payment_outcome"], "PAYMENT_NOT_REQUIRED")
        self.assertTrue(all(flag is False for flag in value["product_boundary"].values()))

    def test_units_are_hardened_systemd_only(self) -> None:
        self.assertEqual(len(UNITS), 9)
        for unit in UNITS:
            source = unit.read_text(encoding="utf-8")
            self.assertNotIn("cron", source.casefold())
            if unit.suffix == ".service":
                self.assertIn("NoNewPrivileges=true", source)
                self.assertIn("ProtectSystem=strict", source)
                self.assertIn("MemoryDenyWriteExecute=true", source)
                self.assertNotIn("Environment=", source)
        for timer in (value for value in UNITS if value.suffix == ".timer"):
            source = timer.read_text(encoding="utf-8")
            self.assertIn("Persistent=true", source)
            self.assertIn("WantedBy=timers.target", source)

    def test_landing_uses_private_aggregate_state(self) -> None:
        historical = LANDING.read_text(encoding="utf-8")
        source = LANDING_DROP_IN.read_text(encoding="utf-8")
        self.assertIn("--aggregate-state /var/lib/tu1nz-adult-public-s9/landing-aggregates.json", source)
        self.assertIn("StateDirectory=tu1nz-adult-public-s9", source)
        self.assertIn("StateDirectoryMode=0700", source)
        self.assertNotIn("aggregate-state", historical)
        self.assertNotIn("LoadCredential", source)

    def test_health_is_privacy_safe_and_checks_all_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(str(HEALTH), cfile=str(Path(temporary) / "health.pyc"), doraise=True)
        source = HEALTH.read_text(encoding="utf-8")
        for expected in (
            "S9_PUBLIC_SFW_GROWTH_GREEN",
            "DISABLED_EXPECTED",
            "adult_content",
            "real_avs",
            "payments",
            "creator_invite",
            "controlled_beta",
            "sitemap_urls",
            "telegram_redirect",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("telegram_user_id", source)
        self.assertNotIn("private_chat_id", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_controller_is_backup_first_bounded_and_reversible(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", CONTROLLER], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "require_backup",
            "require_adult_runtime_closed",
            "require_s8_green",
            "0025_commercial_s9_automated_growth.sql",
            "MIGRATION_0025_PARTIAL_STATE",
            "S8_DATA_FINGERPRINT_DRIFT",
            "systemd-analyze verify",
            "disable_s9",
            "restore_baseline",
            "DEPLOYMENT_ABORTED_S8_STABLE",
            "S9_ROLLBACK_TO_S8_GREEN",
            "s9_database_evidence_preserved",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("git reset", source)
        self.assertNotIn("git clean", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("api.x.com", source)
        self.assertNotIn("reddit.com", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_credentials_are_only_systemd_credentials(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        nurture = (ROOT / "systemd/tu1nz-adult-public-s9-nurture.service").read_text(encoding="utf-8")
        self.assertIn('= "root:root"', controller)
        self.assertIn('= "600"', controller)
        self.assertNotIn('= "root:chatops"', controller)
        self.assertNotIn('= "640"', controller)
        self.assertIn("LoadCredential=s8_telegram_token:", nurture)
        self.assertIn("LoadCredential=s9_database_dsn:", nurture)
        self.assertIn("%d/s8_telegram_token", nurture)
        self.assertNotIn("Environment=", nurture)


if __name__ == "__main__":
    unittest.main()
