from __future__ import annotations

import hashlib
import json
import py_compile
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s7-public-soft-launch.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s7_control.sh"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s7_backup.sh"
HEALTH = ROOT / "scripts/tu1nz_adult_public_s7_health.py"
UNIT = ROOT / "systemd/tu1nz-adult-public-s7.service"
HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s7-health.service"
HEALTH_TIMER = ROOT / "systemd/tu1nz-adult-public-s7-health.timer"
NGINX_ACTIVE = ROOT / "nginx/current/tu1nz.conf"
NGINX_DISABLED = ROOT / "nginx/current/tu1nz.s7-disabled.conf"


class CommercialS7PublicSoftLaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_application_release_is_exactly_bound(self) -> None:
        application = self.value["application"]
        self.assertEqual(application["merge_commit"], "3dd63f7a17626a4d8a8a3b58f317ae6917c33696")
        self.assertEqual(application["tree"], "e247b749ffa155a5ab8ea884ff77d205d5762dd7")
        self.assertEqual(application["schema"], "0021_commercial_s7_public_soft_launch")
        self.assertEqual(
            application["migration_chain_sha256"],
            "7db9b568bdb3439aa1d0d05990afb6c8230b750d710e9319f20e1a15cddd1a51",
        )
        self.assertTrue(self.value["control"]["exact_post_merge_sha_and_tree_required"])

    def test_product_boundary_is_public_sfw_only(self) -> None:
        self.assertTrue(all(value is False for value in self.value["product_boundary"].values()))
        authorization = self.value["authorization"]
        self.assertTrue(authorization["landing_activation_authorized"])
        self.assertTrue(authorization["waitlist_activation_authorized"])
        self.assertTrue(authorization["analytics_activation_authorized"])
        self.assertFalse(authorization["telegram_activation_authorized"])
        self.assertFalse(authorization["x_activation_authorized"])
        self.assertFalse(authorization["reddit_activation_authorized"])
        self.assertEqual(self.value["decision"], "GO_FOR_AUTOMATED_PUBLIC_SFW_LANDING_WAITLIST")

    def test_channels_are_automated_or_disabled_without_manual_fallback(self) -> None:
        channels = self.value["channels"]
        self.assertEqual(channels["landing"], "AUTOMATED_SUPPORTED")
        self.assertEqual(channels["x"], "DISABLED_FOR_NOW")
        self.assertEqual(channels["reddit"], "DISABLED_FOR_NOW")
        self.assertEqual(channels["telegram_bot"], "DISABLED_EXPECTED")
        self.assertEqual(channels["telegram_channel"], "DISABLED_EXPECTED")
        material = MANIFEST.read_text(encoding="ascii").lower()
        self.assertNotIn("manual fallback", material)
        self.assertNotIn("manual posting", material)

    def test_all_installed_material_is_hash_bound(self) -> None:
        expected = {
            UNIT: self.value["files"]["service_unit_sha256"],
            HEALTH: self.value["files"]["health_script_sha256"],
            NGINX_ACTIVE: self.value["files"]["active_nginx_sha256"],
            NGINX_DISABLED: self.value["files"]["disabled_nginx_sha256"],
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_public_unit_is_loopback_only_and_hardened(self) -> None:
        source = UNIT.read_text(encoding="utf-8")
        self.assertIn("IPAddressDeny=any", source)
        self.assertIn("IPAddressAllow=localhost", source)
        self.assertIn("LoadCredential=s7_form_secret:", source)
        self.assertIn("LoadCredential=s7_database_dsn:", source)
        self.assertIn("NoNewPrivileges=true", source)
        self.assertIn("ProtectSystem=strict", source)
        self.assertNotIn("telegram-token", source)
        self.assertNotIn("yoti", source.lower())
        self.assertNotIn("segpay", source.lower())

    def test_nginx_exposes_only_the_s7_loopback_runtime_and_has_kill_switch(self) -> None:
        active = NGINX_ACTIVE.read_text(encoding="utf-8")
        disabled = NGINX_DISABLED.read_text(encoding="utf-8")
        self.assertIn("location ^~ /adult/", active)
        self.assertIn("proxy_pass http://127.0.0.1:8095", active)
        self.assertIn("client_max_body_size 32k", active)
        self.assertNotIn("proxy_pass http://0.0.0.0", active)
        self.assertIn("location ^~ /adult/", disabled)
        self.assertIn("return 503", disabled)
        self.assertNotIn("proxy_pass", disabled)

    def test_health_is_automated_state_aware_and_uses_no_cron(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(str(HEALTH), cfile=str(Path(temporary) / "health.pyc"), doraise=True)
        source = HEALTH.read_text(encoding="utf-8")
        timer = HEALTH_TIMER.read_text(encoding="utf-8")
        health_unit = HEALTH_UNIT.read_text(encoding="utf-8")
        self.assertIn("S7_PUBLIC_HEALTH_GREEN", source)
        self.assertIn("DISABLED_FOR_NOW", source)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("IPAddressAllow=localhost", health_unit)
        self.assertNotIn("cron", timer.lower())

    def test_controller_is_syntax_valid_backup_first_and_bounded(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", CONTROLLER], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("require_backup", source)
        self.assertIn("require_other_adult_services_stopped", source)
        self.assertIn("merge --ff-only", source)
        self.assertIn("0021_commercial_s7_public_soft_launch.sql", source)
        self.assertIn("systemctl start", source)
        self.assertIn("systemctl enable", source)
        self.assertIn("systemd-analyze verify", source)
        self.assertIn("kill-switch", source)
        self.assertIn("abort_public_deploy", source)
        self.assertIn("DISABLED_FOR_NOW", source)
        self.assertNotIn("api.x.com", source)
        self.assertNotIn("reddit.com", source)
        self.assertNotIn("api.telegram.org", source)
        self.assertNotIn("rm -rf", source)
        self.assertIsNone(re.search(r"[0-9]{7,12}:[A-Za-z0-9_-]{30,}", source))

    def test_backup_covers_git_database_nginx_units_and_credentials_metadata(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", BACKUP], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "application.bundle",
            "control.bundle",
            "database-before.dump",
            "nginx-enabled-before.conf",
            "nginx-available-before.conf",
            "s7-configuration-before.tar",
            "s7-units-before.tar",
            "sha256sum --check --strict",
            "pg_restore --list",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("rm -rf", source)


if __name__ == "__main__":
    unittest.main()
