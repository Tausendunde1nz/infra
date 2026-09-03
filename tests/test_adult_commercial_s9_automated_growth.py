from __future__ import annotations

import hashlib
import importlib.util
import json
import py_compile
import re
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s9-automated-growth.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s9_control.sh"
HEALTH = ROOT / "scripts/tu1nz_adult_public_s9_health.py"
TIMER_REPAIR = ROOT / "scripts/tu1nz_adult_public_s9_timer_liveness_repair.sh"
S10_HEALTH_LAUNCHER = ROOT / "scripts/tu1nz_adult_public_s10_1_s9_health.py"
LANDING = ROOT / "systemd/tu1nz-adult-public-s8-landing.service"
LANDING_DROP_IN = ROOT / "systemd/tu1nz-adult-public-s8-landing.service.d/s9-growth.conf"
UNITS = tuple(
    sorted(
        path
        for path in (ROOT / "systemd").glob("tu1nz-adult-public-s9-*")
        if path.is_file()
    )
)


class CommercialS9ControlTests(unittest.TestCase):
    def test_health_rejects_timer_without_future_elapse(self) -> None:
        specification = importlib.util.spec_from_file_location("s9_health_under_test", HEALTH)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with mock.patch.object(module, "_systemctl", side_effect=["", "infinity"]):
            self.assertFalse(module._timer_has_future("example.timer"))
        with mock.patch.object(module, "_systemctl", side_effect=["Thu 2026-09-03 04:15:00 UTC", "0"]):
            self.assertTrue(module._timer_has_future("example.timer"))

    def test_health_tolerates_own_transient_only_while_timer_is_running(self) -> None:
        specification = importlib.util.spec_from_file_location("s9_health_self_timer_under_test", HEALTH)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with (
            mock.patch.object(module, "SERVICES", ()),
            mock.patch.object(module, "TIMERS", (module.SELF_HEALTH_TIMER,)),
            mock.patch.object(
                module,
                "_systemctl",
                side_effect=["active", "enabled", "running", "", "infinity"],
            ),
        ):
            timer = module._system_health()["timers"][module.SELF_HEALTH_TIMER]
            self.assertFalse(timer["future_elapse"])
            self.assertTrue(timer["self_triggered"])
        with (
            mock.patch.object(module, "SERVICES", ()),
            mock.patch.object(module, "TIMERS", (module.SELF_HEALTH_TIMER,)),
            mock.patch.object(
                module,
                "_systemctl",
                side_effect=["active", "enabled", "waiting", "", "infinity"],
            ),
        ):
            with self.assertRaisesRegex(ValueError, "S9_TIMER_LIVENESS_RED"):
                module._system_health()

    def test_s10_health_launcher_is_bound_to_current_s9_health(self) -> None:
        target_hash = hashlib.sha256(HEALTH.read_bytes()).hexdigest()
        launcher = S10_HEALTH_LAUNCHER.read_text(encoding="utf-8")
        self.assertIn(f'TARGET_HEALTH_SHA256 = "{target_hash}"', launcher)

    def test_manifest_is_exactly_bound_and_fail_closed(self) -> None:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(value["application"]["commit"], "8ea16db18c683c89bf38c9b2b02e920d3da84e4f")
        self.assertEqual(value["application"]["tree"], "b446b84c5d9d23a7ac10b052892a275febd7fb2c")
        self.assertEqual(value["application"]["schema"], "0026_commercial_s9_telegram_channel")
        self.assertEqual(value["decision"], "GO_S9_PUBLIC_SFW_ORGANIC_AND_TELEGRAM")
        self.assertEqual(value["audience"]["organic_search"], "AUTOMATED_SUPPORTED")
        self.assertTrue(value["audience"]["audience_seeding_enabled"])
        self.assertEqual(value["audience"]["telegram_channel"], "AUTOMATED_SUPPORTED")
        self.assertEqual(value["audience"]["x"], "DISABLED_FOR_NOW")
        self.assertEqual(value["audience"]["reddit"], "DISABLED_FOR_NOW")
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

    def test_recurring_timers_keep_a_calendar_anchor(self) -> None:
        schedules = {
            "tu1nz-adult-public-s9-audience.timer": "OnCalendar=*:0/15",
            "tu1nz-adult-public-s9-nurture.timer": "OnCalendar=*:3/15",
            "tu1nz-adult-public-s9-health.timer": "OnCalendar=*:4/5",
        }
        for name, schedule in schedules.items():
            source = (ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertIn(schedule, source)
            self.assertNotIn("OnUnitActiveSec=", source)
            self.assertNotIn("OnBootSec=", source)

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
            "S9_TELEGRAM_CHANNEL_GREEN",
            "bot_can_post",
            "adult_content",
            "real_avs",
            "payments",
            "creator_invite",
            "controlled_beta",
            "sitemap_urls",
            "telegram_redirect",
            "S9_TIMER_LIVENESS_RED",
            "SELF_HEALTH_TIMER",
            '"self_triggered"',
            'substate == "running"',
            "NextElapseUSecRealtime",
            "NextElapseUSecMonotonic",
            '"future_elapse": future_elapse',
            'b"SFW CREATOR GUIDE"',
            'b"SFW-CREATOR-GUIDE"',
        ):
            self.assertIn(expected, source)
        self.assertNotIn("telegram_user_id", source)
        self.assertNotIn("private_chat_id", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_timer_liveness_repair_is_backup_first_bounded_and_reversible(self) -> None:
        source = TIMER_REPAIR.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", TIMER_REPAIR], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "capture_backup",
            "require_expected_revision",
            "require_public_baseline",
            "require_adult_runtime_closed",
            "systemd-analyze verify",
            "tu1nz-adult-public-s9-health.service",
            "tu1nz-adult-public-s9-audience.service",
            "SOURCE_AUDIENCE_CREDENTIAL_BINDING_MISSING",
            "SOURCE_HEALTH_CREDENTIAL_BINDING_MISSING",
            '"$backup_path"/*.service',
            "NextElapseUSecRealtime",
            "NextElapseUSecMonotonic",
            "restore_backup",
            "APPLY_FAILED_ROLLED_BACK",
            "S9_TIMER_LIVENESS_REPAIR_GREEN",
        ):
            self.assertIn(expected, source)
        main = source.split("main()", 1)[1]
        self.assertLess(main.index("capture_backup"), main.index("apply_repair"))
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("git reset", source)
        self.assertNotIn("git clean", source)
        self.assertNotIn("api.x.com", source)
        self.assertNotIn("reddit.com", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_controller_is_backup_first_bounded_and_reversible(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", CONTROLLER], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "require_backup",
            "BACKUP_S9_CONFIGURATION_MISSING",
            "BACKUP_S9_AUDIENCE_UNIT_MISSING",
            "BACKUP_S9_HEALTH_UNIT_MISSING",
            "BACKUP_S9_LANDING_DROP_IN_MISSING",
            "BACKUP_S9_MIGRATION_BINDING_MISSING",
            "normalize_s9_control_index_mode",
            "CONTROL_INDEX_MODE_UNEXPECTED",
            "require_adult_runtime_closed",
            "SOURCE_CONTROL_COMMIT_MISSING",
            "SOURCE_HEALTH_SCRIPT_MISSING",
            "require_s8_green",
            "0026_commercial_s9_telegram_channel.sql",
            "0026_commercial_s9_telegram_channel.down.sql",
            "MIGRATION_0026_STATE_DIVERGED",
            "S8_DATA_FINGERPRINT_DRIFT",
            "S9_EVIDENCE_FINGERPRINT_DRIFT",
            "systemd-analyze verify",
            "disable_s9",
            "restore_organic_baseline",
            "CHANNEL_ACTIVATION_ABORTED_ORGANIC_S9_STABLE",
            "S9_CHANNEL_ROLLBACK_TO_ORGANIC_GREEN",
            "s9_database_evidence_preserved",
            "channel-preflight",
            "activate-channel",
            "verify-channel",
            "rollback-channel",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("git reset", source)
        self.assertNotIn("git clean", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("api.x.com", source)
        self.assertNotIn("reddit.com", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

        normalization = source.split("normalize_s9_control_index_mode()", 1)[1].split("require_application_clean()", 1)[0]
        self.assertIn('640) chmod 0660 "$index" ;;', normalization)
        self.assertNotIn("644)", normalization)

    def test_credentials_are_only_systemd_credentials(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        nurture = (ROOT / "systemd/tu1nz-adult-public-s9-nurture.service").read_text(encoding="utf-8")
        audience = (ROOT / "systemd/tu1nz-adult-public-s9-audience.service").read_text(encoding="utf-8")
        health = (ROOT / "systemd/tu1nz-adult-public-s9-health.service").read_text(encoding="utf-8")
        self.assertIn('= "root:root"', controller)
        self.assertIn('= "600"', controller)
        self.assertNotIn('= "root:chatops"', controller)
        self.assertNotIn('= "640"', controller)
        self.assertIn("LoadCredential=s8_telegram_token:", nurture)
        self.assertIn("LoadCredential=s9_database_dsn:", nurture)
        self.assertIn("%d/s8_telegram_token", nurture)
        self.assertNotIn("Environment=", nurture)
        for unit in (audience, health):
            self.assertIn("LoadCredential=s8_telegram_token:", unit)
            self.assertIn("%d/s8_telegram_token", unit)
            self.assertIn("@tu1nz_adult_publishing", unit)
            self.assertNotIn("Environment=", unit)

    def test_backup_captures_the_organic_s9_rollback_surface(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_public_s8_backup.sh").read_text(encoding="utf-8")
        self.assertIn("adult-commercial-s9-growth.json", source)
        self.assertIn("tu1nz-adult-public-s9*", source)
        self.assertIn("0025_commercial_s9_automated_growth.sql", source)
        self.assertIn("s9-timers-before.txt", source)


if __name__ == "__main__":
    unittest.main()
