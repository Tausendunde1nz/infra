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
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s8-public-telegram-early-access.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s8_control.sh"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s8_backup.sh"
HEALTH = ROOT / "scripts/tu1nz_adult_public_s8_health.py"
UNIT = ROOT / "systemd/tu1nz-adult-public-s8-telegram.service"
HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-health.service"
HEALTH_TIMER = ROOT / "systemd/tu1nz-adult-public-s8-health.timer"
LANDING_UNIT = ROOT / "systemd/tu1nz-adult-public-s8-landing.service"
PUBLIC_PROXY = ROOT / "nginx/current/tu1nz.s8-public.conf"
PROXY_ACTIVATION = ROOT / "scripts/tu1nz_adult_public_s8_activate_proxy.sh"
ACCEPTANCE_EVIDENCE = ROOT / "analysis/COMMERCIAL_S8_2_STAGING_ACCEPTANCE_2026-08-30.diagnose"


class CommercialS8PublicTelegramControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_release_is_exactly_bound(self) -> None:
        application = self.value["application"]
        self.assertRegex(application["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(application["tree"], r"^[0-9a-f]{40}$")
        self.assertEqual(application["schema"], "0023_commercial_s8_health_recovery")
        self.assertEqual(
            application["migration_chain_sha256"],
            "b793eb9c5200956f5de52cc536fb125d60df7c7fb8a567808ed47ad71ebd82b8",
        )
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn(f'readonly TARGET_SHA="{application["commit"]}"', controller)
        self.assertIn(f'readonly TARGET_TREE="{application["tree"]}"', controller)

    def test_product_boundary_and_state_cap_are_fail_closed(self) -> None:
        self.assertTrue(all(value is False for value in self.value["product_boundary"].values()))
        self.assertEqual(self.value["data"]["maximum_automated_state"], "WAITLISTED")
        authorization = self.value["authorization"]
        self.assertTrue(authorization["dedicated_public_bot_authorized"])
        self.assertTrue(authorization["automated_waitlist_authorized"])
        for key in (
            "adult_media_authorized",
            "avs_authorized",
            "controlled_beta_authorized",
            "creator_invite_authorized",
            "payment_authorized",
            "production_adult_workflow_authorized",
            "publishing_authorized",
            "real_submission_authorized",
        ):
            self.assertFalse(authorization[key])

    def test_bot_is_dedicated_private_and_has_no_media_capability(self) -> None:
        bot = self.value["bot"]
        self.assertTrue(bot["dedicated"])
        self.assertTrue(bot["private_chats_only"])
        self.assertTrue(bot["group_joining_disabled_required"])
        self.assertFalse(bot["media_download_capability"])
        self.assertFalse(bot["webhook_allowed"])
        self.assertEqual(bot["token_storage"], "SYSTEMD_LOAD_CREDENTIAL_ONLY")

    def test_landing_and_legal_are_consistently_bound(self) -> None:
        landing = self.value["landing"]
        self.assertEqual(
            landing["deep_link"],
            f'https://t.me/{self.value["bot"]["username"]}?start=landing_s8_launch',
        )
        self.assertFalse(landing["legacy_web_waitlist_open"])
        self.assertFalse(self.value["legal"]["age_declaration_is_avs"])
        self.assertEqual(self.value["legal"]["privacy_version"], "s8-privacy-v1")
        self.assertEqual(self.value["legal"]["terms_version"], "s8-terms-v1")

    def test_notification_engine_is_opt_in_bounded_and_not_manual(self) -> None:
        notifications = self.value["notifications"]
        self.assertFalse(notifications["default_opt_in"])
        self.assertFalse(notifications["manual_individual_delivery"])
        self.assertTrue(notifications["opt_out_filtering"])
        self.assertTrue(notifications["provider_neutral_queue"])
        self.assertTrue(notifications["retry_after_bounded"])
        self.assertLessEqual(notifications["maximum_attempts"], 5)

    def test_all_installed_material_is_hash_bound(self) -> None:
        expected = {
            CONTROLLER: self.value["files"]["controller_sha256"],
            BACKUP: self.value["files"]["backup_script_sha256"],
            HEALTH: self.value["files"]["health_script_sha256"],
            UNIT: self.value["files"]["service_unit_sha256"],
            HEALTH_UNIT: self.value["files"]["health_service_sha256"],
            HEALTH_TIMER: self.value["files"]["health_timer_sha256"],
            ROOT / "systemd/tu1nz-adult-public-s8-probe.service": self.value["files"]["probe_service_sha256"],
            LANDING_UNIT: self.value["files"]["landing_service_sha256"],
            PROXY_ACTIVATION: self.value["files"]["proxy_activation_script_sha256"],
            PUBLIC_PROXY: self.value["files"]["public_proxy_sha256"],
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_service_is_hardened_and_uses_loadcredential(self) -> None:
        source = UNIT.read_text(encoding="utf-8")
        self.assertIn("LoadCredential=s8_telegram_token:", source)
        self.assertIn("LoadCredential=s8_database_dsn:", source)
        self.assertIn("NoNewPrivileges=true", source)
        self.assertIn("ProtectSystem=strict", source)
        self.assertIn("MemoryDenyWriteExecute=true", source)
        self.assertNotIn("Environment=", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_health_is_automated_privacy_safe_and_has_no_cron(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(str(HEALTH), cfile=str(Path(temporary) / "health.pyc"), doraise=True)
        source = HEALTH.read_text(encoding="utf-8")
        timer = HEALTH_TIMER.read_text(encoding="utf-8")
        health_unit = HEALTH_UNIT.read_text(encoding="utf-8")
        self.assertIn("S8_DIAGNOSTIC", source)
        self.assertIn("elapsed_ms", source)
        self.assertIn("sqlstate", source)
        self.assertNotIn("telegram_user_id", source)
        self.assertNotIn("private_chat_id", source)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertNotIn("cron", timer.lower())
        self.assertIn("LoadCredential=s8_telegram_token:", health_unit)
        self.assertIn('LANDING_URL = "http://127.0.0.1:18096/adult/"', source)
        self.assertIn('LANDING_HEALTH_URL = "http://127.0.0.1:18096/adult/health"', source)
        self.assertNotIn("127.0.0.1:8096", source)

    def test_controller_is_backup_first_reversible_and_bounded(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", CONTROLLER], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "require_backup",
            "require_adult_runtime_closed",
            "require_bot_secret",
            "0022_commercial_s8_public_telegram_early_access.sql",
            "systemd-analyze verify",
            "configure_bot",
            "diagnostic_probe",
            "await_s7_green",
            "await_external_landing_green",
            "S8_LANDING_READINESS_TIMEOUT",
            "S8_LANDING_CONTRACT_DRIFT",
            "S8_PUBLIC_PROXY_NOT_INSTALLED",
            "S8_ROOT_CAUSE",
            "NOTIFIER_UPDATE_PRIVILEGE_42501_THEN_UNTYPED_POLLING_HEARTBEAT_42P18_COMPOUNDED_BY_S7_START_LIMIT_ORCHESTRATION",
            "open-acceptance",
            "activate-public",
            "kill-switch",
            "set_runtime_control false",
            "abort_deploy",
            "rollback",
            "recover-s7-start-limit",
            "S7_RECOVERY_GREEN",
            "waitlist_data_preserved",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("git reset", source)
        self.assertNotIn("git clean", source)
        self.assertNotIn("getFile", source)
        self.assertNotIn("api.x.com", source)
        self.assertNotIn("reddit.com", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_public_activation_preserves_s7_and_uses_bounded_landing_readiness(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        readiness = source.split("await_s7_green()", 1)[1].split("require_s8_inactive_or_absent()", 1)[0]
        self.assertIn("seq 1 30", readiness)
        self.assertIn("sleep 2", readiness)
        activate = source.split("activate_public()", 1)[1].split("verify()", 1)[0]
        self.assertNotIn('systemctl stop "$S7_SERVICE"', activate)
        self.assertNotIn("start_s7_once", activate)
        self.assertIn("require_s7_green", activate)
        self.assertIn("require_public_proxy_installed", activate)
        self.assertIn("systemctl reload nginx.service", activate)
        self.assertIn('await_external_landing_green || fail "S8_LANDING_READINESS_TIMEOUT"', activate)
        self.assertNotIn("systemctl restart", source)

    def test_s8_landing_candidate_keeps_s7_as_automatic_proxy_fallback(self) -> None:
        landing = LANDING_UNIT.read_text(encoding="utf-8")
        proxy = PUBLIC_PROXY.read_text(encoding="utf-8")
        self.assertIn("tu1nz-adult-public-s7.service", landing)
        self.assertIn("adult-commercial-s8-landing.json", landing)
        self.assertIn("tu1nz-public-s8-landing", landing)
        self.assertNotIn("LoadCredential", landing)
        self.assertIn("server 127.0.0.1:18096", proxy)
        self.assertIn("server 127.0.0.1:8095 backup", proxy)
        self.assertIn("proxy_pass http://tu1nz_adult_public", proxy)

    def test_s7_start_limit_recovery_is_exact_backup_bound_and_single_start(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        recovery = source.split("recover_s7_start_limit()", 1)[1].split('case "${1:-}"', 1)[0]
        self.assertIn("require_backup", recovery)
        self.assertIn("require_s7_start_limit_failure", recovery)
        self.assertIn("start_s7_once", recovery)
        self.assertEqual(recovery.count("start_s7_once"), 1)
        self.assertIn("await_s7_green", recovery)
        self.assertIn("external_s7_health", recovery)
        helper = source.split("start_s7_once()", 1)[1].split("require_s7_start_limit_failure()", 1)[0]
        self.assertIn('systemctl reset-failed "$S7_SERVICE"', helper)
        self.assertEqual(helper.count('systemctl start "$S7_SERVICE"'), 1)

    def test_s8_recovery_accepts_only_dead_failed_units_before_single_start(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn('inactive|failed) ;;', source)
        self.assertIn('S8_SERVICE_NOT_DISABLED', source)
        self.assertIn('S8_LANDING_NOT_DISABLED', source)
        self.assertIn('systemctl reset-failed "$LANDING_SERVICE"', source)
        self.assertIn('systemctl reset-failed "$S8_SERVICE"', source)
        self.assertNotIn('systemctl restart "$LANDING_SERVICE"', source)
        self.assertNotIn('systemctl restart "$S8_SERVICE"', source)

    def test_backup_supports_only_exact_failed_s7_recovery_state(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        self.assertIn('"create-s7-recovery"', source)
        self.assertIn("S7_RECOVERY_RESULT_NOT_START_LIMIT_HIT", source)
        self.assertIn("S8_SERVICE_NOT_INACTIVE", source)
        self.assertIn("S8_SERVICE_NOT_DISABLED", source)
        self.assertIn("S8_S7_RECOVERY_BACKUP_GREEN", source)

    def test_backup_covers_repositories_database_units_and_secret_metadata_only(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", BACKUP], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            "application.bundle",
            "control.bundle",
            "database-before.dump",
            "public-configuration-before.tar",
            "public-units-before.tar",
            "credential-metadata-before.txt",
            "sha256sum --check --strict",
            "pg_restore --list",
            "GIT_INDEX_OWNERSHIP_DRIFT",
            "GIT_INDEX_MODE_DRIFT",
            "bundle create - --all",
            "verify_bundle_isolated",
            "git init --bare --quiet",
            "tu1nz-s8-bundle-verify",
        ):
            self.assertIn(expected, source)
        self.assertIn('runuser -u chatops -- git -C "$APPLICATION_ROOT" bundle create - --all', source)
        self.assertIn('runuser -u chatops -- git -C "$CONTROL_ROOT" bundle create - --all', source)
        self.assertIn('runuser -u chatops -- git -C "$APPLICATION_ROOT" rev-parse', source)
        self.assertIn('runuser -u chatops -- git -C "$CONTROL_ROOT" rev-parse', source)
        self.assertIn('runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1', source)
        self.assertIn('runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1', source)
        self.assertNotIn('git -c safe.directory="$APPLICATION_ROOT"', source)
        self.assertNotIn('git -c safe.directory="$CONTROL_ROOT"', source)
        self.assertNotIn("adult-commercial-s8-telegram.token' -print0", source)
        self.assertNotIn("rm -rf", source)

    def test_backup_has_narrow_idempotent_git_index_mode_recovery(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        controller = CONTROLLER.read_text(encoding="utf-8")
        recovery = source.split("normalize_git_index_mode()", 1)[1].split("verify_bundle_isolated()", 1)[0]
        self.assertIn("umask 0007", source)
        self.assertIn("umask 0007", controller)
        self.assertIn('600|660) ;;', recovery)
        self.assertIn('644) chmod 0660 "$index" ;;', recovery)
        self.assertIn('GIT_INDEX_MODE_UNEXPECTED', recovery)
        self.assertIn('[ -f "$index" ] && [ ! -L "$index" ]', recovery)
        self.assertIn('normalize-index-modes', source)
        self.assertIn('S8_GIT_INDEX_MODES_GREEN', source)

    def test_kill_switch_needs_no_deployment_and_preserves_data(self) -> None:
        switch = self.value["kill_switch"]
        self.assertTrue(switch["database_backed"])
        self.assertFalse(switch["deployment_required"])
        self.assertTrue(switch["blocks_new_waitlist_joins"])
        self.assertTrue(switch["blocks_new_broadcasts"])
        self.assertTrue(switch["preserves_existing_waitlist"])

    def test_internal_acceptance_is_green_while_public_activation_remains_pending(self) -> None:
        execution = self.value["execution"]
        self.assertEqual(execution["live_acceptance"], "GREEN_INTERNAL_SFW")
        self.assertEqual(execution["public_activation"], "PENDING")
        self.assertEqual(
            execution["status"],
            "S8_2_INTERNAL_ACCEPTANCE_GREEN_KILL_SWITCH_CLOSED",
        )
        self.assertFalse(self.value["kill_switch"]["public_telegram_early_access_enabled"])
        self.assertTrue(ACCEPTANCE_EVIDENCE.is_file())
        evidence = ACCEPTANCE_EVIDENCE.read_text(encoding="utf-8")
        self.assertIn("KILL_SWITCH_CLOSED", evidence)
        self.assertIn("PUBLIC_ACTIVATION_PENDING", evidence)
        self.assertIn("file was not", evidence)
        self.assertNotIn("GO_PUBLIC_OBSERVATION_GREEN", evidence)

    def test_public_proxy_activation_is_backup_first_and_reversible(self) -> None:
        source = PROXY_ACTIVATION.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", PROXY_ACTIVATION], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('git -C "$1" rev-parse "$2"', source)
        self.assertNotIn('git -C "$1" "$2"', source)
        self.assertIn('"$BACKUP_TOOL" create "$BACKUP"', source)
        self.assertIn('"$BACKUP_TOOL" verify-existing "$BACKUP"', source)
        self.assertLess(
            source.index('"$BACKUP_TOOL" verify-existing "$BACKUP"'),
            source.index('install -o root -g root -m 0644 "$CANDIDATE_PROXY" "$ACTIVE_PROXY"'),
        )
        self.assertIn("rollback_public_attempt", source)
        self.assertIn('install -o root -g root -m 0644 "$BACKUP/nginx-enabled-before.conf"', source)
        self.assertIn('systemctl reload nginx.service', source)
        self.assertIn('"$CONTROLLER" kill-switch', source)
        self.assertIn('systemctl disable --now "$HEALTH_TIMER" "$S8_SERVICE" "$LANDING_SERVICE"', source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("rm -rf", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))


if __name__ == "__main__":
    unittest.main()
