from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "tu1nz_adult_commercial_s0_install.sh"
BOOTSTRAP = ROOT / "config" / "adult-publishing" / "staging-s0-commercial" / "bootstrap.sql"
IDENTITIES = BOOTSTRAP.with_name("core-identities.synthetic.json")
STATE = BOOTSTRAP.with_name("state.empty.json")


class CommercialS0StoppedInstallationTest(unittest.TestCase):
    def test_installer_is_explicitly_two_phase_and_never_starts_candidate(self) -> None:
        source = INSTALLER.read_text(encoding="ascii")
        for required in (
            "preflight|prepare|partial-preflight|recover-partial|reject-incomplete-bundle|resume-prepare|resume-after-venv-build|resume-after-control-stage|finalize-schema-acceptance|advance-prepared-control|verify-prepared|install-unit",
            "M4_23_STOPPED_INSTALLATION_PREFLIGHT_OK",
            "M4_23_STOPPED_CANDIDATE_PREPARED_OK",
            "M4_23_STOPPED_UNIT_INSTALLED_OK",
            "tu1nz_adult_commercial_installation_authorization_gate.py",
            "tu1nz_adult_commercial_path_access.sh\" apply",
            "tu1nz_adult_commercial_host_access_gate.py",
            "m4_15_durable_commercial_persistence_schema_acceptance.sql",
            "release-manifest.json\" ]] || fail \"post-backup approved release manifest required",
            "systemd-analyze verify",
            "systemctl stop tu1nz_encrypted_backup.timer",
            "systemctl start tu1nz_encrypted_backup.timer",
            "M4_23_PARTIAL_BOUNDARY_OK",
            "M4_23_PARTIAL_TIMER_RECOVERED_OK",
            "M4_23_INCOMPLETE_BUNDLE_PRESERVED_OK",
            "M4_23_BUILT_PARTIAL_BOUNDARY_OK",
            "M4_23_MIGRATION_PARTIAL_BOUNDARY_OK",
            "M4_23_SCHEMA_PARTIAL_BOUNDARY_OK",
            "M4_23_PREPARED_CONTROL_BOUNDARY_OK",
            "resumed_after_venv_build",
            "resumed_after_control_stage",
            "finalized_schema_acceptance",
            "advanced_prepared_control",
            'git -c "safe.directory=$CONTROL_REPOSITORY" -C "$CONTROL_REPOSITORY" bundle verify',
            "git@github.com-infra:Tausendunde1nz/infra.git",
            'git_read "$app_target" archive --format=tar.gz',
            "/usr/bin/chmod g-s",
            '"$app_target/build"',
            '"$app_target/src/tu1nz_adult_publishing_core.egg-info"',
            "rejected-immutable-build-output-$APPLICATION_SHA",
            "--file=-",
            '<"$app_target/migrations/$migration"',
            '--username="$RUNTIME_ROLE"',
            "/usr/bin/mv -T --",
            "tu1nz_encrypted_backup.sh.before-commercial-dump-fix",
            "tu1nz_encrypted_backup.sh.before-commercial-stdout-fix",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "systemctl start \"$UNIT\"",
            "systemctl restart \"$UNIT\"",
            "systemctl enable \"$UNIT\"",
            "WantedBy=",
            "docker run",
            "TELEGRAM_TOKEN",
            "X_TOKEN",
            "REDDIT_TOKEN",
            "PAYMENT_TOKEN",
            "AVS_TOKEN",
            "git clean -fdx",
            "rm -rf",
            '--file="$app_target/migrations/$migration"',
            '--file="$control_target/config/adult-publishing/staging-s0-commercial/bootstrap.sql"',
        ):
            self.assertNotIn(forbidden, source)

    def test_installer_binds_final_application_and_absent_state_backup(self) -> None:
        source = INSTALLER.read_text(encoding="ascii")
        self.assertIn("52494d6121660ead53774deb8616701f14bb7a8f", source)
        self.assertIn("tu1nz_system_backup_20260828T14-39-46Z.tar.gz", source)
        self.assertIn("011856113239a94c83104e9156336dfc0cfbae8208f6cfdc0cee8f68d4316887", source)
        self.assertIn("pre-install archive digest mismatch", source)
        self.assertIn("installed backup baseline drift", source)
        self.assertIn("commercial-aware backup script is not installed", source)
        self.assertIn("exact empty partial staging root required", source)
        self.assertIn("partial commercial database is not empty", source)
        self.assertIn("application bundle digest mismatch", source)
        self.assertIn("a646e244641ae7297834b413c863e43f070458565406faf71fd1dc36868e3167", source)
        self.assertIn("rejected-incomplete-application-", source)

    def test_timer_recovery_state_is_global_and_bundle_is_root_private(self) -> None:
        source = INSTALLER.read_text(encoding="ascii")
        self.assertIn("BACKUP_TIMER_PAUSED=0", source)
        self.assertNotIn("local backup_timer_paused", source)
        self.assertIn("600:root:root:1", source)
        self.assertIn("/opt/tu1nz_repos/backups/m4-23-input/", source)
        self.assertNotIn('/usr/bin/git bundle verify "$APPLICATION_BUNDLE"', source)
        self.assertNotIn("git config --global", source)

    def test_synthetic_identity_and_empty_state_are_exact(self) -> None:
        identities = json.loads(IDENTITIES.read_text(encoding="ascii"))
        self.assertEqual(identities["environment"], "STAGING-S0-COMMERCIAL-CANDIDATE")
        self.assertEqual(
            identities["bindings"],
            {"0" * 64: "41900000-0000-4000-8000-000000000001"},
        )
        self.assertEqual(
            json.loads(STATE.read_text(encoding="ascii")),
            {
                "creator_verifications": {},
                "processed_updates": {},
                "product_events": [],
                "submissions": {},
                "terms_acceptances": {},
                "version": 2,
            },
        )

    def test_bootstrap_is_synthetic_and_least_privilege_scoped(self) -> None:
        source = BOOTSTRAP.read_text(encoding="ascii")
        for required in (
            "REVOKE CONNECT ON DATABASE tu1nz_adult_commercial_s0 FROM PUBLIC",
            "tu1nz_adult_commercial_s0_runtime",
            "tu1nz_adult_commercial_s0_migrator",
            "m3.7-synthetic-policy-v1",
            "'REDDIT', 'TEST'",
            "'TELEGRAM', 'TEST'",
            "'X', 'TEST'",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
        ):
            self.assertIn(required, source)
        for forbidden in ("http://", "https://", "PASSWORD '", "TELEGRAM_TOKEN", "PAYMENT_TOKEN"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
