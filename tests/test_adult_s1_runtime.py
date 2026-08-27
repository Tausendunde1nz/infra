from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_TOOL = ROOT / "scripts" / "tu1nz_adult_s1_manifest.py"
GATE_TOOL = ROOT / "scripts" / "tu1nz_adult_s1_release_gate.py"
PATH_ACCESS_TOOL = ROOT / "scripts" / "tu1nz_adult_s1_path_access.sh"
UNIT = ROOT / "systemd" / "tu1nz-adult-publishing-s1.service"
BACKUP = ROOT / "scripts" / "tu1nz_encrypted_backup.sh"
PGDG_SOURCE = ROOT / "config" / "postgresql" / "pgdg.sources"
BOOTSTRAP = ROOT / "config" / "adult-publishing" / "staging-s1" / "bootstrap.sql"


def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def git(repository: Path, *arguments: str) -> str:
    result = run(["/usr/bin/git", "-C", str(repository), *arguments])
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def create_repository(path: Path, *, application: bool) -> str:
    path.mkdir(parents=True)
    git(path, "init", "-q")
    git(path, "config", "user.email", "m3.9@tu1nz.invalid")
    git(path, "config", "user.name", "M3.9 Test")
    if application:
        (path / "migrations").mkdir()
        (path / "migrations" / "0001.sql").write_text("SELECT 1;\n", encoding="ascii")
        (path / "requirements-m2.lock").write_text("psycopg==3.3.4\n", encoding="ascii")
    else:
        (path / "systemd").mkdir()
        (path / "systemd" / UNIT.name).write_bytes(UNIT.read_bytes())
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    return git(path, "rev-parse", "HEAD")


class PersistentS1RuntimeTest(unittest.TestCase):
    def test_path_access_is_execute_only_exact_and_non_recursive(self) -> None:
        source = PATH_ACCESS_TOOL.read_text(encoding="utf-8")
        for path in (
            "/opt/tu1nz_repos",
            "/opt/tu1nz_repos/releases",
            "/opt/tu1nz_repos/releases/adult-publishing",
            "/opt/tu1nz_repos/backups",
            "/opt/tu1nz_repos/backups/encrypted-system",
            "/etc/tu1nz",
            "/var/lib/tausendunde1nz/adult-publishing",
        ):
            self.assertIn(path, source)
        self.assertIn('user:${RUNTIME_USER}:--x', source)
        self.assertIn('mask::${MASKS[$index]}', source)
        self.assertIn("r-x", source)
        self.assertIn("S1_PATH_ACCESS_OK", source)
        self.assertNotIn("setfacl -R", source)
        self.assertNotIn("chmod -R", source)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.username = pwd.getpwuid(os.getuid()).pw_name
        self.groupname = grp.getgrgid(os.getgid()).gr_name
        self.release_root = self.root / "releases"
        self.application_root = self.release_root / "application"
        self.control_root = self.release_root / "control"
        self.venv_root = self.release_root / "venv"
        for path in (self.application_root, self.control_root, self.venv_root):
            path.mkdir(parents=True)

        application_source = self.root / "application-source"
        self.application_sha = create_repository(application_source, application=True)
        self.application = self.application_root / self.application_sha
        application_source.rename(self.application)
        self.application.chmod(0o750)
        control_source = self.root / "control-source"
        self.control_sha = create_repository(control_source, application=False)
        self.control = self.control_root / self.control_sha
        control_source.rename(self.control)
        self.control.chmod(0o750)

        self.application_active = self.release_root / "application-current"
        self.control_active = self.release_root / "control-current"
        self.application_active.symlink_to(self.application)
        self.control_active.symlink_to(self.control)

        self.venv = self.venv_root / self.application_sha
        (self.venv / "bin").mkdir(parents=True)
        self.venv.chmod(0o750)
        for name, content in (
            ("python", "#!/bin/sh\necho '3.3.4|0.1.0'\n"),
            ("tu1nz-adult-sandbox", "#!/bin/sh\nexit 0\n"),
            ("tu1nz-adult-staging-health", "#!/bin/sh\nexit 0\n"),
        ):
            target = self.venv / "bin" / name
            target.write_text(content, encoding="ascii")
            target.chmod(0o750)
        self.venv_active = self.release_root / "venv-current"
        self.venv_active.symlink_to(self.venv)

        self.configuration = self.root / "config"
        self.configuration.mkdir()
        self.configuration.chmod(0o750)
        self.write_config(
            "identity-policy.json",
            {
                "allowed_user_ids": [101, 202],
                "creator_user_ids": [101],
                "moderator_user_ids": [202],
            },
        )
        self.write_config(
            "core-identities.json",
            {
                "bindings": {
                    "a" * 64: "11111111-1111-4111-8111-111111111111",
                },
                "environment": "STAGING-S1",
            },
        )
        self.write_config(
            "media-registry.json",
            {"synthetic-file": {"sha256": "b" * 64, "source": "fixture"}},
        )
        (self.configuration / "subject-key").write_text("c" * 64 + "\n", encoding="ascii")
        (self.configuration / "runtime.env").write_text(
            "TU1NZ_TELEGRAM_STAGING_S1_TOKEN=123456789:"
            + "A" * 40
            + "\nTU1NZ_STAGING_S1_POSTGRES_DSN=\"postgresql:///tu1nz_adult_s1?"
            "host=/run/postgresql&user=tu1nz-adult-s1&sslmode=disable\"\n",
            encoding="ascii",
        )
        for path in self.configuration.iterdir():
            path.chmod(0o640)

        self.state = self.root / "state"
        (self.state / "media").mkdir(parents=True)
        self.state.chmod(0o750)
        (self.state / "media").chmod(0o700)
        self.write_state(
            "state.json",
            {
                "processed_updates": {},
                "submissions": {},
                "terms_acceptances": {},
                "version": 1,
            },
        )
        self.write_state(
            "telegram-offset.json",
            {"next_update_id": 123, "version": 1},
        )

        self.installed_unit = self.root / UNIT.name
        self.installed_unit.write_bytes(UNIT.read_bytes())
        self.installed_unit.chmod(0o644)
        self.archive = self.root / "tu1nz_system_backup_fixture.tar.gz"
        self.archive.write_bytes(b"synthetic backup")
        self.manifest = self.configuration / "release-manifest.json"
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.manifest.chmod(0o640)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, name: str, payload: object) -> None:
        (self.configuration / name).write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )

    def write_state(self, name: str, payload: object) -> None:
        path = self.state / name
        path.write_text(json.dumps(payload, sort_keys=True), encoding="ascii")
        path.chmod(0o600)

    def manifest_command(self, output: Path | None = None) -> list[str]:
        return [
            str(MANIFEST_TOOL),
            "--application-repository", str(self.application),
            "--control-repository", str(self.control),
            "--archive", str(self.archive),
            "--backup-completed-at", "2026-08-27T09:00:00Z",
            "--rpo-target-seconds", "86400",
            "--rto-target-seconds", "14400",
            "--retention-days", "7",
            "--local-source-required", "yes",
            "--approved-utc", "2026-08-27T09:01:00Z",
            "--output", str(output or self.manifest),
        ]

    def generate(self, output: Path | None = None) -> subprocess.CompletedProcess[str]:
        return run(self.manifest_command(output))

    def gate_command(self) -> list[str]:
        return [
            str(GATE_TOOL),
            "--manifest", str(self.manifest),
            "--application-repository", str(self.application_active),
            "--control-repository", str(self.control_active),
            "--application-release-root", str(self.application_root),
            "--control-release-root", str(self.control_root),
            "--venv", str(self.venv_active),
            "--configuration-root", str(self.configuration),
            "--state-root", str(self.state),
            "--installed-unit", str(self.installed_unit),
            "--runtime-user", self.username,
            "--runtime-group", self.groupname,
            "--release-user", self.username,
            "--configuration-user", self.username,
            "--unit-user", self.username,
            "--unit-group", self.groupname,
            "--require-active",
        ]

    def gate(self) -> subprocess.CompletedProcess[str]:
        return run(self.gate_command())

    def rewrite(self, path: Path, key: str, value: object) -> None:
        payload = json.loads(path.read_text(encoding="ascii"))
        payload[key] = value
        path.write_text(json.dumps(payload, sort_keys=True), encoding="ascii")
        path.chmod(0o640 if path.parent == self.configuration else 0o600)

    def test_positive_manifest_and_release_gate(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("S1_RELEASE_GATE_OK", result.stdout)

    def test_manifest_contract_and_mode(self) -> None:
        payload = json.loads(self.manifest.read_text(encoding="ascii"))
        self.assertEqual(payload["environment"], "STAGING-S1")
        self.assertTrue(payload["telegram_intake_enabled"])
        self.assertFalse(payload["live_publishers_enabled"])
        self.assertTrue(payload["mock_payment_only"])
        fresh = self.root / "fresh.json"
        result = self.generate(fresh)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o600)
        self.assertIn(hashlib.sha256(fresh.read_bytes()).hexdigest(), result.stdout)

    def test_manifest_refuses_dirty_release_and_overwrite(self) -> None:
        self.assertNotEqual(self.generate().returncode, 0)
        (self.application / "dirty").write_text("x", encoding="ascii")
        result = self.generate(self.root / "dirty.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dirty worktree", result.stderr)

    def test_gate_rejects_live_publishers(self) -> None:
        self.rewrite(self.manifest, "live_publishers_enabled", True)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_remote_database(self) -> None:
        runtime = self.configuration / "runtime.env"
        runtime.write_text(
            "TU1NZ_TELEGRAM_STAGING_S1_TOKEN=123456789:"
            + "A" * 40
            + "\nTU1NZ_STAGING_S1_POSTGRES_DSN=postgresql://db.example.invalid/s1\n",
            encoding="ascii",
        )
        runtime.chmod(0o640)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_wrong_identity_environment(self) -> None:
        path = self.configuration / "core-identities.json"
        self.rewrite(path, "environment", "STAGING-S0")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_nonempty_initial_state(self) -> None:
        path = self.state / "state.json"
        self.rewrite(path, "processed_updates", {"1": True})
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_unit_drift(self) -> None:
        self.installed_unit.write_text("[Unit]\n", encoding="ascii")
        self.installed_unit.chmod(0o644)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_requires_active_venv_symlink(self) -> None:
        self.venv_active.unlink()
        self.venv_active.mkdir()
        self.venv_active.chmod(0o750)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_unit_is_persistent_but_sandbox_bounded(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        self.assertIn("Type=simple", text)
        self.assertIn("Restart=on-failure", text)
        self.assertIn("WantedBy=multi-user.target", text)
        self.assertIn("--mode telegram-staging-s1", text)
        self.assertIn("--enable-persistent-telegram-staging-s1", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", text)
        self.assertIn("live_publishers_enabled", GATE_TOOL.read_text(encoding="utf-8"))
        self.assertFalse((UNIT.parent / "tu1nz-adult-publishing-s1.timer").exists())
        forbidden = ("X_TOKEN", "REDDIT_TOKEN", "PAYMENT_TOKEN", "AVS_TOKEN")
        self.assertFalse(any(value in text for value in forbidden))

    def test_encrypted_backup_covers_s1_release_config_state_and_database(self) -> None:
        text = BACKUP.read_text(encoding="utf-8")
        for required in (
            "releases/adult-publishing/staging-s1/application",
            "releases/adult-publishing/staging-s1/control",
            "releases/adult-publishing/staging-s1/venv",
            "tu1nz/adult-publishing/staging-s1",
            "tausendunde1nz/adult-publishing/staging-s1",
            "pg_dump --format=custom",
            "staging-s1-database.dump",
            'chown "$S1_RUNTIME_USER:$S1_RUNTIME_USER" "$DUMP_DIR"',
            'chmod 0700 "$DUMP_DIR"',
            "gcrypt01:backups",
        ):
            self.assertIn(required, text)
        self.assertNotIn("crontab", text)

    def test_postgresql_source_is_exact_noble_pgdg_https_contract(self) -> None:
        self.assertEqual(
            PGDG_SOURCE.read_text(encoding="ascii"),
            "Types: deb\n"
            "URIs: https://apt.postgresql.org/pub/repos/apt\n"
            "Suites: noble-pgdg\n"
            "Architectures: amd64\n"
            "Components: main\n"
            "Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc\n",
        )

    def test_bootstrap_is_synthetic_complete_and_least_privilege(self) -> None:
        text = BOOTSTRAP.read_text(encoding="ascii")
        for required in (
            "BEGIN;",
            "COMMIT;",
            "telegram_user_id",
            "'79000000-0000-4000-8000-000000000101', NULL",
            "m3.7-synthetic-policy-v1",
            "C3_SEXUAL_ACTIVITY",
            "'REDDIT', 'TEST'",
            "'TELEGRAM', 'TEST'",
            "'X', 'TEST'",
            "reddit-data-api+tu1nz-m3.4-reddit-synthetic-v1",
            "telegram-bot-api-10.3+tu1nz-m3.4-synthetic-v1",
            "x-api-v2+tu1nz-m3.4-x-synthetic-v1",
            'TO "tu1nz-adult-s1"',
            "REVOKE CONNECT ON DATABASE tu1nz_adult_s1 FROM PUBLIC",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "SUPERUSER",
            "CREATEDB",
            "CREATEROLE",
            "PASSWORD",
            "http://",
            "https://",
            "crontab",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
