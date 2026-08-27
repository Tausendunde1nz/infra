from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_TOOL = ROOT / "scripts" / "tu1nz_adult_staging_manifest.py"
GATE_TOOL = ROOT / "scripts" / "tu1nz_adult_s0_release_gate.py"
UNIT = ROOT / "systemd" / "tu1nz-adult-s0-release-verify.service"


def run(arguments: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, cwd=cwd, text=True, capture_output=True, check=False, timeout=30)


def git(repository: Path, *arguments: str) -> str:
    result = run(["/usr/bin/git", "-C", str(repository), *arguments])
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def create_repository(path: Path, application: bool = False) -> str:
    path.mkdir(parents=True)
    git(path, "init", "-q")
    git(path, "config", "user.email", "m3.5.2@tu1nz.invalid")
    git(path, "config", "user.name", "M3.5.2 Test")
    if application:
        (path / "migrations").mkdir()
        (path / "migrations" / "0001.sql").write_text("SELECT 1;\n", encoding="ascii")
        (path / "requirements-m2.lock").write_text("psycopg==3.3.4\n", encoding="ascii")
    else:
        (path / "control.txt").write_text("control\n", encoding="ascii")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    return git(path, "rev-parse", "HEAD")


class DeploymentReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release_root = self.root / "releases"
        self.application_release_root = self.release_root / "application"
        self.control_release_root = self.release_root / "control"
        source = self.root / "application-source"
        application_sha = create_repository(source, application=True)
        self.application = self.application_release_root / application_sha
        self.application_release_root.mkdir(parents=True)
        source.rename(self.application)
        self.application.chmod(0o750)
        control_source = self.root / "control-source"
        self.control_sha = create_repository(control_source)
        self.control_release_root.mkdir()
        self.control = self.control_release_root / self.control_sha
        control_source.rename(self.control)
        self.control.chmod(0o750)
        self.archive = self.root / "tu1nz_system_backup_fixture.tar.gz"
        self.archive.write_bytes(b"synthetic backup")
        self.manifest = self.root / "release-manifest.json"
        self.active = self.release_root / "application-current"
        self.control_active = self.release_root / "control-current"
        self.active.symlink_to(self.application)
        self.control_active.symlink_to(self.control)
        self.state = self.root / "state"
        self.media = self.state / "media"
        self.media.mkdir(parents=True)
        self.state.chmod(0o750)
        self.media.chmod(0o750)
        self.configuration = self.root / "config.json"
        self.configuration.write_text(
            json.dumps(
                {
                    "database_name": "tu1nz_adult_s0",
                    "database_socket": "/run/postgresql",
                    "environment": "STAGING-S0",
                    "media_storage_root": str(self.media),
                    "outbound_providers_enabled": False,
                    "required_platforms": ["REDDIT", "TELEGRAM", "X"],
                    "synthetic_data_only": True,
                },
                sort_keys=True,
            ),
            encoding="ascii",
        )
        self.configuration.chmod(0o640)
        self.username = pwd.getpwuid(os.getuid()).pw_name
        self.groupname = grp.getgrgid(os.getgid()).gr_name
        self.assertEqual(self.generate().returncode, 0)
        self.manifest.chmod(0o640)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest_command(self, output: Path | None = None) -> list[str]:
        return [
            str(MANIFEST_TOOL),
            "--application-repository", str(self.application),
            "--control-repository", str(self.control),
            "--archive", str(self.archive),
            "--backup-completed-at", "2026-08-27T08:00:00Z",
            "--rpo-target-seconds", "3600",
            "--rto-target-seconds", "1800",
            "--retention-days", "7",
            "--local-source-required", "yes",
            "--approved-utc", "2026-08-27T08:01:00Z",
            "--output", str(output or self.manifest),
        ]

    def generate(self, output: Path | None = None) -> subprocess.CompletedProcess[str]:
        return run(self.manifest_command(output))

    def gate_command(self) -> list[str]:
        return [
            str(GATE_TOOL),
            "--manifest", str(self.manifest),
            "--application-repository", str(self.active),
            "--control-repository", str(self.control),
            "--application-release-root", str(self.application_release_root),
            "--control-release-root", str(self.control_release_root),
            "--application-active-link", str(self.active),
            "--control-active-link", str(self.control_active),
            "--configuration", str(self.configuration),
            "--state-root", str(self.state),
            "--runtime-user", self.username,
            "--runtime-group", self.groupname,
            "--release-user", self.username,
            "--release-group", self.groupname,
            "--configuration-user", self.username,
            "--require-active",
        ]

    def gate(self) -> subprocess.CompletedProcess[str]:
        return run(self.gate_command())

    def rewrite_json(self, path: Path, key: str, value: object) -> None:
        payload = json.loads(path.read_text(encoding="ascii"))
        payload[key] = value
        path.write_text(json.dumps(payload, sort_keys=True), encoding="ascii")
        if path == self.configuration:
            path.chmod(0o640)

    def test_positive_manifest_and_release_gate(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("S0_RELEASE_GATE_OK", result.stdout)

    def test_manifest_is_mode_0600_and_reports_digest(self) -> None:
        fresh = self.root / "fresh.json"
        result = self.generate(fresh)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o600)
        self.assertIn(hashlib.sha256(fresh.read_bytes()).hexdigest(), result.stdout)

    def test_manifest_refuses_overwrite(self) -> None:
        result = self.generate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)

    def test_manifest_requires_positive_rpo(self) -> None:
        command = self.manifest_command(self.root / "bad-rpo.json")
        command[command.index("--rpo-target-seconds") + 1] = "0"
        result = run(command)
        self.assertNotEqual(result.returncode, 0)

    def test_manifest_requires_positive_retention(self) -> None:
        command = self.manifest_command(self.root / "bad-retention.json")
        command[command.index("--retention-days") + 1] = "0"
        result = run(command)
        self.assertNotEqual(result.returncode, 0)

    def test_manifest_rejects_approval_before_backup(self) -> None:
        command = self.manifest_command(self.root / "bad-time.json")
        command[command.index("--approved-utc") + 1] = "2026-08-27T07:59:59Z"
        result = run(command)
        self.assertNotEqual(result.returncode, 0)

    def test_manifest_rejects_dirty_application(self) -> None:
        (self.application / "dirty.txt").write_text("dirty", encoding="ascii")
        result = self.generate(self.root / "dirty.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dirty worktree", result.stderr)

    def test_gate_rejects_outbound_manifest(self) -> None:
        self.rewrite_json(self.manifest, "outbound_providers_enabled", True)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_non_synthetic_config(self) -> None:
        self.rewrite_json(self.configuration, "synthetic_data_only", False)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_credential_like_extra_config(self) -> None:
        self.rewrite_json(self.configuration, "telegram_token", "forbidden")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_remote_database_endpoint(self) -> None:
        self.rewrite_json(self.configuration, "database_socket", "db.example.invalid")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_wrong_active_release(self) -> None:
        self.active.unlink()
        self.active.symlink_to(self.release_root)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_wrong_control_release(self) -> None:
        self.control_active.unlink()
        self.control_active.symlink_to(self.control_release_root)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_ignored_release_file(self) -> None:
        (self.application / ".ignored").write_text("untracked", encoding="ascii")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_unsafe_configuration_mode(self) -> None:
        self.configuration.chmod(0o644)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_unsafe_release_mode(self) -> None:
        self.application.chmod(0o770)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_unsafe_manifest_mode(self) -> None:
        self.manifest.chmod(0o600)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_symlinked_media(self) -> None:
        self.media.rmdir()
        self.media.symlink_to(self.root)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_artifact_hash_drift(self) -> None:
        migration = self.application / "migrations" / "0001.sql"
        migration.write_text("SELECT 2;\n", encoding="ascii")
        git(self.application, "add", str(migration))
        git(self.application, "commit", "-qm", "drift")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_manifest_bound_local_rollback_layout_passes(self) -> None:
        source = self.root / "rollback-source"
        create_repository(source, application=True)
        (source / "README.md").write_text("prior synthetic release\n", encoding="ascii")
        git(source, "add", "README.md")
        git(source, "commit", "-qm", "prior release fixture")
        rollback_sha = git(source, "rev-parse", "HEAD")
        rollback = self.application_release_root / rollback_sha
        source.rename(rollback)
        rollback.chmod(0o750)
        rollback_manifest = self.root / "rollback-manifest.json"
        command = self.manifest_command(rollback_manifest)
        command[command.index("--application-repository") + 1] = str(rollback)
        result = run(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        rollback_manifest.chmod(0o640)
        self.active.unlink()
        self.active.symlink_to(rollback)
        self.application = rollback
        self.manifest = rollback_manifest
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unit_has_no_activation_timer_or_network(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", text)
        self.assertIn("PrivateNetwork=yes", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", text)
        self.assertNotIn("WantedBy=", text)
        self.assertFalse((UNIT.parent / "tu1nz-adult-s0-release-verify.timer").exists())


if __name__ == "__main__":
    unittest.main()
