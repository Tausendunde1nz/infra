from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_TOOL = ROOT / "scripts" / "tu1nz_adult_commercial_s0_manifest.py"
GATE_TOOL = ROOT / "scripts" / "tu1nz_adult_commercial_s0_release_gate.py"
UNIT = ROOT / "systemd" / "tu1nz-adult-commercial-s0.service"
READINESS = ROOT / "manifests" / "adult-publishing-commercial-readiness.m4-18.json"
BACKUP = ROOT / "scripts" / "tu1nz_encrypted_backup.sh"
ENVIRONMENT = "STAGING-S0-COMMERCIAL-CANDIDATE"


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
    git(path, "config", "user.email", "m4.19@tu1nz.invalid")
    git(path, "config", "user.name", "M4.19 Test")
    if application:
        (path / "migrations").mkdir()
        for name in (
            "0014_m4_15_durable_commercial_persistence.sql",
            "0014_m4_15_durable_commercial_persistence.down.sql",
        ):
            (path / "migrations" / name).write_text("SELECT 1;\n", encoding="ascii")
        (path / "requirements-m2.lock").write_text("psycopg==3.3.4\n", encoding="ascii")
        (path / "pyproject.toml").write_text(
            '[project.scripts]\n'
            'tu1nz-commercial-runtime-candidate = "tu1nz_sandbox.commercial_candidate:runtime_entrypoint"\n'
            'tu1nz-commercial-candidate-health = "tu1nz_sandbox.commercial_candidate:health_entrypoint"\n',
            encoding="ascii",
        )
        candidate = {
            "active": False,
            "commercial_composition_enabled": True,
            "commercial_contract_version": "tu1nz-commercial-persistence-m4.15-v1",
            "database_scope": "LOCAL_ONLY",
            "environment": ENVIRONMENT,
            "external_providers_enabled": False,
            "installed": False,
            "network_enabled": False,
            "real_media_enabled": False,
            "persistence_schema_version": "0014_m4_15_durable_commercial_persistence",
            "repository_entrypoint_available": True,
            "runtime_version": "tu1nz-commercial-runtime-candidate-m4.17-v1",
            "server_enabled": False,
            "synthetic_data_only": True,
            "synthetic_publishers_only": True,
        }
        target = path / "config" / "commercial-runtime-candidate.disabled.json"
        target.parent.mkdir()
        target.write_text(json.dumps(candidate, sort_keys=True), encoding="ascii")
    else:
        (path / "systemd").mkdir()
        (path / "systemd" / UNIT.name).write_bytes(UNIT.read_bytes())
        (path / "manifests").mkdir()
        (path / "manifests" / READINESS.name).write_bytes(READINESS.read_bytes())
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    return git(path, "rev-parse", "HEAD")


class CommercialS0InstallationDesignTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.username = pwd.getpwuid(os.getuid()).pw_name
        self.groupname = grp.getgrgid(os.getgid()).gr_name
        self.release_root = self.root / "release"
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
            ("tu1nz-commercial-runtime-candidate", "#!/bin/sh\nexit 0\n"),
            ("tu1nz-commercial-candidate-health", "#!/bin/sh\nexit 0\n"),
        ):
            target = self.venv / "bin" / name
            target.write_text(content, encoding="ascii")
            target.chmod(0o750)
        self.venv_active = self.release_root / "venv-current"
        self.venv_active.symlink_to(self.venv)

        self.configuration = self.root / "config"
        self.configuration.mkdir()
        self.configuration.chmod(0o750)
        (self.configuration / "runtime.env").write_text(
            'TU1NZ_COMMERCIAL_CANDIDATE_POSTGRES_DSN="'
            "postgresql:///tu1nz_adult_commercial_s0?host=/run/postgresql"
            '&user=tu1nz_adult_commercial_s0_runtime&sslmode=disable"\n',
            encoding="ascii",
        )
        (self.configuration / "runtime.env").chmod(0o640)
        (self.configuration / "core-identities.json").write_text(
            json.dumps(
                {
                    "bindings": {
                        "a" * 64: "41900000-0000-4000-8000-000000000001",
                    },
                    "environment": ENVIRONMENT,
                },
                sort_keys=True,
            ),
            encoding="ascii",
        )
        (self.configuration / "core-identities.json").chmod(0o600)

        self.state = self.root / "state"
        self.state.mkdir()
        self.state.chmod(0o700)
        (self.state / "state.json").write_text(
            json.dumps(
                {
                    "creator_verifications": {},
                    "processed_updates": {},
                    "product_events": [],
                    "submissions": {},
                    "terms_acceptances": {},
                    "version": 2,
                },
                sort_keys=True,
            ),
            encoding="ascii",
        )
        (self.state / "state.json").chmod(0o600)

        self.installed_unit = self.root / UNIT.name
        self.installed_unit.write_bytes(UNIT.read_bytes())
        self.installed_unit.chmod(0o644)
        self.archive = self.root / "tu1nz_system_backup_m4-19-fixture.tar.gz"
        self.create_archive()
        self.manifest = self.configuration / "release-manifest.json"
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.manifest.chmod(0o640)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_archive(self) -> None:
        source = self.root / "archive-source"
        base = source / "releases" / "adult-publishing" / "staging-s0-commercial"
        for kind, sha in (
            ("application", self.application_sha),
            ("control", self.control_sha),
            ("venv", self.application_sha),
        ):
            target = base / kind / sha
            target.mkdir(parents=True)
            (target / "fixture").write_text(kind + "\n", encoding="ascii")
            if kind == "venv":
                (target / "python3").write_text("synthetic interpreter\n", encoding="ascii")
                (target / "python").symlink_to("python3")
        config = source / "tu1nz" / "adult-publishing" / "staging-s0-commercial"
        config.mkdir(parents=True)
        (config / "core-identities.json").write_text("{}\n", encoding="ascii")
        state = (
            source
            / "tausendunde1nz"
            / "adult-publishing"
            / "staging-s0-commercial"
        )
        state.mkdir(parents=True)
        (state / "state.json").write_text("{}\n", encoding="ascii")
        (source / "commercial-s0-database.dump").write_bytes(b"synthetic dump")
        with tarfile.open(self.archive, "w:gz") as handle:
            for name in (
                "releases",
                "tu1nz",
                "tausendunde1nz",
                "commercial-s0-database.dump",
            ):
                handle.add(source / name, arcname=name)

    def manifest_command(self, output: Path | None = None) -> list[str]:
        return [
            str(MANIFEST_TOOL),
            "--application-repository", str(self.application),
            "--control-repository", str(self.control),
            "--archive", str(self.archive),
            "--readiness-contract", str(self.control / "manifests" / READINESS.name),
            "--unit", str(self.control / "systemd" / UNIT.name),
            "--backup-completed-at", "2026-08-28T12:00:00Z",
            "--rpo-target-seconds", "86400",
            "--rto-target-seconds", "14400",
            "--retention-days", "7",
            "--local-source-required", "yes",
            "--approved-utc", "2026-08-28T12:01:00Z",
            "--output", str(output or self.manifest),
        ]

    def generate(self, output: Path | None = None) -> subprocess.CompletedProcess[str]:
        return run(self.manifest_command(output))

    def gate_command(self, *, include_archive: bool = True) -> list[str]:
        command = [
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
        if include_archive:
            command.extend(("--archive", str(self.archive)))
        return command

    def gate(self, *, include_archive: bool = True) -> subprocess.CompletedProcess[str]:
        return run(self.gate_command(include_archive=include_archive))

    def rewrite_manifest(self, key: str, value: object) -> None:
        payload = json.loads(self.manifest.read_text(encoding="ascii"))
        payload[key] = value
        self.manifest.write_text(json.dumps(payload, sort_keys=True), encoding="ascii")
        self.manifest.chmod(0o640)

    def test_positive_exact_release_gate_and_archive_contract(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COMMERCIAL_S0_RELEASE_GATE_OK", result.stdout)
        self.assertEqual(self.gate(include_archive=False).returncode, 0)

    def test_manifest_is_private_and_binds_exact_artifacts(self) -> None:
        payload = json.loads(self.manifest.read_text(encoding="ascii"))
        self.assertEqual(payload["application_sha"], self.application_sha)
        self.assertEqual(payload["control_sha"], self.control_sha)
        self.assertEqual(payload["environment"], ENVIRONMENT)
        self.assertFalse(payload["network_enabled"])
        self.assertFalse(payload["real_payment_enabled"])
        self.assertEqual(payload["paid_targets"], ["REDDIT", "TELEGRAM"])
        self.assertEqual(payload["uncompensated_targets"], ["X"])
        self.assertEqual(
            payload["archive_sha256"],
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        )
        fresh = self.root / "fresh.json"
        result = self.generate(fresh)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o600)

    def test_manifest_rejects_missing_exact_backup_member(self) -> None:
        bad = self.root / "tu1nz_system_backup_incomplete.tar.gz"
        with tarfile.open(bad, "w:gz") as handle:
            handle.add(self.root / "archive-source" / "tu1nz", arcname="tu1nz")
        command = self.manifest_command(self.root / "bad.json")
        command[command.index("--archive") + 1] = str(bad)
        result = run(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commercial backup root is not a directory", result.stderr)

    def test_manifest_rejects_archive_write_through_symlink(self) -> None:
        bad = self.root / "tu1nz_system_backup_symlink-traversal.tar.gz"
        with tarfile.open(bad, "w:gz") as handle:
            symlink = tarfile.TarInfo("pivot")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "/tmp"
            handle.addfile(symlink)
            payload = b"unsafe"
            child = tarfile.TarInfo("pivot/child")
            child.size = len(payload)
            handle.addfile(child, io.BytesIO(payload))
        command = self.manifest_command(self.root / "symlink.json")
        command[command.index("--archive") + 1] = str(bad)
        result = run(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("writes through a symlink member", result.stderr)

    def test_gate_rejects_network_or_real_payment(self) -> None:
        self.rewrite_manifest("network_enabled", True)
        self.assertNotEqual(self.gate().returncode, 0)
        self.rewrite_manifest("network_enabled", False)
        self.rewrite_manifest("real_payment_enabled", True)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_x_as_paid_target(self) -> None:
        self.rewrite_manifest("paid_targets", ["REDDIT", "TELEGRAM", "X"])
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_remote_database(self) -> None:
        runtime = self.configuration / "runtime.env"
        runtime.write_text(
            "TU1NZ_COMMERCIAL_CANDIDATE_POSTGRES_DSN="
            "postgresql://database.example.invalid/commercial\n",
            encoding="ascii",
        )
        runtime.chmod(0o640)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_credential_like_extra_configuration(self) -> None:
        extra = self.configuration / "provider-token"
        extra.write_text("not-a-real-token\n", encoding="ascii")
        extra.chmod(0o640)
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected file", result.stderr)

    def test_gate_rejects_nonempty_initial_state(self) -> None:
        state = json.loads((self.state / "state.json").read_text(encoding="ascii"))
        state["product_events"] = [{"unsafe": True}]
        (self.state / "state.json").write_text(json.dumps(state), encoding="ascii")
        (self.state / "state.json").chmod(0o600)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_unit_drift(self) -> None:
        self.installed_unit.write_text("[Unit]\n", encoding="ascii")
        self.installed_unit.chmod(0o644)
        self.assertNotEqual(self.gate().returncode, 0)

    def test_gate_rejects_archive_drift(self) -> None:
        self.archive.write_bytes(self.archive.read_bytes() + b"drift")
        self.assertNotEqual(self.gate().returncode, 0)

    def test_unit_is_network_free_and_cannot_be_enabled(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        for required in (
            "PrivateNetwork=yes",
            "IPAddressDeny=any",
            "RestrictAddressFamilies=AF_UNIX",
            "--enable-network-free-commercial-candidate",
            "ProtectSystem=strict",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "[Install]",
            "WantedBy=",
            "network-online.target",
            "AF_INET",
            "TELEGRAM_TOKEN",
            "X_TOKEN",
            "REDDIT_TOKEN",
            "PAYMENT_TOKEN",
            "AVS_TOKEN",
        ):
            self.assertNotIn(forbidden, text)
        self.assertFalse((UNIT.parent / "tu1nz-adult-commercial-s0.timer").exists())

    def test_backup_is_optional_before_install_and_fail_closed_when_partial(self) -> None:
        text = BACKUP.read_text(encoding="utf-8")
        for required in (
            "staging-s0-commercial/application",
            "staging-s0-commercial/control",
            "staging-s0-commercial/venv",
            "commercial-s0-database.dump",
            "tu1nz_adult_commercial_s0",
            "Commercial S0 backup paths are only partially provisioned",
            'COMMERCIAL_RUNTIME_USER="postgres"',
            'chown root:root "$COMMERCIAL_DUMP_DIR"',
            '/usr/bin/pg_dump --format=custom --file=-',
            '--dbname=tu1nz_adult_commercial_s0 >"$COMMERCIAL_DB_DUMP"',
            'chmod 0600 "$COMMERCIAL_DB_DUMP"',
        ):
            self.assertIn(required, text)
        self.assertIn("commercial_present != 0", text)
        self.assertNotIn("crontab", text)
        self.assertNotIn(
            'chown "$COMMERCIAL_RUNTIME_USER:$COMMERCIAL_RUNTIME_USER" "$COMMERCIAL_DUMP_DIR"',
            text,
        )

    def test_gate_scopes_git_safety_and_contains_no_mutation_actions(self) -> None:
        text = GATE_TOOL.read_text(encoding="utf-8")
        self.assertGreaterEqual(text.count('"safe.directory=" + str(repository)'), 2)
        self.assertNotIn("--global", text)
        self.assertNotIn("systemctl", text)
        self.assertNotIn("docker", text)


if __name__ == "__main__":
    unittest.main()
