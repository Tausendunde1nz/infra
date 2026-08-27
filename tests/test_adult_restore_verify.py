from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "tu1nz_adult_restore_verify.sh"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class AdultRestoreVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        self.control = self.fixture / "control"
        self.application = self.fixture / "adult-publishing-core"
        self.control_sha = self._git_repository(
            self.control,
            {"README.md": "synthetic control\n"},
        )
        self.application_sha = self._git_repository(
            self.application,
            {
                "migrations/0001.sql": "SELECT 1;\n",
                "requirements-m2.lock": "synthetic-lock==1\n",
                "README.md": "synthetic application\n",
            },
        )
        self.archive = self.remote / "tu1nz_system_backup_20260827T000000Z.tar.gz"
        self._build_archive()
        self.manifest = self.root / "manifest.json"
        self._write_manifest()
        self.fake_rclone = self.root / "fake-rclone"
        self.fake_rclone.write_text(
            """#!/usr/bin/env python3
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

if sys.argv[1] == "lsjson":
    root = Path(sys.argv[2])
    items = []
    for path in sorted(root.glob("*.tar.gz")):
        timestamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        items.append({"Name": path.name, "ModTime": timestamp.isoformat().replace("+00:00", "Z")})
    print(json.dumps(items))
    raise SystemExit(0)
if sys.argv[1] == "copyto":
    if os.environ.get("FAKE_RCLONE_COPY_FAIL") == "1":
        raise SystemExit(9)
    source = Path(sys.argv[2])
    target = Path(sys.argv[3])
    shutil.copy2(source, target)
    raise SystemExit(0)
raise SystemExit(8)
""",
            encoding="utf-8",
        )
        self.fake_rclone.chmod(0o700)
        self.component_verifier = self.root / "component-verifier"
        self.component_verifier.write_text(
            "#!/bin/sh\ntest -d \"$1/control/.git\" && test -d \"$1/adult-publishing-core/.git\"\n",
            encoding="utf-8",
        )
        self.component_verifier.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git_repository(self, path: Path, files: dict[str, str]) -> str:
        path.mkdir()
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "Synthetic Test"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "synthetic@example.invalid"], check=True)
        for relative, contents in files.items():
            target = path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")
        subprocess.run(["git", "-C", str(path), "add", "--all"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-qm", "synthetic fixture"], check=True)
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _build_archive(
        self,
        *,
        include_control: bool = True,
        include_application: bool = True,
    ) -> None:
        self.archive.unlink(missing_ok=True)
        with tarfile.open(self.archive, "w:gz") as bundle:
            if include_control:
                bundle.add(self.control, arcname="control")
            if include_application:
                bundle.add(self.application, arcname="adult-publishing-core")

    def _manifest_payload(self) -> dict[str, object]:
        return {
            "environment": "STAGING-S0",
            "application_sha": self.application_sha,
            "control_sha": self.control_sha,
            "outbound_providers_enabled": False,
            "synthetic_data_only": True,
            "migration_hashes": {
                "migrations/0001.sql": sha256(self.application / "migrations/0001.sql")
            },
            "dependency_lock_sha256": sha256(self.application / "requirements-m2.lock"),
            "archive_sha256": sha256(self.archive),
            "backup_completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "rpo_target_seconds": 3600,
            "rto_target_seconds": 30,
            "local_source_required": True,
            "approved_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _write_manifest(self, **updates: object) -> None:
        payload = self._manifest_payload()
        payload.update(updates)
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")

    def _run(
        self,
        *,
        manifest: Path | None = None,
        source_archive: Path | None = None,
        component_verifier: Path | None = None,
        notification_hook: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            str(VERIFIER),
            "--manifest",
            str(manifest or self.manifest),
            "--remote",
            str(self.remote),
            "--rclone-bin",
            str(self.fake_rclone),
            "--work-root",
            str(self.root / "runs"),
            "--source-archive",
            str(source_archive or self.archive),
            "--component-verifier",
            str(component_verifier or self.component_verifier),
        ]
        if notification_hook is not None:
            command.extend(["--notification-hook", str(notification_hook)])
        process_environment = os.environ.copy()
        process_environment.update(environment or {})
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=process_environment,
            timeout=20,
        )

    def assert_failure(self, result: subprocess.CompletedProcess[str], code: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ERROR code={0}".format(code), result.stderr)
        self.assertNotIn("RESTORE_VERIFY=PASS", result.stdout)

    def test_positive_restore_emits_all_required_markers(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for marker in (
            "RESTORE_PREFLIGHT=PASS",
            "RESTORE_ARCHIVE_COMPARE=PASS",
            "RESTORE_ARCHIVE_INTEGRITY=PASS",
            "RESTORE_REPOSITORY=PASS repo=control",
            "RESTORE_REPOSITORY=PASS repo=adult-publishing-core",
            "RESTORE_EXPECTED_SHA=PASS",
            "RESTORE_RPO=PASS",
            "RESTORE_RTO=PASS",
            "RESTORE_VERIFY=PASS",
        ):
            self.assertIn(marker, result.stdout)

    def test_n01_manifest_missing(self) -> None:
        self.assert_failure(self._run(manifest=self.root / "missing.json"), "MANIFEST_MISSING")

    def test_n02_environment_mismatch(self) -> None:
        self._write_manifest(environment="PRODUCTION")
        self.assert_failure(self._run(), "ENVIRONMENT_MISMATCH")

    def test_n03_outbound_enabled(self) -> None:
        self._write_manifest(outbound_providers_enabled=True)
        self.assert_failure(self._run(), "OUTBOUND_NOT_DISABLED")

    def test_n04_archive_not_found(self) -> None:
        self.archive.unlink()
        self.assert_failure(self._run(), "ARCHIVE_NOT_FOUND")

    def test_n05_ambiguous_archive(self) -> None:
        second = self.remote / "tu1nz_system_backup_20260827T000001Z.tar.gz"
        shutil.copy2(self.archive, second)
        timestamp = 1_800_000_000
        os.utime(self.archive, (timestamp, timestamp))
        os.utime(second, (timestamp, timestamp))
        self.assert_failure(self._run(), "ARCHIVE_AMBIGUOUS")

    def test_n06_download_failure(self) -> None:
        self.assert_failure(
            self._run(environment={"FAKE_RCLONE_COPY_FAIL": "1"}),
            "DOWNLOAD_FAILED",
        )

    def test_n07_archive_compare_failure(self) -> None:
        other = self.root / "other.tar.gz"
        other.write_bytes(b"different synthetic bytes")
        self.assert_failure(self._run(source_archive=other), "ARCHIVE_COMPARE_FAILED")

    def test_n08_checksum_mismatch(self) -> None:
        self._write_manifest(archive_sha256="0" * 64)
        self.assert_failure(self._run(), "CHECKSUM_MISMATCH")

    def test_n09_unsafe_archive(self) -> None:
        self.archive.unlink()
        source = self.root / "unsafe.txt"
        source.write_text("unsafe", encoding="utf-8")
        with tarfile.open(self.archive, "w:gz") as bundle:
            bundle.add(source, arcname="../escape")
        self._write_manifest()
        self.assert_failure(self._run(), "ARCHIVE_INVALID")

    def test_n10_repository_missing(self) -> None:
        self._build_archive(include_application=False)
        self._write_manifest()
        self.assert_failure(self._run(), "REPOSITORY_MISSING")

    def test_n11_git_integrity_failure(self) -> None:
        objects = [
            path
            for path in (self.application / ".git" / "objects").glob("*/*")
            if path.is_file()
        ]
        self.assertTrue(objects)
        objects[0].chmod(0o600)
        objects[0].write_bytes(b"corrupt")
        self._build_archive()
        self._write_manifest()
        self.assert_failure(self._run(), "GIT_INTEGRITY_FAILED")

    def test_n12_dirty_worktree(self) -> None:
        (self.application / "README.md").write_text("dirty synthetic application\n", encoding="utf-8")
        self._build_archive()
        self._write_manifest()
        self.assert_failure(self._run(), "WORKTREE_DIRTY")

    def test_n13_application_sha_mismatch(self) -> None:
        self._write_manifest(application_sha="1" * 40)
        self.assert_failure(self._run(), "APPLICATION_SHA_MISMATCH")

    def test_n14_artifact_hash_mismatch(self) -> None:
        self._write_manifest(dependency_lock_sha256="2" * 64)
        self.assert_failure(self._run(), "ARTIFACT_HASH_MISMATCH")

    def test_n15_rpo_missed(self) -> None:
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        self._write_manifest(
            backup_completed_at=old.isoformat().replace("+00:00", "Z"),
            rpo_target_seconds=60,
        )
        self.assert_failure(self._run(), "RPO_MISSED")

    def test_n16_rto_missed(self) -> None:
        slow = self.root / "slow-component-verifier"
        slow.write_text("#!/bin/sh\nsleep 2\nexit 0\n", encoding="utf-8")
        slow.chmod(0o700)
        self._write_manifest(rto_target_seconds=1)
        self.assert_failure(self._run(component_verifier=slow), "RTO_MISSED")

    def test_n17_component_assertion_failure(self) -> None:
        failing = self.root / "failing-component-verifier"
        failing.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        failing.chmod(0o700)
        self.assert_failure(
            self._run(component_verifier=failing),
            "COMPONENT_ASSERTION_FAILED",
        )

    def test_n18_notification_failure_does_not_change_verified_result(self) -> None:
        failing = self.root / "failing-notification"
        failing.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        failing.chmod(0o700)
        result = self._run(notification_hook=failing)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESTORE_VERIFY=PASS", result.stdout)
        self.assertIn("NOTIFICATION=FAIL code=NOTIFICATION_FAILED", result.stderr)

    def test_missing_notification_hook_does_not_change_verified_result(self) -> None:
        result = self._run(notification_hook=self.root / "missing-notification")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESTORE_VERIFY=PASS", result.stdout)
        self.assertIn("NOTIFICATION=FAIL code=NOTIFICATION_FAILED", result.stderr)


if __name__ == "__main__":
    unittest.main()
