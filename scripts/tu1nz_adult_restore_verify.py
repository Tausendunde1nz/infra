#!/usr/bin/env python3
"""Fail-closed, synthetic-safe Adult Publishing restore verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import NoReturn
from uuid import uuid4


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ARCHIVE_RE = re.compile(r"^tu1nz_system_backup_[A-Za-z0-9._-]+\.tar\.gz$")
SAFE_RELATIVE_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


class RestoreFailure(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Manifest:
    application_sha: str
    control_sha: str
    archive_sha256: str
    backup_completed_at: datetime
    migration_hashes: dict[str, str]
    dependency_lock_sha256: str
    rpo_target_seconds: int
    rto_target_seconds: int
    local_source_required: bool


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RestoreFailure("MANIFEST_INVALID", field)
    return value


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RestoreFailure("MANIFEST_INVALID", field)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RestoreFailure("MANIFEST_INVALID", field) from error
    if parsed.tzinfo != timezone.utc:
        raise RestoreFailure("MANIFEST_INVALID", field)
    return parsed


def load_manifest(path: Path) -> Manifest:
    if not path.is_file():
        raise RestoreFailure("MANIFEST_MISSING")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RestoreFailure("MANIFEST_INVALID") from error
    if not isinstance(payload, dict):
        raise RestoreFailure("MANIFEST_INVALID")
    if payload.get("environment") != "STAGING-S0":
        raise RestoreFailure("ENVIRONMENT_MISMATCH")
    if payload.get("outbound_providers_enabled") is not False:
        raise RestoreFailure("OUTBOUND_NOT_DISABLED")
    if payload.get("synthetic_data_only") is not True:
        raise RestoreFailure("SYNTHETIC_ONLY_REQUIRED")
    application_sha = payload.get("application_sha")
    control_sha = payload.get("control_sha")
    archive_sha256 = payload.get("archive_sha256")
    dependency_lock_sha256 = payload.get("dependency_lock_sha256")
    for value, pattern, field in (
        (application_sha, GIT_SHA_RE, "application_sha"),
        (control_sha, GIT_SHA_RE, "control_sha"),
        (archive_sha256, SHA256_RE, "archive_sha256"),
        (dependency_lock_sha256, SHA256_RE, "dependency_lock_sha256"),
    ):
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise RestoreFailure("MANIFEST_INVALID", field)
    migration_hashes = payload.get("migration_hashes")
    if not isinstance(migration_hashes, dict) or not migration_hashes:
        raise RestoreFailure("MANIFEST_INVALID", "migration_hashes")
    for relative, digest in migration_hashes.items():
        if (
            not isinstance(relative, str)
            or SAFE_RELATIVE_RE.fullmatch(relative) is None
            or relative.startswith("/")
            or ".." in PurePosixPath(relative).parts
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise RestoreFailure("MANIFEST_INVALID", "migration_hashes")
    if not isinstance(payload.get("local_source_required"), bool):
        raise RestoreFailure("MANIFEST_INVALID", "local_source_required")
    _utc_timestamp(payload.get("approved_utc"), "approved_utc")
    return Manifest(
        application_sha,
        control_sha,
        archive_sha256,
        _utc_timestamp(payload.get("backup_completed_at"), "backup_completed_at"),
        migration_hashes,
        dependency_lock_sha256,
        _positive_int(payload.get("rpo_target_seconds"), "rpo_target_seconds"),
        _positive_int(payload.get("rto_target_seconds"), "rto_target_seconds"),
        payload["local_source_required"],
    )


def run_checked(arguments: list[str], code: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RestoreFailure(code) from error
    if result.returncode != 0:
        raise RestoreFailure(code)
    return result


def select_archive(rclone: Path, remote: str) -> str:
    result = run_checked(
        [str(rclone), "lsjson", remote, "--files-only"],
        "ARCHIVE_LIST_FAILED",
    )
    try:
        listing = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RestoreFailure("ARCHIVE_LIST_FAILED") from error
    candidates: list[tuple[datetime, str]] = []
    if not isinstance(listing, list):
        raise RestoreFailure("ARCHIVE_LIST_FAILED")
    for item in listing:
        if not isinstance(item, dict):
            raise RestoreFailure("ARCHIVE_LIST_FAILED")
        name = item.get("Name") or item.get("Path")
        modified = item.get("ModTime")
        if not isinstance(name, str) or ARCHIVE_RE.fullmatch(Path(name).name) is None:
            continue
        timestamp = _utc_timestamp(modified, "archive ModTime")
        candidates.append((timestamp, Path(name).name))
    if not candidates:
        raise RestoreFailure("ARCHIVE_NOT_FOUND")
    newest = max(timestamp for timestamp, _ in candidates)
    selected = sorted(name for timestamp, name in candidates if timestamp == newest)
    if len(selected) != 1:
        raise RestoreFailure("ARCHIVE_AMBIGUOUS")
    return selected[0]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise RestoreFailure("CHECKSUM_READ_FAILED") from error
    return digest.hexdigest()


def extract_archive(archive: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if not members or len(members) > 100000:
                raise RestoreFailure("ARCHIVE_INVALID")
            names: set[str] = set()
            total_size = 0
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not relative.parts
                    or member.name in names
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                    or not (member.isdir() or member.isfile())
                ):
                    raise RestoreFailure("ARCHIVE_INVALID")
                names.add(member.name)
                total_size += member.size
                if total_size > 20 * 1024 * 1024 * 1024:
                    raise RestoreFailure("ARCHIVE_INVALID")
            for member in members:
                target = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = bundle.extractfile(member)
                if source is None:
                    raise RestoreFailure("ARCHIVE_INVALID")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                target.chmod(0o600)
    except RestoreFailure:
        raise
    except (OSError, EOFError, tarfile.TarError) as error:
        raise RestoreFailure("ARCHIVE_INVALID") from error


def verify_repository(path: Path, expected_sha: str, mismatch_code: str) -> str:
    if not path.is_dir() or not (path / ".git").is_dir():
        raise RestoreFailure("REPOSITORY_MISSING")
    run_checked(["/usr/bin/git", "-C", str(path), "fsck", "--full"], "GIT_INTEGRITY_FAILED")
    status_result = run_checked(
        ["/usr/bin/git", "-C", str(path), "status", "--porcelain=v1"],
        "GIT_INTEGRITY_FAILED",
    )
    if status_result.stdout:
        raise RestoreFailure("WORKTREE_DIRTY")
    head = run_checked(
        ["/usr/bin/git", "-C", str(path), "rev-parse", "HEAD"],
        "GIT_INTEGRITY_FAILED",
    ).stdout.strip()
    if head != expected_sha:
        raise RestoreFailure(mismatch_code)
    return head


def verify_artifact_hashes(application: Path, manifest: Manifest) -> None:
    for relative, expected in manifest.migration_hashes.items():
        target = application / relative
        if not target.is_file() or sha256_file(target) != expected:
            raise RestoreFailure("ARTIFACT_HASH_MISMATCH")
    lock = application / "requirements-m2.lock"
    if not lock.is_file() or sha256_file(lock) != manifest.dependency_lock_sha256:
        raise RestoreFailure("ARTIFACT_HASH_MISMATCH")


def write_evidence(run_directory: Path, payload: dict[str, object]) -> None:
    target = run_directory / "restore-evidence.json"
    temporary = run_directory / ".restore-evidence.json.tmp"
    temporary.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    temporary.chmod(0o600)
    temporary.replace(target)


def fail(code: str, detail: str = "", run_directory: Path | None = None) -> NoReturn:
    record = {"code": code, "result": "FAIL"}
    if run_directory is not None:
        try:
            write_evidence(run_directory, record)
        except OSError:
            pass
    suffix = " detail={0}".format(detail) if detail else ""
    print("ERROR code={0}{1}".format(code, suffix), file=sys.stderr)
    raise SystemExit(1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--rclone-bin", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--component-verifier", required=True, type=Path)
    parser.add_argument("--notification-hook", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    started = time.monotonic()
    run_directory: Path | None = None
    try:
        manifest = load_manifest(arguments.manifest)
        if not arguments.rclone_bin.is_file() or not os.access(arguments.rclone_bin, os.X_OK):
            raise RestoreFailure("RCLONE_UNAVAILABLE")
        if not arguments.component_verifier.is_file() or not os.access(
            arguments.component_verifier, os.X_OK
        ):
            raise RestoreFailure("COMPONENT_VERIFIER_MISSING")
        arguments.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid4().hex
        run_directory = arguments.work_root / run_id
        run_directory.mkdir(mode=0o700)
        print("RESTORE_PREFLIGHT=PASS")

        archive_name = select_archive(arguments.rclone_bin, arguments.remote)
        downloaded = run_directory / archive_name
        remote_object = arguments.remote.rstrip("/") + "/" + archive_name
        run_checked(
            [str(arguments.rclone_bin), "copyto", remote_object, str(downloaded)],
            "DOWNLOAD_FAILED",
        )
        if not downloaded.is_file():
            raise RestoreFailure("DOWNLOAD_FAILED")

        downloaded_sha = sha256_file(downloaded)
        if manifest.local_source_required:
            if arguments.source_archive is None or not arguments.source_archive.is_file():
                raise RestoreFailure("ARCHIVE_COMPARE_FAILED")
            source_sha = sha256_file(arguments.source_archive)
            if source_sha != downloaded_sha:
                raise RestoreFailure("ARCHIVE_COMPARE_FAILED")
        if downloaded_sha != manifest.archive_sha256:
            raise RestoreFailure("CHECKSUM_MISMATCH")
        print("RESTORE_ARCHIVE_COMPARE=PASS sha256={0}".format(downloaded_sha))

        extracted = run_directory / "restored"
        extracted.mkdir(mode=0o700)
        extract_archive(downloaded, extracted)
        print("RESTORE_ARCHIVE_INTEGRITY=PASS")

        control_head = verify_repository(
            extracted / "control",
            manifest.control_sha,
            "CONTROL_SHA_MISMATCH",
        )
        print("RESTORE_REPOSITORY=PASS repo=control head={0}".format(control_head))
        application_head = verify_repository(
            extracted / "adult-publishing-core",
            manifest.application_sha,
            "APPLICATION_SHA_MISMATCH",
        )
        print(
            "RESTORE_REPOSITORY=PASS repo=adult-publishing-core head={0}".format(
                application_head
            )
        )
        print(
            "RESTORE_EXPECTED_SHA=PASS expected={0} actual={1}".format(
                manifest.application_sha,
                application_head,
            )
        )
        verify_artifact_hashes(extracted / "adult-publishing-core", manifest)

        run_checked(
            [str(arguments.component_verifier), str(extracted), str(arguments.manifest)],
            "COMPONENT_ASSERTION_FAILED",
        )
        now = datetime.now(timezone.utc)
        rpo_seconds = max(0, int((now - manifest.backup_completed_at).total_seconds()))
        if rpo_seconds > manifest.rpo_target_seconds:
            raise RestoreFailure("RPO_MISSED")
        rto_seconds = max(0, int(time.monotonic() - started))
        if rto_seconds > manifest.rto_target_seconds:
            raise RestoreFailure("RTO_MISSED")
        print(
            "RESTORE_RPO=PASS target_seconds={0} measured_seconds={1}".format(
                manifest.rpo_target_seconds,
                rpo_seconds,
            )
        )
        print(
            "RESTORE_RTO=PASS target_seconds={0} measured_seconds={1}".format(
                manifest.rto_target_seconds,
                rto_seconds,
            )
        )
        evidence = {
            "application_sha": application_head,
            "archive_sha256": downloaded_sha,
            "control_sha": control_head,
            "environment": "STAGING-S0",
            "result": "PASS",
            "rpo_measured_seconds": rpo_seconds,
            "rto_measured_seconds": rto_seconds,
            "run_id": run_id,
            "synthetic_data_only": True,
        }
        write_evidence(run_directory, evidence)
        print("RESTORE_VERIFY=PASS run_id={0}".format(run_id))
        if arguments.notification_hook is not None:
            try:
                notification = subprocess.run(
                    [str(arguments.notification_hook), "RESTORE_VERIFY_PASS", run_id],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                notification_failed = notification.returncode != 0
            except (OSError, subprocess.SubprocessError):
                notification_failed = True
            if notification_failed:
                print("NOTIFICATION=FAIL code=NOTIFICATION_FAILED", file=sys.stderr)
            else:
                print("NOTIFICATION=PASS")
        return 0
    except RestoreFailure as error:
        fail(error.code, error.detail, run_directory)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        fail("UNEXPECTED_FAILURE", type(error).__name__, run_directory)


if __name__ == "__main__":
    raise SystemExit(main())
