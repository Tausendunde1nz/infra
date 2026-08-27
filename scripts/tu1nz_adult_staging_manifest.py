#!/usr/bin/env python3
"""Generate an immutable, fail-closed STAGING-S0 release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


class ManifestFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ManifestFailure(f"regular file required: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repository: Path, *arguments: str) -> str:
    if not repository.is_dir() or not (repository / ".git").is_dir():
        raise ManifestFailure(f"Git repository missing: {repository}")
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise ManifestFailure(f"Git validation failed: {repository}")
    return result.stdout.strip()


def verified_sha(repository: Path) -> str:
    git(repository, "fsck", "--full")
    if git(repository, "status", "--porcelain=v1"):
        raise ManifestFailure(f"dirty worktree: {repository}")
    sha = git(repository, "rev-parse", "HEAD")
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise ManifestFailure(f"invalid Git SHA: {repository}")
    return sha


def utc_timestamp(value: str, field: str) -> datetime:
    if not value.endswith("Z"):
        raise ManifestFailure(f"{field} must be UTC and end in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ManifestFailure(f"invalid {field}") from error
    if parsed.tzinfo != timezone.utc:
        raise ManifestFailure(f"invalid {field}")
    return parsed


def positive(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ManifestFailure(f"{field} must be a positive integer") from error
    if parsed <= 0:
        raise ManifestFailure(f"{field} must be a positive integer")
    return parsed


def migration_hashes(application: Path) -> dict[str, str]:
    migrations = sorted((application / "migrations").glob("*.sql"))
    if not migrations:
        raise ManifestFailure("no SQL migrations found")
    return {
        str(path.relative_to(application)): sha256_file(path)
        for path in migrations
    }


def build_manifest(arguments: argparse.Namespace) -> dict[str, object]:
    application = arguments.application_repository.resolve(strict=True)
    control = arguments.control_repository.resolve(strict=True)
    archive = arguments.archive.resolve(strict=True)
    output = arguments.output.absolute()
    if output.exists() or output.is_symlink():
        raise ManifestFailure(f"refusing to overwrite: {output}")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ManifestFailure("output parent must be an existing regular directory")
    if archive.name.startswith("tu1nz_system_backup_") is False or archive.suffixes[-2:] != [".tar", ".gz"]:
        raise ManifestFailure("archive name does not match TU1NZ backup contract")

    backup_completed = utc_timestamp(arguments.backup_completed_at, "backup_completed_at")
    approved = utc_timestamp(arguments.approved_utc, "approved_utc")
    if approved < backup_completed:
        raise ManifestFailure("approved_utc predates backup completion")

    return {
        "environment": "STAGING-S0",
        "application_sha": verified_sha(application),
        "control_sha": verified_sha(control),
        "outbound_providers_enabled": False,
        "synthetic_data_only": True,
        "migration_hashes": migration_hashes(application),
        "dependency_lock_sha256": sha256_file(application / "requirements-m2.lock"),
        "archive_sha256": sha256_file(archive),
        "backup_completed_at": arguments.backup_completed_at,
        "rpo_target_seconds": positive(arguments.rpo_target_seconds, "rpo_target_seconds"),
        "rto_target_seconds": positive(arguments.rto_target_seconds, "rto_target_seconds"),
        "retention_days": positive(arguments.retention_days, "retention_days"),
        "local_source_required": arguments.local_source_required == "yes",
        "approved_utc": arguments.approved_utc,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-repository", type=Path, required=True)
    parser.add_argument("--control-repository", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--backup-completed-at", required=True)
    parser.add_argument("--rpo-target-seconds", required=True)
    parser.add_argument("--rto-target-seconds", required=True)
    parser.add_argument("--retention-days", required=True)
    parser.add_argument("--local-source-required", choices=("yes", "no"), required=True)
    parser.add_argument("--approved-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        payload = build_manifest(arguments)
        descriptor = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        descriptor_bytes = descriptor.encode("ascii")
        descriptor_fd = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor_fd, "wb") as handle:
            handle.write(descriptor_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        print(f"MANIFEST_OK sha256={hashlib.sha256(descriptor_bytes).hexdigest()}")
        return 0
    except (ManifestFailure, OSError, subprocess.SubprocessError) as error:
        print(f"MANIFEST_BLOCKED {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
