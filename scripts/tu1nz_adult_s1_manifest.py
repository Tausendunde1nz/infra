#!/usr/bin/env python3
"""Generate an immutable STAGING-S1 release and recovery manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from tu1nz_adult_staging_manifest import (
    ManifestFailure,
    migration_hashes,
    positive,
    sha256_file,
    utc_timestamp,
    verified_sha,
)


def build_manifest(arguments: argparse.Namespace) -> dict[str, object]:
    application = arguments.application_repository.resolve(strict=True)
    control = arguments.control_repository.resolve(strict=True)
    archive = arguments.archive.resolve(strict=True)
    output = arguments.output.absolute()
    if output.exists() or output.is_symlink():
        raise ManifestFailure(f"refusing to overwrite: {output}")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ManifestFailure("output parent must be an existing regular directory")
    if (
        not archive.name.startswith("tu1nz_system_backup_")
        or archive.suffixes[-2:] != [".tar", ".gz"]
    ):
        raise ManifestFailure("archive name does not match TU1NZ backup contract")
    backup_completed = utc_timestamp(
        arguments.backup_completed_at,
        "backup_completed_at",
    )
    approved = utc_timestamp(arguments.approved_utc, "approved_utc")
    if approved < backup_completed:
        raise ManifestFailure("approved_utc predates backup completion")
    return {
        "application_sha": verified_sha(application),
        "approved_utc": arguments.approved_utc,
        "archive_sha256": sha256_file(archive),
        "backup_completed_at": arguments.backup_completed_at,
        "bot_username": "TU1NZ_Adult_Sandbox_Bot",
        "control_sha": verified_sha(control),
        "dependency_lock_sha256": sha256_file(
            application / "requirements-m2.lock"
        ),
        "environment": "STAGING-S1",
        "live_publishers_enabled": False,
        "local_source_required": arguments.local_source_required == "yes",
        "migration_hashes": migration_hashes(application),
        "mock_payment_only": True,
        "required_platforms": ["REDDIT", "TELEGRAM", "X"],
        "retention_days": positive(arguments.retention_days, "retention_days"),
        "rpo_target_seconds": positive(
            arguments.rpo_target_seconds,
            "rpo_target_seconds",
        ),
        "rto_target_seconds": positive(
            arguments.rto_target_seconds,
            "rto_target_seconds",
        ),
        "synthetic_data_only": True,
        "telegram_intake_enabled": True,
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
    parser.add_argument(
        "--local-source-required",
        choices=("yes", "no"),
        required=True,
    )
    parser.add_argument("--approved-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        payload = build_manifest(arguments)
        descriptor = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        material = descriptor.encode("ascii")
        descriptor_fd = os.open(
            arguments.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor_fd, "wb") as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
        print("S1_MANIFEST_OK sha256=" + hashlib.sha256(material).hexdigest())
        return 0
    except (ManifestFailure, OSError, subprocess.SubprocessError) as error:
        print("S1_MANIFEST_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
