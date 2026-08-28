#!/usr/bin/env python3
"""Generate an immutable, network-free commercial S0 release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

from tu1nz_adult_staging_manifest import (
    ManifestFailure,
    migration_hashes,
    positive,
    sha256_file,
    utc_timestamp,
    verified_sha,
)


ENVIRONMENT = "STAGING-S0-COMMERCIAL-CANDIDATE"
CONTRACT_VERSION = "tu1nz-commercial-s0-installation-m4.19-v1"
COMMERCIAL_CONTRACT_VERSION = "tu1nz-commercial-persistence-m4.15-v1"
RUNTIME_VERSION = "tu1nz-commercial-runtime-candidate-m4.17-v1"
PERSISTENCE_SCHEMA_VERSION = "0014_m4_15_durable_commercial_persistence"
UNIT_NAME = "tu1nz-adult-commercial-s0.service"


def required_backup_roots(application_sha: str, control_sha: str) -> list[str]:
    base = "releases/adult-publishing/staging-s0-commercial"
    return [
        f"{base}/application/{application_sha}",
        f"{base}/control/{control_sha}",
        f"{base}/venv/{application_sha}",
        "tu1nz/adult-publishing/staging-s0-commercial",
        "tausendunde1nz/adult-publishing/staging-s0-commercial",
        "commercial-s0-database.dump",
    ]


def archive_inventory(archive: Path, required_roots: list[str]) -> str:
    if not archive.is_file() or archive.is_symlink():
        raise ManifestFailure("backup archive must be a safe regular file")
    try:
        with tarfile.open(archive, mode="r:gz") as handle:
            members = handle.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise ManifestFailure("backup archive is unreadable") from error
    if not members:
        raise ManifestFailure("backup archive is empty")
    names = [member.name.rstrip("/") for member in members]
    if len(names) != len(set(names)):
        raise ManifestFailure("backup archive contains duplicate members")
    for member, name in zip(members, names):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not name:
            raise ManifestFailure("backup archive contains an unsafe member")
        if member.islnk() or member.isdev() or member.isfifo():
            raise ManifestFailure("backup archive contains an unsafe member type")
    symlink_names = {name for member, name in zip(members, names) if member.issym()}
    if any(
        other.startswith(symlink + "/")
        for symlink in symlink_names
        for other in names
        if other != symlink
    ):
        raise ManifestFailure("backup archive writes through a symlink member")
    member_by_name = dict(zip(names, members))
    for root in required_roots[:-1]:
        required_member = member_by_name.get(root)
        if required_member is None or not required_member.isdir():
            raise ManifestFailure("commercial backup root is not a directory: " + root)
    database_dump = member_by_name.get("commercial-s0-database.dump")
    if database_dump is None or not database_dump.isfile() or database_dump.size <= 0:
        raise ManifestFailure("commercial database dump is missing or empty")
    names = sorted(names)
    material = ("\n".join(names) + "\n").encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def build_manifest(arguments: argparse.Namespace) -> dict[str, object]:
    application = arguments.application_repository.resolve(strict=True)
    control = arguments.control_repository.resolve(strict=True)
    archive = arguments.archive.resolve(strict=True)
    readiness = arguments.readiness_contract.resolve(strict=True)
    unit = arguments.unit.resolve(strict=True)
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
    if unit.name != UNIT_NAME or unit.parent != control / "systemd":
        raise ManifestFailure("unit must be the versioned commercial S0 unit")
    if readiness.name != "adult-publishing-commercial-readiness.m4-18.json":
        raise ManifestFailure("M4.18 readiness contract is required")
    if readiness.parent != control / "manifests":
        raise ManifestFailure("readiness contract must be versioned in Control")
    backup_completed = utc_timestamp(arguments.backup_completed_at, "backup_completed_at")
    approved = utc_timestamp(arguments.approved_utc, "approved_utc")
    if approved < backup_completed:
        raise ManifestFailure("approved_utc predates backup completion")
    application_sha = verified_sha(application)
    control_sha = verified_sha(control)
    roots = required_backup_roots(application_sha, control_sha)
    hashes = migration_hashes(application)
    required_migrations = {
        "migrations/0014_m4_15_durable_commercial_persistence.sql",
        "migrations/0014_m4_15_durable_commercial_persistence.down.sql",
    }
    if not required_migrations <= set(hashes):
        raise ManifestFailure("commercial migration 0014 and rollback are required")
    return {
        "application_sha": application_sha,
        "approved_utc": arguments.approved_utc,
        "archive_inventory_sha256": archive_inventory(archive, roots),
        "archive_name": archive.name,
        "archive_sha256": sha256_file(archive),
        "backup_completed_at": arguments.backup_completed_at,
        "backup_member_roots": roots,
        "commercial_contract_version": COMMERCIAL_CONTRACT_VERSION,
        "control_sha": control_sha,
        "dependency_lock_sha256": sha256_file(application / "requirements-m2.lock"),
        "environment": ENVIRONMENT,
        "external_providers_enabled": False,
        "local_source_required": arguments.local_source_required == "yes",
        "migration_hashes": hashes,
        "network_enabled": False,
        "paid_targets": ["REDDIT", "TELEGRAM"],
        "persistence_schema_version": PERSISTENCE_SCHEMA_VERSION,
        "readiness_contract_sha256": sha256_file(readiness),
        "real_media_enabled": False,
        "real_payment_enabled": False,
        "release_contract_version": CONTRACT_VERSION,
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
        "runtime_version": RUNTIME_VERSION,
        "synthetic_data_only": True,
        "synthetic_publishers_only": True,
        "telegram_intake_enabled": False,
        "uncompensated_targets": ["X"],
        "unit_sha256": sha256_file(unit),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-repository", type=Path, required=True)
    parser.add_argument("--control-repository", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--readiness-contract", type=Path, required=True)
    parser.add_argument("--unit", type=Path, required=True)
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
        print("COMMERCIAL_S0_MANIFEST_OK sha256=" + hashlib.sha256(material).hexdigest())
        return 0
    except (ManifestFailure, OSError, subprocess.SubprocessError) as error:
        print("COMMERCIAL_S0_MANIFEST_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
