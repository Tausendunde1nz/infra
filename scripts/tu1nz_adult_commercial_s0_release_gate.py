#!/usr/bin/env python3
"""Read-only release gate for the isolated commercial S0 candidate."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from uuid import UUID

from tu1nz_adult_commercial_s0_manifest import (
    COMMERCIAL_CONTRACT_VERSION,
    CONTRACT_VERSION,
    ENVIRONMENT,
    PERSISTENCE_SCHEMA_VERSION,
    RUNTIME_VERSION,
    UNIT_NAME,
    archive_inventory,
    required_backup_roots,
)
from tu1nz_adult_staging_manifest import (
    ManifestFailure,
    migration_hashes,
    sha256_file,
    utc_timestamp,
)


class GateFailure(RuntimeError):
    pass


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_DSN = (
    "postgresql:///tu1nz_adult_commercial_s0?host=/run/postgresql"
    "&user=tu1nz_adult_commercial_s0_runtime&sslmode=disable"
)
MANIFEST_KEYS = {
    "application_sha",
    "approved_utc",
    "archive_inventory_sha256",
    "archive_name",
    "archive_sha256",
    "backup_completed_at",
    "backup_member_roots",
    "commercial_contract_version",
    "control_sha",
    "dependency_lock_sha256",
    "environment",
    "external_providers_enabled",
    "local_source_required",
    "migration_hashes",
    "network_enabled",
    "paid_targets",
    "persistence_schema_version",
    "readiness_contract_sha256",
    "real_media_enabled",
    "real_payment_enabled",
    "release_contract_version",
    "required_platforms",
    "retention_days",
    "rpo_target_seconds",
    "rto_target_seconds",
    "runtime_version",
    "synthetic_data_only",
    "synthetic_publishers_only",
    "telegram_intake_enabled",
    "uncompensated_targets",
    "unit_sha256",
}


def account(name: str, *, group: bool = False) -> int:
    try:
        return grp.getgrnam(name).gr_gid if group else pwd.getpwnam(name).pw_uid
    except KeyError as error:
        raise GateFailure("required account missing: " + name) from error


def verify_metadata(path: Path, mode: int, uid: int, gid: int, field: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateFailure(field + ": missing") from error
    if path.is_symlink() or not (
        stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
    ):
        raise GateFailure(field + ": regular file or directory required")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise GateFailure("{0}: mode must be {1:o}".format(field, mode))
    if metadata.st_uid != uid or metadata.st_gid != gid:
        raise GateFailure(field + ": owner mismatch")


def read_json(path: Path, field: str) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure(field + ": safe regular file required")
    if path.stat().st_size > 8 * 1024 * 1024:
        raise GateFailure(field + ": file is too large")
    try:
        return json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure(field + ": invalid JSON") from error


def load_manifest(path: Path) -> dict[str, object]:
    payload = read_json(path, "manifest")
    if not isinstance(payload, dict) or set(payload) != MANIFEST_KEYS:
        raise GateFailure("manifest: exact key set required")
    if (
        payload.get("environment") != ENVIRONMENT
        or payload.get("release_contract_version") != CONTRACT_VERSION
        or payload.get("commercial_contract_version") != COMMERCIAL_CONTRACT_VERSION
        or payload.get("runtime_version") != RUNTIME_VERSION
        or payload.get("persistence_schema_version") != PERSISTENCE_SCHEMA_VERSION
        or payload.get("synthetic_data_only") is not True
        or payload.get("synthetic_publishers_only") is not True
        or payload.get("network_enabled") is not False
        or payload.get("external_providers_enabled") is not False
        or payload.get("telegram_intake_enabled") is not False
        or payload.get("real_media_enabled") is not False
        or payload.get("real_payment_enabled") is not False
        or payload.get("local_source_required") is not True
        or payload.get("required_platforms") != ["REDDIT", "TELEGRAM", "X"]
        or payload.get("paid_targets") != ["REDDIT", "TELEGRAM"]
        or payload.get("uncompensated_targets") != ["X"]
    ):
        raise GateFailure("manifest: commercial S0 safety contract mismatch")
    for field in ("application_sha", "control_sha"):
        if not isinstance(payload[field], str) or SHA_RE.fullmatch(payload[field]) is None:
            raise GateFailure("manifest: invalid " + field)
    for field in (
        "archive_inventory_sha256",
        "archive_sha256",
        "dependency_lock_sha256",
        "readiness_contract_sha256",
        "unit_sha256",
    ):
        if not isinstance(payload[field], str) or DIGEST_RE.fullmatch(payload[field]) is None:
            raise GateFailure("manifest: invalid " + field)
    if (
        not isinstance(payload["archive_name"], str)
        or not payload["archive_name"].startswith("tu1nz_system_backup_")
        or not payload["archive_name"].endswith(".tar.gz")
        or "/" in payload["archive_name"]
    ):
        raise GateFailure("manifest: invalid archive name")
    expected_roots = required_backup_roots(
        str(payload["application_sha"]),
        str(payload["control_sha"]),
    )
    if payload.get("backup_member_roots") != expected_roots:
        raise GateFailure("manifest: backup roots mismatch")
    for field in ("rpo_target_seconds", "rto_target_seconds", "retention_days"):
        if (
            isinstance(payload[field], bool)
            or not isinstance(payload[field], int)
            or payload[field] <= 0
        ):
            raise GateFailure("manifest: invalid " + field)
    try:
        backup_completed = utc_timestamp(
            str(payload["backup_completed_at"]),
            "backup_completed_at",
        )
        approved = utc_timestamp(str(payload["approved_utc"]), "approved_utc")
    except ManifestFailure as error:
        raise GateFailure("manifest: invalid timestamp") from error
    if approved < backup_completed:
        raise GateFailure("manifest: approval predates backup")
    hashes = payload.get("migration_hashes")
    if (
        not isinstance(hashes, dict)
        or not hashes
        or any(
            not isinstance(name, str)
            or not isinstance(digest, str)
            or DIGEST_RE.fullmatch(digest) is None
            for name, digest in hashes.items()
        )
    ):
        raise GateFailure("manifest: migration hashes invalid")
    for required in (
        "migrations/0014_m4_15_durable_commercial_persistence.sql",
        "migrations/0014_m4_15_durable_commercial_persistence.down.sql",
    ):
        if required not in hashes:
            raise GateFailure("manifest: commercial migration evidence missing")
    return payload


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "safe.directory=" + str(repository),
            "-C",
            str(repository),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise GateFailure("Git verification failed")
    return result.stdout.strip()


def resolve_release(
    path: Path,
    root: Path,
    expected_sha: str,
    field: str,
    *,
    active: bool,
) -> Path:
    if active and not path.is_symlink():
        raise GateFailure(field + ": active link missing")
    if not active and path.is_symlink():
        raise GateFailure(field + ": symlink forbidden")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise GateFailure(field + ": path escapes release root") from error
    if resolved.parent != resolved_root or resolved.name != expected_sha:
        raise GateFailure(field + ": directory must equal exact SHA")
    return resolved


def verify_repository(repository: Path, expected_sha: str, field: str) -> None:
    if git(repository, "rev-parse", "HEAD") != expected_sha:
        raise GateFailure(field + ": SHA mismatch")
    if git(repository, "status", "--porcelain=v1"):
        raise GateFailure(field + ": worktree is dirty")
    git(repository, "fsck", "--full")
    ignored = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "safe.directory=" + str(repository),
            "-C",
            str(repository),
            "clean",
            "-ndx",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if ignored.returncode != 0 or ignored.stdout:
        raise GateFailure(field + ": untracked or ignored files present")


def load_runtime_environment(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise GateFailure("runtime environment is unreadable") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            raise GateFailure("runtime environment must contain exactly one assignment")
        key, value = line.split("=", 1)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key in values:
            raise GateFailure("runtime environment contains a duplicate key")
        values[key] = value
    if set(values) != {"TU1NZ_COMMERCIAL_CANDIDATE_POSTGRES_DSN"}:
        raise GateFailure("runtime environment key set mismatch")
    if values["TU1NZ_COMMERCIAL_CANDIDATE_POSTGRES_DSN"] != EXPECTED_DSN:
        raise GateFailure("runtime PostgreSQL DSN is not local commercial S0")
    return values


def verify_configuration(
    root: Path,
    root_uid: int,
    runtime_uid: int,
    runtime_gid: int,
) -> None:
    verify_metadata(root, 0o750, root_uid, runtime_gid, "configuration root")
    if {path.name for path in root.iterdir()} != {
        "core-identities.json",
        "release-manifest.json",
        "runtime.env",
    }:
        raise GateFailure("configuration root contains an unexpected file")
    verify_metadata(root / "runtime.env", 0o640, root_uid, runtime_gid, "runtime environment")
    verify_metadata(
        root / "release-manifest.json",
        0o640,
        root_uid,
        runtime_gid,
        "release manifest",
    )
    verify_metadata(
        root / "core-identities.json",
        0o600,
        runtime_uid,
        runtime_gid,
        "core identities",
    )
    load_runtime_environment(root / "runtime.env")
    identities = read_json(root / "core-identities.json", "core identities")
    if (
        not isinstance(identities, dict)
        or set(identities) != {"bindings", "environment"}
        or identities.get("environment") != ENVIRONMENT
        or not isinstance(identities.get("bindings"), dict)
        or not identities["bindings"]
    ):
        raise GateFailure("core identities shape invalid")
    try:
        for subject, creator_id in identities["bindings"].items():
            if not isinstance(subject, str) or DIGEST_RE.fullmatch(subject) is None:
                raise ValueError
            UUID(creator_id)
    except (AttributeError, TypeError, ValueError) as error:
        raise GateFailure("core identity binding invalid") from error


def verify_state(root: Path, runtime_uid: int, runtime_gid: int) -> None:
    verify_metadata(root, 0o700, runtime_uid, runtime_gid, "state root")
    if not {path.name for path in root.iterdir()} <= {
        "runtime-status.json",
        "runtime.lock",
        "state.json",
    }:
        raise GateFailure("state root contains an unexpected file")
    verify_metadata(root / "state.json", 0o600, runtime_uid, runtime_gid, "state")
    state_payload = read_json(root / "state.json", "state")
    if (
        not isinstance(state_payload, dict)
        or set(state_payload)
        != {
            "creator_verifications",
            "processed_updates",
            "product_events",
            "submissions",
            "terms_acceptances",
            "version",
        }
        or state_payload["version"] != 2
        or state_payload["product_events"] != []
        or any(
            state_payload[key] != {}
            for key in (
                "creator_verifications",
                "processed_updates",
                "submissions",
                "terms_acceptances",
            )
        )
    ):
        raise GateFailure("initial commercial state is not empty")
    status_path = root / "runtime-status.json"
    if status_path.exists() or status_path.is_symlink():
        verify_metadata(status_path, 0o600, runtime_uid, runtime_gid, "runtime status")
        status_payload = read_json(status_path, "runtime status")
        if (
            not isinstance(status_payload, dict)
            or status_payload.get("environment") != ENVIRONMENT
            or status_payload.get("synthetic_data_only") is not True
            or status_payload.get("outbound_providers_enabled") is not False
        ):
            raise GateFailure("runtime status safety contract mismatch")
    lock_path = root / "runtime.lock"
    if lock_path.exists() or lock_path.is_symlink():
        verify_metadata(lock_path, 0o600, runtime_uid, runtime_gid, "runtime lock")


def verify_venv(path: Path, release_uid: int, runtime_gid: int) -> None:
    verify_metadata(path, 0o750, release_uid, runtime_gid, "venv")
    result = subprocess.run(
        [
            str(path / "bin" / "python"),
            "-c",
            "import importlib.metadata,psycopg,tu1nz_sandbox;"
            "print(psycopg.__version__+'|'"
            "+importlib.metadata.version('tu1nz-adult-publishing-core'))",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode != 0 or result.stdout.strip() != "3.3.4|0.1.0":
        raise GateFailure("venv dependency or application import mismatch")
    for command in (
        "tu1nz-commercial-runtime-candidate",
        "tu1nz-commercial-candidate-health",
    ):
        target = path / "bin" / command
        if not target.is_file() or target.is_symlink() or not os.access(target, os.X_OK):
            raise GateFailure("venv command missing: " + command)


def verify_application_contract(application: Path) -> None:
    configuration = read_json(
        application / "config" / "commercial-runtime-candidate.disabled.json",
        "application candidate configuration",
    )
    if (
        not isinstance(configuration, dict)
        or set(configuration)
        != {
            "active",
            "commercial_composition_enabled",
            "commercial_contract_version",
            "database_scope",
            "environment",
            "external_providers_enabled",
            "installed",
            "network_enabled",
            "persistence_schema_version",
            "real_media_enabled",
            "repository_entrypoint_available",
            "runtime_version",
            "server_enabled",
            "synthetic_data_only",
            "synthetic_publishers_only",
        }
        or configuration.get("environment") != ENVIRONMENT
        or configuration.get("active") is not False
        or configuration.get("installed") is not False
        or configuration.get("server_enabled") is not False
        or configuration.get("network_enabled") is not False
        or configuration.get("external_providers_enabled") is not False
        or configuration.get("real_media_enabled") is not False
        or configuration.get("commercial_composition_enabled") is not True
        or configuration.get("database_scope") != "LOCAL_ONLY"
        or configuration.get("persistence_schema_version")
        != PERSISTENCE_SCHEMA_VERSION
        or configuration.get("repository_entrypoint_available") is not True
        or configuration.get("synthetic_data_only") is not True
        or configuration.get("synthetic_publishers_only") is not True
        or configuration.get("commercial_contract_version")
        != COMMERCIAL_CONTRACT_VERSION
        or configuration.get("runtime_version") != RUNTIME_VERSION
    ):
        raise GateFailure("application candidate configuration is unsafe")
    try:
        project = (application / "pyproject.toml").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateFailure("application entrypoints are unreadable") from error
    for entrypoint in (
        'tu1nz-commercial-runtime-candidate = "tu1nz_sandbox.commercial_candidate:runtime_entrypoint"',
        'tu1nz-commercial-candidate-health = "tu1nz_sandbox.commercial_candidate:health_entrypoint"',
    ):
        if entrypoint not in project:
            raise GateFailure("application commercial entrypoint missing")


def verify_archive(archive: Path, manifest: dict[str, object]) -> None:
    if archive.name != manifest["archive_name"]:
        raise GateFailure("backup archive name mismatch")
    if sha256_file(archive) != manifest["archive_sha256"]:
        raise GateFailure("backup archive digest mismatch")
    try:
        inventory = archive_inventory(archive, list(manifest["backup_member_roots"]))
    except (ManifestFailure, TypeError) as error:
        raise GateFailure("backup archive contract mismatch") from error
    if inventory != manifest["archive_inventory_sha256"]:
        raise GateFailure("backup archive inventory mismatch")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--application-repository", type=Path, required=True)
    parser.add_argument("--control-repository", type=Path, required=True)
    parser.add_argument("--application-release-root", type=Path, required=True)
    parser.add_argument("--control-release-root", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--configuration-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--installed-unit", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--runtime-user", required=True)
    parser.add_argument("--runtime-group", required=True)
    parser.add_argument("--release-user", required=True)
    parser.add_argument("--configuration-user", required=True)
    parser.add_argument("--unit-user", required=True)
    parser.add_argument("--unit-group", required=True)
    parser.add_argument("--require-active", action="store_true")
    return parser.parse_args()


def execute(arguments: argparse.Namespace) -> None:
    manifest = load_manifest(arguments.manifest)
    runtime_uid = account(arguments.runtime_user)
    runtime_gid = account(arguments.runtime_group, group=True)
    release_uid = account(arguments.release_user)
    configuration_uid = account(arguments.configuration_user)
    unit_uid = account(arguments.unit_user)
    unit_gid = account(arguments.unit_group, group=True)
    application = resolve_release(
        arguments.application_repository,
        arguments.application_release_root,
        str(manifest["application_sha"]),
        "application",
        active=arguments.require_active,
    )
    control = resolve_release(
        arguments.control_repository,
        arguments.control_release_root,
        str(manifest["control_sha"]),
        "control",
        active=arguments.require_active,
    )
    verify_repository(application, str(manifest["application_sha"]), "application")
    verify_repository(control, str(manifest["control_sha"]), "control")
    verify_metadata(application, 0o750, release_uid, runtime_gid, "application release")
    verify_metadata(control, 0o750, release_uid, runtime_gid, "control release")
    if migration_hashes(application) != manifest["migration_hashes"]:
        raise GateFailure("application migration hashes mismatch")
    if sha256_file(application / "requirements-m2.lock") != manifest[
        "dependency_lock_sha256"
    ]:
        raise GateFailure("application dependency lock mismatch")
    verify_application_contract(application)
    versioned_readiness = (
        control / "manifests" / "adult-publishing-commercial-readiness.m4-18.json"
    )
    if sha256_file(versioned_readiness) != manifest["readiness_contract_sha256"]:
        raise GateFailure("M4.18 readiness contract drift")
    versioned_unit = control / "systemd" / UNIT_NAME
    if sha256_file(versioned_unit) != manifest["unit_sha256"]:
        raise GateFailure("versioned unit drift")
    verify_metadata(arguments.installed_unit, 0o644, unit_uid, unit_gid, "installed unit")
    if arguments.installed_unit.read_bytes() != versioned_unit.read_bytes():
        raise GateFailure("installed unit differs from Control SSOT")
    verify_configuration(
        arguments.configuration_root,
        configuration_uid,
        runtime_uid,
        runtime_gid,
    )
    if arguments.manifest.resolve() != (
        arguments.configuration_root / "release-manifest.json"
    ).resolve():
        raise GateFailure("manifest must be the configured release manifest")
    verify_state(arguments.state_root, runtime_uid, runtime_gid)
    if arguments.require_active and not arguments.venv.is_symlink():
        raise GateFailure("venv: active link missing")
    if not arguments.require_active and arguments.venv.is_symlink():
        raise GateFailure("venv: symlink forbidden")
    venv = arguments.venv.resolve(strict=True)
    expected_venv_root = arguments.application_release_root.parent / "venv"
    try:
        venv.relative_to(expected_venv_root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise GateFailure("venv escapes its immutable root") from error
    if venv.name != manifest["application_sha"]:
        raise GateFailure("venv directory must equal application SHA")
    verify_venv(venv, release_uid, runtime_gid)
    if arguments.archive is not None:
        verify_archive(arguments.archive.resolve(strict=True), manifest)


def main() -> int:
    try:
        execute(parse_arguments())
        print("COMMERCIAL_S0_RELEASE_GATE_OK")
        return 0
    except (GateFailure, ManifestFailure, OSError, subprocess.SubprocessError) as error:
        print("COMMERCIAL_S0_RELEASE_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
