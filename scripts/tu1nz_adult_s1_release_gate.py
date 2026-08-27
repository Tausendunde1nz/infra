#!/usr/bin/env python3
"""Read-only immutable release gate for persistent Telegram STAGING-S1."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from uuid import UUID

from tu1nz_adult_staging_manifest import migration_hashes, sha256_file


class GateFailure(RuntimeError):
    pass


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[0-9]{6,16}:[A-Za-z0-9_-]{30,96}$")
EXPECTED_DSN = (
    "postgresql:///tu1nz_adult_s1?host=/run/postgresql"
    "&user=tu1nz-adult-s1&sslmode=disable"
)
MANIFEST_KEYS = {
    "application_sha",
    "approved_utc",
    "archive_sha256",
    "backup_completed_at",
    "bot_username",
    "control_sha",
    "dependency_lock_sha256",
    "environment",
    "live_publishers_enabled",
    "local_source_required",
    "migration_hashes",
    "mock_payment_only",
    "required_platforms",
    "retention_days",
    "rpo_target_seconds",
    "rto_target_seconds",
    "synthetic_data_only",
    "telegram_intake_enabled",
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
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(
        metadata.st_mode
    ):
        raise GateFailure(field + ": regular file or directory required")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise GateFailure("{0}: mode must be {1:o}".format(field, mode))
    if metadata.st_uid != uid or metadata.st_gid != gid:
        raise GateFailure(field + ": owner mismatch")


def read_json(path: Path, field: str) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure(field + ": safe regular file required")
    if path.stat().st_size > 1024 * 1024:
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
        payload.get("environment") != "STAGING-S1"
        or payload.get("bot_username") != "TU1NZ_Adult_Sandbox_Bot"
        or payload.get("synthetic_data_only") is not True
        or payload.get("telegram_intake_enabled") is not True
        or payload.get("live_publishers_enabled") is not False
        or payload.get("mock_payment_only") is not True
        or payload.get("required_platforms") != ["REDDIT", "TELEGRAM", "X"]
        or payload.get("local_source_required") is not True
    ):
        raise GateFailure("manifest: S1 safety contract mismatch")
    for field in ("application_sha", "control_sha"):
        if not isinstance(payload[field], str) or SHA_RE.fullmatch(payload[field]) is None:
            raise GateFailure("manifest: invalid " + field)
    for field in ("archive_sha256", "dependency_lock_sha256"):
        if not isinstance(payload[field], str) or DIGEST_RE.fullmatch(payload[field]) is None:
            raise GateFailure("manifest: invalid " + field)
    for field in ("rpo_target_seconds", "rto_target_seconds", "retention_days"):
        if isinstance(payload[field], bool) or not isinstance(payload[field], int) or payload[field] <= 0:
            raise GateFailure("manifest: invalid " + field)
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
    return payload


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
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
        ["/usr/bin/git", "-C", str(repository), "clean", "-ndx"],
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
            raise GateFailure("runtime environment must contain exactly two assignments")
        key, value = line.split("=", 1)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key in values:
            raise GateFailure("runtime environment contains a duplicate key")
        values[key] = value
    if set(values) != {
        "TU1NZ_TELEGRAM_STAGING_S1_TOKEN",
        "TU1NZ_STAGING_S1_POSTGRES_DSN",
    }:
        raise GateFailure("runtime environment key set mismatch")
    if TOKEN_RE.fullmatch(values["TU1NZ_TELEGRAM_STAGING_S1_TOKEN"]) is None:
        raise GateFailure("runtime Telegram token has invalid shape")
    if values["TU1NZ_STAGING_S1_POSTGRES_DSN"] != EXPECTED_DSN:
        raise GateFailure("runtime PostgreSQL DSN is not local S1")
    return values


def verify_configuration(root: Path, root_uid: int, runtime_gid: int) -> None:
    verify_metadata(root, 0o750, root_uid, runtime_gid, "configuration root")
    files = {
        "core-identities.json": "core identities",
        "identity-policy.json": "identity policy",
        "media-registry.json": "media registry",
        "runtime.env": "runtime environment",
        "subject-key": "subject key",
    }
    for name, field in files.items():
        verify_metadata(root / name, 0o640, root_uid, runtime_gid, field)
    policy = read_json(root / "identity-policy.json", "identity policy")
    if not isinstance(policy, dict) or set(policy) != {
        "allowed_user_ids",
        "creator_user_ids",
        "moderator_user_ids",
    }:
        raise GateFailure("identity policy shape invalid")
    for key in policy:
        if (
            not isinstance(policy[key], list)
            or not policy[key]
            or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in policy[key])
        ):
            raise GateFailure("identity policy values invalid")
    if not set(policy["creator_user_ids"]) | set(policy["moderator_user_ids"]) <= set(
        policy["allowed_user_ids"]
    ):
        raise GateFailure("identity policy roles are not allowlisted")
    identities = read_json(root / "core-identities.json", "core identities")
    if (
        not isinstance(identities, dict)
        or set(identities) != {"bindings", "environment"}
        or identities.get("environment") != "STAGING-S1"
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
    registry = read_json(root / "media-registry.json", "media registry")
    if not isinstance(registry, dict) or not registry:
        raise GateFailure("media registry is empty")
    for reference, record in registry.items():
        if (
            not isinstance(reference, str)
            or not reference
            or not isinstance(record, dict)
            or set(record) - {"sha256", "source"}
            or DIGEST_RE.fullmatch(record.get("sha256", "")) is None
        ):
            raise GateFailure("media registry entry invalid")
    try:
        subject_key = bytes.fromhex(
            (root / "subject-key").read_text(encoding="ascii").strip()
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise GateFailure("subject key is invalid") from error
    if len(subject_key) < 32:
        raise GateFailure("subject key is too short")
    load_runtime_environment(root / "runtime.env")


def verify_state(root: Path, runtime_uid: int, runtime_gid: int) -> None:
    verify_metadata(root, 0o750, runtime_uid, runtime_gid, "state root")
    verify_metadata(root / "media", 0o700, runtime_uid, runtime_gid, "media root")
    for name, field in (
        ("state.json", "conversation state"),
        ("telegram-offset.json", "Telegram cursor"),
    ):
        verify_metadata(root / name, 0o600, runtime_uid, runtime_gid, field)
    state = read_json(root / "state.json", "conversation state")
    if (
        not isinstance(state, dict)
        or set(state) != {
            "processed_updates",
            "submissions",
            "terms_acceptances",
            "version",
        }
        or state["version"] != 1
        or any(state[key] != {} for key in ("processed_updates", "submissions", "terms_acceptances"))
    ):
        raise GateFailure("initial conversation state is not empty")
    cursor = read_json(root / "telegram-offset.json", "Telegram cursor")
    if (
        not isinstance(cursor, dict)
        or set(cursor) != {"next_update_id", "version"}
        or cursor["version"] != 1
        or isinstance(cursor["next_update_id"], bool)
        or not isinstance(cursor["next_update_id"], int)
        or cursor["next_update_id"] < 0
    ):
        raise GateFailure("Telegram cursor is invalid")


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
    )
    if result.returncode != 0 or result.stdout.strip() != "3.3.4|0.1.0":
        raise GateFailure("venv dependency or application import mismatch")
    for command in ("tu1nz-adult-sandbox", "tu1nz-adult-staging-health"):
        target = path / "bin" / command
        if not target.is_file() or target.is_symlink() or not os.access(target, os.X_OK):
            raise GateFailure("venv command missing: " + command)


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
    verify_metadata(
        arguments.manifest,
        0o640,
        configuration_uid,
        runtime_gid,
        "manifest",
    )
    verify_configuration(arguments.configuration_root, configuration_uid, runtime_gid)
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
    verify_metadata(arguments.installed_unit, 0o644, unit_uid, unit_gid, "installed unit")
    versioned_unit = control / "systemd" / "tu1nz-adult-publishing-s1.service"
    if not versioned_unit.is_file() or arguments.installed_unit.read_bytes() != versioned_unit.read_bytes():
        raise GateFailure("installed unit differs from Control SSOT")


def main() -> int:
    try:
        execute(parse_arguments())
        print("S1_RELEASE_GATE_OK")
        return 0
    except (GateFailure, OSError, subprocess.SubprocessError) as error:
        print("S1_RELEASE_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
