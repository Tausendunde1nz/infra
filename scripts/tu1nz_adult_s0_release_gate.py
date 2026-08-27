#!/usr/bin/env python3
"""Read-only STAGING-S0 release gate; permits no live or outbound content."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path

from tu1nz_adult_restore_verify import RestoreFailure, load_manifest, verify_artifact_hashes, verify_repository


class GateFailure(RuntimeError):
    pass


CONFIG_KEYS = {
    "database_name",
    "database_socket",
    "environment",
    "media_storage_root",
    "outbound_providers_enabled",
    "required_platforms",
    "synthetic_data_only",
}


def resolved_beneath(path: Path, parent: Path, field: str, allow_symlink: bool = False) -> Path:
    if path.is_symlink() and not allow_symlink:
        raise GateFailure(f"{field}: symlink forbidden")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(parent.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise GateFailure(f"{field}: path escapes approved root") from error
    return resolved


def account(name: str, group: bool = False) -> int:
    try:
        return grp.getgrnam(name).gr_gid if group else pwd.getpwnam(name).pw_uid
    except KeyError as error:
        raise GateFailure(f"required account missing: {name}") from error


def verify_metadata(path: Path, mode: int, uid: int, gid: int, field: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateFailure(f"{field}: missing") from error
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise GateFailure(f"{field}: mode must be {mode:o}")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        raise GateFailure(f"{field}: owner mismatch")


def read_config(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise GateFailure("configuration must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("configuration is invalid JSON") from error
    if not isinstance(payload, dict) or set(payload) != CONFIG_KEYS:
        raise GateFailure("configuration keys violate the exact allowlist")
    if payload.get("environment") != "STAGING-S0":
        raise GateFailure("environment mismatch")
    if payload.get("synthetic_data_only") is not True:
        raise GateFailure("synthetic-only flag required")
    if payload.get("outbound_providers_enabled") is not False:
        raise GateFailure("outbound providers must be disabled")
    if payload.get("required_platforms") != ["REDDIT", "TELEGRAM", "X"]:
        raise GateFailure("required platform set mismatch")
    if payload.get("database_socket") != "/run/postgresql":
        raise GateFailure("only the local PostgreSQL socket is allowed")
    if payload.get("database_name") != "tu1nz_adult_s0":
        raise GateFailure("database name mismatch")
    return payload


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--application-repository", type=Path, required=True)
    parser.add_argument("--control-repository", type=Path, required=True)
    parser.add_argument("--application-release-root", type=Path, required=True)
    parser.add_argument("--control-release-root", type=Path, required=True)
    parser.add_argument("--application-active-link", type=Path, required=True)
    parser.add_argument("--control-active-link", type=Path, required=True)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--runtime-user", required=True)
    parser.add_argument("--runtime-group", required=True)
    parser.add_argument("--release-user", required=True)
    parser.add_argument("--release-group", required=True)
    parser.add_argument("--configuration-user", required=True)
    parser.add_argument("--require-active", action="store_true")
    return parser.parse_args()


def execute(arguments: argparse.Namespace) -> None:
    if arguments.manifest.is_symlink():
        raise GateFailure("manifest must not be a symlink")
    try:
        manifest = load_manifest(arguments.manifest)
    except RestoreFailure as error:
        raise GateFailure(f"manifest rejected: {error.code}") from error

    if arguments.application_release_root.is_symlink() or arguments.control_release_root.is_symlink():
        raise GateFailure("release roots must not be symlinks")
    application_release_root = arguments.application_release_root.resolve(strict=True)
    control_release_root = arguments.control_release_root.resolve(strict=True)
    application = resolved_beneath(
        arguments.application_repository,
        application_release_root,
        "application",
        allow_symlink=arguments.require_active,
    )
    if application.name != manifest.application_sha:
        raise GateFailure("release directory must equal application SHA")
    control = resolved_beneath(
        arguments.control_repository,
        control_release_root,
        "control",
        allow_symlink=arguments.require_active,
    )
    if control.name != manifest.control_sha:
        raise GateFailure("control release directory must equal control SHA")
    try:
        verify_repository(application, manifest.application_sha, "APPLICATION_SHA_MISMATCH")
        verify_repository(control, manifest.control_sha, "CONTROL_SHA_MISMATCH")
        verify_artifact_hashes(application, manifest)
    except RestoreFailure as error:
        raise GateFailure(f"immutable artifact rejected: {error.code}") from error
    for repository in (application, control):
        clean = subprocess.run(
            ["/usr/bin/git", "-C", str(repository), "clean", "-ndx"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if clean.returncode != 0 or clean.stdout:
            raise GateFailure("immutable release contains untracked or ignored files")

    if arguments.require_active:
        for link, expected, field in (
            (arguments.application_active_link, application, "application"),
            (arguments.control_active_link, control, "control"),
        ):
            if not link.is_symlink():
                raise GateFailure(f"active {field} release link missing")
            if link.resolve(strict=True) != expected:
                raise GateFailure(f"active {field} release points to a different artifact")

    runtime_uid = account(arguments.runtime_user)
    runtime_gid = account(arguments.runtime_group, group=True)
    release_uid = account(arguments.release_user)
    release_gid = account(arguments.release_group, group=True)
    configuration_uid = account(arguments.configuration_user)
    verify_metadata(application, 0o750, release_uid, release_gid, "application release")
    verify_metadata(control, 0o750, release_uid, release_gid, "control release")
    if arguments.configuration.is_symlink() or arguments.state_root.is_symlink():
        raise GateFailure("configuration and state root must not be symlinks")
    verify_metadata(
        arguments.manifest.resolve(strict=True),
        0o640,
        configuration_uid,
        runtime_gid,
        "manifest",
    )
    configuration = arguments.configuration.resolve(strict=True)
    verify_metadata(configuration, 0o640, configuration_uid, runtime_gid, "configuration")
    state_root = arguments.state_root.resolve(strict=True)
    verify_metadata(state_root, 0o750, runtime_uid, runtime_gid, "state root")

    payload = read_config(configuration)
    media = Path(str(payload["media_storage_root"]))
    resolved_beneath(media, state_root, "media storage")
    verify_metadata(media, 0o750, runtime_uid, runtime_gid, "media storage")


def main() -> int:
    try:
        execute(parse_arguments())
        print("S0_RELEASE_GATE_OK")
        return 0
    except (GateFailure, OSError, subprocess.SubprocessError) as error:
        print(f"S0_RELEASE_GATE_BLOCKED {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
