#!/usr/bin/env python3
"""Backup-first, exactly-once S12.1 Yoti Sandbox runtime deployment.

This controller is intentionally release-bound and non-resumable.  It performs
one bounded acceptance, restores the public nginx configuration immediately,
and leaves the external-provider runtime controlled inactive.  It never reads
credential values into output or retained evidence.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence


APPLICATION_COMMIT = "93555d8a141caf8ace33522f9340d30bfc47d2bb"
APPLICATION_TREE = "1e8a644115127818f394b6f9d24f31826e04ecba"
FREEZE_TAG = "s12-yoti-sandbox-runtime-freeze-r8"
CONTRACT_VERSION = "tu1nz-s12-yoti-sandbox-runtime-v1"
BACKUP_SCHEMA = "TU1NZ_S12_1_RUNTIME_BACKUP_V8"
BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V3"
XATTR_BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V2"
LEGACY_BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V1"
BARRIER_RELEASE_COMPLETION_SCHEMA = "TU1NZ_S12_1_BARRIER_RELEASE_COMPLETE_V1"
TRACKED_PATH_HASH_SCHEMA = b"TU1NZ_S12_1_TRACKED_PATH_HASHES_V1\0"
ROLLBACK_PROGRESS_SCHEMA = "TU1NZ_S12_1_ROLLBACK_PROGRESS_V1"
ROLLBACK_PHASE_STARTED = "RESTORE_STARTED"
ROLLBACK_PHASE_REPOSITORIES_RESTORED = "REPOSITORIES_RESTORED"
RUNTIME_DEPENDENCY_VERSIONS = {
    "cffi": "2.1.1",
    "cryptography": "50.0.1",
    "psycopg": "3.3.4",
    "psycopg-binary": "3.3.4",
    "pycparser": "3.0",
}
RUNTIME_PYTHON_SHA256 = "1d3cf64f97cadc79fdc6fe2496a21b7b456cb94211978cfef5a65f616af74fd5"
RUNTIME_VENV_SHA256 = "e7a8a8ffa3cba387541f4d0cc0ebea09bd2ade9901c7ab88aaf5e62b3d1df9fa"
BASE_NGINX_SHA256 = "cba472a56bb57d52721430a9b01eeb3f5bd3930a784b8e13e90c8a05ff4ab97c"
HARD_GATE_KEYS = frozenset(
    {
        "adult_media", "adult_submission", "community_adult_media",
        "controlled_beta", "external_publishing", "payments", "production",
        "real_avs",
    }
)
APPLICATION_ROOT = Path("/opt/tu1nz_repos/adult-publishing-core")
CONTROL_ROOT = Path("/opt/tu1nz_repos/control")
DEPLOYMENT_LOCK_ROOT = CONTROL_ROOT.parent
PRIVATE_ROOT = Path("/etc/tu1nz/adult-commercial-s12-1-private")
BACKUP_ROOT = PRIVATE_ROOT / "backups"
STATE_ROOT = PRIVATE_ROOT / "state"
RELEASE_ROOT = PRIVATE_ROOT / "release"
RELEASE_STAGING_ROOT = PRIVATE_ROOT / ".release-staging"
RELEASE_APPLICATION_ROOT = RELEASE_ROOT / "application"
RELEASE_CONTROL_ROOT = RELEASE_ROOT / "control"
RELEASE_VENV_ROOT = RELEASE_ROOT / "venv"
RELEASE_ENVIRONMENT = RELEASE_ROOT / "runtime-environment.json"
ATTEMPT_MARKER = STATE_ROOT / "deployment-attempted.json"
BARRIER_MARKER = STATE_ROOT / "repository-barrier.json"
BARRIER_RELEASE_BACKUP = STATE_ROOT / "repository-barrier.release-backup.json"
BARRIER_RELEASE_COMPLETION = STATE_ROOT / "repository-barrier.release-complete.json"
FETCH_ROOT = DEPLOYMENT_LOCK_ROOT / ".s12-1-fetch"
RELEASE_INPUT_ROOT = Path("/opt/tu1nz_repos/backups/s12-1-input")
APPLICATION_INPUT_BUNDLE = RELEASE_INPUT_ROOT / "application.bundle"
CONTROL_INPUT_BUNDLE = RELEASE_INPUT_ROOT / "control.bundle"
APPLICATION_BUNDLE_DIGEST_ENV = "TU1NZ_S12_1_APPLICATION_BUNDLE_SHA256"
CONTROL_BUNDLE_DIGEST_ENV = "TU1NZ_S12_1_CONTROL_BUNDLE_SHA256"
RUNTIME_CONTRACT = Path("/etc/tu1nz/adult-commercial-s12-1-yoti-runtime.json")
SDK_ID = Path("/etc/tu1nz/adult-commercial-s5.yoti-sdk-id")
PRIVATE_KEY = Path("/etc/tu1nz/adult-commercial-s5.yoti-private-key")
CHATOPS_USER = "chatops"
RUNUSER = "/usr/sbin/runuser"
UNIT_NAME = "tu1nz-adult-commercial-s12-yoti-runtime.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
NGINX_SITE = Path("/etc/nginx/sites-available/wantmeseen.conf")
NGINX_ENABLED = Path("/etc/nginx/sites-enabled/wantmeseen.conf")
PUBLIC_URLS = (
    ("https://wantmeseen.com/", "200"),
    ("https://wantmeseen.com/health", "200"),
    ("https://wantmeseen.com/privacy", "200"),
    ("https://wantmeseen.com/terms", "200"),
    ("https://wantmeseen.com/imprint", "200"),
    ("https://wantmeseen.de/", "308"),
)
SERVICES = (
    "tu1nz-adult-public-s7.service",
    "tu1nz-adult-public-s8-landing.service",
    "tu1nz-adult-public-s8-telegram.service",
    "tu1nz-adult-public-s10-wms.service",
    "nginx.service",
)
S11_TIMER = "tu1nz-adult-public-s11-canary-controller.timer"
SYSTEMD_UNIT_ROOTS = (
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
)
TRUSTED_CONTROLLER_PATH = Path(
    "/etc/tu1nz/.tu1nz-adult-commercial-s12-1-runtime.py"
)
TRUSTED_CONTROLLER_DIGEST_ENV = "TU1NZ_S12_1_TRUSTED_CONTROLLER_SHA256"
SOURCE_ROOT = (
    CONTROL_ROOT
    if Path(__file__).absolute() == TRUSTED_CONTROLLER_PATH
    else Path(__file__).resolve().parents[1]
)
MANIFEST = SOURCE_ROOT / "manifests/adult-publishing-commercial-s12-1-yoti-sandbox-runtime.json"
SOURCE_UNIT = SOURCE_ROOT / "systemd" / UNIT_NAME
SOURCE_NGINX = SOURCE_ROOT / "nginx/current/wantmeseen.s12-1-acceptance.conf"
SOURCE_BASE_NGINX = SOURCE_ROOT / "nginx/current/wantmeseen.s10-1-final.conf"
RECOVERY_GIT_DIRECTORY = ".git.s12-1-recovery"
ALLOWED_LOCAL_GIT_CONFIG = (
    re.compile(
        r"core\.(repositoryformatversion|filemode|bare|logallrefupdates|"
        r"ignorecase|precomposeunicode|sshcommand)\Z"
    ),
    re.compile(r"remote\.origin\.(url|fetch)\Z"),
    re.compile(r"branch\.[A-Za-z0-9._/-]+\.(remote|merge)\Z"),
    re.compile(r"user\.(name|email)\Z"),
)


class S12ControlError(RuntimeError):
    def __init__(self, safe_code: str) -> None:
        self.safe_code = safe_code
        super().__init__(safe_code)


def expected_manifest_contract() -> dict[str, Any]:
    """Return the complete immutable S12.1 runtime manifest contract."""

    return {
        "application": {
            "commit": APPLICATION_COMMIT,
            "tree": APPLICATION_TREE,
        },
        "callback": {
            "authority": "AUTHENTICATED_RESULT_FETCH_ONLY",
            "bind": "127.0.0.1:18126",
            "body_limit_bytes": 16384,
            "method": "POST",
            "path": "/avs/sandbox/callback",
            "public_url": "https://wantmeseen.com/avs/sandbox/callback",
            "signature": "YOTI_SANDBOX_RSA_PSS_SHA256",
            "trigger_only": True,
        },
        "contract_version": CONTRACT_VERSION,
        "control": {
            "commit_binding": "ANNOTATED_RUNTIME_FREEZE_TARGET",
            "tree_binding": "ANNOTATED_RUNTIME_FREEZE_TARGET_TREE",
        },
        "credentials": {
            "delivery": "SYSTEMD_LOAD_CREDENTIAL",
            "private_key_reference": str(PRIVATE_KEY),
            "sdk_id_reference": str(SDK_ID),
            "values_committed": False,
        },
        "decision": "SOURCE_GREEN_RUNTIME_DEPLOYMENT_REQUIRES_EXACT_FREEZE",
        "environment": "SANDBOX",
        "final_posture": {
            "callback": "INACTIVE",
            "runtime": "CONTROLLED_INACTIVE",
            "yoti_sandbox_enabled_for_real_users": False,
        },
        "hard_gates": {key: False for key in sorted(HARD_GATE_KEYS)},
        "health": {
            "credential_values_visible": False,
            "privacy_safe": True,
            "required_safe_code": "S12_RUNTIME_HEALTH_GREEN",
        },
        "network": {
            "allowed_hosts": ["age.yoti.com", "auth.api.yoti.com"],
            "https_only": True,
            "production_endpoint_allowed": False,
            "redirect_to_unknown_host_allowed": False,
        },
        "provider": "YOTI",
        "rollback": {
            "contract": "EXACTLY_ONCE_BACKUP_FIRST_CONTROLLED_INACTIVE",
            "credentials_preserved": True,
            "second_deployment_allowed": False,
        },
        "runtime_environment": {
            "python_sha256": RUNTIME_PYTHON_SHA256,
            "source": "REVIEWED_APPLICATION_VENV_SHA256",
            "venv_sha256": RUNTIME_VENV_SHA256,
        },
        "runtime_freeze": FREEZE_TAG,
        "sandbox_policy": {
            "allowed_methods": ["AGE_ESTIMATION"],
            "provider_result_authority": "AUTHENTICATED_RESULT_FETCH",
            "real_identity_allowed": False,
            "synthetic_subject_only": True,
            "threshold": 18,
        },
        "systemd": {
            "credential_names": [
                "s12-runtime-contract",
                "yoti-private-key",
                "yoti-sdk-id",
            ],
            "unit": UNIT_NAME,
        },
    }


def _exact_json_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (
            actual.keys() == expected.keys()
            and all(_exact_json_equal(actual[key], value) for key, value in expected.items())
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_json_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


def manifest_contract_is_exact(raw: object) -> bool:
    return _exact_json_equal(raw, expected_manifest_contract())


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise S12ControlError("S12_1_CONTROL_MANIFEST_DUPLICATE_KEY_RED")
        value[key] = item
    return value


def parse_manifest_contract(payload: str) -> dict[str, Any]:
    try:
        raw = json.loads(payload, object_pairs_hook=_reject_duplicate_json_pairs)
    except json.JSONDecodeError:
        raise S12ControlError("S12_1_CONTROL_MANIFEST_RED") from None
    if not manifest_contract_is_exact(raw):
        raise S12ControlError("S12_1_CONTROL_MANIFEST_RED")
    return raw


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError
        os.fsync(descriptor)
    except OSError:
        raise S12ControlError("S12_1_DURABILITY_RED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sync_repository_filesystem(root: Path) -> None:
    """Durably flush repository worktree and Git metadata on Linux."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        metadata = os.fstat(descriptor)
        path_metadata = root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError
        library = ctypes.CDLL(None, use_errno=True)
        operation = getattr(library, "syncfs", None)
        if operation is None:
            raise OSError
        operation.argtypes = [ctypes.c_int]
        operation.restype = ctypes.c_int
        if operation(descriptor) != 0:
            raise OSError(ctypes.get_errno(), "syncfs failed")
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_DURABILITY_RED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_secure_directory_chain(path: Path, anchor: Path) -> None:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            raise S12ControlError("S12_1_BACKUP_PATH_RED") from None
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise S12ControlError("S12_1_BACKUP_PATH_RED")
        if current == anchor:
            return
        if current == current.parent:
            raise S12ControlError("S12_1_BACKUP_PATH_RED")
        current = current.parent


def _ensure_private_directory_durable(path: Path, anchor: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        if current.is_symlink() or current == current.parent:
            raise S12ControlError("S12_1_DURABILITY_RED")
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise S12ControlError("S12_1_DURABILITY_RED")
    _validate_secure_directory_chain(current, anchor)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
            os.chown(directory, 0, 0)
            os.chmod(directory, 0o700)
        except OSError:
            raise S12ControlError("S12_1_DURABILITY_RED") from None
        _fsync_directory(directory)
        _fsync_directory(directory.parent)
    _validate_secure_directory_chain(path, anchor)


def _durable_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        raise S12ControlError("S12_1_DURABILITY_RED") from None
    _fsync_directory(path.parent)


def _barrier_path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _barrier_journal_present() -> bool:
    return _barrier_path_present(BARRIER_MARKER) or _barrier_path_present(
        BARRIER_RELEASE_BACKUP
    )


def _assert_barrier_release_file(path: Path, *, links: int) -> os.stat_result:
    try:
        metadata = path.lstat()
        expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
        expected_gid = 0 if os.geteuid() == 0 else os.getegid()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != links
            or not 1 <= metadata.st_size <= 131072
        ):
            raise OSError
        return metadata
    except OSError:
        raise S12ControlError(
            "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
        ) from None


def _barrier_release_completion() -> dict[str, Any] | None:
    if not _barrier_path_present(BARRIER_RELEASE_COMPLETION):
        return None
    value = _private_json(
        BARRIER_RELEASE_COMPLETION,
        "S12_1_REPOSITORY_BARRIER_JOURNAL_RED",
    )
    if (
        set(value) != {"schema", "completed_at", "journal_sha256"}
        or value.get("schema") != BARRIER_RELEASE_COMPLETION_SCHEMA
        or not isinstance(value.get("completed_at"), str)
        or not value["completed_at"]
        or not isinstance(value.get("journal_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["journal_sha256"]) is None
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return value


def _write_barrier_release_completion() -> None:
    _assert_barrier_release_file(BARRIER_RELEASE_BACKUP, links=1)
    _atomic_json(
        BARRIER_RELEASE_COMPLETION,
        {
            "schema": BARRIER_RELEASE_COMPLETION_SCHEMA,
            "completed_at": datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "journal_sha256": _sha256(BARRIER_RELEASE_BACKUP),
        },
    )
    completion = _barrier_release_completion()
    if (
        completion is None
        or completion["journal_sha256"] != _sha256(BARRIER_RELEASE_BACKUP)
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")


def _normalize_barrier_release_backup() -> None:
    """Restore the canonical journal after an interrupted guarded release."""

    marker_present = _barrier_path_present(BARRIER_MARKER)
    backup_present = _barrier_path_present(BARRIER_RELEASE_BACKUP)
    if not backup_present:
        return
    if marker_present:
        marker = _assert_barrier_release_file(BARRIER_MARKER, links=2)
        backup = _assert_barrier_release_file(BARRIER_RELEASE_BACKUP, links=2)
        if (marker.st_dev, marker.st_ino) != (backup.st_dev, backup.st_ino):
            raise S12ControlError(
                "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
            )
        _durable_unlink(BARRIER_RELEASE_BACKUP)
        _assert_barrier_release_file(BARRIER_MARKER, links=1)
        return
    completion = _barrier_release_completion()
    if completion is not None:
        _assert_barrier_release_file(BARRIER_RELEASE_BACKUP, links=1)
        if _sha256(BARRIER_RELEASE_BACKUP) != completion["journal_sha256"]:
            raise S12ControlError(
                "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
            )
        _fsync_directory(STATE_ROOT)
        _durable_unlink(BARRIER_RELEASE_BACKUP)
        return
    _assert_barrier_release_file(BARRIER_RELEASE_BACKUP, links=1)
    try:
        os.replace(BARRIER_RELEASE_BACKUP, BARRIER_MARKER)
    except OSError:
        raise S12ControlError("S12_1_DURABILITY_RED") from None
    _fsync_directory(STATE_ROOT)
    _assert_barrier_release_file(BARRIER_MARKER, links=1)


def _prepare_barrier_release_backup() -> None:
    """Retain one durable journal link until every guard has finalized."""

    if _barrier_path_present(BARRIER_RELEASE_BACKUP):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    marker = _assert_barrier_release_file(BARRIER_MARKER, links=1)
    try:
        os.link(
            BARRIER_MARKER,
            BARRIER_RELEASE_BACKUP,
            follow_symlinks=False,
        )
    except OSError:
        raise S12ControlError("S12_1_DURABILITY_RED") from None
    _fsync_directory(STATE_ROOT)
    linked_marker = _assert_barrier_release_file(BARRIER_MARKER, links=2)
    linked_backup = _assert_barrier_release_file(
        BARRIER_RELEASE_BACKUP, links=2
    )
    if (
        marker.st_dev,
        marker.st_ino,
        marker.st_size,
    ) != (
        linked_marker.st_dev,
        linked_marker.st_ino,
        linked_marker.st_size,
    ) or (linked_marker.st_dev, linked_marker.st_ino) != (
        linked_backup.st_dev,
        linked_backup.st_ino,
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")


def _durable_symlink(target: str, path: Path) -> None:
    _durable_unlink(path)
    try:
        path.symlink_to(target)
    except OSError:
        raise S12ControlError("S12_1_DURABILITY_RED") from None
    _fsync_directory(path.parent)


@contextmanager
def _exclusive_deployment_lock():
    descriptor: int | None = None
    try:
        descriptor = os.open(
            DEPLOYMENT_LOCK_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        path_metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise OSError
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise S12ControlError("S12_1_DEPLOYMENT_LOCK_RED") from None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        os.close(descriptor)
        raise S12ControlError("S12_1_DEPLOYMENT_ALREADY_RUNNING_RED") from None
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _run(
    arguments: Sequence[str],
    *,
    check: bool = True,
    timeout: int = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            input=input_text,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        raise S12ControlError("S12_1_CONTROL_COMMAND_RED") from None
    if check and completed.returncode != 0:
        raise S12ControlError("S12_1_CONTROL_COMMAND_RED")
    return completed


def _as_chatops(arguments: Sequence[str]) -> list[str]:
    command = list(arguments)
    if os.geteuid() == 0:
        return [RUNUSER, "--user", CHATOPS_USER, "--", *command]
    return command


def _git_arguments(root: Path, *arguments: str) -> list[str]:
    return _as_chatops(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), *arguments]
    )


def _isolated_root_git_prefix(root: Path) -> list[str]:
    return [
        "/usr/bin/env",
        "-i",
        "HOME=/",
        "PATH=/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_OPTIONAL_LOCKS=0",
        "/usr/bin/git",
        "-c",
        f"safe.directory={root}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.sshCommand=/bin/false",
        "-c",
        "credential.helper=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
    ]


def _recovery_git_arguments(
    root: Path, git_directory: Path, *arguments: str
) -> list[str]:
    return [
        *_isolated_root_git_prefix(root),
        f"--git-dir={git_directory}",
        f"--work-tree={root}",
        *arguments,
    ]


def _recovery_git(root: Path, git_directory: Path, *arguments: str) -> str:
    completed = _run(_recovery_git_arguments(root, git_directory, *arguments))
    if completed.stderr.strip():
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    return completed.stdout.strip()


def _selected_git_arguments(
    root: Path, git_directory: Path | None, *arguments: str
) -> list[str]:
    if git_directory is None:
        return _git_arguments(root, *arguments)
    return _recovery_git_arguments(root, git_directory, *arguments)


def _selected_git(
    root: Path, git_directory: Path | None, *arguments: str
) -> str:
    completed = _run(_selected_git_arguments(root, git_directory, *arguments))
    if completed.stderr.strip():
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    return completed.stdout.strip()


def _bounded_nul_command_records(
    arguments: Sequence[str], safe_code: str
) -> tuple[bytes, ...]:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        raise S12ControlError(safe_code) from None
    output = completed.stdout
    if (
        completed.returncode != 0
        or completed.stderr.strip()
        or len(output) > 32 * 1024 * 1024
    ):
        raise S12ControlError(safe_code)
    if not output:
        return ()
    if not output.endswith(b"\0"):
        raise S12ControlError(safe_code)
    records = tuple(output[:-1].split(b"\0"))
    if len(records) > 500_000 or any(not record for record in records):
        raise S12ControlError(safe_code)
    return records


def _validate_canonical_index(
    root: Path, git_directory: Path | None
) -> None:
    records = _bounded_nul_command_records(
        _selected_git_arguments(root, git_directory, "ls-files", "-v", "-z", "--"),
        "S12_1_BACKUP_REPOSITORY_INDEX_RED",
    )
    paths: set[bytes] = set()
    for record in records:
        if (
            len(record) < 3
            or record[:2] != b"H "
            or record[2:] in paths
        ):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_INDEX_RED")
        paths.add(record[2:])


def _selected_identity(
    root: Path, git_directory: Path | None
) -> tuple[str, str]:
    status_arguments = ["status", "--porcelain"]
    if git_directory is not None:
        status_arguments.extend(
            ["--", ".", f":(exclude){RECOVERY_GIT_DIRECTORY}"]
        )
    if _selected_git(root, git_directory, *status_arguments):
        raise S12ControlError("S12_1_RELEASE_DIRTY_RED")
    return (
        _selected_git(root, git_directory, "rev-parse", "HEAD"),
        _selected_git(root, git_directory, "rev-parse", "HEAD^{tree}"),
    )


def _selected_branch_or_none(root: Path, git_directory: Path | None) -> str | None:
    completed = _run(
        _selected_git_arguments(
            root, git_directory, "symbolic-ref", "--quiet", "--short", "HEAD"
        ),
        check=False,
    )
    if completed.returncode == 0:
        branch = completed.stdout.strip()
        if not branch or completed.stderr.strip():
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
        return branch
    if completed.returncode == 1 and not completed.stdout.strip():
        return None
    raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")


def _selected_ref_or_none(
    root: Path, git_directory: Path | None, reference: str
) -> str | None:
    completed = _run(
        _selected_git_arguments(root, git_directory, "rev-parse", "--verify", reference),
        check=False,
    )
    if completed.returncode == 0:
        value = completed.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40}", value) is None or completed.stderr.strip():
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
        return value
    if completed.returncode == 128 and not completed.stdout.strip():
        return None
    raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")


def _git(root: Path, *arguments: str) -> str:
    completed = _run(_git_arguments(root, *arguments))
    if completed.stderr.strip():
        raise S12ControlError("S12_1_RELEASE_BINDING_RED")
    return completed.stdout.strip()


def _identity(root: Path) -> tuple[str, str]:
    if root.is_symlink() or not (root / ".git").exists():
        raise S12ControlError("S12_1_RELEASE_ROOT_RED")
    if _git(root, "status", "--porcelain"):
        raise S12ControlError("S12_1_RELEASE_DIRTY_RED")
    return _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")


def _branch_or_none(root: Path) -> str | None:
    completed = _run(
        _git_arguments(root, "symbolic-ref", "--quiet", "--short", "HEAD"),
        check=False,
    )
    if completed.returncode == 0:
        branch = completed.stdout.strip()
        if not branch or completed.stderr.strip():
            raise S12ControlError("S12_1_RELEASE_BINDING_RED")
        return branch
    if completed.returncode == 1 and not completed.stdout.strip():
        return None
    raise S12ControlError("S12_1_RELEASE_BINDING_RED")


def _ref_or_none(root: Path, reference: str) -> str | None:
    completed = _run(
        _git_arguments(root, "rev-parse", "--verify", reference),
        check=False,
    )
    if completed.returncode == 0:
        value = completed.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40}", value) is None or completed.stderr.strip():
            raise S12ControlError("S12_1_RELEASE_BINDING_RED")
        return value
    if completed.returncode == 128 and not completed.stdout.strip():
        return None
    raise S12ControlError("S12_1_RELEASE_BINDING_RED")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _trusted_controller_digest() -> str:
    expected = os.environ.get(TRUSTED_CONTROLLER_DIGEST_ENV, "")
    controller = Path(__file__).absolute()
    try:
        metadata = controller.lstat()
        parent_metadata = controller.parent.lstat()
        if (
            controller != TRUSTED_CONTROLLER_PATH
            or controller.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or metadata.st_nlink != 1
            or controller.parent.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or _sha256(controller) != expected
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_TRUSTED_CONTROLLER_RED") from None
    return expected


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        parent_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_file_metadata(path: Path, maximum: int) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError:
        raise S12ControlError("S12_1_CREDENTIAL_METADATA_RED") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise S12ControlError("S12_1_CREDENTIAL_METADATA_RED")
    return {
        "exists": True,
        "owner": "root",
        "group": "root",
        "mode": "0600",
        "regular": True,
        "single_link": True,
        "nonempty": True,
    }


def credential_metadata() -> dict[str, Any]:
    return {
        "ok": True,
        "safe_code": "S12_1_CREDENTIAL_METADATA_GREEN",
        "sdk_id": _safe_file_metadata(SDK_ID, 128),
        "private_key": _safe_file_metadata(PRIVATE_KEY, 16384),
    }


def _systemctl_property(unit: str, name: str) -> str:
    return _run(["systemctl", "show", unit, "-p", name, "--value"]).stdout.strip()


def _rollback_unit_state() -> tuple[str, str]:
    completed = _run(
        [
            "systemctl", "show", UNIT_NAME, "--no-pager",
            "--property=LoadState,ActiveState,SubState",
        ],
        check=False,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"LoadState", "ActiveState", "SubState"}:
            values[key] = value
    if values.get("LoadState") == "not-found" or (
        completed.returncode != 0
        and re.search(r"(?:could not be found|not[- ]found|no such unit)", completed.stderr, re.I)
    ):
        return "inactive", "dead"
    if completed.returncode != 0 or set(values) != {
        "LoadState", "ActiveState", "SubState"
    }:
        raise S12ControlError("S12_1_ROLLBACK_STATE_RED")
    return values["ActiveState"], values["SubState"]


def _runtime_unit_enablement_state() -> str:
    completed = _run(["systemctl", "is-enabled", UNIT_NAME], check=False)
    state = completed.stdout.strip()
    known = {
        "alias", "bad", "disabled", "enabled", "enabled-runtime", "generated",
        "indirect", "linked", "linked-runtime", "masked", "masked-runtime",
        "not-found", "static", "transient",
    }
    if state in known:
        return state
    if not state and re.search(
        r"(?:could not be found|not[- ]found|no such unit)", completed.stderr, re.I
    ):
        return "not-found"
    raise S12ControlError("S12_1_RUNTIME_UNIT_ENABLEMENT_RED")


def _s11_timer_has_finite_next_elapse() -> bool:
    """Accept the systemd clock domain actually used by the timer contract."""

    unavailable = {"", "0", "0s", "0us", "infinity", "n/a"}
    values = (
        _systemctl_property(S11_TIMER, "NextElapseUSecRealtime"),
        _systemctl_property(S11_TIMER, "NextElapseUSecMonotonic"),
    )
    return any(value.strip().lower() not in unavailable for value in values)


def _runtime_unit_dropin_directories(
    roots: Sequence[Path] = SYSTEMD_UNIT_ROOTS,
) -> tuple[Path, ...]:
    stem, suffix = UNIT_NAME.rsplit(".", 1)
    parts = stem.split("-")
    names = [f"{UNIT_NAME}.d"]
    names.extend(
        f"{'-'.join(parts[:index])}-.{suffix}.d"
        for index in range(len(parts) - 1, 0, -1)
    )
    names.append(f"{suffix}.d")
    return tuple(root / name for root in roots for name in names)


def _runtime_unit_dropin_count(roots: Sequence[Path] = SYSTEMD_UNIT_ROOTS) -> int:
    count = 0
    for directory in _runtime_unit_dropin_directories(roots):
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise S12ControlError("S12_1_RUNTIME_UNIT_DROPIN_RED") from None
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise S12ControlError("S12_1_RUNTIME_UNIT_DROPIN_RED")
        try:
            entries = tuple(directory.iterdir())
        except OSError:
            raise S12ControlError("S12_1_RUNTIME_UNIT_DROPIN_RED") from None
        for entry in entries:
            if entry.name.endswith(".conf"):
                count += 1
    return count


def _competing_control_sync_count() -> int:
    processes = _run(["/bin/ps", "-eo", "pid=,user=,args="]).stdout
    pattern = re.compile(
        r"^\s*[0-9]+\s+\S+\s+(?:bash\s+)?"
        r"/usr/local/bin/tu1nz_sync_all\.sh\s+--loop(?:\s|$)"
    )
    return sum(pattern.search(line) is not None for line in processes.splitlines())


def read_only_preflight(*, immutable_release_allowed: bool = False) -> dict[str, Any]:
    if _competing_control_sync_count() != 0:
        raise S12ControlError("WAITING_OPERATOR_CONFLICTING_CONTROL_SYNC")
    if any(
        _recovery_git_path(root).exists()
        or _recovery_git_path(root).is_symlink()
        for root in (APPLICATION_ROOT, CONTROL_ROOT)
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    if _runtime_unit_dropin_count() != 0:
        raise S12ControlError("S12_1_RUNTIME_UNIT_DROPIN_RED")
    unit_enablement = _runtime_unit_enablement_state()
    if unit_enablement not in {"not-found", "disabled", "static"}:
        raise S12ControlError("S12_1_RUNTIME_UNIT_ENABLEMENT_RED")
    if unit_enablement == "static" and (
        _systemctl_property(UNIT_NAME, "FragmentPath") != str(UNIT_PATH)
        or _systemctl_property(UNIT_NAME, "DropInPaths")
    ):
        raise S12ControlError("S12_1_RUNTIME_UNIT_FRAGMENT_RED")
    release_paths_exist = any(
        path.exists() or path.is_symlink()
        for path in (RELEASE_ROOT, RELEASE_STAGING_ROOT)
    )
    if immutable_release_allowed:
        if RELEASE_STAGING_ROOT.exists() or RELEASE_STAGING_ROOT.is_symlink():
            raise S12ControlError("S12_1_RELEASE_STAGE_RED")
        _verify_immutable_release_stage()
    elif release_paths_exist:
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    else:
        _validate_source_runtime_environment()
    for service in SERVICES:
        if _systemctl_property(service, "ActiveState") != "active":
            raise S12ControlError("S12_1_PREDEPLOY_SERVICE_RED")
        if _systemctl_property(service, "NRestarts") != "0":
            raise S12ControlError("S12_1_PREDEPLOY_RESTART_RED")
    if _run(["systemctl", "is-enabled", S11_TIMER]).stdout.strip() != "enabled":
        raise S12ControlError("S12_1_S11_TIMER_RED")
    if (
        _systemctl_property(S11_TIMER, "ActiveState") != "active"
        or _systemctl_property(S11_TIMER, "SubState") != "waiting"
        or not _s11_timer_has_finite_next_elapse()
    ):
        raise S12ControlError("S12_1_S11_TIMER_RED")
    if (
        _systemctl_property("tu1nz-adult-public-s11-canary-controller.service", "Result")
        != "success"
        or _systemctl_property(
            "tu1nz-adult-public-s11-canary-controller.service", "ExecMainStatus"
        )
        != "0"
    ):
        raise S12ControlError("S12_1_S11_CONTROLLER_RED")
    if (
        not NGINX_SITE.is_file()
        or NGINX_SITE.is_symlink()
        or _sha256(NGINX_SITE) != BASE_NGINX_SHA256
    ):
        raise S12ControlError("S12_1_NGINX_BASELINE_RED")
    for url, expected in PUBLIC_URLS:
        response = _run(
            [
                "curl", "--silent", "--show-error", "--output", "/dev/null",
                "--max-time", "15", "--write-out", "%{http_code}", url,
            ]
        ).stdout
        if response != expected:
            raise S12ControlError("S12_1_PUBLIC_WMS_RED")
    credential_metadata()
    return {
        "ok": True,
        "safe_code": "S12_1_PREDEPLOY_GREEN",
        "s11": "UNCHANGED_GREEN",
        "public_wms": "GREEN",
        "hard_gates_closed": True,
    }


def validate_source_contract() -> dict[str, Any]:
    parse_manifest_contract(MANIFEST.read_text(encoding="utf-8"))
    if (
        SOURCE_UNIT.is_symlink()
        or SOURCE_NGINX.is_symlink()
        or SOURCE_BASE_NGINX.is_symlink()
        or not SOURCE_BASE_NGINX.is_file()
        or _sha256(SOURCE_BASE_NGINX) != BASE_NGINX_SHA256
    ):
        raise S12ControlError("S12_1_CONTROL_SOURCE_RED")
    return {"ok": True, "safe_code": "S12_1_CONTROL_SOURCE_GREEN"}


def _copy_if_present(path: Path, destination: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {"present": False}
    if path.is_symlink():
        return {"present": True, "symlink": os.readlink(path)}
    if not path.is_file():
        raise S12ControlError("S12_1_BACKUP_SOURCE_RED")
    shutil.copy2(path, destination)
    return {
        "present": True,
        "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
        "uid": path.stat().st_uid,
        "gid": path.stat().st_gid,
        "sha256": _sha256(destination),
    }


def _durably_complete_backup(backup: Path) -> None:
    for current, directories, files in os.walk(backup, topdown=False, followlinks=False):
        directory = Path(current)
        for name in files:
            path = directory / name
            descriptor: int | None = None
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                metadata = os.fstat(descriptor)
                path_metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or (metadata.st_dev, metadata.st_ino)
                    != (path_metadata.st_dev, path_metadata.st_ino)
                ):
                    raise OSError
                if directory == backup:
                    os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            except OSError:
                raise S12ControlError("S12_1_BACKUP_DURABILITY_RED") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        for name in directories:
            path = directory / name
            try:
                metadata = path.lstat()
                if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise OSError
            except OSError:
                raise S12ControlError("S12_1_BACKUP_DURABILITY_RED") from None
        _fsync_directory(directory)
    _fsync_directory(backup.parent)


def _reflog_tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    if not path.exists() and not path.is_symlink():
        digest.update(b"ABSENT\0")
        return digest.hexdigest()
    try:
        root_metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            raise OSError
        digest.update(
            f"D\0.\0{stat.S_IMODE(root_metadata.st_mode):04o}\0".encode("ascii")
        )
        for current, directories, files in os.walk(path, followlinks=False):
            directories.sort()
            files.sort()
            directory = Path(current)
            for name in directories:
                candidate = directory / name
                metadata = candidate.lstat()
                if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise OSError
                relative = candidate.relative_to(path).as_posix()
                digest.update(
                    f"D\0{relative}\0{stat.S_IMODE(metadata.st_mode):04o}\0".encode(
                        "ascii"
                    )
                )
            for name in files:
                candidate = directory / name
                metadata = candidate.lstat()
                if (
                    candidate.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                ):
                    raise OSError
                relative = candidate.relative_to(path).as_posix()
                digest.update(
                    (
                        f"F\0{relative}\0{stat.S_IMODE(metadata.st_mode):04o}\0"
                        f"{metadata.st_size}\0{_sha256(candidate)}\0"
                    ).encode("ascii")
                )
    except OSError:
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED") from None
    return digest.hexdigest()


def _copy_reflog_snapshot(git_directory: Path, destination: Path) -> tuple[bool, str]:
    source = git_directory / "logs"
    source_digest = _reflog_tree_digest(source)
    present = source.exists() or source.is_symlink()
    if not present:
        return False, source_digest
    try:
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    except OSError:
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED") from None
    if _reflog_tree_digest(destination) != source_digest:
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED")
    return True, source_digest


def _restore_reflog_snapshot(
    git_directory: Path, source: Path, record: dict[str, Any]
) -> None:
    present = record.get("reflogs_present")
    expected_digest = record.get("reflog_snapshot_sha256")
    if (
        not isinstance(present, bool)
        or not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        or _reflog_tree_digest(source) != expected_digest
        or (source.exists() or source.is_symlink()) is not present
    ):
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED")
    destination = git_directory / "logs"
    try:
        if destination.exists() or destination.is_symlink():
            metadata = destination.lstat()
            if destination.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise OSError
            shutil.rmtree(destination)
            _fsync_directory(git_directory)
        if present:
            shutil.copytree(
                source,
                destination,
                symlinks=True,
                copy_function=shutil.copy2,
            )
            _fsync_directory(git_directory)
    except OSError:
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED") from None
    if _reflog_tree_digest(destination) != expected_digest:
        raise S12ControlError("S12_1_BACKUP_REFLOG_RED")


def _create_git_bundle(
    root: Path, destination: Path, git_directory: Path | None = None
) -> None:
    revisions = ["HEAD", "--all"]
    if _selected_ref_or_none(root, git_directory, "ORIG_HEAD") is not None:
        revisions.append("ORIG_HEAD")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            completed = subprocess.run(
                _selected_git_arguments(
                    root, git_directory, "bundle", "create", "-", *revisions
                ),
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=300,
            )
            output.flush()
            os.fsync(output.fileno())
        if completed.returncode != 0:
            raise OSError
    except (OSError, subprocess.SubprocessError):
        destination.unlink(missing_ok=True)
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_git_bundle(
    root: Path, source: Path, git_directory: Path | None = None
) -> None:
    try:
        with source.open("rb") as input_stream:
            completed = subprocess.run(
                _selected_git_arguments(
                    root, git_directory, "bundle", "verify", "/dev/stdin"
                ),
                check=False,
                stdin=input_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
    except (OSError, subprocess.SubprocessError):
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED") from None
    if completed.returncode != 0:
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")


def _git_bundle_heads(
    root: Path, source: Path, git_directory: Path | None = None
) -> dict[str, str]:
    try:
        with source.open("rb") as input_stream:
            completed = subprocess.run(
                _selected_git_arguments(
                    root, git_directory, "bundle", "list-heads", "/dev/stdin"
                ),
                check=False,
                stdin=input_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
    except (OSError, subprocess.SubprocessError):
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED") from None
    if completed.returncode != 0 or completed.stderr.strip():
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
    heads: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        commit, separator, reference = line.partition(" ")
        if (
            not separator
            or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            or not reference
            or reference in heads
        ):
            raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
        heads[reference] = commit
    return heads


def _repository_path_metadata(root: Path) -> dict[str, Any]:
    git_directory = root / ".git"
    try:
        root_metadata = root.lstat()
        git_metadata = git_directory.lstat()
        if (
            root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or git_directory.is_symlink()
            or not stat.S_ISDIR(git_metadata.st_mode)
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED") from None
    return {
        "root_uid": root_metadata.st_uid,
        "root_gid": root_metadata.st_gid,
        "root_mode": f"{stat.S_IMODE(root_metadata.st_mode):04o}",
        "git_uid": git_metadata.st_uid,
        "git_gid": git_metadata.st_gid,
        "git_mode": f"{stat.S_IMODE(git_metadata.st_mode):04o}",
    }


def _repository_parent_metadata() -> dict[str, Any]:
    try:
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None
    return {
        "path": str(DEPLOYMENT_LOCK_ROOT),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "xattr_fingerprint": _repository_parent_xattr_fingerprint(),
    }


def _repository_backup_state(
    root: Path,
    release_branch: str,
    managed_refs: Sequence[str] = (),
    *,
    git_directory: Path | None = None,
    path_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    captured_path_metadata = path_metadata or _repository_path_metadata(root)
    try:
        selected_path_metadata = {
            name: captured_path_metadata[name]
            for name in (
                "root_uid", "root_gid", "root_mode",
                "git_uid", "git_gid", "git_mode",
            )
        }
    except (KeyError, TypeError):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED") from None
    _validate_canonical_index(root, git_directory)
    commit, tree = _selected_identity(root, git_directory)
    branch = _selected_branch_or_none(root, git_directory)
    if branch is not None and branch.startswith("-"):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_BRANCH_RED")
    return {
        "branch": branch,
        "detached": branch is None,
        "release_branch": release_branch,
        "release_branch_tip": _selected_git(
            root,
            git_directory,
            "rev-parse",
            "--verify",
            f"refs/heads/{release_branch}",
        ),
        "commit": commit,
        "tree": tree,
        "orig_head": _selected_ref_or_none(root, git_directory, "ORIG_HEAD"),
        "managed_refs": {
            reference: _selected_ref_or_none(root, git_directory, reference)
            for reference in sorted(managed_refs)
        },
        **selected_path_metadata,
    }


def _release_repository_states(
    git_directories: dict[Path, Path],
    path_records: dict[Path, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    def state(
        root: Path,
        release_branch: str,
        managed_refs: Sequence[str] = (),
    ) -> dict[str, Any]:
        git_directory = git_directories[root]
        references_output = _selected_git(
            root,
            git_directory,
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
        )
        if len(references_output.encode("utf-8")) > 65536:
            raise S12ControlError("S12_1_RELEASE_REPOSITORY_STATE_RED")
        references: dict[str, str] = {}
        for line in references_output.splitlines():
            reference, separator, target = line.partition("\0")
            if (
                not separator
                or not reference.startswith("refs/")
                or re.fullmatch(r"[0-9a-f]{40}", target) is None
                or reference in references
            ):
                raise S12ControlError("S12_1_RELEASE_REPOSITORY_STATE_RED")
            references[reference] = target
        if len(references) > 1024:
            raise S12ControlError("S12_1_RELEASE_REPOSITORY_STATE_RED")
        return {
            **_repository_backup_state(
                root,
                release_branch,
                managed_refs,
                git_directory=git_directory,
                path_metadata=path_records[root],
            ),
            "all_refs": dict(sorted(references.items())),
            "reflog_tree_sha256": _reflog_tree_digest(git_directory / "logs"),
        }

    states = {
        "application": state(
            APPLICATION_ROOT,
            "main",
        ),
        "control": state(
            CONTROL_ROOT,
            "control-main",
            (f"refs/tags/{FREEZE_TAG}",),
        ),
    }
    if len(
        json.dumps(states, sort_keys=True, separators=(",", ":")).encode("ascii")
    ) > 98304:
        raise S12ControlError("S12_1_RELEASE_REPOSITORY_STATE_RED")
    return states


def _validate_release_repository_states(
    expected: dict[str, Any],
    git_directories: dict[Path, Path],
    path_records: dict[Path, dict[str, Any]],
) -> None:
    if set(expected) != {"application", "control"} or not all(
        isinstance(expected.get(key), dict) for key in expected
    ):
        raise S12ControlError("S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED")
    try:
        current = _release_repository_states(git_directories, path_records)
    except S12ControlError:
        raise S12ControlError(
            "S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED"
        ) from None
    if current != expected:
        raise S12ControlError("S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED")


def _validate_backup_snapshot(
    backup: Path,
    index: dict[str, Any],
    git_directories: dict[Path, Path] | None = None,
) -> None:
    roots = (APPLICATION_ROOT, CONTROL_ROOT)
    if (
        _competing_control_sync_count() != 0
        or _active_repository_git_count(roots) != 0
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_ACTIVE_RED")
    specifications = (
        (APPLICATION_ROOT, "application", "main", ()),
        (
            CONTROL_ROOT,
            "control",
            "control-main",
            (f"refs/tags/{FREEZE_TAG}",),
        ),
    )
    for root, key, release_branch, managed_refs in specifications:
        record = index.get(key)
        if not isinstance(record, dict):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
        recorded_state = {
            name: value
            for name, value in record.items()
            if name
            not in {
                "bundle_sha256",
                "reflogs_present",
                "reflog_snapshot_sha256",
                "tracked_path_hashes_sha256",
            }
        }
        if recorded_state != _repository_backup_state(
            root,
            release_branch,
            managed_refs,
            git_directory=(git_directories or {}).get(root),
            path_metadata={
                name: record.get(name)
                for name in (
                    "root_uid", "root_gid", "root_mode",
                    "git_uid", "git_gid", "git_mode",
                )
            },
        ):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
        tracked_path_payload = _read_private_backup_blob(
            backup / f"{key}.tracked-path-hashes",
            record.get("tracked_path_hashes_sha256"),
            "S12_1_BACKUP_TRACKED_PATHS_RED",
        )
        current_tracked_path_payload = _tracked_path_hash_payload(
            _tracked_tree_paths(
                root,
                (git_directories or {}).get(root, root / ".git"),
                str(record.get("commit", "")),
                "S12_1_BACKUP_TRACKED_PATHS_RED",
            )
        )
        if tracked_path_payload != current_tracked_path_payload:
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
        bundle = backup / f"{key}.bundle"
        expected_digest = record.get("bundle_sha256")
        if (
            not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
            or _sha256(bundle) != expected_digest
        ):
            raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
        selected_git_directory = (git_directories or {}).get(root)
        _verify_git_bundle(root, bundle, selected_git_directory)
        heads = _git_bundle_heads(root, bundle, selected_git_directory)
        expected_heads = {
            "HEAD": record.get("commit"),
            f"refs/heads/{record.get('release_branch')}": record.get(
                "release_branch_tip"
            ),
        }
        branch = record.get("branch")
        if branch is not None:
            expected_heads[f"refs/heads/{branch}"] = record.get("commit")
        orig_head = record.get("orig_head")
        if orig_head is None:
            if "ORIG_HEAD" in heads:
                raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
        else:
            expected_heads["ORIG_HEAD"] = orig_head
        managed = record.get("managed_refs")
        if not isinstance(managed, dict):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
        for reference, target in managed.items():
            if target is None:
                if reference in heads:
                    raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
            else:
                expected_heads[reference] = target
        if any(heads.get(reference) != target for reference, target in expected_heads.items()):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
        reflog_source = (git_directories or {}).get(root, root / ".git") / "logs"
        reflog_snapshot = backup / f"{key}.reflogs"
        reflogs_present = record.get("reflogs_present")
        reflog_digest = record.get("reflog_snapshot_sha256")
        if (
            not isinstance(reflogs_present, bool)
            or not isinstance(reflog_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", reflog_digest) is None
            or (reflog_snapshot.exists() or reflog_snapshot.is_symlink())
            is not reflogs_present
            or _reflog_tree_digest(reflog_snapshot) != reflog_digest
            or _reflog_tree_digest(reflog_source) != reflog_digest
        ):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_RACE_RED")
    if (
        _competing_control_sync_count() != 0
        or _active_repository_git_count(roots) != 0
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_ACTIVE_RED")


def create_backup(
    git_directories: dict[Path, Path] | None = None,
    path_records: dict[Path, dict[str, Any]] | None = None,
    parent_record: dict[str, Any] | None = None,
) -> tuple[Path, dict[str, Any]]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_ROOT / f"{timestamp}-predeploy"
    if backup.exists() or backup.is_symlink():
        raise S12ControlError("S12_1_BACKUP_COLLISION_RED")
    _ensure_private_directory_durable(BACKUP_ROOT, Path("/"))
    _ensure_private_directory_durable(backup, BACKUP_ROOT)
    if (
        _competing_control_sync_count() != 0
        or _active_repository_git_count((APPLICATION_ROOT, CONTROL_ROOT)) != 0
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_ACTIVE_RED")
    application_state = _repository_backup_state(
        APPLICATION_ROOT,
        "main",
        git_directory=(git_directories or {}).get(APPLICATION_ROOT),
        path_metadata=(path_records or {}).get(APPLICATION_ROOT),
    )
    control_state = _repository_backup_state(
        CONTROL_ROOT,
        "control-main",
        (f"refs/tags/{FREEZE_TAG}",),
        git_directory=(git_directories or {}).get(CONTROL_ROOT),
        path_metadata=(path_records or {}).get(CONTROL_ROOT),
    )
    application_reflogs_present, application_reflog_digest = _copy_reflog_snapshot(
        (git_directories or {}).get(APPLICATION_ROOT, APPLICATION_ROOT / ".git"),
        backup / "application.reflogs",
    )
    control_reflogs_present, control_reflog_digest = _copy_reflog_snapshot(
        (git_directories or {}).get(CONTROL_ROOT, CONTROL_ROOT / ".git"),
        backup / "control.reflogs",
    )
    _create_git_bundle(
        APPLICATION_ROOT,
        backup / "application.bundle",
        (git_directories or {}).get(APPLICATION_ROOT),
    )
    _create_git_bundle(
        CONTROL_ROOT,
        backup / "control.bundle",
        (git_directories or {}).get(CONTROL_ROOT),
    )
    _verify_git_bundle(
        APPLICATION_ROOT,
        backup / "application.bundle",
        (git_directories or {}).get(APPLICATION_ROOT),
    )
    _verify_git_bundle(
        CONTROL_ROOT,
        backup / "control.bundle",
        (git_directories or {}).get(CONTROL_ROOT),
    )
    application_tracked_path_digest = _write_private_backup_blob(
        backup / "application.tracked-path-hashes",
        _tracked_path_hash_payload(
            _tracked_tree_paths(
                APPLICATION_ROOT,
                (git_directories or {}).get(
                    APPLICATION_ROOT, APPLICATION_ROOT / ".git"
                ),
                application_state["commit"],
                "S12_1_BACKUP_TRACKED_PATHS_RED",
            )
        ),
    )
    control_tracked_path_digest = _write_private_backup_blob(
        backup / "control.tracked-path-hashes",
        _tracked_path_hash_payload(
            _tracked_tree_paths(
                CONTROL_ROOT,
                (git_directories or {}).get(CONTROL_ROOT, CONTROL_ROOT / ".git"),
                control_state["commit"],
                "S12_1_BACKUP_TRACKED_PATHS_RED",
            )
        ),
    )
    files = {
        "unit": _copy_if_present(UNIT_PATH, backup / "unit.before"),
        "runtime_contract": _copy_if_present(
            RUNTIME_CONTRACT, backup / "runtime-contract.before"
        ),
        "nginx_site": _copy_if_present(NGINX_SITE, backup / "nginx-site.before"),
        "nginx_enabled": _copy_if_present(
            NGINX_ENABLED, backup / "nginx-enabled.before"
        ),
        "acceptance_evidence": _copy_if_present(
            STATE_ROOT / "acceptance.json", backup / "acceptance.before"
        ),
        "final_state_evidence": _copy_if_present(
            STATE_ROOT / "final-state.json", backup / "final-state.before"
        ),
        "deployment_result": _copy_if_present(
            STATE_ROOT / "deployment-result.json", backup / "deployment-result.before"
        ),
    }
    index = {
        "schema": BACKUP_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "application": {
            **application_state,
            "bundle_sha256": _sha256(backup / "application.bundle"),
            "reflogs_present": application_reflogs_present,
            "reflog_snapshot_sha256": application_reflog_digest,
            "tracked_path_hashes_sha256": application_tracked_path_digest,
        },
        "control": {
            **control_state,
            "bundle_sha256": _sha256(backup / "control.bundle"),
            "reflogs_present": control_reflogs_present,
            "reflog_snapshot_sha256": control_reflog_digest,
            "tracked_path_hashes_sha256": control_tracked_path_digest,
        },
        "credential_metadata": credential_metadata(),
        "credential_values_backed_up": False,
        "files": files,
        "rollback": "EXACTLY_ONCE",
        "release_stage": {"path": str(RELEASE_ROOT), "present": False},
        "fetch_stage": {"path": str(FETCH_ROOT), "present": False},
        "repository_parent": parent_record or _repository_parent_metadata(),
    }
    _validate_backup_snapshot(backup, index, git_directories)
    _atomic_json(backup / "restore-index.json", index)
    _durably_complete_backup(backup)
    return backup, index


def _restore_file(record: dict[str, Any], backup_file: Path, destination: Path) -> None:
    if not record["present"]:
        _durable_unlink(destination)
    elif "symlink" in record:
        _durable_symlink(record["symlink"], destination)
    else:
        _atomic_copy(
            backup_file,
            destination,
            int(record["mode"], 8),
            int(record["uid"]),
            int(record["gid"]),
        )


def _runtime_environment_fingerprint(
    root: Path,
    *,
    allow_file_symlinks: bool,
) -> str:
    """Hash a venv as materialized paths and bytes, independent of hardening mode."""

    digest = hashlib.sha256()
    try:
        root_metadata = root.lstat()
        if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            raise OSError
        entries: list[Path] = [root]
        for current, directories, files in os.walk(root, followlinks=False):
            directories.sort()
            files.sort()
            current_root = Path(current)
            for name in directories:
                candidate = current_root / name
                metadata = candidate.lstat()
                if candidate.is_symlink():
                    resolved = candidate.resolve(strict=True)
                    resolved.relative_to(root.resolve(strict=True))
                    if os.path.isabs(os.readlink(candidate)) or not resolved.is_dir():
                        raise OSError
                elif not stat.S_ISDIR(metadata.st_mode):
                    raise OSError
                entries.append(candidate)
            entries.extend(current_root / name for name in files)
        for candidate in sorted(entries, key=lambda item: str(item.relative_to(root))):
            relative = "." if candidate == root else candidate.relative_to(root).as_posix()
            metadata = candidate.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(f"D\0{relative}\0".encode("ascii"))
                continue
            if candidate.is_symlink():
                resolved = candidate.resolve(strict=True)
                effective = resolved.stat()
                if stat.S_ISDIR(effective.st_mode):
                    resolved.relative_to(root.resolve(strict=True))
                    link_target = os.readlink(candidate)
                    if os.path.isabs(link_target):
                        raise OSError
                    digest.update(
                        f"L\0{relative}\0{link_target}\0".encode("utf-8")
                    )
                    continue
                if not allow_file_symlinks or not stat.S_ISREG(effective.st_mode):
                    raise OSError
            else:
                effective = metadata
                if not stat.S_ISREG(effective.st_mode) or effective.st_nlink != 1:
                    raise OSError
            digest.update(
                f"F\0{relative}\0{effective.st_size}\0".encode(
                    "ascii"
                )
            )
            with candidate.open("rb") as handle:
                for block in iter(lambda: handle.read(65536), b""):
                    digest.update(block)
            digest.update(b"\0")
    except (OSError, RuntimeError, ValueError):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    return digest.hexdigest()


def _runtime_dependency_versions(root: Path) -> dict[str, str]:
    candidates = tuple((root / "lib").glob("python3.*/site-packages"))
    if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_dir():
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    versions: dict[str, str] = {}
    try:
        for metadata_file in sorted(candidates[0].glob("*.dist-info/METADATA")):
            if metadata_file.is_symlink() or not metadata_file.is_file():
                raise OSError
            name: str | None = None
            version: str | None = None
            for line in metadata_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("Name: ") and name is None:
                    name = re.sub(r"[-_.]+", "-", line[6:].strip()).lower()
                elif line.startswith("Version: ") and version is None:
                    version = line[9:].strip()
                if name is not None and version is not None:
                    break
            if name in RUNTIME_DEPENDENCY_VERSIONS:
                if name in versions or not version:
                    raise ValueError
                versions[name] = version
    except (OSError, UnicodeError, ValueError):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    if versions != RUNTIME_DEPENDENCY_VERSIONS:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    return versions


def _runtime_environment_record(root: Path) -> dict[str, Any]:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    python = root / "bin/python"
    try:
        metadata = python.lstat()
        if (
            python.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o222
            or not stat.S_IMODE(metadata.st_mode) & 0o111
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    record = {
        "dependency_versions": _runtime_dependency_versions(root),
        "python_sha256": _sha256(python),
        "schema": "TU1NZ_S12_1_IMMUTABLE_RUNTIME_ENVIRONMENT_V1",
        "venv_sha256": _runtime_environment_fingerprint(
            root, allow_file_symlinks=False
        ),
    }
    if (
        record["python_sha256"] != RUNTIME_PYTHON_SHA256
        or record["venv_sha256"] != RUNTIME_VENV_SHA256
    ):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    return record


def _copy_runtime_environment(source: Path, destination: Path) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    before = _runtime_environment_fingerprint(source, allow_file_symlinks=True)
    try:
        source_python_sha256 = _sha256((source / "bin/python").resolve(strict=True))
    except OSError:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    if before != RUNTIME_VENV_SHA256 or source_python_sha256 != RUNTIME_PYTHON_SHA256:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    try:
        shutil.copytree(
            source,
            destination,
            symlinks=True,
            copy_function=shutil.copy2,
        )
        for current, _, files in os.walk(source, followlinks=False):
            current_root = Path(current)
            for name in files:
                source_file = current_root / name
                if not source_file.is_symlink():
                    continue
                relative = source_file.relative_to(source)
                destination_file = destination / relative
                resolved = source_file.resolve(strict=True)
                if not resolved.is_file():
                    raise OSError
                destination_file.unlink()
                shutil.copy2(resolved, destination_file)
    except (OSError, shutil.Error):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    after = _runtime_environment_fingerprint(source, allow_file_symlinks=True)
    materialized = _runtime_environment_fingerprint(
        destination, allow_file_symlinks=False
    )
    if before != after or materialized != before:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    _harden_immutable_release_tree(destination)
    record = _runtime_environment_record(destination)
    if record["venv_sha256"] != before:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    return record


def _validate_source_runtime_environment() -> None:
    source = APPLICATION_ROOT / ".venv"
    python = source / "bin/python"
    try:
        resolved_python = python.resolve(strict=True)
        metadata = resolved_python.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not stat.S_IMODE(metadata.st_mode) & 0o111
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None
    if (
        _runtime_environment_fingerprint(source, allow_file_symlinks=True)
        != RUNTIME_VENV_SHA256
        or _sha256(resolved_python) != RUNTIME_PYTHON_SHA256
    ):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    _runtime_dependency_versions(source)


def _release_environment_record() -> dict[str, Any]:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    try:
        metadata = RELEASE_ENVIRONMENT.lstat()
        if (
            RELEASE_ENVIRONMENT.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o222
            or not 1 <= metadata.st_size <= 4096
        ):
            raise ValueError
        value = json.loads(RELEASE_ENVIRONMENT.read_text(encoding="ascii"))
        if not isinstance(value, dict) or set(value) != {
            "dependency_versions", "python_sha256", "schema", "venv_sha256"
        }:
            raise ValueError
        if (
            value.get("schema")
            != "TU1NZ_S12_1_IMMUTABLE_RUNTIME_ENVIRONMENT_V1"
            or value.get("dependency_versions") != RUNTIME_DEPENDENCY_VERSIONS
            or value.get("python_sha256") != RUNTIME_PYTHON_SHA256
            or value.get("venv_sha256") != RUNTIME_VENV_SHA256
            or any(
                not isinstance(value.get(key), str)
                or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
                for key in ("python_sha256", "venv_sha256")
            )
        ):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED") from None


def _root_git_arguments(root: Path, *arguments: str) -> list[str]:
    return [
        *_isolated_root_git_prefix(root),
        "-C",
        str(root),
        *arguments,
    ]


def _root_git(root: Path, *arguments: str) -> str:
    completed = _run(_root_git_arguments(root, *arguments))
    if completed.stderr.strip():
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    return completed.stdout.strip()


def _root_identity(root: Path) -> tuple[str, str]:
    if root.is_symlink() or not (root / ".git").is_dir():
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    if _root_git(root, "status", "--porcelain"):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    return (
        _root_git(root, "rev-parse", "HEAD"),
        _root_git(root, "rev-parse", "HEAD^{tree}"),
    )


def _validate_internal_release_symlink(root: Path, path: Path) -> None:
    link_target = os.readlink(path)
    if os.path.isabs(link_target):
        raise OSError
    resolved = path.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
        raise OSError


def _harden_immutable_release_tree(root: Path) -> None:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    try:
        for current, directories, files in os.walk(root, topdown=False):
            for name in files:
                path = Path(current) / name
                metadata = path.lstat()
                if path.is_symlink():
                    _validate_internal_release_symlink(root, path)
                    os.chown(path, expected_uid, expected_gid, follow_symlinks=False)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise OSError
                os.chown(path, expected_uid, expected_gid)
                os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o222)
            for name in directories:
                path = Path(current) / name
                if path.is_symlink():
                    _validate_internal_release_symlink(root, path)
                    if not path.resolve(strict=True).is_dir():
                        raise OSError
                    os.chown(path, expected_uid, expected_gid, follow_symlinks=False)
                    continue
                if not path.is_dir():
                    raise OSError
                os.chown(path, expected_uid, expected_gid)
                os.chmod(path, 0o500)
        os.chown(root, expected_uid, expected_gid)
        os.chmod(root, 0o500)
    except (OSError, RuntimeError, ValueError):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED") from None


def _validate_immutable_release_tree(root: Path) -> None:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    try:
        entries = [root]
        for current, directories, files in os.walk(root, followlinks=False):
            entries.extend(Path(current) / name for name in (*directories, *files))
        for path in entries:
            metadata = path.lstat()
            if path.is_symlink():
                _validate_internal_release_symlink(root, path)
            if (
                metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or (not path.is_symlink() and stat.S_IMODE(metadata.st_mode) & 0o222)
                or (
                    not path.is_symlink()
                    and not stat.S_ISDIR(metadata.st_mode)
                    and not stat.S_ISREG(metadata.st_mode)
                )
                or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
            ):
                raise OSError
    except (OSError, RuntimeError, ValueError):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED") from None


def _verify_immutable_release_stage(
    control_sha: str | None = None,
    control_tree: str | None = None,
) -> tuple[str, str]:
    _validate_immutable_release_tree(RELEASE_ROOT)
    if _root_identity(RELEASE_APPLICATION_ROOT) != (
        APPLICATION_COMMIT,
        APPLICATION_TREE,
    ):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    staged_control = _root_identity(RELEASE_CONTROL_ROOT)
    if control_sha is not None and staged_control[0] != control_sha:
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    if control_tree is not None and staged_control[1] != control_tree:
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    if (
        _root_git(RELEASE_CONTROL_ROOT, "cat-file", "-t", FREEZE_TAG) != "tag"
        or _root_git(
            RELEASE_CONTROL_ROOT, "rev-parse", f"{FREEZE_TAG}^{{commit}}"
        )
        != staged_control[0]
    ):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    recorded_environment = _release_environment_record()
    if _runtime_environment_record(RELEASE_VENV_ROOT) != recorded_environment:
        raise S12ControlError("S12_1_RELEASE_ENVIRONMENT_RED")
    return staged_control


def _clone_immutable_repository(
    source_git: Path,
    destination: Path,
    commit: str,
) -> None:
    _validate_recovery_git_directory(source_git)
    _validate_root_git_contract(source_git)
    _run(
        [
            *_isolated_root_git_prefix(source_git),
            "clone",
            "--no-local",
            "--no-checkout",
            str(source_git),
            str(destination),
        ],
        timeout=300,
    )
    _validate_root_git_contract(destination / ".git")
    _run(
        _root_git_arguments(
            destination,
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "--force",
            "--detach",
            commit,
        )
    )


def _create_immutable_release_stage(
    git_directories: dict[Path, Path],
    control_sha: str,
    control_tree: str,
) -> None:
    if any(
        path.exists() or path.is_symlink()
        for path in (RELEASE_ROOT, RELEASE_STAGING_ROOT)
    ):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    _ensure_private_directory_durable(RELEASE_STAGING_ROOT, PRIVATE_ROOT)
    _clone_immutable_repository(
        git_directories[APPLICATION_ROOT],
        RELEASE_STAGING_ROOT / "application",
        APPLICATION_COMMIT,
    )
    _clone_immutable_repository(
        git_directories[CONTROL_ROOT],
        RELEASE_STAGING_ROOT / "control",
        control_sha,
    )
    staging_application = RELEASE_STAGING_ROOT / "application"
    staging_control = RELEASE_STAGING_ROOT / "control"
    staging_venv = RELEASE_STAGING_ROOT / "venv"
    if _root_identity(staging_application) != (APPLICATION_COMMIT, APPLICATION_TREE):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    if _root_identity(staging_control) != (control_sha, control_tree):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    if (
        _root_git(staging_control, "cat-file", "-t", FREEZE_TAG) != "tag"
        or _root_git(staging_control, "rev-parse", f"{FREEZE_TAG}^{{commit}}")
        != control_sha
    ):
        raise S12ControlError("S12_1_RELEASE_STAGE_RED")
    environment = _copy_runtime_environment(
        APPLICATION_ROOT / ".venv",
        staging_venv,
    )
    _atomic_json(
        RELEASE_STAGING_ROOT / "runtime-environment.json",
        environment,
        mode=0o400,
    )
    try:
        os.replace(RELEASE_STAGING_ROOT, RELEASE_ROOT)
    except OSError:
        raise S12ControlError("S12_1_RELEASE_STAGE_RED") from None
    _fsync_directory(RELEASE_ROOT.parent)
    _harden_immutable_release_tree(RELEASE_ROOT)
    _sync_repository_filesystem(RELEASE_ROOT)
    _verify_immutable_release_stage(control_sha, control_tree)


def _remove_release_stages(index: dict[str, Any]) -> None:
    if index.get("release_stage") != {
        "path": str(RELEASE_ROOT),
        "present": False,
    }:
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    for path in (RELEASE_STAGING_ROOT, RELEASE_ROOT):
        if path.is_symlink():
            raise S12ControlError("S12_1_RELEASE_STAGE_RED")
        if path.exists():
            try:
                shutil.rmtree(path)
            except OSError:
                raise S12ControlError("S12_1_RELEASE_STAGE_RED") from None
            _fsync_directory(path.parent)


def _remove_fetch_stage(index: dict[str, Any]) -> None:
    if index.get("fetch_stage") != {
        "path": str(FETCH_ROOT),
        "present": False,
    }:
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    if FETCH_ROOT.is_symlink():
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    if FETCH_ROOT.exists():
        try:
            shutil.rmtree(FETCH_ROOT)
        except OSError:
            raise S12ControlError("S12_1_FETCH_STAGE_RED") from None
        _fsync_directory(FETCH_ROOT.parent)


def _selector_path(value: str, cwd: Path) -> Path:
    selected = Path(value)
    if not selected.is_absolute():
        selected = cwd / selected
    return selected.resolve(strict=False)


def _git_repository_selectors(
    arguments: Sequence[str], cwd: Path, environment: dict[str, str]
) -> set[Path]:
    original_cwd = cwd.resolve(strict=False)
    effective_cwd = original_cwd
    selectors = {original_cwd}
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        value: str | None = None
        changes_directory = False
        if argument in {"--git-dir", "--work-tree", "-C"}:
            if index + 1 < len(arguments):
                value = arguments[index + 1]
                changes_directory = argument == "-C"
                index += 1
        elif argument.startswith("--git-dir="):
            value = argument.split("=", 1)[1]
        elif argument.startswith("--work-tree="):
            value = argument.split("=", 1)[1]
        elif argument.startswith("-C") and argument != "-C":
            value = argument[2:]
            changes_directory = True
        if value:
            selected = _selector_path(value, effective_cwd)
            selectors.add(selected)
            if changes_directory:
                effective_cwd = selected
        index += 1
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"):
        if environment.get(name):
            selectors.add(_selector_path(environment[name], effective_cwd))
            selectors.add(_selector_path(environment[name], original_cwd))
    for value in environment.get("GIT_ALTERNATE_OBJECT_DIRECTORIES", "").split(os.pathsep):
        if value:
            selectors.add(_selector_path(value, effective_cwd))
            selectors.add(_selector_path(value, original_cwd))
    return selectors


def _active_repository_git_count(roots: Sequence[Path]) -> int:
    proc = Path("/proc")
    if not proc.is_dir():
        raise S12ControlError("S12_1_RECOVERY_GIT_PROCESS_RED")
    count = 0
    for process in proc.iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = [
                item.decode("utf-8", errors="ignore")
                for item in (process / "cmdline").read_bytes().split(b"\0")
                if item
            ]
            if not arguments:
                continue
            executable = Path(arguments[0]).name
            if executable != "git" and not executable.startswith("git-"):
                continue
            cwd = (process / "cwd").resolve(strict=True)
            environment: dict[str, str] = {}
            for item in (process / "environ").read_bytes().split(b"\0"):
                key, separator, value = item.partition(b"=")
                if separator and key.decode("ascii", errors="ignore").startswith("GIT_"):
                    environment[key.decode("ascii", errors="ignore")] = value.decode(
                        "utf-8", errors="ignore"
                    )
            selectors = _git_repository_selectors(arguments, cwd, environment)
        except FileNotFoundError:
            continue
        except OSError:
            count += 1
            continue
        if any(
            selector == root
            or root in selector.parents
            or selector == root / ".git"
            or root / ".git" in selector.parents
            for root in roots
            for selector in selectors
        ):
            count += 1
    return count


def _git_owner_uids() -> set[int]:
    if os.geteuid() != 0:
        return {os.geteuid()}
    try:
        return {0, pwd.getpwnam(CHATOPS_USER).pw_uid}
    except KeyError:
        raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED") from None


def _clear_stale_git_locks(root: Path, git_dir: Path | None = None) -> None:
    git_dir = git_dir or root / ".git"
    try:
        git_metadata = git_dir.lstat()
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED") from None
    allowed_uids = _git_owner_uids()
    if (
        git_dir.is_symlink()
        or not stat.S_ISDIR(git_metadata.st_mode)
        or git_metadata.st_uid not in allowed_uids
        or stat.S_IMODE(git_metadata.st_mode) & 0o022
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED")
    try:
        candidates = sorted(git_dir.rglob("*.lock"))
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED") from None
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError:
            raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED") from None
        current = candidate.parent
        while True:
            directory_metadata = current.lstat()
            if (
                current.is_symlink()
                or not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid not in allowed_uids
                or stat.S_IMODE(directory_metadata.st_mode) & 0o022
            ):
                raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED")
            if current == git_dir:
                break
            if current == current.parent:
                raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED")
            current = current.parent
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in allowed_uids
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_nlink != 1
            or metadata.st_size > 16 * 1024 * 1024
        ):
            raise S12ControlError("S12_1_RECOVERY_GIT_LOCK_RED")
        _durable_unlink(candidate)


def _protected_inode_identities(paths: Sequence[Path]) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    try:
        for root in paths:
            root_metadata = root.lstat()
            if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
                raise OSError
            identities.add((root_metadata.st_dev, root_metadata.st_ino))
            for current, directories, files in os.walk(root, followlinks=False):
                for name in (*directories, *files):
                    metadata = (Path(current) / name).lstat()
                    if stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
                        identities.add((metadata.st_dev, metadata.st_ino))
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_PROCESS_RED") from None
    return identities


def _mapped_inode_identity(device: str, inode: str) -> tuple[int, int] | None:
    try:
        major, separator, minor = device.partition(":")
        numeric_inode = int(inode, 10)
        if not separator or numeric_inode == 0:
            return None
        return os.makedev(int(major, 16), int(minor, 16)), numeric_inode
    except (ValueError, OverflowError, OSError):
        return None


def _active_recovery_git_handle_count(git_directories: Sequence[Path]) -> int:
    """Count processes retaining protected inodes through cwd, fds or maps."""

    proc = Path("/proc")
    if not proc.is_dir():
        raise S12ControlError("S12_1_RECOVERY_GIT_PROCESS_RED")
    protected_inodes = _protected_inode_identities(git_directories)
    count = 0
    for process in proc.iterdir():
        if not process.name.isdigit() or process.name == str(os.getpid()):
            continue
        links: list[Path] = [process / "cwd"]
        try:
            links.extend((process / "fd").iterdir())
            matched = False
            for link in links:
                try:
                    retained = link.stat()
                    target = link.resolve(strict=True)
                except FileNotFoundError:
                    try:
                        retained = link.stat()
                    except FileNotFoundError:
                        continue
                    target = None
                if (
                    (retained.st_dev, retained.st_ino) in protected_inodes
                    or target is not None
                    and any(
                        target == git_directory or git_directory in target.parents
                        for git_directory in git_directories
                    )
                ):
                    matched = True
                    break
            if not matched:
                maps = (process / "maps").read_text(
                    encoding="utf-8", errors="surrogateescape"
                )
                for line in maps.splitlines():
                    fields = line.split(maxsplit=5)
                    if len(fields) < 5:
                        continue
                    identity = _mapped_inode_identity(fields[3], fields[4])
                    if identity in protected_inodes:
                        matched = True
                        break
                    if len(fields) != 6:
                        continue
                    mapped_name = fields[5]
                    if mapped_name.endswith(" (deleted)"):
                        mapped_name = mapped_name[:-10]
                    if not mapped_name.startswith("/"):
                        continue
                    target = Path(os.path.realpath(mapped_name))
                    if any(
                        target == git_directory or git_directory in target.parents
                        for git_directory in git_directories
                    ):
                        matched = True
                        break
            if matched:
                count += 1
        except FileNotFoundError:
            continue
        except OSError:
            count += 1
    return count


def _repository_recovery_git_directory(root: Path) -> Path:
    """Select the real Git directory before or during a recovery exchange."""

    git_directory = root / ".git"
    recovery_directory = _recovery_git_path(root)
    if _is_canonical_git_directory(git_directory):
        return git_directory
    if _is_recovery_guard(git_directory) and _is_recovery_git_directory(
        recovery_directory
    ):
        return recovery_directory
    raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _tracked_worktree_regular_paths(
    roots: Sequence[Path],
    *,
    allow_missing: bool = False,
) -> tuple[Path, ...]:
    """Resolve regular index entries without treating runtime-only files as protected."""

    tracked: list[Path] = []
    for root in roots:
        for path, metadata in _tracked_worktree_index_entries(
            root, allow_missing=allow_missing
        ):
            if stat.S_ISREG(metadata.st_mode):
                tracked.append(path)
    return tuple(tracked)


def _tracked_worktree_index_entries(
    root: Path,
    *,
    allow_missing: bool = False,
) -> tuple[tuple[Path, os.stat_result], ...]:
    """Resolve and validate every current index path exactly once."""

    git_directory = _repository_recovery_git_directory(root)
    records = _bounded_nul_command_records(
        _selected_git_arguments(root, git_directory, "ls-files", "-z", "--"),
        "S12_1_RECOVERY_WORKTREE_HANDLE_RED",
    )
    selected: list[tuple[Path, os.stat_result]] = []
    seen: set[Path] = set()
    for record in records:
        parts = record.split(b"/")
        if (
            record.startswith(b"/")
            or any(part in {b"", b".", b".."} for part in parts)
        ):
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        path = root / os.fsdecode(record)
        if path in seen:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        seen.add(path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
            ) from None
        except OSError:
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
            ) from None
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        elif not (
            stat.S_ISLNK(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        selected.append((path, metadata))
    return tuple(selected)


def _fdinfo_is_write_capable(path: Path) -> bool:
    try:
        payload = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return False
    except (OSError, UnicodeError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED") from None
    for line in payload.splitlines():
        label, separator, value = line.partition(":")
        if label != "flags" or not separator:
            continue
        try:
            flags = int(value.strip(), 8)
        except ValueError:
            break
        return flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR}
    raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")


_SMAPS_HEADER = re.compile(
    r"^[0-9a-f]+-[0-9a-f]+\s+(?P<permissions>[-rwxps]{4})\s+"
    r"[0-9a-f]+\s+(?P<device>[0-9a-f]+:[0-9a-f]+)\s+"
    r"(?P<inode>[0-9]+)(?:\s+.*)?$"
)


def _smaps_has_write_capable_shared_mapping(
    path: Path, protected_inodes: set[tuple[int, int]]
) -> bool:
    try:
        lines = path.read_text(
            encoding="utf-8", errors="surrogateescape"
        ).splitlines()
    except FileNotFoundError:
        return False
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED") from None
    tracked_shared = False
    for line in lines:
        header = _SMAPS_HEADER.fullmatch(line)
        if header is not None:
            identity = _mapped_inode_identity(
                header.group("device"), header.group("inode")
            )
            permissions = header.group("permissions")
            tracked_shared = (
                identity in protected_inodes and permissions[3] == "s"
            )
            if tracked_shared and "w" in permissions[:3]:
                return True
            continue
        if tracked_shared and line.startswith("VmFlags:"):
            if "mw" in line.split()[1:]:
                return True
            tracked_shared = False
    return False


def _active_tracked_worktree_write_handle_count(
    tracked_paths: Sequence[Path],
) -> int:
    """Count processes that can mutate a currently tracked regular inode."""

    proc = Path("/proc")
    if not proc.is_dir():
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
    protected_inodes: set[tuple[int, int]] = set()
    try:
        for path in tracked_paths:
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise OSError
            protected_inodes.add((metadata.st_dev, metadata.st_ino))
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED") from None
    if not protected_inodes:
        return 0
    count = 0
    for process in proc.iterdir():
        if not process.name.isdigit() or process.name == str(os.getpid()):
            continue
        try:
            matched = False
            for descriptor in (process / "fd").iterdir():
                try:
                    metadata = descriptor.stat()
                except FileNotFoundError:
                    continue
                if (metadata.st_dev, metadata.st_ino) not in protected_inodes:
                    continue
                if _fdinfo_is_write_capable(process / "fdinfo" / descriptor.name):
                    matched = True
                    break
            if not matched:
                matched = _smaps_has_write_capable_shared_mapping(
                    process / "smaps", protected_inodes
                )
            if matched:
                count += 1
        except FileNotFoundError:
            continue
        except S12ControlError:
            if os.geteuid() == 0:
                count += 1
        except OSError:
            if os.geteuid() == 0:
                count += 1
    return count


def _tracked_worktree_barrier_paths(
    root: Path,
    *,
    allow_missing: bool = False,
) -> tuple[Path, ...]:
    """Return tracked regular entries and every directory needed to reach them."""

    protected: set[Path] = set()
    for path, metadata in _tracked_worktree_index_entries(
        root, allow_missing=allow_missing
    ):
        if stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode):
            protected.add(path)
        parent = path.parent
        while parent != root:
            if root not in parent.parents:
                raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
            protected.add(parent)
            parent = parent.parent
    return tuple(
        sorted(
            protected,
            key=lambda path: (
                len(path.relative_to(root).parts),
                os.fsencode(path.relative_to(root)),
            ),
        )
    )


def _worktree_barrier_mode(
    mode: int, uid: int, gid: int, *, kind: str = "regular"
) -> int:
    """Return the root-owned barrier mode backed by a named-owner ACL."""

    if kind not in {"directory", "regular"}:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
    if (mode & stat.S_ISUID) or (
        kind == "regular" and mode & stat.S_ISGID
    ):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
    restricted = mode & ~0o222
    if uid == 0:
        return restricted
    owner_access = (restricted & 0o500) >> 6
    group_access = (restricted & 0o050) >> 3
    other_access = restricted & 0o005
    if owner_access & ~other_access:
        # The group-class mode bits represent the ACL mask, not access granted
        # to the owning group.  A single named-user ACL below carries the
        # former owner's exact read/execute class without relying on NSS group
        # enumeration or making a GID an authorization capability.
        restricted = (restricted & ~0o070) | (
            (owner_access | group_access) << 3
        )
    return restricted


def _worktree_barrier_owner_acl(
    mode: int, uid: int, *, kind: str
) -> bytes | None:
    """Build the exact temporary POSIX ACL for a non-root former owner."""

    restricted = mode & ~0o222
    if uid == 0:
        return None
    owner_access = (restricted & 0o500) >> 6
    group_access = (restricted & 0o050) >> 3
    other_access = restricted & 0o005
    if not (owner_access & ~other_access):
        return None
    if uid < 0 or uid >= 0xFFFFFFFF or kind not in {"regular", "directory"}:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
    header = struct.Struct("<I")
    entry = struct.Struct("<HHI")
    return b"".join(
        (
            header.pack(2),
            entry.pack(0x01, owner_access, 0xFFFFFFFF),
            entry.pack(0x02, owner_access, uid),
            entry.pack(0x04, group_access, 0xFFFFFFFF),
            entry.pack(0x10, owner_access | group_access, 0xFFFFFFFF),
            entry.pack(0x20, other_access, 0xFFFFFFFF),
        )
    )


def _assert_post_chown_acl_preserves_access(
    path: Path,
    uid: int,
    required_access: int,
    target_mask: int,
    target_other: int,
    safe_code: str,
    *,
    reject_access_acl: bool = False,
) -> None:
    """Reject an ACL that would reduce the former owner's post-chown access."""

    if uid == 0:
        return
    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        if sys.platform == "linux":
            raise S12ControlError(safe_code)
        return
    try:
        before = path.lstat()
        names = sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        )
        if "system.posix_acl_access" not in names:
            value = None
        else:
            value = os.getxattr(
                path,
                "system.posix_acl_access",
                follow_symlinks=False,
            )
        if names != sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        ):
            raise OSError
        after = path.lstat()
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise OSError
        if reject_access_acl and value is not None:
            raise OSError
        if value is None:
            # A retained GID is never an authorization capability: NSS may be
            # incomplete and a setgid executable can grant the numeric group
            # after a point-in-time check.  Only public access is stable here.
            effective_access = target_other
            if required_access & ~effective_access:
                raise OSError
            return

        acl_header = struct.Struct("<I")
        acl_entry = struct.Struct("<HHI")
        if (
            len(value) < acl_header.size
            or acl_header.unpack_from(value)[0] != 2
            or (len(value) - acl_header.size) % acl_entry.size
        ):
            raise OSError
        entries = [
            acl_entry.unpack_from(value, offset)
            for offset in range(
                acl_header.size, len(value), acl_entry.size
            )
        ]
        if any(
            tag not in {0x01, 0x02, 0x04, 0x08, 0x10, 0x20}
            or permissions & ~0o7
            for tag, permissions, _identifier in entries
        ):
            raise OSError
        for tag in (0x01, 0x04, 0x20):
            if sum(entry_tag == tag for entry_tag, *_rest in entries) != 1:
                raise OSError
        named_entries = [
            (tag, permissions, identifier)
            for tag, permissions, identifier in entries
            if tag in {0x02, 0x08}
        ]
        if (
            len({(tag, identifier) for tag, _, identifier in named_entries})
            != len(named_entries)
            or any(identifier == 0xFFFFFFFF for _, _, identifier in named_entries)
            or any(
                identifier != 0xFFFFFFFF
                for tag, _, identifier in entries
                if tag in {0x01, 0x04, 0x10, 0x20}
            )
            or sum(tag == 0x10 for tag, *_rest in entries)
            not in ({1} if named_entries else {0, 1})
        ):
            raise OSError
        named_users = [
            permissions
            for tag, permissions, identifier in entries
            if tag == 0x02 and identifier == uid
        ]
        if len(named_users) > 1:
            raise OSError
        effective_access = (
            named_users[0] & target_mask if named_users else target_other
        )
        if required_access & ~effective_access:
            raise OSError
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError(safe_code) from None


def _assert_no_posix_access_acl(path: Path, safe_code: str) -> None:
    """Require a mode-only source contract before adding the bounded ACL."""

    if not hasattr(os, "listxattr"):
        if sys.platform == "linux":
            raise S12ControlError(safe_code)
        return
    try:
        before = path.lstat()
        names = sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        )
        if "system.posix_acl_access" in names:
            raise OSError
        if names != sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        ):
            raise OSError
        after = path.lstat()
        if any(
            getattr(before, field) != getattr(after, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_ctime_ns",
            )
        ):
            raise OSError
    except OSError:
        raise S12ControlError(safe_code) from None


def _worktree_source_access_acl(path: Path, safe_code: str) -> bytes | None:
    """Return a stable source ACL without treating its GID entries as proof."""

    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        if sys.platform == "linux":
            raise S12ControlError(safe_code)
        return None
    try:
        before = path.lstat()
        names = sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        )
        value = (
            os.getxattr(
                path,
                "system.posix_acl_access",
                follow_symlinks=False,
            )
            if "system.posix_acl_access" in names
            else None
        )
        if names != sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        ):
            raise OSError
        after = path.lstat()
        if any(
            getattr(before, field) != getattr(after, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_ctime_ns",
            )
        ):
            raise OSError
        return value
    except OSError:
        raise S12ControlError(safe_code) from None


def _assert_source_worktree_acl_access(
    path: Path,
    mode: int,
    uid: int,
    safe_code: str,
) -> bytes | None:
    """Accept a source ACL only when its named UID survives a tighter mask."""

    acl = _worktree_source_access_acl(path, safe_code)
    if acl is None:
        return None
    restricted = mode & ~0o222
    _assert_post_chown_acl_preserves_access(
        path,
        uid,
        (restricted & 0o500) >> 6,
        (restricted & 0o050) >> 3,
        restricted & 0o005,
        safe_code,
    )
    return acl


def _worktree_path_xattr_fingerprint(
    path: Path, *, barrier_acl: bytes | None = None
) -> str:
    try:
        omitted = (
            {path: {"system.posix_acl_access": barrier_acl}}
            if barrier_acl is not None
            else None
        )
        return _release_xattr_fingerprint(
            (path,), expected_omitted_xattrs=omitted
        )
    except S12ControlError:
        raise S12ControlError(
            "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
        ) from None


def _assert_worktree_path_xattrs(
    path: Path,
    record: dict[str, Any],
    *,
    barrier_locked: bool = False,
) -> None:
    fingerprint = record.get("xattr_fingerprint")
    if not isinstance(fingerprint, str) or re.fullmatch(
        r"[0-9a-f]{64}", fingerprint
    ) is None:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
    if not barrier_locked:
        if _worktree_path_xattr_fingerprint(path) != fingerprint:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
        return
    _worktree_locked_acl_state(path, record)


def _worktree_locked_acl_state(
    path: Path, record: dict[str, Any]
) -> tuple[str, int]:
    """Return the exact locked ACL class and mode for one journaled inode."""

    fingerprint = record.get("xattr_fingerprint")
    if not isinstance(fingerprint, str) or re.fullmatch(
        r"[0-9a-f]{64}", fingerprint
    ) is None:
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
    original_mode = int(record["mode"], 8)
    base_mode = original_mode & ~0o222
    generated_mode = _worktree_barrier_mode(
        original_mode,
        record["uid"],
        record["gid"],
        kind=record["kind"],
    )
    try:
        if _worktree_path_xattr_fingerprint(path) == fingerprint:
            acl = _assert_source_worktree_acl_access(
                path,
                original_mode,
                record["uid"],
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            )
            if acl is not None:
                return "preserved", base_mode
            if _worktree_barrier_owner_acl(
                original_mode, record["uid"], kind=record["kind"]
            ) is None:
                return "none", base_mode
        generated_acl = _worktree_barrier_owner_acl(
            original_mode, record["uid"], kind=record["kind"]
        )
        if (
            generated_acl is not None
            and _worktree_path_xattr_fingerprint(
                path, barrier_acl=generated_acl
            )
            == fingerprint
        ):
            _assert_worktree_barrier_owner_acl(
                path,
                record,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            )
            return "generated", generated_mode
    except (KeyError, TypeError, ValueError):
        pass
    raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")


def _install_worktree_barrier_owner_acl(
    path: Path, record: dict[str, Any]
) -> None:
    acl = _worktree_barrier_owner_acl(
        int(record["mode"], 8), record["uid"], kind=record["kind"]
    )
    if acl is None:
        return
    if not hasattr(os, "setxattr"):
        raise OSError
    os.setxattr(
        path,
        "system.posix_acl_access",
        acl,
        follow_symlinks=False,
    )


def _remove_worktree_barrier_owner_acl(
    path: Path, record: dict[str, Any]
) -> None:
    acl = _worktree_barrier_owner_acl(
        int(record["mode"], 8), record["uid"], kind=record["kind"]
    )
    if acl is None:
        return
    if not hasattr(os, "removexattr"):
        raise OSError
    os.removexattr(
        path,
        "system.posix_acl_access",
        follow_symlinks=False,
    )


def _assert_worktree_barrier_owner_acl(
    path: Path, record: dict[str, Any], safe_code: str
) -> None:
    acl = _worktree_barrier_owner_acl(
        int(record["mode"], 8), record["uid"], kind=record["kind"]
    )
    if acl is None:
        _assert_no_posix_access_acl(path, safe_code)
        return
    if not hasattr(os, "getxattr"):
        raise S12ControlError(safe_code)
    try:
        if (
            os.getxattr(
                path,
                "system.posix_acl_access",
                follow_symlinks=False,
            )
            != acl
        ):
            raise OSError
    except OSError:
        raise S12ControlError(safe_code) from None


def _worktree_release_xattr_omissions(
    records: dict[Path, dict[Path, dict[str, Any]]],
) -> dict[Path, dict[str, bytes]]:
    """Return only exact generated ACLs that teardown intentionally removes."""

    omissions: dict[Path, dict[str, bytes]] = {}
    try:
        for root_entries in records.values():
            for path, record in root_entries.items():
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                try:
                    acl_state, _locked_mode = _worktree_locked_acl_state(
                        path, record
                    )
                except S12ControlError:
                    # A newly journaled root-owned checkout path can already
                    # carry its exact source xattrs without a temporary ACL.
                    _assert_worktree_path_xattrs(path, record)
                    continue
                if acl_state != "generated":
                    continue
                acl = _worktree_barrier_owner_acl(
                    int(record["mode"], 8),
                    record["uid"],
                    kind=record["kind"],
                )
                if acl is None:
                    raise OSError
                omissions[path] = {"system.posix_acl_access": acl}
    except S12ControlError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    return omissions


def _capture_worktree_write_barrier(
    roots: Sequence[Path],
    repository_records: dict[Path, dict[str, Any]],
) -> dict[Path, dict[Path, dict[str, Any]]]:
    """Capture the exact metadata needed to recover a tracked-path write barrier."""

    captured: dict[Path, dict[Path, dict[str, Any]]] = {}
    try:
        for root in roots:
            expected_uid, expected_gid, _ = _recorded_path_metadata(
                repository_records[root], "root"
            )
            entries: dict[Path, dict[str, Any]] = {}
            for path in _tracked_worktree_barrier_paths(root):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    kind = "regular"
                    _assert_no_security_capability(path)
                else:
                    raise OSError
                if (metadata.st_uid, metadata.st_gid) != (
                    expected_uid,
                    expected_gid,
                ):
                    raise OSError
                mode = stat.S_IMODE(metadata.st_mode)
                _worktree_barrier_mode(
                    mode, metadata.st_uid, metadata.st_gid, kind=kind
                )
                _assert_source_worktree_acl_access(
                    path,
                    mode,
                    metadata.st_uid,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                )
                xattr_fingerprint = _worktree_path_xattr_fingerprint(path)
                entries[path] = {
                    "kind": kind,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "mode": f"{mode:04o}",
                    "xattr_fingerprint": xattr_fingerprint,
                }
            captured[root] = entries
    except (KeyError, OSError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None
    return captured


def _worktree_barrier_payload(
    roots: Sequence[Path],
    records: dict[Path, dict[Path, dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    payload: dict[str, list[dict[str, Any]]] = {}
    for key, root in (("application", roots[0]), ("control", roots[1])):
        entries = records.get(root)
        if not isinstance(entries, dict):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        payload[key] = [
            {
                "path_hex": os.fsencode(path.relative_to(root)).hex(),
                **entry,
            }
            for path, entry in sorted(
                entries.items(),
                key=lambda item: os.fsencode(item[0].relative_to(root)),
            )
        ]
    return payload


def _refresh_worktree_barrier_for_release(
    roots: Sequence[Path],
    repository_records: dict[Path, dict[str, Any]],
    records: dict[Path, dict[Path, dict[str, Any]]],
) -> None:
    """Journal canonical metadata for tracked inodes created by root Git."""

    if os.geteuid() != 0:
        return
    try:
        for root in roots:
            expected_uid, expected_gid, _ = _recorded_path_metadata(
                repository_records[root], "root"
            )
            root_records = records[root]
            for path in _tracked_worktree_barrier_paths(root):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    kind = "regular"
                else:
                    raise OSError
                mode = stat.S_IMODE(metadata.st_mode)
                if metadata.st_uid != 0 or mode & 0o022:
                    raise OSError
                existing = root_records.get(path)
                if existing is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (existing["device"], existing["inode"]):
                    original_mode = int(existing["mode"], 8)
                    try:
                        _state, expected_locked_mode = (
                            _worktree_locked_acl_state(path, existing)
                        )
                    except S12ControlError:
                        raise S12ControlError(
                            "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
                        ) from None
                    if mode != expected_locked_mode:
                        raise OSError
                    continue
                _worktree_barrier_mode(
                    mode, expected_uid, expected_gid, kind=kind
                )
                _assert_source_worktree_acl_access(
                    path,
                    mode,
                    expected_uid,
                    "S12_1_REPOSITORY_BARRIER_JOURNAL_RED",
                )
                root_records[path] = {
                    "kind": kind,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "uid": expected_uid,
                    "gid": expected_gid,
                    "mode": f"{mode:04o}",
                    "xattr_fingerprint": (
                        _worktree_path_xattr_fingerprint(path)
                    ),
                }
        if (
            tuple(roots) == (APPLICATION_ROOT, CONTROL_ROOT)
            and (BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink())
        ):
            journal = _private_json(
                BARRIER_MARKER, "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
            )
            journal["worktree_write_barrier"] = _worktree_barrier_payload(
                roots, records
            )
            _atomic_json(BARRIER_MARKER, journal)
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError(
            "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
        ) from None


def _parse_worktree_barrier_payload(
    payload: Any,
    roots: Sequence[Path],
    *,
    require_xattr: bool = True,
) -> dict[Path, dict[Path, dict[str, Any]]]:
    if not isinstance(payload, dict) or set(payload) != {"application", "control"}:
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    parsed: dict[Path, dict[Path, dict[str, Any]]] = {}
    for key, root in (("application", roots[0]), ("control", roots[1])):
        raw_entries = payload.get(key)
        if not isinstance(raw_entries, list):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        entries: dict[Path, dict[str, Any]] = {}
        for raw in raw_entries:
            expected_keys = {
                "path_hex",
                "kind",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
            }
            if require_xattr:
                expected_keys.add("xattr_fingerprint")
            if not isinstance(raw, dict) or set(raw) != expected_keys:
                raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
            try:
                relative_bytes = bytes.fromhex(raw["path_hex"])
                relative = Path(os.fsdecode(relative_bytes))
            except (TypeError, ValueError):
                raise S12ControlError(
                    "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
                ) from None
            if (
                not relative_bytes
                or b"\0" in relative_bytes
                or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
                or raw["kind"] not in {"regular", "directory"}
                or any(
                    type(raw[name]) is not int
                    for name in ("device", "inode", "uid", "gid")
                )
                or raw["device"] < 0
                or raw["inode"] <= 0
                or raw["uid"] < 0
                or raw["gid"] < 0
                or not isinstance(raw["mode"], str)
                or re.fullmatch(r"[0-7]{4}", raw["mode"]) is None
                or (
                    require_xattr
                    and (
                        not isinstance(raw["xattr_fingerprint"], str)
                        or re.fullmatch(
                            r"[0-9a-f]{64}", raw["xattr_fingerprint"]
                        )
                        is None
                    )
                )
            ):
                raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
            path = root / relative
            if path in entries:
                raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
            entries[path] = {
                name: raw[name]
                for name in ("kind", "device", "inode", "uid", "gid", "mode")
            }
            if require_xattr:
                entries[path]["xattr_fingerprint"] = raw[
                    "xattr_fingerprint"
                ]
        parsed[root] = entries
    return parsed


def _upgrade_legacy_worktree_xattr_records(
    records: dict[Path, dict[Path, dict[str, Any]]]
) -> None:
    """Bind safe current xattrs while durably upgrading a V1 orphan."""

    for root_entries in records.values():
        for path, record in root_entries.items():
            if "xattr_fingerprint" in record:
                raise S12ControlError(
                    "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
                )
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                ) from None
            else:
                _assert_legacy_path_xattrs_safe(
                    path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                )
            record["xattr_fingerprint"] = (
                _worktree_path_xattr_fingerprint(path)
            )


def _lock_worktree_write_barrier(
    records: dict[Path, dict[Path, dict[str, Any]]],
    *,
    allow_missing: bool = False,
) -> None:
    """Prevent new non-root tracked-file writes while preserving read traversal."""

    if os.geteuid() != 0:
        return
    try:
        for root, root_entries in records.items():
            for path, record in sorted(
                root_entries.items(),
                key=lambda item: (len(item[0].parts), os.fsencode(item[0])),
            ):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    # A prior interrupted Git checkout may legitimately have
                    # removed an old index path. Current paths are sealed in
                    # the second pass below.
                    continue
                mode = int(record["mode"], 8)
                base_restricted_mode = mode & ~0o222
                generated_restricted_mode = _worktree_barrier_mode(
                    mode,
                    record["uid"],
                    record["gid"],
                    kind=record["kind"],
                )
                expected_kind = record["kind"]
                original = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == record["uid"]
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode) == mode
                )
                locked = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == 0
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode)
                    in {base_restricted_mode, generated_restricted_mode}
                )
                target_locked = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == 0
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode) == mode
                    and not (mode & 0o022)
                )
                restricted = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == record["uid"]
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode)
                    == base_restricted_mode
                )
                owner_acl_transition = False
                if (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == record["uid"]
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode)
                    == generated_restricted_mode
                ):
                    try:
                        transition_state, transition_mode = (
                            _worktree_locked_acl_state(path, record)
                        )
                    except S12ControlError:
                        pass
                    else:
                        owner_acl_transition = (
                            transition_state == "generated"
                            and transition_mode == generated_restricted_mode
                        )
                actual_kind = (
                    "directory"
                    if stat.S_ISDIR(metadata.st_mode)
                    else "regular"
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    else "invalid"
                )
                root_transition = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == 0
                    and metadata.st_gid == record["gid"]
                    and stat.S_IMODE(metadata.st_mode)
                    in {
                        mode,
                        base_restricted_mode,
                        generated_restricted_mode,
                    }
                    and not stat.S_IMODE(metadata.st_mode) & 0o022
                )
                if actual_kind != expected_kind or not (
                    original
                    or locked
                    or target_locked
                    or restricted
                    or root_transition
                    or owner_acl_transition
                ):
                    raise OSError
                if actual_kind == "regular":
                    _assert_no_security_capability(path)
                if locked:
                    try:
                        _state, expected_locked_mode = (
                            _worktree_locked_acl_state(path, record)
                        )
                    except S12ControlError:
                        # removexattr(2) may leave the former ACL-mask bits in
                        # st_mode if a release was interrupted.  Accept only
                        # the exact original non-ACL xattrs, then reseal.
                        _assert_worktree_path_xattrs(path, record)
                        _assert_no_posix_access_acl(
                            path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                        )
                    else:
                        if stat.S_IMODE(metadata.st_mode) == expected_locked_mode:
                            continue
                if owner_acl_transition:
                    source_acl = None
                    restricted_mode = generated_restricted_mode
                else:
                    _assert_worktree_path_xattrs(path, record)
                    source_acl = _assert_source_worktree_acl_access(
                        path,
                        mode,
                        record["uid"],
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                    )
                    restricted_mode = (
                        base_restricted_mode
                        if source_acl is not None
                        else generated_restricted_mode
                    )
                    os.chmod(
                        path, base_restricted_mode, follow_symlinks=False
                    )
                    if source_acl is None:
                        _install_worktree_barrier_owner_acl(path, record)
                        os.chmod(
                            path,
                            generated_restricted_mode,
                            follow_symlinks=False,
                        )
                        _assert_worktree_barrier_owner_acl(
                            path,
                            record,
                            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                        )
                        _assert_worktree_path_xattrs(
                            path, record, barrier_locked=True
                        )
                if metadata.st_uid != 0:
                    os.chown(path, 0, record["gid"], follow_symlinks=False)
                os.chmod(path, restricted_mode, follow_symlinks=False)
                sealed = path.lstat()
                if (
                    sealed.st_uid != 0
                    or sealed.st_gid != record["gid"]
                    or stat.S_IMODE(sealed.st_mode) != restricted_mode
                ):
                    raise OSError
                _assert_worktree_path_xattrs(
                    path, record, barrier_locked=True
                )
            # New target paths created by a previously interrupted root Git
            # checkout are absent from the durable pre-mutation record. They
            # are safe to resume only when root-owned and already closed to
            # group/other writers. Their root-only write bit remains intact so
            # the final ownership restore releases their canonical Git mode.
            for path in _tracked_worktree_barrier_paths(
                root, allow_missing=allow_missing
            ):
                metadata = path.lstat()
                record = root_entries.get(path)
                if record is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (record["device"], record["inode"]):
                    continue
                if (
                    metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink != 1
                    )
                    or not (
                        stat.S_ISREG(metadata.st_mode)
                        or stat.S_ISDIR(metadata.st_mode)
                    )
                ):
                    raise OSError
        for root in records:
            _sync_repository_filesystem(root)
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None


def _assert_worktree_write_barrier(
    roots: Sequence[Path],
    records: dict[Path, dict[Path, dict[str, Any]]],
    *,
    allow_missing: bool = False,
) -> None:
    """Require every current tracked inode and ancestor to reject non-root writes."""

    if os.geteuid() != 0:
        return
    try:
        recorded_paths = {
            path: record
            for entries in records.values()
            for path, record in entries.items()
        }
        for root in roots:
            for path in _tracked_worktree_barrier_paths(
                root, allow_missing=allow_missing
            ):
                metadata = path.lstat()
                record = recorded_paths.get(path)
                if record is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (record["device"], record["inode"]):
                    expected_gid = record["gid"]
                    original_mode = int(record["mode"], 8)
                    try:
                        _state, locked_mode = _worktree_locked_acl_state(
                            path, record
                        )
                    except S12ControlError:
                        locked_mode = -1
                    if stat.S_IMODE(metadata.st_mode) == locked_mode:
                        expected_mode = locked_mode
                    elif (
                        stat.S_IMODE(metadata.st_mode) == original_mode
                        and not original_mode & 0o022
                    ):
                        _assert_worktree_path_xattrs(path, record)
                        _assert_no_posix_access_acl(
                            path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                        )
                        expected_mode = original_mode
                    else:
                        raise OSError
                else:
                    expected_gid = metadata.st_gid
                    expected_mode = stat.S_IMODE(metadata.st_mode)
                if (
                    metadata.st_uid != 0
                    or metadata.st_gid != expected_gid
                    or stat.S_IMODE(metadata.st_mode) != expected_mode
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink != 1
                    )
                    or not (
                        stat.S_ISREG(metadata.st_mode)
                        or stat.S_ISDIR(metadata.st_mode)
                    )
                ):
                    raise OSError
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None


def _restore_worktree_write_barrier(
    records: dict[Path, dict[Path, dict[str, Any]]],
    repository_records: dict[Path, dict[str, Any]] | None = None,
) -> None:
    if os.geteuid() != 0:
        return
    try:
        for root_entries in records.values():
            for path, record in sorted(
                root_entries.items(),
                key=lambda item: (-len(item[0].parts), os.fsencode(item[0])),
            ):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                if (metadata.st_dev, metadata.st_ino) != (
                    record["device"],
                    record["inode"],
                ):
                    continue
                expected_kind = record["kind"]
                actual_kind = (
                    "directory"
                    if stat.S_ISDIR(metadata.st_mode)
                    else "regular"
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    else "invalid"
                )
                if actual_kind != expected_kind:
                    raise OSError
                original_mode = int(record["mode"], 8)
                base_restricted_mode = original_mode & ~0o222
                generated_restricted_mode = _worktree_barrier_mode(
                    original_mode,
                    record["uid"],
                    record["gid"],
                    kind=record["kind"],
                )
                if (
                    metadata.st_uid not in {0, record["uid"]}
                    or metadata.st_gid != record["gid"]
                ):
                    raise OSError
                if (
                    metadata.st_uid == record["uid"]
                    and stat.S_IMODE(metadata.st_mode) == original_mode
                ):
                    try:
                        _assert_worktree_path_xattrs(path, record)
                    except S12ControlError:
                        # An interrupted reverse transition may already have
                        # restored ownership while the generated named-owner
                        # ACL remains.  Its mask can equal an originally
                        # read-only mode, so mode equality alone is not proof
                        # that the source xattr contract is restored.
                        pass
                    else:
                        continue
                try:
                    acl_state, expected_locked_mode = (
                        _worktree_locked_acl_state(path, record)
                    )
                except S12ControlError:
                    acl_state = "interrupted"
                    expected_locked_mode = -1
                if stat.S_IMODE(metadata.st_mode) == expected_locked_mode:
                    pass
                elif stat.S_IMODE(metadata.st_mode) in {
                    base_restricted_mode,
                    generated_restricted_mode,
                    *({original_mode} if not original_mode & 0o022 else set()),
                }:
                    _assert_worktree_path_xattrs(path, record)
                    _assert_no_posix_access_acl(
                        path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                    )
                else:
                    raise OSError
                if metadata.st_uid == 0 and record["uid"] != 0:
                    os.chown(
                        path,
                        record["uid"],
                        record["gid"],
                        follow_symlinks=False,
                    )
                if acl_state == "generated":
                    _remove_worktree_barrier_owner_acl(path, record)
                    _assert_worktree_path_xattrs(path, record)
                    _assert_no_posix_access_acl(
                        path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                    )
                os.chmod(path, original_mode, follow_symlinks=False)
                _assert_worktree_path_xattrs(path, record)
        if repository_records is not None:
            if set(repository_records) != set(records):
                raise OSError
            for root, root_entries in records.items():
                expected_uid, expected_gid, _ = _recorded_path_metadata(
                    repository_records[root], "root"
                )
                for path in sorted(
                    _tracked_worktree_barrier_paths(root),
                    key=lambda item: (-len(item.parts), os.fsencode(item)),
                ):
                    metadata = path.lstat()
                    record = root_entries.get(path)
                    if record is not None and (
                        metadata.st_dev,
                        metadata.st_ino,
                    ) == (record["device"], record["inode"]):
                        continue
                    if (
                        metadata.st_uid != 0
                        or stat.S_IMODE(metadata.st_mode) & 0o022
                        or (
                            stat.S_ISREG(metadata.st_mode)
                            and metadata.st_nlink != 1
                        )
                        or not (
                            stat.S_ISREG(metadata.st_mode)
                            or stat.S_ISDIR(metadata.st_mode)
                        )
                    ):
                        raise OSError
                    os.chown(
                        path,
                        expected_uid,
                        expected_gid,
                        follow_symlinks=False,
                    )
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None


def _validate_released_worktree_contract(
    roots: Sequence[Path],
    repository_records: dict[Path, dict[str, Any]],
    barrier_records: dict[Path, dict[Path, dict[str, Any]]],
) -> None:
    """Validate exact old entries and safe canonical metadata for new entries."""

    if os.geteuid() != 0:
        return
    try:
        for root in roots:
            expected_uid, expected_gid, _ = _recorded_path_metadata(
                repository_records[root], "root"
            )
            root_records = barrier_records[root]
            current_paths = set(_tracked_worktree_barrier_paths(root))
            for path in sorted(
                current_paths | set(root_records), key=os.fsencode
            ):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    if path in current_paths:
                        raise
                    continue
                record = root_records.get(path)
                same_recorded_inode = record is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (record["device"], record["inode"])
                if same_recorded_inode:
                    _assert_worktree_path_xattrs(path, record)
                    valid_metadata = (
                        metadata.st_uid == record["uid"]
                        and metadata.st_gid == record["gid"]
                        and stat.S_IMODE(metadata.st_mode)
                        == int(record["mode"], 8)
                    )
                    expected_kind = record["kind"]
                else:
                    valid_metadata = (
                        metadata.st_uid == expected_uid
                        and metadata.st_gid == expected_gid
                        and not (stat.S_IMODE(metadata.st_mode) & 0o022)
                    )
                    expected_kind = (
                        "directory"
                        if stat.S_ISDIR(metadata.st_mode)
                        else "regular"
                    )
                actual_kind = (
                    "directory"
                    if stat.S_ISDIR(metadata.st_mode)
                    else "regular"
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    else "invalid"
                )
                if not valid_metadata or actual_kind != expected_kind:
                    raise OSError
            _validate_repository_worktree_contract(
                root,
                repository_records[root],
                allow_journaled_transition=True,
            )
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None


def _reseal_released_worktree_contract(
    roots: Sequence[Path],
    repository_records: dict[Path, dict[str, Any]],
    barrier_records: dict[Path, dict[Path, dict[str, Any]]],
    *,
    include_current: bool,
) -> None:
    """Restore the durable root-owned write barrier before releasing leases."""

    if os.geteuid() != 0:
        return
    try:
        for root in roots:
            expected_uid, expected_gid, _ = _recorded_path_metadata(
                repository_records[root], "root"
            )
            root_records = barrier_records[root]
            protected = set(root_records)
            if include_current:
                protected.update(_tracked_worktree_barrier_paths(root))
            for path in sorted(
                protected,
                key=lambda item: (len(item.parts), os.fsencode(item)),
            ):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                record = root_records.get(path)
                same_recorded_inode = record is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (record["device"], record["inode"])
                generated_acl_transition = False
                if same_recorded_inode:
                    expected_kind = record["kind"]
                    source_mode = int(record["mode"], 8)
                    target_uid = record["uid"]
                    target_gid = record["gid"]
                    base_restricted_mode = source_mode & ~0o222
                    generated_restricted_mode = _worktree_barrier_mode(
                        source_mode,
                        target_uid,
                        target_gid,
                        kind=expected_kind,
                    )
                    actual_mode = stat.S_IMODE(metadata.st_mode)
                    try:
                        acl_state, expected_locked_mode = (
                            _worktree_locked_acl_state(path, record)
                        )
                    except S12ControlError:
                        _assert_worktree_path_xattrs(path, record)
                    else:
                        if acl_state == "generated":
                            if actual_mode != expected_locked_mode:
                                raise OSError
                            generated_acl_transition = True
                        else:
                            _assert_worktree_path_xattrs(path, record)
                    if generated_acl_transition:
                        released = (
                            metadata.st_uid in {0, target_uid}
                            and metadata.st_gid == target_gid
                        )
                    else:
                        allowed_modes = {
                            source_mode,
                            base_restricted_mode,
                            generated_restricted_mode,
                        }
                        released = (
                            metadata.st_uid == target_uid
                            and metadata.st_gid == target_gid
                            and actual_mode in allowed_modes
                        ) or (
                            metadata.st_uid == 0
                            and metadata.st_gid == target_gid
                            and actual_mode
                            in {
                                base_restricted_mode,
                                generated_restricted_mode,
                                *(
                                    {source_mode}
                                    if not source_mode & 0o022
                                    else set()
                                ),
                            }
                        )
                else:
                    released = (
                        include_current
                        and metadata.st_uid == expected_uid
                        and metadata.st_gid == expected_gid
                        and not (stat.S_IMODE(metadata.st_mode) & 0o022)
                    )
                    expected_kind = (
                        "directory"
                        if stat.S_ISDIR(metadata.st_mode)
                        else "regular"
                    )
                    source_mode = stat.S_IMODE(metadata.st_mode)
                    target_uid = expected_uid
                    target_gid = expected_gid
                actual_kind = (
                    "directory"
                    if stat.S_ISDIR(metadata.st_mode)
                    else "regular"
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    else "invalid"
                )
                if not released or actual_kind != expected_kind:
                    raise OSError
                if generated_acl_transition:
                    _assert_worktree_barrier_owner_acl(
                        path,
                        record,
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                    )
                    if metadata.st_uid != 0:
                        os.chown(
                            path, 0, target_gid, follow_symlinks=False
                        )
                    os.chmod(
                        path,
                        generated_restricted_mode,
                        follow_symlinks=False,
                    )
                    sealed = path.lstat()
                    if (
                        sealed.st_uid != 0
                        or sealed.st_gid != target_gid
                        or stat.S_IMODE(sealed.st_mode)
                        != generated_restricted_mode
                    ):
                        raise OSError
                    _assert_worktree_path_xattrs(
                        path, record, barrier_locked=True
                    )
                    continue
                restricted_mode = _worktree_barrier_mode(
                    source_mode,
                    target_uid,
                    target_gid,
                    kind=expected_kind,
                )
                source_acl = _assert_source_worktree_acl_access(
                    path,
                    source_mode,
                    target_uid,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                )
                os.chmod(
                    path, source_mode & ~0o222, follow_symlinks=False
                )
                acl_record = {
                    "kind": expected_kind,
                    "uid": target_uid,
                    "gid": target_gid,
                    "mode": f"{source_mode:04o}",
                }
                if source_acl is None:
                    _install_worktree_barrier_owner_acl(path, acl_record)
                    os.chmod(
                        path, restricted_mode, follow_symlinks=False
                    )
                    _assert_worktree_barrier_owner_acl(
                        path,
                        acl_record,
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                    )
                    if same_recorded_inode:
                        _assert_worktree_path_xattrs(
                            path, record, barrier_locked=True
                        )
                else:
                    restricted_mode = source_mode & ~0o222
                os.chown(path, 0, target_gid, follow_symlinks=False)
                os.chmod(path, restricted_mode, follow_symlinks=False)
                sealed = path.lstat()
                if (
                    sealed.st_uid != 0
                    or sealed.st_gid != target_gid
                    or stat.S_IMODE(sealed.st_mode) != restricted_mode
                ):
                    raise OSError
                if same_recorded_inode:
                    _assert_worktree_path_xattrs(
                        path, record, barrier_locked=True
                    )
            _sync_repository_filesystem(root)
    except (KeyError, OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED") from None


def _repository_git_metadata_paths(roots: Sequence[Path]) -> tuple[Path, ...]:
    """Return only Git metadata paths participating in recovery exclusion."""

    protected: list[Path] = []
    for root in roots:
        git_directory = root / ".git"
        recovery_directory = _recovery_git_path(root)
        if _is_recovery_guard(git_directory) and _is_recovery_git_directory(
            recovery_directory
        ):
            protected.extend((git_directory, recovery_directory))
        elif _is_canonical_git_directory(git_directory):
            if _is_recovery_guard(recovery_directory):
                protected.extend((git_directory, recovery_directory))
            elif recovery_directory.exists() or recovery_directory.is_symlink():
                raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
            else:
                protected.append(git_directory)
        else:
            raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    return tuple(protected)


def _repository_git_metadata_directories(
    roots: Sequence[Path],
) -> tuple[Path, ...]:
    """Return every Git metadata directory requiring a recursive release mark."""

    directories: list[Path] = []
    try:
        for root in roots:
            git_directory = root / ".git"
            for current, children, _files in os.walk(
                git_directory, topdown=True, followlinks=False
            ):
                directory = Path(current)
                metadata = directory.lstat()
                if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise OSError
                directories.append(directory)
                for name in children:
                    child = directory / name
                    child_metadata = child.lstat()
                    if child.is_symlink() or not stat.S_ISDIR(
                        child_metadata.st_mode
                    ):
                        raise OSError
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    return tuple(directories)


def _assert_no_security_capability(path: Path) -> None:
    """Reject file capabilities that chown(2) would silently discard."""

    if not hasattr(os, "listxattr"):
        if sys.platform == "linux":
            raise OSError
        return
    before = path.lstat()
    names = sorted(
        os.listxattr(path, follow_symlinks=False), key=os.fsencode
    )
    after = path.lstat()
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_ctime_ns")
    if (
        "security.capability" in names
        or names
        != sorted(
            os.listxattr(path, follow_symlinks=False), key=os.fsencode
        )
        or any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        )
    ):
        raise OSError


def _normalize_posix_acl_mode_entries(value: bytes) -> bytes:
    """Ignore only ACL fields deterministically rewritten by chmod(2)."""

    acl_header = struct.Struct("<I")
    acl_entry = struct.Struct("<HHI")
    if (
        len(value) < acl_header.size
        or (len(value) - acl_header.size) % acl_entry.size != 0
        or acl_header.unpack_from(value)[0] != 2
    ):
        raise OSError
    entries = [
        acl_entry.unpack_from(value, offset)
        for offset in range(acl_header.size, len(value), acl_entry.size)
    ]
    has_mask = any(tag == 0x10 for tag, _permissions, _identifier in entries)
    normalized = bytearray(value[: acl_header.size])
    for tag, permissions, identifier in entries:
        if tag in {0x01, 0x10, 0x20} or (tag == 0x04 and not has_mask):
            permissions = 0
        normalized.extend(acl_entry.pack(tag, permissions, identifier))
    return bytes(normalized)


def _stable_xattr_payload(
    path: Path,
    metadata: os.stat_result,
    *,
    normalize_posix_acl_mode: bool = False,
    expected_omitted_xattrs: dict[str, bytes] | None = None,
) -> bytes:
    """Read one inode's extended attributes without accepting concurrent drift."""

    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        if sys.platform == "linux":
            raise OSError
        return b""
    before = path.lstat()
    names = sorted(
        os.listxattr(path, follow_symlinks=False), key=os.fsencode
    )
    payload = bytearray()
    omitted = set()
    for name in names:
        encoded = os.fsencode(name)
        value = os.getxattr(path, name, follow_symlinks=False)
        if expected_omitted_xattrs is not None and name in expected_omitted_xattrs:
            if value != expected_omitted_xattrs[name]:
                raise OSError
            omitted.add(name)
            continue
        if normalize_posix_acl_mode and name == "system.posix_acl_access":
            value = _normalize_posix_acl_mode_entries(value)
        payload.extend(len(encoded).to_bytes(8, "big"))
        payload.extend(encoded)
        payload.extend(len(value).to_bytes(8, "big"))
        payload.extend(value)
    if names != sorted(
        os.listxattr(path, follow_symlinks=False), key=os.fsencode
    ) or (
        expected_omitted_xattrs is not None
        and omitted != set(expected_omitted_xattrs)
    ):
        raise OSError
    after = path.lstat()
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field) != getattr(after, field)
        or getattr(before, field) != getattr(metadata, field)
        for field in stable_fields
    ):
        raise OSError
    return bytes(payload)


def _release_xattr_fingerprint(
    paths: Sequence[Path],
    *,
    expected_omitted_xattrs: dict[Path, dict[str, bytes]] | None = None,
) -> str:
    """Bind extended attributes for every existing release-guard path."""

    digest = hashlib.sha256()
    try:
        for path in sorted(set(paths), key=os.fsencode):
            encoded_path = os.fsencode(path)
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                digest.update(b"missing\0" + encoded_path + b"\0")
                continue
            if path.is_symlink() or not (
                stat.S_ISDIR(metadata.st_mode)
                or (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink == 1
                )
            ):
                raise OSError
            digest.update(
                b"present\0"
                + encoded_path
                + b"\0"
                + str(metadata.st_dev).encode("ascii")
                + b":"
                + str(metadata.st_ino).encode("ascii")
                + b"\0"
                + _stable_xattr_payload(
                    path,
                    metadata,
                    normalize_posix_acl_mode=True,
                    expected_omitted_xattrs=(
                        expected_omitted_xattrs.get(path)
                        if expected_omitted_xattrs is not None
                        else None
                    ),
                )
                + b"\0"
            )
    except (OSError, TypeError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    return digest.hexdigest()


def _git_metadata_release_fingerprint(roots: Sequence[Path]) -> str:
    """Bind Git namespace, bytes and modes while ignoring intentional chown."""

    digest = hashlib.sha256()
    try:
        for root_index, root in enumerate(roots):
            git_directory = root / ".git"
            git_metadata = git_directory.lstat()
            if git_directory.is_symlink() or not stat.S_ISDIR(
                git_metadata.st_mode
            ):
                raise OSError
            digest.update(
                b"root\0"
                + str(root_index).encode("ascii")
                + b"\0"
                + str(git_metadata.st_dev).encode("ascii")
                + b":"
                + str(git_metadata.st_ino).encode("ascii")
                + b"\0"
                + _stable_xattr_payload(
                    git_directory,
                    git_metadata,
                    normalize_posix_acl_mode=True,
                )
                + b"\0"
            )
            pending = [git_directory]
            while pending:
                directory = pending.pop()
                entries = sorted(
                    os.scandir(directory), key=lambda entry: os.fsencode(entry.name)
                )
                child_directories: list[Path] = []
                for entry in entries:
                    path = Path(entry.path)
                    metadata = entry.stat(follow_symlinks=False)
                    relative = os.fsencode(path.relative_to(git_directory))
                    if stat.S_ISDIR(metadata.st_mode):
                        kind = b"directory"
                        child_directories.append(path)
                        payload = b""
                    elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                        kind = b"regular"
                        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        try:
                            before = os.fstat(descriptor)
                            content = hashlib.sha256()
                            while True:
                                block = os.read(descriptor, 1024 * 1024)
                                if not block:
                                    break
                                content.update(block)
                            after = os.fstat(descriptor)
                        finally:
                            os.close(descriptor)
                        stable_fields = (
                            "st_dev",
                            "st_ino",
                            "st_mode",
                            "st_nlink",
                            "st_size",
                            "st_mtime_ns",
                        )
                        if any(
                            getattr(before, field) != getattr(after, field)
                            or getattr(before, field) != getattr(metadata, field)
                            for field in stable_fields
                        ):
                            raise OSError
                        payload = content.digest()
                    else:
                        raise OSError
                    digest.update(
                        str(root_index).encode("ascii")
                        + b"\0"
                        + relative
                        + b"\0"
                        + kind
                        + b"\0"
                        + b":".join(
                            str(value).encode("ascii")
                            for value in (
                                metadata.st_dev,
                                metadata.st_ino,
                                metadata.st_mode,
                                metadata.st_nlink,
                                metadata.st_size,
                                metadata.st_mtime_ns,
                            )
                        )
                        + b"\0"
                        + payload
                        + b"\0"
                        + _stable_xattr_payload(path, metadata)
                        + b"\0"
                    )
                pending.extend(reversed(child_directories))
    except (OSError, ValueError):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    return digest.hexdigest()


def _git_metadata_transition_fingerprint(paths: Sequence[Path]) -> str:
    """Bind the complete protected tree while normalizing its top lock attrs."""

    digest = hashlib.sha256()
    for index, root in enumerate(paths):
        try:
            root_metadata = root.lstat()
            if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
                raise OSError
            digest.update(
                b"root\0"
                + str(index).encode("ascii")
                + b"\0"
                + str(root_metadata.st_dev).encode("ascii")
                + b":"
                + str(root_metadata.st_ino).encode("ascii")
                + b"\0"
                + _stable_xattr_payload(
                    root,
                    root_metadata,
                    normalize_posix_acl_mode=True,
                )
                + b"\0"
            )
            pending = [root]
            while pending:
                directory = pending.pop()
                entries = sorted(
                    os.scandir(directory), key=lambda entry: os.fsencode(entry.name)
                )
                child_directories: list[Path] = []
                for entry in entries:
                    path = Path(entry.path)
                    metadata = entry.stat(follow_symlinks=False)
                    relative = os.fsencode(path.relative_to(root))
                    if stat.S_ISDIR(metadata.st_mode):
                        kind = b"directory"
                        child_directories.append(path)
                        payload = b""
                    elif stat.S_ISREG(metadata.st_mode):
                        kind = b"regular"
                        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        try:
                            before = os.fstat(descriptor)
                            content = hashlib.sha256()
                            while True:
                                block = os.read(descriptor, 1024 * 1024)
                                if not block:
                                    break
                                content.update(block)
                            after = os.fstat(descriptor)
                        finally:
                            os.close(descriptor)
                        stable_fields = (
                            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                            "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
                        )
                        if any(
                            getattr(before, field) != getattr(after, field)
                            or getattr(before, field) != getattr(metadata, field)
                            for field in stable_fields
                        ):
                            raise OSError
                        payload = content.digest()
                    elif stat.S_ISLNK(metadata.st_mode):
                        kind = b"symlink"
                        payload = os.fsencode(os.readlink(path))
                    else:
                        raise OSError
                    digest.update(
                        relative
                        + b"\0"
                        + kind
                        + b"\0"
                        + b":".join(
                            str(value).encode("ascii")
                            for value in (
                                metadata.st_dev,
                                metadata.st_ino,
                                metadata.st_mode,
                                metadata.st_uid,
                                metadata.st_gid,
                                metadata.st_nlink,
                                metadata.st_size,
                                metadata.st_mtime_ns,
                                metadata.st_ctime_ns,
                            )
                        )
                        + b"\0"
                        + payload
                        + b"\0"
                    )
                pending.extend(reversed(child_directories))
        except (OSError, ValueError):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED") from None
    return digest.hexdigest()


class _GitMetadataTransitionGuard:
    """Detect even short-lived metadata writers across the lock transition."""

    _EVENT = struct.Struct("iIII")
    _MUTATION_MASK = (
        0x00000002  # IN_MODIFY
        | 0x00000004  # IN_ATTRIB
        | 0x00000008  # IN_CLOSE_WRITE
        | 0x00000040  # IN_MOVED_FROM
        | 0x00000080  # IN_MOVED_TO
        | 0x00000100  # IN_CREATE
        | 0x00000200  # IN_DELETE
        | 0x00000400  # IN_DELETE_SELF
        | 0x00000800  # IN_MOVE_SELF
    )
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _IN_ISDIR = 0x40000000
    _ROOT_LOCK_EVENTS = 0x00000004 | 0x00000800  # ATTRIB | MOVE_SELF

    def __init__(
        self,
        paths: Sequence[Path],
        *,
        allow_root_lock_events: bool = True,
    ):
        self.paths = tuple(paths)
        self.descriptor: int | None = None
        self.watches: set[int] = set()
        self.root_watches: set[int] = set()
        self.allow_root_lock_events = allow_root_lock_events
        self.baseline = ""
        try:
            self.baseline = _git_metadata_transition_fingerprint(self.paths)
            if sys.platform == "linux":
                library = ctypes.CDLL(None, use_errno=True)
                init = library.inotify_init1
                init.argtypes = [ctypes.c_int]
                init.restype = ctypes.c_int
                descriptor = init(os.O_NONBLOCK | os.O_CLOEXEC)
                if descriptor < 0:
                    raise OSError(ctypes.get_errno(), "inotify_init1")
                self.descriptor = descriptor
                add = library.inotify_add_watch
                add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
                add.restype = ctypes.c_int
                for root in self.paths:
                    pending = [root]
                    first = True
                    while pending:
                        directory = pending.pop()
                        watch = add(
                            descriptor,
                            os.fsencode(directory),
                            self._MUTATION_MASK,
                        )
                        if watch < 0:
                            raise OSError(ctypes.get_errno(), "inotify_add_watch")
                        self.watches.add(watch)
                        if first:
                            self.root_watches.add(watch)
                            first = False
                        entries = sorted(
                            os.scandir(directory),
                            key=lambda entry: os.fsencode(entry.name),
                        )
                        children = [
                            Path(entry.path)
                            for entry in entries
                            if entry.is_dir(follow_symlinks=False)
                        ]
                        pending.extend(reversed(children))
            if _git_metadata_transition_fingerprint(self.paths) != self.baseline:
                raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
            self._assert_event_queue_quiet()
        except S12ControlError:
            self.close()
            raise
        except (OSError, ValueError, AttributeError):
            self.close()
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED") from None

    def _assert_event_queue_quiet(self) -> None:
        if self.descriptor is None:
            return
        while True:
            try:
                payload = os.read(self.descriptor, 1024 * 1024)
            except BlockingIOError:
                return
            except OSError:
                raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED") from None
            if not payload:
                return
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < self._EVENT.size:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
                watch, mask, _cookie, name_length = self._EVENT.unpack_from(
                    payload, offset
                )
                offset += self._EVENT.size
                if name_length > len(payload) - offset:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
                name = payload[offset : offset + name_length].rstrip(b"\0")
                offset += name_length
                normalized = mask & ~self._IN_ISDIR
                if normalized & self._IN_Q_OVERFLOW:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
                if (
                    self.allow_root_lock_events
                    and watch in self.root_watches
                    and not name
                    and normalized
                    and normalized & ~self._ROOT_LOCK_EVENTS == 0
                ):
                    continue
                if normalized:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")

    def assert_unchanged(self) -> None:
        self._assert_event_queue_quiet()
        if _git_metadata_transition_fingerprint(self.paths) != self.baseline:
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        self._assert_event_queue_quiet()

    def assert_no_writer_events(self) -> None:
        self._assert_event_queue_quiet()

    def assert_quarantined_unchanged(self, paths: Sequence[Path]) -> None:
        """Seal mmap and already-open-fd races after metadata is unreachable."""

        self._assert_event_queue_quiet()
        if _git_metadata_transition_fingerprint(paths) != self.baseline:
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        self._assert_event_queue_quiet()

    def _synchronized_inotify_shutdown(self) -> None:
        """Remove every metadata watch behind an IN_IGNORED queue barrier."""

        if self.descriptor is None:
            return
        descriptor = self.descriptor
        pending = set(self.watches)
        try:
            library = ctypes.CDLL(None, use_errno=True)
            remove = library.inotify_rm_watch
            remove.argtypes = [ctypes.c_int, ctypes.c_int]
            remove.restype = ctypes.c_int
            for watch in sorted(pending):
                if remove(descriptor, watch) < 0:
                    raise OSError(ctypes.get_errno(), "inotify_rm_watch")
            deadline = time.monotonic() + 1.0
            while pending:
                try:
                    payload = os.read(descriptor, 1024 * 1024)
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OSError("inotify shutdown timeout")
                    readable, _, _ = select.select(
                        (descriptor,), (), (), remaining
                    )
                    if not readable:
                        raise OSError("inotify shutdown timeout")
                    continue
                if not payload:
                    raise OSError("inotify shutdown EOF")
                offset = 0
                while offset < len(payload):
                    if len(payload) - offset < self._EVENT.size:
                        raise OSError("short inotify shutdown event")
                    watch, mask, _cookie, name_length = self._EVENT.unpack_from(
                        payload, offset
                    )
                    offset += self._EVENT.size
                    if name_length > len(payload) - offset:
                        raise OSError("invalid inotify shutdown event")
                    name = payload[offset : offset + name_length].rstrip(b"\0")
                    offset += name_length
                    normalized = mask & ~self._IN_ISDIR
                    if (
                        watch in pending
                        and not name
                        and normalized == self._IN_IGNORED
                    ):
                        pending.remove(watch)
                    elif normalized:
                        raise OSError("mutation during inotify shutdown")
            os.close(descriptor)
        except (OSError, ValueError, AttributeError):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED") from None
        self.descriptor = None
        self.watches.clear()
        self.root_watches.clear()

    def finalize_release(self) -> None:
        """Cross an ordered watch barrier while a journal backup remains."""

        self.assert_unchanged()
        self._synchronized_inotify_shutdown()

    def close(self) -> None:
        if self.descriptor is not None:
            try:
                os.close(self.descriptor)
            finally:
                self.descriptor = None
                self.watches.clear()
                self.root_watches.clear()


class _WorktreeReleaseGuard:
    """Observe mutations and block external opens through Worktree release."""

    _EVENT = struct.Struct("iIII")
    _ATTRIB = 0x00000004
    _WATCH_MASK = (
        0x00000002  # IN_MODIFY
        | _ATTRIB
        | 0x00000008  # IN_CLOSE_WRITE
        | 0x00000040  # IN_MOVED_FROM
        | 0x00000080  # IN_MOVED_TO
        | 0x00000100  # IN_CREATE
        | 0x00000200  # IN_DELETE
        | 0x00000400  # IN_DELETE_SELF
        | 0x00000800  # IN_MOVE_SELF
    )
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _IN_ISDIR = 0x40000000
    _FAN_EVENT = struct.Struct("=IBBHQii")
    _FAN_RESPONSE = struct.Struct("=iI")
    _FANOTIFY_METADATA_VERSION = 3
    _FAN_CLOEXEC = 0x00000001
    _FAN_NONBLOCK = 0x00000002
    _FAN_CLASS_CONTENT = 0x00000004
    _FAN_REPORT_TID = 0x00000100
    _FAN_MARK_ADD = 0x00000001
    _FAN_MARK_ONLYDIR = 0x00000008
    _FAN_MARK_FLUSH = 0x00000080
    _FAN_OPEN_PERM = 0x00010000
    _FAN_EVENT_ON_CHILD = 0x08000000
    _FAN_ALLOW = 0x01
    _FAN_DENY = 0x02

    def __init__(
        self,
        roots: Sequence[Path],
        tracked_paths: Sequence[Path] | None = None,
    ):
        self.descriptor: int | None = None
        self.sentinel_path: Path | None = None
        self.sentinel_watch: int | None = None
        self.inotify_watches: set[int] = set()
        self.fanotify_descriptor: int | None = None
        self.fanotify_stop = threading.Event()
        self.fanotify_thread: threading.Thread | None = None
        self.fanotify_lock = threading.Lock()
        self.fanotify_external_open = False
        self.fanotify_error = False
        self.fanotify_pending: list[int] = []
        self.controller_pid = os.getpid()
        if sys.platform != "linux":
            return
        try:
            library = ctypes.CDLL(None, use_errno=True)
            init = library.inotify_init1
            init.argtypes = [ctypes.c_int]
            init.restype = ctypes.c_int
            descriptor = init(os.O_NONBLOCK | os.O_CLOEXEC)
            if descriptor < 0:
                raise OSError(ctypes.get_errno(), "inotify_init1")
            self.descriptor = descriptor
            add = library.inotify_add_watch
            add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            add.restype = ctypes.c_int
            paths = set(roots)
            if tracked_paths is None:
                for root in roots:
                    paths.update(_tracked_worktree_barrier_paths(root))
            else:
                paths.update(tracked_paths)
            self.sentinel_path = roots[0]
            for path in sorted(paths, key=os.fsencode):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                watch = add(descriptor, os.fsencode(path), self._WATCH_MASK)
                if watch < 0:
                    raise OSError(ctypes.get_errno(), "inotify_add_watch")
                self.inotify_watches.add(watch)
                if path == self.sentinel_path:
                    self.sentinel_watch = watch
            if self.sentinel_watch is None:
                raise OSError("release sentinel watch missing")
            if os.geteuid() == 0:
                fanotify_init = library.fanotify_init
                fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
                fanotify_init.restype = ctypes.c_int
                fanotify_descriptor = fanotify_init(
                    self._FAN_CLOEXEC
                    | self._FAN_NONBLOCK
                    | self._FAN_CLASS_CONTENT
                    | self._FAN_REPORT_TID,
                    os.O_RDONLY | os.O_CLOEXEC,
                )
                if fanotify_descriptor < 0:
                    raise OSError(ctypes.get_errno(), "fanotify_init")
                self.fanotify_descriptor = fanotify_descriptor
                fanotify_mark = library.fanotify_mark
                fanotify_mark.argtypes = [
                    ctypes.c_int,
                    ctypes.c_uint,
                    ctypes.c_uint64,
                    ctypes.c_int,
                    ctypes.c_char_p,
                ]
                fanotify_mark.restype = ctypes.c_int
                for path in sorted(paths, key=os.fsencode):
                    try:
                        metadata = path.lstat()
                    except FileNotFoundError:
                        continue
                    mark_flags = self._FAN_MARK_ADD
                    mask = self._FAN_OPEN_PERM
                    if stat.S_ISDIR(metadata.st_mode):
                        mark_flags |= self._FAN_MARK_ONLYDIR
                        mask |= self._FAN_EVENT_ON_CHILD
                    if (
                        fanotify_mark(
                            fanotify_descriptor,
                            mark_flags,
                            mask,
                            -100,
                            os.fsencode(path),
                        )
                        < 0
                    ):
                        raise OSError(ctypes.get_errno(), "fanotify_mark")
                self.fanotify_thread = threading.Thread(
                    target=self._fanotify_loop,
                    name="s12-worktree-release-guard",
                    daemon=True,
                )
                self.fanotify_thread.start()
            self.assert_no_events()
        except S12ControlError:
            self.close()
            raise
        except (OSError, ValueError, AttributeError):
            self.close()
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
            ) from None

    def _trusted_fanotify_pid(self, pid: int) -> bool:
        current = pid
        for _ in range(128):
            if current == self.controller_pid:
                return True
            if current <= 1:
                return False
            try:
                payload = Path(f"/proc/{current}/stat").read_text(
                    encoding="ascii"
                )
                _, separator, remainder = payload.rpartition(")")
                fields = remainder.strip().split()
                if not separator or len(fields) < 2:
                    return False
                current = int(fields[1])
            except (OSError, UnicodeError, ValueError):
                return False
        return False

    def _fanotify_respond(
        self,
        event_descriptor: int,
        decision: int,
        *,
        group_descriptor: int | None = None,
    ) -> None:
        descriptor = (
            self.fanotify_descriptor
            if group_descriptor is None
            else group_descriptor
        )
        if descriptor is None:
            raise OSError("fanotify descriptor closed")
        os.write(
            descriptor,
            self._FAN_RESPONSE.pack(event_descriptor, decision),
        )
        os.close(event_descriptor)

    @classmethod
    def _fanotify_request_is_read_only(cls, pid: int) -> bool:
        """Classify the blocked opener; unknown requests remain fail-closed."""

        try:
            fields = Path(f"/proc/{pid}/syscall").read_text(
                encoding="ascii"
            ).split()
            if len(fields) < 5:
                return False
            syscall = int(fields[0], 0)
            machine = os.uname().machine.lower()
            open_flags_index: dict[int, int]
            creators: set[int]
            open_by_handle: set[int]
            if machine in {"x86_64", "amd64"}:
                open_flags_index = {2: 2, 257: 3}
                creators = {85}
                open_by_handle = {304}
            elif machine in {"aarch64", "arm64", "riscv64"}:
                open_flags_index = {56: 3}
                creators = set()
                open_by_handle = {265}
            elif machine in {"i386", "i486", "i586", "i686"}:
                open_flags_index = {5: 2, 295: 3}
                creators = {8}
                open_by_handle = {342}
            elif machine.startswith("arm"):
                open_flags_index = {5: 2, 322: 3}
                creators = {8}
                open_by_handle = {371}
            elif machine in {"ppc64", "ppc64le"}:
                open_flags_index = {5: 2, 286: 3}
                creators = {8}
                open_by_handle = {346}
            else:
                return False
            if syscall in creators:
                return False
            if syscall == 437:
                # The kernel already copied open_how before the permission
                # event; its userspace pointer is mutable while blocked.
                return False
            if syscall in open_by_handle:
                flags = int(fields[3], 0)
            else:
                index = open_flags_index.get(syscall)
                if index is None or index >= len(fields):
                    return False
                flags = int(fields[index], 0)
            mutation_flags = os.O_CREAT | os.O_TRUNC | os.O_APPEND
            return (
                flags & os.O_ACCMODE == os.O_RDONLY
                and not flags & mutation_flags
            )
        except (OSError, UnicodeError, ValueError, AttributeError):
            return False

    def _fanotify_loop(self) -> None:
        descriptor = self.fanotify_descriptor
        if descriptor is None:
            return
        try:
            while not self.fanotify_stop.is_set():
                readable, _, _ = select.select((descriptor,), (), (), 0.05)
                if not readable:
                    continue
                try:
                    payload = os.read(descriptor, 1024 * 1024)
                except BlockingIOError:
                    continue
                offset = 0
                while offset < len(payload):
                    if len(payload) - offset < self._FAN_EVENT.size:
                        raise OSError("short fanotify event")
                    (
                        event_length,
                        version,
                        _reserved,
                        metadata_length,
                        mask,
                        event_descriptor,
                        pid,
                    ) = self._FAN_EVENT.unpack_from(payload, offset)
                    if (
                        version != self._FANOTIFY_METADATA_VERSION
                        or event_length < metadata_length
                        or metadata_length < self._FAN_EVENT.size
                        or event_length > len(payload) - offset
                    ):
                        raise OSError("invalid fanotify event")
                    offset += event_length
                    if (
                        event_descriptor < 0
                        or mask & self._IN_Q_OVERFLOW
                        or not (mask & self._FAN_OPEN_PERM)
                    ):
                        if event_descriptor >= 0:
                            self._fanotify_respond(
                                event_descriptor, self._FAN_DENY
                            )
                        raise OSError("unexpected fanotify event")
                    if self._trusted_fanotify_pid(pid):
                        self._fanotify_respond(event_descriptor, self._FAN_ALLOW)
                    elif self._fanotify_request_is_read_only(pid):
                        self._fanotify_respond(event_descriptor, self._FAN_ALLOW)
                    else:
                        with self.fanotify_lock:
                            self.fanotify_external_open = True
                            self.fanotify_pending.append(event_descriptor)
        except OSError:
            failed_descriptor: int | None = None
            with self.fanotify_lock:
                self.fanotify_error = True
                if self.fanotify_descriptor == descriptor:
                    failed_descriptor = descriptor
                    self.fanotify_descriptor = None
            if failed_descriptor is not None:
                try:
                    os.close(failed_descriptor)
                except OSError:
                    pass

    def _assert_fanotify_quiet(self) -> None:
        if self.fanotify_descriptor is None:
            if self.fanotify_error:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                )
            return
        with self.fanotify_lock:
            worker_failed = (
                self.fanotify_error
                or self.fanotify_thread is None
                or not self.fanotify_thread.is_alive()
            )
        if worker_failed or self.sentinel_path is None:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
        try:
            sentinel = os.open(
                self.sentinel_path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            os.close(sentinel)
        except OSError:
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
            ) from None
        with self.fanotify_lock:
            if self.fanotify_external_open or self.fanotify_error:
                raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")

    def _assert_events(
        self,
        *,
        allow_attributes: bool,
        sentinel_watch: int | None = None,
    ) -> bool:
        if self.descriptor is None:
            return True
        self._assert_fanotify_quiet()
        sentinel_seen = False
        while True:
            try:
                payload = os.read(self.descriptor, 1024 * 1024)
            except BlockingIOError:
                self._assert_fanotify_quiet()
                return sentinel_seen
            except OSError:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                ) from None
            if not payload:
                return
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < self._EVENT.size:
                    raise S12ControlError(
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                    )
                watch, mask, _cookie, name_length = self._EVENT.unpack_from(
                    payload, offset
                )
                offset += self._EVENT.size
                if name_length > len(payload) - offset:
                    raise S12ControlError(
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                    )
                offset += name_length
                normalized = mask & ~self._IN_ISDIR
                if (
                    sentinel_watch is not None
                    and watch == sentinel_watch
                    and name_length == 0
                    and normalized == self._ATTRIB
                ):
                    sentinel_seen = True
                if normalized & self._IN_Q_OVERFLOW or (
                    normalized
                    and not (
                        allow_attributes
                        and (normalized & ~self._ATTRIB) == 0
                    )
                ):
                    raise S12ControlError(
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                    )
            self._assert_fanotify_quiet()

    def accept_release_attributes(self) -> None:
        if self.descriptor is None:
            return
        self._assert_events(allow_attributes=True)
        if self.sentinel_path is None or self.sentinel_watch is None:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")
        try:
            mode = stat.S_IMODE(self.sentinel_path.lstat().st_mode)
            os.chmod(self.sentinel_path, mode)
        except OSError:
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
            ) from None
        deadline = time.monotonic() + 1.0
        while True:
            if self._assert_events(
                allow_attributes=True,
                sentinel_watch=self.sentinel_watch,
            ):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                )
            try:
                readable, _, _ = select.select(
                    (self.descriptor,), (), (), remaining
                )
            except OSError:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                ) from None
            if not readable:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                )

    def assert_no_events(self) -> None:
        self._assert_events(allow_attributes=False)

    def _synchronized_inotify_shutdown(self) -> None:
        """Remove every watch behind an IN_IGNORED queue barrier."""

        if self.descriptor is None:
            return
        descriptor = self.descriptor
        pending = set(self.inotify_watches)
        try:
            library = ctypes.CDLL(None, use_errno=True)
            remove = library.inotify_rm_watch
            remove.argtypes = [ctypes.c_int, ctypes.c_int]
            remove.restype = ctypes.c_int
            for watch in sorted(pending):
                if remove(descriptor, watch) < 0:
                    raise OSError(ctypes.get_errno(), "inotify_rm_watch")
            deadline = time.monotonic() + 1.0
            while pending:
                try:
                    payload = os.read(descriptor, 1024 * 1024)
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OSError("inotify shutdown timeout")
                    readable, _, _ = select.select(
                        (descriptor,), (), (), remaining
                    )
                    if not readable:
                        raise OSError("inotify shutdown timeout")
                    continue
                if not payload:
                    raise OSError("inotify shutdown EOF")
                offset = 0
                while offset < len(payload):
                    if len(payload) - offset < self._EVENT.size:
                        raise OSError("short inotify shutdown event")
                    watch, mask, _cookie, name_length = self._EVENT.unpack_from(
                        payload, offset
                    )
                    offset += self._EVENT.size
                    if name_length > len(payload) - offset:
                        raise OSError("invalid inotify shutdown event")
                    name = payload[offset : offset + name_length].rstrip(b"\0")
                    offset += name_length
                    normalized = mask & ~self._IN_ISDIR
                    if (
                        watch in pending
                        and not name
                        and normalized == self._IN_IGNORED
                    ):
                        pending.remove(watch)
                    elif normalized:
                        raise OSError("mutation during inotify shutdown")
            os.close(descriptor)
        except (OSError, ValueError, AttributeError):
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
            ) from None
        self.descriptor = None
        self.inotify_watches.clear()

    def finalize_release(
        self,
        validator: Callable[[], None],
        shutdown_validator: Callable[[], None],
    ) -> None:
        """Validate released state and cross the ordered watch barrier."""

        self.assert_no_events()
        validator()
        self._synchronized_inotify_shutdown()
        shutdown_validator()
        self._assert_fanotify_quiet()
        self.close()

    def _deny_queued_fanotify_events(self, group_descriptor: int) -> bool:
        """Deny permission events that never reached the stopped worker."""

        clean = True
        while True:
            try:
                payload = os.read(group_descriptor, 1024 * 1024)
            except BlockingIOError:
                return clean
            except OSError:
                return False
            if not payload:
                return False
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < self._FAN_EVENT.size:
                    return False
                (
                    event_length,
                    version,
                    _reserved,
                    metadata_length,
                    mask,
                    event_descriptor,
                    _pid,
                ) = self._FAN_EVENT.unpack_from(payload, offset)
                if (
                    version != self._FANOTIFY_METADATA_VERSION
                    or event_length < metadata_length
                    or metadata_length < self._FAN_EVENT.size
                    or event_length > len(payload) - offset
                ):
                    if event_descriptor >= 0:
                        try:
                            os.close(event_descriptor)
                        except OSError:
                            pass
                    return False
                offset += event_length
                if (
                    event_descriptor < 0
                    or mask & self._IN_Q_OVERFLOW
                    or not (mask & self._FAN_OPEN_PERM)
                ):
                    if event_descriptor >= 0:
                        try:
                            self._fanotify_respond(
                                event_descriptor,
                                self._FAN_DENY,
                                group_descriptor=group_descriptor,
                            )
                        except OSError:
                            try:
                                os.close(event_descriptor)
                            except OSError:
                                pass
                    return False
                try:
                    self._fanotify_respond(
                        event_descriptor,
                        self._FAN_DENY,
                        group_descriptor=group_descriptor,
                    )
                except OSError:
                    clean = False
                    try:
                        os.close(event_descriptor)
                    except OSError:
                        pass

    def _flush_fanotify_marks(self, group_descriptor: int) -> bool:
        """Atomically prevent new events before draining the permission group."""

        try:
            library = ctypes.CDLL(None, use_errno=True)
            fanotify_mark = library.fanotify_mark
            fanotify_mark.argtypes = [
                ctypes.c_int,
                ctypes.c_uint,
                ctypes.c_uint64,
                ctypes.c_int,
                ctypes.c_char_p,
            ]
            fanotify_mark.restype = ctypes.c_int
            return (
                fanotify_mark(
                    group_descriptor,
                    self._FAN_MARK_FLUSH,
                    0,
                    -100,
                    None,
                )
                == 0
            )
        except (OSError, ValueError, AttributeError):
            return False

    def close(self) -> None:
        self.fanotify_stop.set()
        worker_stopped = True
        if self.fanotify_thread is not None:
            self.fanotify_thread.join(timeout=1.0)
            worker_stopped = not self.fanotify_thread.is_alive()
            self.fanotify_thread = None
        with self.fanotify_lock:
            pending = tuple(self.fanotify_pending)
            self.fanotify_pending.clear()
            fanotify_descriptor = self.fanotify_descriptor
            self.fanotify_descriptor = None
        shutdown_clean = worker_stopped
        if fanotify_descriptor is not None:
            shutdown_clean = (
                self._flush_fanotify_marks(fanotify_descriptor)
                and shutdown_clean
            )
        for event_descriptor in pending:
            try:
                self._fanotify_respond(
                    event_descriptor,
                    self._FAN_DENY,
                    group_descriptor=fanotify_descriptor,
                )
            except OSError:
                shutdown_clean = False
                try:
                    os.close(event_descriptor)
                except OSError:
                    pass
        if fanotify_descriptor is not None:
            if worker_stopped:
                shutdown_clean = (
                    self._deny_queued_fanotify_events(fanotify_descriptor)
                    and shutdown_clean
                )
            try:
                os.close(fanotify_descriptor)
            except OSError:
                shutdown_clean = False
        if self.descriptor is not None:
            try:
                os.close(self.descriptor)
            finally:
                self.descriptor = None
                self.inotify_watches.clear()
        if not shutdown_clean:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_BARRIER_RED")


def _current_process_ancestry() -> set[str]:
    ancestry = {str(os.getpid())}
    current = os.getpid()
    proc = Path("/proc")
    while current > 1:
        try:
            payload = (proc / str(current) / "stat").read_text(encoding="ascii")
            _, separator, remainder = payload.rpartition(")")
            fields = remainder.strip().split()
            if not separator or len(fields) < 2:
                break
            current = int(fields[1])
        except (OSError, UnicodeError, ValueError):
            break
        ancestry.add(str(current))
    return ancestry


def _process_state_and_start_time(process: Path) -> tuple[str, int]:
    payload = (process / "stat").read_text(encoding="ascii")
    _, separator, remainder = payload.rpartition(")")
    fields = remainder.strip().split()
    if not separator or len(fields) < 20:
        raise OSError("invalid process stat")
    return fields[0], int(fields[19])


_PTRACE_DETACH = 17
_PTRACE_SEIZE = 0x4206
_PTRACE_INTERRUPT = 0x4207
_PTRACE_EVENT_STOP = 128
_WAIT_WALL = 0x40000000


def _ptrace(request: int, thread_id: int, signal_number: int = 0) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    operation = library.ptrace
    operation.argtypes = (
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    operation.restype = ctypes.c_long
    ctypes.set_errno(0)
    if (
        operation(
            request,
            thread_id,
            None,
            ctypes.c_void_p(signal_number),
        )
        == -1
    ):
        error = ctypes.get_errno()
        if error == errno.ESRCH:
            raise ProcessLookupError(error, os.strerror(error))
        raise OSError(error, os.strerror(error))


def _wait_ptrace_stop(thread_id: int) -> int:
    try:
        waited, status = os.waitpid(thread_id, _WAIT_WALL)
    except ChildProcessError:
        raise ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH)) from None
    if waited != thread_id or not os.WIFSTOPPED(status):
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
    event = status >> 16
    if event == _PTRACE_EVENT_STOP:
        return 0
    if event == 0:
        return os.WSTOPSIG(status)
    raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")


def _process_threads(pid: int) -> dict[int, int]:
    task_root = Path("/proc") / str(pid) / "task"
    try:
        tasks = tuple(task_root.iterdir())
    except FileNotFoundError:
        return {}
    threads: dict[int, int] = {}
    for task in tasks:
        if not task.name.isdigit():
            continue
        try:
            _state, start_time = _process_state_and_start_time(task)
        except FileNotFoundError:
            continue
        threads[int(task.name)] = start_time
    return threads


def _guarded_handle_processes(
    paths: Sequence[Path], roots: Sequence[Path]
) -> dict[int, tuple[str, int]]:
    """Return every other process able to reach guarded inodes."""

    proc = Path("/proc")
    if not proc.is_dir():
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
    try:
        protected: set[tuple[int, int]] = set()
        present_paths = 0
        for path in set(paths):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                # A journaled pre-checkout path may have been deleted by the
                # completed checkout. Release validation separately proves
                # that an absent recorded path is obsolete, so it has no inode
                # whose retained handles could be quiesced here.
                continue
            present_paths += 1
            if path.is_symlink() or not (
                stat.S_ISDIR(metadata.st_mode)
                or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
            ):
                raise OSError
            protected.add((metadata.st_dev, metadata.st_ino))
        if len(protected) != present_paths:
            raise OSError
        canonical_roots = tuple(root.resolve(strict=True) for root in roots)
    except OSError:
        raise S12ControlError(
            "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
        ) from None
    controller_pid = str(os.getpid())
    holders: dict[int, tuple[str, int]] = {}
    for process in proc.iterdir():
        if not process.name.isdigit() or process.name == controller_pid:
            continue
        try:
            links: list[Path] = [process / "cwd"]
            links.extend((process / "fd").iterdir())
            matched = False
            for link in links:
                try:
                    metadata = link.stat()
                except FileNotFoundError:
                    continue
                if (metadata.st_dev, metadata.st_ino) in protected:
                    matched = True
                    break
                if stat.S_ISDIR(metadata.st_mode):
                    try:
                        target = link.resolve(strict=True)
                    except FileNotFoundError:
                        # An unlinked directory fd must not hide a later
                        # guarded fd owned by the same process.
                        continue
                    if any(
                        target == root or root in target.parents
                        for root in canonical_roots
                    ):
                        matched = True
                        break
            if matched:
                holders[int(process.name)] = _process_state_and_start_time(
                    process
                )
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError):
            if os.geteuid() == 0:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                ) from None
    return holders


class _GuardedHandleQuiescence:
    """Ptrace-stop retained handle owners with crash-safe kernel cleanup."""

    def __init__(self, paths: Sequence[Path], roots: Sequence[Path]):
        self.paths = tuple(paths)
        self.roots = tuple(roots)
        self.processes: dict[int, tuple[int, int]] = {}
        self.threads: dict[int, tuple[int, int, int | None]] = {}

    def acquire(self) -> None:
        if os.geteuid() != 0:
            return
        try:
            for _round in range(8):
                holders = _guarded_handle_processes(self.paths, self.roots)
                added = False
                for pid in sorted(holders):
                    state, start_time = holders[pid]
                    process_record = self.processes.get(pid)
                    if process_record is None:
                        if state in {"T", "t"}:
                            raise OSError
                        try:
                            descriptor = os.pidfd_open(pid, 0)
                        except ProcessLookupError:
                            continue
                        try:
                            current_state, current_start = (
                                _process_state_and_start_time(
                                    Path("/proc") / str(pid)
                                )
                            )
                        except (OSError, UnicodeError, ValueError):
                            os.close(descriptor)
                            raise
                        if (
                            current_start != start_time
                            or current_state in {"T", "t"}
                        ):
                            os.close(descriptor)
                            raise OSError
                        self.processes[pid] = (start_time, descriptor)
                    elif process_record[0] != start_time:
                        raise OSError
                    for thread_id, thread_start in sorted(
                        _process_threads(pid).items()
                    ):
                        existing = self.threads.get(thread_id)
                        if existing is not None:
                            if existing[:2] != (pid, thread_start):
                                raise OSError
                            continue
                        try:
                            # Zero options deliberately exclude EXITKILL:
                            # tracer death auto-detaches and restarts tracees.
                            _ptrace(_PTRACE_SEIZE, thread_id)
                        except ProcessLookupError:
                            continue
                        self.threads[thread_id] = (
                            pid,
                            thread_start,
                            None,
                        )
                        try:
                            _ptrace(_PTRACE_INTERRUPT, thread_id)
                            detach_signal = _wait_ptrace_stop(thread_id)
                        except ProcessLookupError:
                            del self.threads[thread_id]
                            continue
                        self.threads[thread_id] = (
                            pid,
                            thread_start,
                            detach_signal,
                        )
                        added = True
                if not added:
                    self.assert_quiesced()
                    return
        except (OSError, AttributeError, UnicodeError, ValueError):
            raise S12ControlError(
                "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
            ) from None
        raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")

    def assert_quiesced(self) -> None:
        if os.geteuid() != 0:
            return
        for pid, (start_time, _descriptor) in tuple(self.processes.items()):
            try:
                _state, current_start = _process_state_and_start_time(
                    Path("/proc") / str(pid)
                )
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError, ValueError):
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                ) from None
            if current_start != start_time:
                raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        for thread_id, (
            pid,
            start_time,
            detach_signal,
        ) in tuple(self.threads.items()):
            try:
                state, current_start = _process_state_and_start_time(
                    Path("/proc")
                    / str(pid)
                    / "task"
                    / str(thread_id)
                )
            except FileNotFoundError:
                del self.threads[thread_id]
                continue
            except (OSError, UnicodeError, ValueError):
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                ) from None
            if (
                current_start != start_time
                or detach_signal is None
                or state not in {"T", "t"}
            ):
                raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")
        holders = _guarded_handle_processes(self.paths, self.roots)
        for pid, (_state, start_time) in holders.items():
            process_record = self.processes.get(pid)
            if process_record is None or process_record[0] != start_time:
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                )
            if set(_process_threads(pid)) - set(self.threads):
                raise S12ControlError(
                    "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                )

    def close(self) -> None:
        failed = False
        for thread_id, (
            _pid,
            _start_time,
            detach_signal,
        ) in reversed(tuple(self.threads.items())):
            try:
                if detach_signal is None:
                    _ptrace(_PTRACE_INTERRUPT, thread_id)
                    detach_signal = _wait_ptrace_stop(thread_id)
                _ptrace(_PTRACE_DETACH, thread_id, detach_signal)
            except ProcessLookupError:
                continue
            except (OSError, AttributeError, S12ControlError):
                failed = True
        self.threads.clear()
        for _pid, (_start_time, descriptor) in self.processes.items():
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        self.processes.clear()
        if failed:
            raise S12ControlError("S12_1_RECOVERY_WORKTREE_HANDLE_RED")


def _active_exact_directory_handle_count(directory: Path) -> int:
    """Count non-controller processes retaining an exact directory handle."""

    proc = Path("/proc")
    if not proc.is_dir():
        raise S12ControlError("S12_1_RECOVERY_GIT_PROCESS_RED")
    excluded = _current_process_ancestry()
    count = 0
    for process in proc.iterdir():
        if not process.name.isdigit() or process.name in excluded:
            continue
        links: list[Path] = [process / "cwd"]
        try:
            links.extend((process / "fd").iterdir())
            if any(
                link.resolve(strict=True) == directory
                for link in links
                if link.exists()
            ):
                count += 1
        except FileNotFoundError:
            continue
        except OSError:
            count += 1
    return count


def _validate_recovery_guard(path: Path) -> None:
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 0 if os.geteuid() == 0 else os.getegid()
    try:
        metadata = path.lstat()
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _validate_recovery_git_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in _git_owner_uids()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not (path / "HEAD").is_file()
        or (path / "HEAD").is_symlink()
        or not (path / "objects").is_dir()
        or (path / "objects").is_symlink()
        or not (path / "refs").is_dir()
        or (path / "refs").is_symlink()
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _is_recovery_guard(path: Path) -> bool:
    try:
        _validate_recovery_guard(path)
    except S12ControlError:
        return False
    return True


def _is_recovery_git_directory(path: Path) -> bool:
    try:
        _validate_recovery_git_directory(path)
    except S12ControlError:
        return False
    return True


def _is_canonical_git_directory(path: Path) -> bool:
    """Recognize pre-lock Git metadata; exact baseline validation follows."""

    try:
        metadata = path.lstat()
        return (
            not path.is_symlink()
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid in _git_owner_uids()
            and (path / "HEAD").is_file()
            and not (path / "HEAD").is_symlink()
            and (path / "objects").is_dir()
            and not (path / "objects").is_symlink()
            and (path / "refs").is_dir()
            and not (path / "refs").is_symlink()
        )
    except (OSError, S12ControlError):
        return False


def _atomic_exchange(first: Path, second: Path) -> None:
    if first.parent != second.parent:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    library = ctypes.CDLL(None, use_errno=True)
    first_bytes = os.fsencode(first)
    second_bytes = os.fsencode(second)
    if sys.platform == "darwin" and hasattr(library, "renamex_np"):
        operation = library.renamex_np
        operation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(first_bytes, second_bytes, 0x00000002)  # RENAME_SWAP
    elif hasattr(library, "renameat2"):
        operation = library.renameat2
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        result = operation(-100, first_bytes, -100, second_bytes, 0x00000002)
    else:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_UNSUPPORTED_RED")
    if result != 0:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _create_recovery_guard(path: Path) -> None:
    try:
        path.mkdir(mode=0o000)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        os.chmod(path, 0o000)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    _fsync_directory(path.parent)
    _validate_recovery_guard(path)


def _recovery_git_path(root: Path) -> Path:
    return root / RECOVERY_GIT_DIRECTORY


def _validate_root_git_contract(git_directory: Path) -> None:
    try:
        git_metadata = git_directory.lstat()
        objects = git_directory / "objects"
        objects_metadata = objects.lstat()
        if (
            git_directory.is_symlink()
            or not stat.S_ISDIR(git_metadata.st_mode)
            or objects.is_symlink()
            or not stat.S_ISDIR(objects_metadata.st_mode)
        ):
            raise OSError
        pending = [git_directory]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise OSError
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
                    elif (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                    ):
                        raise OSError
        for directory in (objects / "info", objects / "pack"):
            if directory.exists() or directory.is_symlink():
                metadata = directory.lstat()
                if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise OSError
        for forbidden in (
            git_directory / "commondir",
            objects / "info" / "alternates",
            objects / "info" / "http-alternates",
        ):
            if forbidden.exists() or forbidden.is_symlink():
                raise OSError
    except OSError:
        raise S12ControlError("S12_1_ROOT_GIT_LAYOUT_RED") from None
    config_names: list[str] = []
    for name, required in (("config", True), ("config.worktree", False)):
        config = git_directory / name
        if not config.exists() and not config.is_symlink() and not required:
            continue
        try:
            metadata = config.lstat()
            if (
                config.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not 1 <= metadata.st_size <= 131072
            ):
                raise OSError
        except OSError:
            raise S12ControlError("S12_1_ROOT_GIT_CONFIG_RED") from None
        completed = _run(
            [
                "/usr/bin/env",
                "-i",
                "HOME=/",
                "PATH=/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "/usr/bin/git",
                "config",
                "--no-includes",
                "--file",
                str(config),
                "--null",
                "--name-only",
                "--list",
            ]
        )
        config_names.extend(item for item in completed.stdout.split("\0") if item)
    if any(
        not any(pattern.fullmatch(name) for pattern in ALLOWED_LOCAL_GIT_CONFIG)
        for name in config_names
    ):
        raise S12ControlError("S12_1_ROOT_GIT_CONFIG_RED")
    hooks = git_directory / "hooks"
    try:
        if hooks.is_symlink() or (hooks.exists() and not hooks.is_dir()):
            raise OSError
        if hooks.exists():
            for entry in hooks.iterdir():
                metadata = entry.lstat()
                if (
                    entry.is_symlink()
                    or not entry.name.endswith(".sample")
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size > 131072
                ):
                    raise OSError
    except OSError:
        raise S12ControlError("S12_1_ROOT_GIT_HOOK_RED") from None


def _recorded_path_metadata(record: dict[str, Any], prefix: str) -> tuple[int, int, int]:
    uid = record.get(f"{prefix}_uid")
    gid = record.get(f"{prefix}_gid")
    mode = record.get(f"{prefix}_mode")
    if (
        type(uid) is not int
        or type(gid) is not int
        or not isinstance(mode, str)
        or re.fullmatch(r"[0-7]{4}", mode) is None
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    return uid, gid, int(mode, 8)


def _barrier_repository_record(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    _recorded_path_metadata(record, "root")
    _recorded_path_metadata(record, "git")
    root_xattr_fingerprint = record.get("root_xattr_fingerprint")
    if (
        not isinstance(root_xattr_fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", root_xattr_fingerprint) is None
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return {
        "root": str(root),
        **{
            key: record[key]
            for key in (
                "root_uid", "root_gid", "root_mode",
                "git_uid", "git_gid", "git_mode",
            )
        },
        "root_xattr_fingerprint": root_xattr_fingerprint,
    }


def _recorded_parent_metadata(
    record: dict[str, Any], *, require_xattr: bool = True
) -> tuple[int, int, int]:
    uid = record.get("uid")
    gid = record.get("gid")
    mode = record.get("mode")
    xattr_fingerprint = record.get("xattr_fingerprint")
    if (
        record.get("path") != str(DEPLOYMENT_LOCK_ROOT)
        or type(uid) is not int
        or type(gid) is not int
        or not isinstance(mode, str)
        or re.fullmatch(r"[0-7]{4}", mode) is None
        or (
            xattr_fingerprint is not None
            and (
                not isinstance(xattr_fingerprint, str)
                or re.fullmatch(r"[0-9a-f]{64}", xattr_fingerprint) is None
            )
        )
        or (require_xattr and xattr_fingerprint is None)
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return uid, gid, int(mode, 8)


def _repository_parent_xattr_fingerprint() -> str:
    try:
        return _release_xattr_fingerprint((DEPLOYMENT_LOCK_ROOT,))
    except S12ControlError:
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _assert_repository_parent_xattrs(record: dict[str, Any]) -> None:
    _recorded_parent_metadata(record)
    if _repository_parent_xattr_fingerprint() != record["xattr_fingerprint"]:
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED")


def _repository_root_xattr_fingerprint(root: Path) -> str:
    try:
        return _release_xattr_fingerprint((root,))
    except S12ControlError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


def _assert_repository_root_xattrs(
    root: Path, record: dict[str, Any]
) -> None:
    fingerprint = record.get("root_xattr_fingerprint")
    if (
        not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        or _repository_root_xattr_fingerprint(root) != fingerprint
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _assert_legacy_path_xattrs_safe(path: Path, safe_code: str) -> None:
    """Permit a V1 upgrade only for structurally valid POSIX ACL xattrs."""

    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        if sys.platform == "linux":
            raise S12ControlError(safe_code)
        return
    try:
        metadata = path.lstat()
        names = sorted(
            os.listxattr(path, follow_symlinks=False),
            key=os.fsencode,
        )
        allowed_names = {"system.posix_acl_access"}
        if stat.S_ISDIR(metadata.st_mode):
            allowed_names.add("system.posix_acl_default")
        if any(name not in allowed_names for name in names):
            raise OSError
        for name in names:
            value = os.getxattr(
                path,
                name,
                follow_symlinks=False,
            )
            acl_header = struct.Struct("<I")
            acl_entry = struct.Struct("<HHI")
            if (
                len(value) < acl_header.size
                or acl_header.unpack_from(value)[0] != 2
                or (len(value) - acl_header.size) % acl_entry.size
            ):
                raise OSError
            entries = [
                acl_entry.unpack_from(value, offset)
                for offset in range(
                    acl_header.size, len(value), acl_entry.size
                )
            ]
            named_entries = [
                (tag, permissions, identifier)
                for tag, permissions, identifier in entries
                if tag in {0x02, 0x08}
            ]
            user_entries = [entry for entry in entries if entry[0] == 0x02]
            group_entries = [entry for entry in entries if entry[0] == 0x08]
            canonical_entries = (
                [entry for entry in entries if entry[0] == 0x01]
                + sorted(user_entries, key=lambda entry: entry[2])
                + [entry for entry in entries if entry[0] == 0x04]
                + sorted(group_entries, key=lambda entry: entry[2])
                + [entry for entry in entries if entry[0] == 0x10]
                + [entry for entry in entries if entry[0] == 0x20]
            )
            if (
                any(
                    tag not in {0x01, 0x02, 0x04, 0x08, 0x10, 0x20}
                    or permissions & ~0o7
                    for tag, permissions, _identifier in entries
                )
                or sum(tag == 0x01 for tag, *_rest in entries) != 1
                or sum(tag == 0x04 for tag, *_rest in entries) != 1
                or sum(tag == 0x20 for tag, *_rest in entries) != 1
                or sum(tag == 0x10 for tag, *_rest in entries)
                not in ({1} if named_entries else {0, 1})
                or any(
                    identifier != 0xFFFFFFFF
                    for tag, _permissions, identifier in entries
                    if tag in {0x01, 0x04, 0x10, 0x20}
                )
                or any(
                    identifier == 0xFFFFFFFF
                    for _tag, _permissions, identifier in named_entries
                )
                or len({(tag, identifier) for tag, _, identifier in named_entries})
                != len(named_entries)
                or entries != canonical_entries
            ):
                raise OSError
        _stable_xattr_payload(
            path,
            metadata,
            normalize_posix_acl_mode=True,
        )
    except (OSError, TypeError, ValueError):
        raise S12ControlError(safe_code) from None


def _assert_legacy_repository_parent_xattrs_safe() -> None:
    _assert_legacy_path_xattrs_safe(
        DEPLOYMENT_LOCK_ROOT, "S12_1_REPOSITORY_PARENT_RED"
    )


def _metadata_barrier_mode(mode: int) -> int:
    """Remove namespace mutation while retaining every prior traversal class."""

    restricted = mode & ~0o222
    if restricted & 0o050 != 0o050:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    return restricted


def _write_barrier_journal(
    records: dict[Path, dict[str, Any]], parent_record: dict[str, Any]
) -> dict[Path, dict[Path, dict[str, Any]]]:
    if _barrier_journal_present():
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    if set(records) != {APPLICATION_ROOT, CONTROL_ROOT}:
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    _recorded_parent_metadata(parent_record)
    _assert_repository_parent_xattrs(parent_record)
    roots = (APPLICATION_ROOT, CONTROL_ROOT)
    for root in roots:
        records[root]["root_xattr_fingerprint"] = (
            _repository_root_xattr_fingerprint(root)
        )
    worktree_barrier = _capture_worktree_write_barrier(roots, records)
    _atomic_json(
        BARRIER_MARKER,
        {
            "schema": BARRIER_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "repositories": {
                "application": _barrier_repository_record(
                    APPLICATION_ROOT, records[APPLICATION_ROOT]
                ),
                "control": _barrier_repository_record(
                    CONTROL_ROOT, records[CONTROL_ROOT]
                ),
            },
            "repository_parent": parent_record,
            "worktree_write_barrier": _worktree_barrier_payload(
                roots, worktree_barrier
            ),
        },
    )
    _assert_repository_parent_xattrs(parent_record)
    for root in roots:
        _assert_repository_root_xattrs(root, records[root])
    return worktree_barrier


def _load_barrier_journal() -> tuple[
    dict[Path, dict[str, Any]],
    dict[str, Any],
    dict[Path, dict[Path, dict[str, Any]]] | None,
    str,
]:
    journal = _private_json(
        BARRIER_MARKER, "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
    )
    repositories = journal.get("repositories")
    parent_record = journal.get("repository_parent")
    if (
        journal.get("schema")
        not in {
            BARRIER_SCHEMA,
            XATTR_BARRIER_SCHEMA,
            LEGACY_BARRIER_SCHEMA,
        }
        or not isinstance(journal.get("created_at"), str)
        or not journal["created_at"]
        or not isinstance(repositories, dict)
        or set(repositories) != {"application", "control"}
        or not isinstance(parent_record, dict)
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    journal_schema = journal["schema"]
    expected_parent_keys = {"path", "uid", "gid", "mode"}
    if journal_schema in {BARRIER_SCHEMA, XATTR_BARRIER_SCHEMA}:
        expected_parent_keys.add("xattr_fingerprint")
    if set(parent_record) != expected_parent_keys:
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    _recorded_parent_metadata(
        parent_record,
        require_xattr=journal_schema != LEGACY_BARRIER_SCHEMA,
    )
    if (
        journal_schema == LEGACY_BARRIER_SCHEMA
        and "xattr_fingerprint" in parent_record
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    records: dict[Path, dict[str, Any]] = {}
    for key, root in (
        ("application", APPLICATION_ROOT),
        ("control", CONTROL_ROOT),
    ):
        item = repositories.get(key)
        if not isinstance(item, dict) or item.get("root") != str(root):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        record = {name: value for name, value in item.items() if name != "root"}
        expected_record_keys = {
            "root_uid", "root_gid", "root_mode",
            "git_uid", "git_gid", "git_mode",
        }
        if journal_schema == BARRIER_SCHEMA:
            expected_record_keys.add("root_xattr_fingerprint")
        if set(record) != expected_record_keys:
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        _recorded_path_metadata(record, "root")
        _recorded_path_metadata(record, "git")
        if journal_schema == BARRIER_SCHEMA:
            fingerprint = record.get("root_xattr_fingerprint")
            if (
                not isinstance(fingerprint, str)
                or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
            ):
                raise S12ControlError(
                    "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
                )
        records[root] = record
    raw_worktree_barrier = journal.get("worktree_write_barrier")
    worktree_barrier = (
        None
        if raw_worktree_barrier is None
        else _parse_worktree_barrier_payload(
            raw_worktree_barrier,
            (APPLICATION_ROOT, CONTROL_ROOT),
            require_xattr=journal_schema != LEGACY_BARRIER_SCHEMA,
        )
    )
    if set(journal) not in (
        {"schema", "created_at", "repositories", "repository_parent"},
        {
            "schema",
            "created_at",
            "repositories",
            "repository_parent",
            "worktree_write_barrier",
        },
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return records, parent_record, worktree_barrier, journal_schema


def _ensure_barrier_journal(
    records: dict[Path, dict[str, Any]], parent_record: dict[str, Any]
) -> dict[Path, dict[Path, dict[str, Any]]]:
    _recorded_parent_metadata(parent_record, require_xattr=False)
    if BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
        recorded_repositories, recorded_parent, worktree_barrier, schema = (
            _load_barrier_journal()
        )
        recorded_parent_base = {
            key: recorded_parent[key] for key in ("path", "uid", "gid", "mode")
        }
        parent_base = {
            key: parent_record[key] for key in ("path", "uid", "gid", "mode")
        }
        repository_fields = (
            "root_uid", "root_gid", "root_mode",
            "git_uid", "git_gid", "git_mode",
        )
        recorded_repository_base = {
            root: {key: record[key] for key in repository_fields}
            for root, record in recorded_repositories.items()
        }
        repository_base = {
            root: {key: record[key] for key in repository_fields}
            for root, record in records.items()
        }
        if (
            recorded_repository_base != repository_base
            or recorded_parent_base != parent_base
        ):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        journal_changed = False
        if schema == LEGACY_BARRIER_SCHEMA:
            _assert_legacy_repository_parent_xattrs_safe()
            recorded_parent["xattr_fingerprint"] = (
                _repository_parent_xattr_fingerprint()
            )
            if worktree_barrier is not None:
                _upgrade_legacy_worktree_xattr_records(worktree_barrier)
            journal_changed = True
        elif (
            parent_record.get("xattr_fingerprint") is not None
            and parent_record["xattr_fingerprint"]
            != recorded_parent["xattr_fingerprint"]
        ):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        parent_record["xattr_fingerprint"] = recorded_parent[
            "xattr_fingerprint"
        ]
        _assert_repository_parent_xattrs(parent_record)
        for root in (APPLICATION_ROOT, CONTROL_ROOT):
            recorded = recorded_repositories[root]
            if schema != BARRIER_SCHEMA:
                _assert_legacy_path_xattrs_safe(
                    root, "S12_1_RECOVERY_GIT_BARRIER_RED"
                )
                recorded["root_xattr_fingerprint"] = (
                    _repository_root_xattr_fingerprint(root)
                )
                journal_changed = True
            elif (
                records[root].get("root_xattr_fingerprint") is not None
                and records[root]["root_xattr_fingerprint"]
                != recorded["root_xattr_fingerprint"]
            ):
                raise S12ControlError(
                    "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
                )
            records[root]["root_xattr_fingerprint"] = recorded[
                "root_xattr_fingerprint"
            ]
            _assert_repository_root_xattrs(root, records[root])
        if worktree_barrier is None:
            # A legacy R3 orphan never mutated Worktree children. Upgrade its
            # private journal durably before installing the new write barrier.
            worktree_barrier = _capture_worktree_write_barrier(
                (APPLICATION_ROOT, CONTROL_ROOT), records
            )
            journal_changed = True
        if not journal_changed:
            return worktree_barrier
        journal = _private_json(
            BARRIER_MARKER, "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
        )
        journal["schema"] = BARRIER_SCHEMA
        journal["repositories"] = {
            "application": _barrier_repository_record(
                APPLICATION_ROOT, recorded_repositories[APPLICATION_ROOT]
            ),
            "control": _barrier_repository_record(
                CONTROL_ROOT, recorded_repositories[CONTROL_ROOT]
            ),
        }
        journal["repository_parent"] = recorded_parent
        journal["worktree_write_barrier"] = _worktree_barrier_payload(
            (APPLICATION_ROOT, CONTROL_ROOT), worktree_barrier
        )
        _atomic_json(BARRIER_MARKER, journal)
        _assert_repository_parent_xattrs(parent_record)
        for root in (APPLICATION_ROOT, CONTROL_ROOT):
            _assert_repository_root_xattrs(root, records[root])
        return worktree_barrier
    if parent_record.get("xattr_fingerprint") is None:
        _assert_legacy_repository_parent_xattrs_safe()
        parent_record["xattr_fingerprint"] = (
            _repository_parent_xattr_fingerprint()
        )
    return _write_barrier_journal(records, parent_record)


def _lock_repository_parent(record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    expected_uid, expected_gid, expected_mode = _recorded_parent_metadata(record)
    restricted_mode = _metadata_barrier_mode(expected_mode)
    try:
        _assert_repository_parent_xattrs(record)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        original = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == expected_mode
        )
        locked = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        restricted = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_locked = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        hard_chowned = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_restricted = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        owner_hard_restricted = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (
                original
                or locked
                or restricted
                or hard_locked
                or hard_chowned
                or hard_restricted
                or owner_hard_restricted
            )
        ):
            raise OSError
        if original:
            os.chmod(DEPLOYMENT_LOCK_ROOT, restricted_mode)
        _assert_post_chown_acl_preserves_access(
            DEPLOYMENT_LOCK_ROOT,
            expected_uid,
            (restricted_mode & 0o050) >> 3,
            (restricted_mode & 0o050) >> 3,
            restricted_mode & 0o005,
            "S12_1_REPOSITORY_PARENT_RED",
        )
        os.chown(DEPLOYMENT_LOCK_ROOT, 0, expected_gid)
        os.chmod(DEPLOYMENT_LOCK_ROOT, restricted_mode)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != restricted_mode
        ):
            raise OSError
        _assert_repository_parent_xattrs(record)
        _fsync_directory(DEPLOYMENT_LOCK_ROOT.parent)
    except (OSError, S12ControlError):
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _hard_lock_repository_parent(record: dict[str, Any]) -> None:
    """Remove every non-root traversal path through the shared parent."""

    if os.geteuid() != 0:
        return
    _expected_uid, expected_gid, expected_mode = _recorded_parent_metadata(
        record
    )
    restricted_mode = _metadata_barrier_mode(expected_mode)
    try:
        _assert_repository_parent_xattrs(record)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        soft_locked = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_chowned = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_restricted = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        hard_locked = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (
                soft_locked
                or hard_chowned
                or hard_restricted
                or hard_locked
            )
        ):
            raise OSError
        os.chown(DEPLOYMENT_LOCK_ROOT, 0, 0)
        os.chmod(DEPLOYMENT_LOCK_ROOT, 0o500)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o500
        ):
            raise OSError
        _assert_repository_parent_xattrs(record)
        _fsync_directory(DEPLOYMENT_LOCK_ROOT.parent)
    except (OSError, S12ControlError):
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _assert_hard_locked_repository_parent(record: dict[str, Any]) -> None:
    """Prove namespace exclusion before fanotify marks are flushed."""

    if os.geteuid() != 0:
        return
    _recorded_parent_metadata(record)
    try:
        _assert_repository_parent_xattrs(record)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o500
        ):
            raise OSError
    except (OSError, S12ControlError):
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _restore_repository_parent(record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    uid, gid, mode = _recorded_parent_metadata(record)
    restricted_mode = _metadata_barrier_mode(mode)
    try:
        _assert_repository_parent_xattrs(record)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        locked = (
            metadata.st_uid == 0
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        restricted = (
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_locked = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        hard_chowned = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        hard_restricted = (
            metadata.st_uid == 0
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        owner_hard_restricted = (
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (
                locked
                or restricted
                or hard_locked
                or hard_chowned
                or hard_restricted
                or owner_hard_restricted
            )
        ):
            raise OSError
        os.chown(DEPLOYMENT_LOCK_ROOT, uid, gid)
        os.chmod(DEPLOYMENT_LOCK_ROOT, mode)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise OSError
        _assert_repository_parent_xattrs(record)
        _fsync_directory(DEPLOYMENT_LOCK_ROOT.parent)
    except (OSError, S12ControlError):
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _validate_repository_worktree_contract(
    root: Path,
    record: dict[str, Any],
    *,
    allow_journaled_transition: bool = False,
) -> None:
    """Reject worktree state that recursive post-barrier ownership cannot preserve."""

    root_uid, root_gid, _ = _recorded_path_metadata(record, "root")
    git_uid, git_gid, _ = _recorded_path_metadata(record, "git")

    def validate_tree(
        tree: Path, expected_uid: int, expected_gid: int, excluded_top: set[str]
    ) -> None:
        pending = [tree]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if directory == tree and entry.name in excluded_top:
                        continue
                    metadata = entry.stat(follow_symlinks=False)
                    allowed_owners = {(expected_uid, expected_gid)}
                    if allow_journaled_transition:
                        allowed_owners.update({(0, 0), (0, expected_gid)})
                    if (
                        (metadata.st_uid, metadata.st_gid) not in allowed_owners
                        or (
                            stat.S_ISREG(metadata.st_mode)
                            and metadata.st_nlink != 1
                        )
                    ):
                        raise OSError
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))

    git_directory = root / ".git"
    try:
        root_metadata = root.lstat()
        git_metadata = git_directory.lstat()
        _, _, root_mode = _recorded_path_metadata(record, "root")
        _, _, git_mode = _recorded_path_metadata(record, "git")
        root_states = {(root_uid, root_gid, root_mode)}
        git_states = {(git_uid, git_gid, git_mode)}
        if allow_journaled_transition:
            root_states.update(
                {
                    (root_uid, root_gid, 0o500),
                    (0, 0, 0o500),
                    (0, root_gid, 0o500),
                    (root_uid, root_gid, _metadata_barrier_mode(root_mode)),
                    (0, root_gid, _metadata_barrier_mode(root_mode)),
                }
            )
            git_states.update(
                {
                    (git_uid, git_gid, 0o700),
                    (0, 0, 0o700),
                }
            )
        if (
            root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or (
                root_metadata.st_uid,
                root_metadata.st_gid,
                stat.S_IMODE(root_metadata.st_mode),
            )
            not in root_states
            or git_directory.is_symlink()
            or not stat.S_ISDIR(git_metadata.st_mode)
            or (
                git_metadata.st_uid,
                git_metadata.st_gid,
                stat.S_IMODE(git_metadata.st_mode),
            )
            not in git_states
        ):
            raise OSError
        validate_tree(
            root,
            root_uid,
            root_gid,
            {".git", RECOVERY_GIT_DIRECTORY},
        )
        validate_tree(git_directory, git_uid, git_gid, set())
    except OSError:
        raise S12ControlError("S12_1_WORKTREE_LAYOUT_RED") from None


def _lock_repository_root(root: Path, record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    expected_uid, expected_gid, expected_mode = _recorded_path_metadata(
        record, "root"
    )
    restricted_mode = _metadata_barrier_mode(expected_mode)
    try:
        _assert_repository_root_xattrs(root, record)
        metadata = root.lstat()
        original = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == expected_mode
        )
        locked = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        restricted = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == restricted_mode
        )
        legacy_locked = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        legacy_chowned = (
            metadata.st_uid == 0
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o500
        )
        if (
            root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (
                original
                or locked
                or restricted
                or legacy_locked
                or legacy_chowned
            )
        ):
            raise OSError
        if original:
            os.chmod(root, restricted_mode)
        _assert_repository_root_xattrs(root, record)
        _assert_post_chown_acl_preserves_access(
            root,
            expected_uid,
            (restricted_mode & 0o050) >> 3,
            (restricted_mode & 0o050) >> 3,
            restricted_mode & 0o005,
            "S12_1_RECOVERY_GIT_BARRIER_RED",
        )
        if original or restricted or legacy_locked:
            os.chown(root, 0, expected_gid)
        if original or restricted or legacy_locked or legacy_chowned:
            os.chmod(root, restricted_mode)
        metadata = root.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != restricted_mode
        ):
            raise OSError
        _assert_repository_root_xattrs(root, record)
        _fsync_directory(root.parent)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


def _lock_repository_git_metadata(root: Path, record: dict[str, Any]) -> None:
    """Block new unprivileged Git access without hiding the Worktree."""

    if os.geteuid() != 0:
        return
    git_directory = root / ".git"
    recovery_directory = _recovery_git_path(root)
    if _is_recovery_guard(git_directory) and _is_recovery_git_directory(
        recovery_directory
    ):
        return
    expected_uid, expected_gid, expected_mode = _recorded_path_metadata(
        record, "git"
    )
    try:
        metadata = git_directory.lstat()
        original = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == expected_mode
        )
        locked = (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o700
        )
        restricted = (
            metadata.st_uid == expected_uid
            and metadata.st_gid == expected_gid
            and stat.S_IMODE(metadata.st_mode) == 0o700
        )
        if (
            git_directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (original or locked or restricted)
        ):
            raise OSError
        if original:
            os.chmod(git_directory, 0o700)
        if original or restricted:
            os.chown(git_directory, 0, 0)
            os.chmod(git_directory, 0o700)
        metadata = git_directory.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError
        _fsync_directory(root)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


def _chown_tree(
    root: Path, uid: int, gid: int, excluded_top: set[str] | None = None
) -> None:
    excluded = excluded_top or set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        if Path(current) == root:
            directories[:] = [name for name in directories if name not in excluded]
            files = [name for name in files if name not in excluded]
        for name in directories:
            path = Path(current) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) and (
                metadata.st_uid,
                metadata.st_gid,
            ) != (uid, gid):
                os.chown(path, uid, gid, follow_symlinks=False)
        for name in files:
            path = Path(current) / name
            metadata = path.lstat()
            if (metadata.st_uid, metadata.st_gid) != (uid, gid):
                os.chown(path, uid, gid, follow_symlinks=False)
        if Path(current) != root:
            metadata = Path(current).lstat()
            if (metadata.st_uid, metadata.st_gid) != (uid, gid):
                os.chown(current, uid, gid)
    metadata = root.lstat()
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        os.chown(root, uid, gid)


def _restore_repository_worktree_metadata(
    root: Path, record: dict[str, Any]
) -> None:
    if os.geteuid() != 0:
        return
    root_uid, root_gid, root_mode = _recorded_path_metadata(record, "root")
    try:
        _chown_tree(
            root,
            root_uid,
            root_gid,
            {".git", RECOVERY_GIT_DIRECTORY},
        )
        os.chown(root, root_uid, root_gid)
        os.chmod(root, root_mode)
        _fsync_directory(root.parent)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


def _restore_repository_git_metadata(root: Path, record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    git_uid, git_gid, git_mode = _recorded_path_metadata(record, "git")
    git_directory = root / ".git"
    try:
        _chown_tree(git_directory, git_uid, git_gid)
        os.chown(git_directory, git_uid, git_gid)
        os.chmod(git_directory, git_mode)
        _fsync_directory(root)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


def _restore_repository_path_metadata(root: Path, record: dict[str, Any]) -> None:
    _restore_repository_worktree_metadata(root, record)
    _restore_repository_git_metadata(root, record)


def _fsync_recovery_exchange_parents(root: Path, recovery_dir: Path) -> None:
    _fsync_directory(root)


def _install_repository_recovery_barrier(
    root: Path, record: dict[str, Any]
) -> Path:
    git_dir = root / ".git"
    recovery_dir = _recovery_git_path(root)
    if _is_recovery_guard(git_dir) and _is_recovery_git_directory(recovery_dir):
        if os.geteuid() == 0:
            try:
                os.chmod(recovery_dir, 0o700)
                os.chown(recovery_dir, 0, 0)
            except OSError:
                raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
        return recovery_dir
    if _is_recovery_git_directory(git_dir) and _is_recovery_guard(recovery_dir):
        try:
            recovery_dir.rmdir()
        except OSError:
            raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
        _fsync_recovery_exchange_parents(root, recovery_dir)
    if not _is_recovery_git_directory(git_dir) or (
        recovery_dir.exists() or recovery_dir.is_symlink()
    ):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    _create_recovery_guard(recovery_dir)
    try:
        _atomic_exchange(git_dir, recovery_dir)
    except S12ControlError:
        try:
            recovery_dir.rmdir()
            _fsync_directory(recovery_dir.parent)
        except OSError:
            pass
        raise
    _fsync_recovery_exchange_parents(root, recovery_dir)
    if os.geteuid() == 0:
        try:
            os.chmod(recovery_dir, 0o700)
            os.chown(recovery_dir, 0, 0)
        except OSError:
            raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    _validate_recovery_guard(git_dir)
    _validate_recovery_git_directory(recovery_dir)
    return recovery_dir


def _remove_repository_recovery_barrier(
    root: Path, recovery_dir: Path, record: dict[str, Any]
) -> None:
    git_dir = root / ".git"
    if recovery_dir != _recovery_git_path(root):
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    _validate_recovery_guard(git_dir)
    _validate_recovery_git_directory(recovery_dir)
    _atomic_exchange(git_dir, recovery_dir)
    _fsync_recovery_exchange_parents(root, recovery_dir)
    _validate_recovery_git_directory(git_dir)
    _validate_recovery_guard(recovery_dir)
    try:
        recovery_dir.rmdir()
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None
    _fsync_directory(recovery_dir.parent)


@contextmanager
def _serialized_repository_recovery(
    roots: Sequence[Path] | None = None,
    records: dict[Path, dict[str, Any]] | None = None,
    parent_record: dict[str, Any] | None = None,
    worktree_barrier: dict[Path, dict[Path, dict[str, Any]]] | None = None,
    preserve_on_error: bool = False,
    allow_journaled_transition: bool = False,
):
    selected_roots = tuple(roots or (APPLICATION_ROOT, CONTROL_ROOT))
    metadata_paths = _repository_git_metadata_paths(selected_roots)
    transition_guard = _GitMetadataTransitionGuard(
        tuple(path for path in metadata_paths if not _is_recovery_guard(path))
    )
    tracked_paths = _tracked_worktree_regular_paths(
        selected_roots,
        allow_missing=allow_journaled_transition,
    )
    selected_records: dict[Path, dict[str, Any]] = records or {}
    selected_worktree_barrier = worktree_barrier
    barriers: dict[Path, Path] = {}
    parent_locked = False
    transition_started = False
    completed = False
    try:
        if (
            _competing_control_sync_count() != 0
            or _active_repository_git_count(selected_roots) != 0
            or _active_recovery_git_handle_count(metadata_paths) != 0
            or _active_tracked_worktree_write_handle_count(tracked_paths) != 0
        ):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        if records is None:
            selected_records = {
                root: _repository_path_metadata(root) for root in selected_roots
            }
        if selected_worktree_barrier is None:
            selected_worktree_barrier = _capture_worktree_write_barrier(
                selected_roots, selected_records
            )
        for root in selected_roots:
            if not (
                _is_recovery_guard(root / ".git")
                and _is_recovery_git_directory(_recovery_git_path(root))
            ):
                _validate_repository_worktree_contract(
                    root,
                    selected_records[root],
                    allow_journaled_transition=allow_journaled_transition,
                )
        transition_guard.assert_unchanged()
        if parent_record is not None:
            transition_started = True
            parent_locked = True
            _lock_repository_parent(parent_record)
            if (
                _active_exact_directory_handle_count(DEPLOYMENT_LOCK_ROOT) != 0
                or _active_recovery_git_handle_count(metadata_paths) != 0
                or _active_tracked_worktree_write_handle_count(tracked_paths) != 0
            ):
                raise S12ControlError("S12_1_REPOSITORY_PARENT_ACTIVE_RED")
        for root in selected_roots:
            if not (
                _is_recovery_guard(root / ".git")
                and _is_recovery_git_directory(_recovery_git_path(root))
            ):
                _validate_repository_worktree_contract(
                    root,
                    selected_records[root],
                    allow_journaled_transition=allow_journaled_transition,
                )
        transition_started = True
        for root in selected_roots:
            _lock_repository_root(root, selected_records[root])
        _lock_worktree_write_barrier(
            selected_worktree_barrier,
            allow_missing=allow_journaled_transition,
        )
        for root in selected_roots:
            _lock_repository_git_metadata(root, selected_records[root])
        transition_guard.assert_unchanged()
        metadata_paths = _repository_git_metadata_paths(selected_roots)
        if (
            _active_repository_git_count(selected_roots) != 0
            or _active_recovery_git_handle_count(metadata_paths) != 0
            or _active_tracked_worktree_write_handle_count(tracked_paths) != 0
        ):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        _assert_worktree_write_barrier(
            selected_roots,
            selected_worktree_barrier,
            allow_missing=allow_journaled_transition,
        )
        for root in selected_roots:
            _selected_identity(
                root, _repository_recovery_git_directory(root)
            )
        for root in selected_roots:
            barriers[root] = _install_repository_recovery_barrier(
                root, selected_records[root]
            )
        transition_guard.assert_no_writer_events()
        if (
            _competing_control_sync_count() != 0
            or _active_repository_git_count(selected_roots) != 0
            or _active_recovery_git_handle_count(
                tuple(root / ".git" for root in selected_roots)
                + tuple(barriers.values())
            )
            != 0
            or _active_tracked_worktree_write_handle_count(tracked_paths) != 0
        ):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        transition_guard.assert_no_writer_events()
        transition_guard.assert_quarantined_unchanged(tuple(barriers.values()))
        transition_guard.close()
        for git_directory in barriers.values():
            _validate_root_git_contract(git_directory)
        for root, git_dir in barriers.items():
            _clear_stale_git_locks(root, git_dir)
        yield barriers
        tracked_paths = _tracked_worktree_regular_paths(selected_roots)
        _assert_worktree_write_barrier(
            selected_roots, selected_worktree_barrier
        )
        if _active_tracked_worktree_write_handle_count(tracked_paths) != 0:
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        for root, git_directory in barriers.items():
            _selected_identity(root, git_directory)
        if _active_tracked_worktree_write_handle_count(tracked_paths) != 0:
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        completed = True
    finally:
        transition_guard.close()
        cleanup_failed = False
        if transition_started and not (preserve_on_error and not completed):
            for root, git_dir in reversed(tuple(barriers.items())):
                try:
                    _remove_repository_recovery_barrier(
                        root, git_dir, selected_records[root]
                    )
                except S12ControlError:
                    cleanup_failed = True
            for root in reversed(selected_roots):
                if root in barriers:
                    continue
                try:
                    recovery_dir = _recovery_git_path(root)
                    if _is_recovery_guard(
                        root / ".git"
                    ) and _is_recovery_git_directory(recovery_dir):
                        _remove_repository_recovery_barrier(
                            root, recovery_dir, selected_records[root]
                        )
                except S12ControlError:
                    cleanup_failed = True
            if not cleanup_failed:
                release_guard: _WorktreeReleaseGuard | None = None
                release_quiescence: _GuardedHandleQuiescence | None = None
                try:
                    if completed:
                        _refresh_worktree_barrier_for_release(
                            selected_roots,
                            selected_records,
                            selected_worktree_barrier,
                        )
                        _assert_worktree_write_barrier(
                            selected_roots, selected_worktree_barrier
                        )
                        for root in selected_roots:
                            _selected_identity(root, root / ".git")
                        if (
                            _active_tracked_worktree_write_handle_count(
                                _tracked_worktree_regular_paths(selected_roots)
                            )
                            != 0
                        ):
                            raise S12ControlError(
                                "S12_1_RECOVERY_GIT_ACTIVE_RED"
                            )
                    release_paths = {
                        path
                        for root_entries in selected_worktree_barrier.values()
                        for path in root_entries
                    }
                    release_paths.update(selected_roots)
                    release_paths.update(
                        _repository_git_metadata_directories(selected_roots)
                    )
                    git_release_fingerprint = ""
                    if completed:
                        for root in selected_roots:
                            release_paths.update(
                                _tracked_worktree_barrier_paths(root)
                            )
                        git_release_fingerprint = (
                            _git_metadata_release_fingerprint(selected_roots)
                        )
                    if parent_locked:
                        _hard_lock_repository_parent(parent_record)
                    release_guard = _WorktreeReleaseGuard(
                        selected_roots,
                        tuple(release_paths),
                    )
                    release_xattr_omissions = (
                        _worktree_release_xattr_omissions(
                            selected_worktree_barrier
                        )
                    )
                    release_xattr_fingerprint = _release_xattr_fingerprint(
                        tuple(release_paths),
                        expected_omitted_xattrs=release_xattr_omissions,
                    )
                    release_quiescence = _GuardedHandleQuiescence(
                        tuple(release_paths), selected_roots
                    )
                    release_quiescence.acquire()
                    _restore_worktree_write_barrier(
                        selected_worktree_barrier,
                        selected_records if completed else None,
                    )
                    for root in reversed(selected_roots):
                        _restore_repository_worktree_metadata(
                            root, selected_records[root]
                        )
                    release_guard.accept_release_attributes()
                    if completed:
                        _validate_released_worktree_contract(
                            selected_roots,
                            selected_records,
                            selected_worktree_barrier,
                        )
                        for root in selected_roots:
                            _selected_identity(root, root / ".git")
                        released_paths = _tracked_worktree_regular_paths(
                            selected_roots
                        )
                        if (
                            _active_tracked_worktree_write_handle_count(
                                released_paths
                            )
                            != 0
                        ):
                            raise S12ControlError(
                                "S12_1_RECOVERY_GIT_ACTIVE_RED"
                            )
                        for root in selected_roots:
                            _selected_identity(root, root / ".git")
                    release_guard.assert_no_events()
                    for root in reversed(selected_roots):
                        _restore_repository_git_metadata(
                            root, selected_records[root]
                        )
                    release_guard.accept_release_attributes()

                    def validate_final_release() -> None:
                        release_quiescence.assert_quiesced()
                        if not completed:
                            return
                        _validate_released_worktree_contract(
                            selected_roots,
                            selected_records,
                            selected_worktree_barrier,
                        )
                        for root in selected_roots:
                            _validate_repository_worktree_contract(
                                root, selected_records[root]
                            )
                        if (
                            _git_metadata_release_fingerprint(selected_roots)
                            != git_release_fingerprint
                            or _release_xattr_fingerprint(
                                tuple(release_paths)
                            )
                            != release_xattr_fingerprint
                        ):
                            raise S12ControlError(
                                "S12_1_RECOVERY_GIT_BARRIER_RED"
                            )
                        metadata_paths = tuple(
                            root / ".git" for root in selected_roots
                        )
                        if (
                            _active_repository_git_count(selected_roots) != 0
                            or _active_recovery_git_handle_count(metadata_paths)
                            != 0
                            or _active_tracked_worktree_write_handle_count(
                                _tracked_worktree_regular_paths(selected_roots)
                            )
                            != 0
                        ):
                            raise S12ControlError(
                                "S12_1_RECOVERY_GIT_ACTIVE_RED"
                            )
                        for root in selected_roots:
                            _selected_identity(root, root / ".git")

                    def validate_release_shutdown() -> None:
                        release_quiescence.assert_quiesced()
                        if release_guard.fanotify_descriptor is not None:
                            if not parent_locked or parent_record is None:
                                raise S12ControlError(
                                    "S12_1_REPOSITORY_PARENT_RED"
                                )
                            _assert_hard_locked_repository_parent(parent_record)

                    release_guard.finalize_release(
                        validate_final_release,
                        validate_release_shutdown,
                    )
                    release_guard = None
                    if parent_locked:
                        _restore_repository_parent(parent_record)
                        parent_locked = False
                except S12ControlError:
                    cleanup_failed = True
                    try:
                        if parent_locked:
                            _lock_repository_parent(parent_record)
                        for root in selected_roots:
                            _lock_repository_root(root, selected_records[root])
                        _reseal_released_worktree_contract(
                            selected_roots,
                            selected_records,
                            selected_worktree_barrier,
                            include_current=completed,
                        )
                        for root in selected_roots:
                            _lock_repository_git_metadata(
                                root, selected_records[root]
                            )
                    except S12ControlError:
                        pass
                finally:
                    if release_guard is not None:
                        release_guard.close()
                    if release_quiescence is not None:
                        try:
                            release_quiescence.close()
                        except S12ControlError:
                            cleanup_failed = True
        if cleanup_failed:
            raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")


def _seed_repository_from_bundle(
    root: Path,
    git_arguments,
    bundle: Path,
    record: dict[str, Any],
) -> None:
    expected_digest = record.get("bundle_sha256")
    try:
        metadata = bundle.lstat()
        invalid = (
            not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
            or bundle.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or _sha256(bundle) != expected_digest
        )
    except OSError:
        invalid = True
    if invalid:
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
    for operation in ("verify", "unbundle"):
        try:
            with bundle.open("rb") as input_stream:
                completed = subprocess.run(
                    git_arguments("bundle", operation, "/dev/stdin"),
                    check=False,
                    stdin=input_stream,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=300,
                )
        except (OSError, subprocess.SubprocessError):
            raise S12ControlError("S12_1_BACKUP_BUNDLE_RED") from None
        if completed.returncode != 0:
            raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
    for object_name, object_type in (
        (record.get("commit"), "commit"),
        (record.get("tree"), "tree"),
        (record.get("release_branch_tip"), "commit"),
    ):
        if (
            not isinstance(object_name, str)
            or re.fullmatch(r"[0-9a-f]{40}", object_name) is None
            or _run(
                git_arguments("cat-file", "-e", f"{object_name}^{{{object_type}}}"),
                check=False,
            ).returncode
            != 0
        ):
            raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")
    orig_head = record.get("orig_head")
    if orig_head is not None and (
        not isinstance(orig_head, str)
        or re.fullmatch(r"[0-9a-f]{40}", orig_head) is None
        or _run(
            git_arguments("cat-file", "-e", f"{orig_head}^{{commit}}"),
            check=False,
        ).returncode
        != 0
    ):
        raise S12ControlError("S12_1_BACKUP_BUNDLE_RED")


def _restore_repository(
    root: Path,
    record: dict[str, Any],
    bundle: Path,
    reflog_snapshot: Path,
    git_directory: Path | None = None,
) -> None:
    git_arguments = (
        (lambda *arguments: _recovery_git_arguments(root, git_directory, *arguments))
        if git_directory is not None
        else (lambda *arguments: _git_arguments(root, *arguments))
    )
    git = (
        (lambda *arguments: _recovery_git(root, git_directory, *arguments))
        if git_directory is not None
        else (lambda *arguments: _git(root, *arguments))
    )
    clean_arguments = ["clean", "-f", "-d"]
    if git_directory is not None:
        clean_arguments.extend(["-e", RECOVERY_GIT_DIRECTORY])
    branch = record["branch"]
    commit = record["commit"]
    detached = record["detached"]
    release_branch = record["release_branch"]
    release_branch_tip = record["release_branch_tip"]
    if (
        detached is not (branch is None)
        or (
            branch is not None
            and (not isinstance(branch, str) or branch.startswith("-"))
        )
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    _seed_repository_from_bundle(root, git_arguments, bundle, record)
    _run(git_arguments("checkout", "--force", "--detach", commit))
    _run(git_arguments(*clean_arguments))
    _run(git_arguments("branch", "-f", release_branch, release_branch_tip))
    if branch is not None:
        if branch != release_branch:
            _run(git_arguments("branch", "-f", branch, commit))
        _run(git_arguments("checkout", "--force", branch))
        _run(git_arguments(*clean_arguments))
    managed_refs = record.get("managed_refs", {})
    if not isinstance(managed_refs, dict):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    for reference, target in sorted(managed_refs.items()):
        if reference != f"refs/tags/{FREEZE_TAG}" or (
            target is not None
            and (
                not isinstance(target, str)
                or re.fullmatch(r"[0-9a-f]{40}", target) is None
            )
        ):
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
        if target is None:
            _run(git_arguments("update-ref", "-d", reference))
        else:
            _run(git_arguments("update-ref", reference, target))
    orig_head = record.get("orig_head")
    if orig_head is not None and (
        not isinstance(orig_head, str)
        or re.fullmatch(r"[0-9a-f]{40}", orig_head) is None
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    if orig_head is None:
        _run(git_arguments("update-ref", "-d", "ORIG_HEAD"), check=False)
    else:
        _run(git_arguments("update-ref", "ORIG_HEAD", orig_head))
    status = git("status", "--porcelain")
    identity = (git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}"))
    if status or identity != (commit, record["tree"]):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    if git("rev-parse", f"refs/heads/{release_branch}") != release_branch_tip:
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    for reference, target in sorted(managed_refs.items()):
        completed = _run(git_arguments("rev-parse", "--verify", reference), check=False)
        restored = completed.stdout.strip() if completed.returncode == 0 else None
        if completed.returncode not in {0, 128} or restored != target:
            raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    completed = _run(
        git_arguments("rev-parse", "--verify", "ORIG_HEAD"), check=False
    )
    restored_orig_head = completed.stdout.strip() if completed.returncode == 0 else None
    if completed.returncode not in {0, 128} or restored_orig_head != orig_head:
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    _restore_reflog_snapshot(
        git_directory or root / ".git", reflog_snapshot, record
    )


def _restore_public_nginx_backup(backup: Path, index: dict[str, Any]) -> None:
    _restore_file(
        index["files"]["nginx_site"], backup / "nginx-site.before", NGINX_SITE
    )
    _restore_file(
        index["files"]["nginx_enabled"],
        backup / "nginx-enabled.before",
        NGINX_ENABLED,
    )
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx.service"])


def _restore_non_repository_backup(backup: Path, index: dict[str, Any]) -> None:
    _restore_file(index["files"]["unit"], backup / "unit.before", UNIT_PATH)
    _restore_file(
        index["files"]["runtime_contract"],
        backup / "runtime-contract.before",
        RUNTIME_CONTRACT,
    )
    _restore_file(
        index["files"]["acceptance_evidence"],
        backup / "acceptance.before",
        STATE_ROOT / "acceptance.json",
    )
    _restore_file(
        index["files"]["final_state_evidence"],
        backup / "final-state.before",
        STATE_ROOT / "final-state.json",
    )
    _restore_file(
        index["files"]["deployment_result"],
        backup / "deployment-result.before",
        STATE_ROOT / "deployment-result.json",
    )


def _validate_ignored_backup_collisions(
    backup: Path,
    index: dict[str, Any],
    git_directories: dict[Path, Path],
) -> None:
    specifications = (
        (APPLICATION_ROOT, "application"),
        (CONTROL_ROOT, "control"),
    )
    for root, key in specifications:
        record = index.get(key)
        if not isinstance(record, dict) or root not in git_directories:
            raise S12ControlError("S12_1_ROLLBACK_IGNORED_COLLISION_RED")
        payload = _read_private_backup_blob(
            backup / f"{key}.tracked-path-hashes",
            record.get("tracked_path_hashes_sha256"),
            "S12_1_ROLLBACK_IGNORED_COLLISION_RED",
        )
        exact, tracked_ancestors = _parse_tracked_path_hash_payload(
            payload, "S12_1_ROLLBACK_IGNORED_COLLISION_RED"
        )
        ignored = _ignored_worktree_paths(
            root,
            git_directories[root],
            "S12_1_ROLLBACK_IGNORED_COLLISION_RED",
        )
        for path in ignored:
            if (
                _path_digest(path) in exact
                or _path_digest(path) in tracked_ancestors
                or any(
                    _path_digest(ancestor) in exact
                    for ancestor in _path_ancestors(path)
                )
            ):
                raise S12ControlError(
                    "S12_1_ROLLBACK_IGNORED_COLLISION_RED"
                )


def _restore_repositories_under_barrier(
    backup: Path,
    index: dict[str, Any],
    git_directories: dict[Path, Path],
) -> None:
    _validate_ignored_backup_collisions(backup, index, git_directories)
    _remove_release_stages(index)
    _remove_fetch_stage(index)
    _restore_repository(
        APPLICATION_ROOT,
        index["application"],
        backup / "application.bundle",
        backup / "application.reflogs",
        git_directories[APPLICATION_ROOT],
    )
    _restore_repository(
        CONTROL_ROOT,
        index["control"],
        backup / "control.bundle",
        backup / "control.reflogs",
        git_directories[CONTROL_ROOT],
    )
    _sync_repository_filesystem(APPLICATION_ROOT)
    _sync_repository_filesystem(CONTROL_ROOT)


def _rollback_progress_path(backup: Path) -> Path:
    return backup / "rollback-progress.json"


def _load_rollback_progress(backup: Path) -> dict[str, Any] | None:
    path = _rollback_progress_path(backup)
    if not path.exists() and not path.is_symlink():
        return None
    value = _private_json(path, "S12_1_ROLLBACK_PROGRESS_RED")
    phase = value.get("phase")
    expected_keys = {"schema", "backup", "phase"}
    if phase == ROLLBACK_PHASE_REPOSITORIES_RESTORED:
        expected_keys.add("repository_state")
    if (
        set(value) != expected_keys
        or value.get("schema") != ROLLBACK_PROGRESS_SCHEMA
        or value.get("backup") != str(backup)
        or phase
        not in {ROLLBACK_PHASE_STARTED, ROLLBACK_PHASE_REPOSITORIES_RESTORED}
        or (
            phase == ROLLBACK_PHASE_REPOSITORIES_RESTORED
            and not isinstance(value.get("repository_state"), dict)
        )
    ):
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    return value


def _write_rollback_progress(
    backup: Path,
    phase: str,
    repository_state: dict[str, Any] | None = None,
) -> None:
    if phase not in {
        ROLLBACK_PHASE_STARTED,
        ROLLBACK_PHASE_REPOSITORIES_RESTORED,
    }:
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    if (phase == ROLLBACK_PHASE_REPOSITORIES_RESTORED) is not (
        repository_state is not None
    ):
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    payload: dict[str, Any] = {
        "schema": ROLLBACK_PROGRESS_SCHEMA,
        "backup": str(backup),
        "phase": phase,
    }
    if repository_state is not None:
        payload["repository_state"] = repository_state
    _atomic_json(_rollback_progress_path(backup), payload)


def _repository_barriers_are_installed() -> bool:
    return all(
        _is_recovery_guard(root / ".git")
        and _is_recovery_git_directory(_recovery_git_path(root))
        for root in (APPLICATION_ROOT, CONTROL_ROOT)
    )


def _perform_restore_under_barrier(
    backup: Path,
    index: dict[str, Any],
    git_directories: dict[Path, Path],
    progress: dict[str, Any] | None,
    path_records: dict[Path, dict[str, Any]],
) -> None:
    if progress is None:
        _write_rollback_progress(backup, ROLLBACK_PHASE_STARTED)
    elif progress.get("phase") != ROLLBACK_PHASE_STARTED:
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    _restore_non_repository_backup(backup, index)
    _restore_repositories_under_barrier(backup, index, git_directories)
    repository_state = _release_repository_states(git_directories, path_records)
    _write_rollback_progress(
        backup,
        ROLLBACK_PHASE_REPOSITORIES_RESTORED,
        repository_state,
    )


def _finalize_rollback(backup: Path, index: dict[str, Any]) -> None:
    marker = backup / "rollback-complete.json"
    progress = _load_rollback_progress(backup)
    if (
        progress is None
        or progress.get("phase") != ROLLBACK_PHASE_REPOSITORIES_RESTORED
        or not isinstance(progress.get("repository_state"), dict)
    ):
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    path_records = {
        APPLICATION_ROOT: index["application"],
        CONTROL_ROOT: index["control"],
    }
    parent_record = index.get("repository_parent")
    if not isinstance(parent_record, dict):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    _recorded_parent_metadata(parent_record, require_xattr=False)
    worktree_barrier = _ensure_barrier_journal(path_records, parent_record)
    with _serialized_repository_recovery(
        records=path_records,
        parent_record=parent_record,
        worktree_barrier=worktree_barrier,
        preserve_on_error=True,
        allow_journaled_transition=True,
    ) as git_directories:
        _validate_release_repository_states(
            progress["repository_state"], git_directories, path_records
        )
        _sync_repository_filesystem(APPLICATION_ROOT)
        _sync_repository_filesystem(CONTROL_ROOT)
        _run(["systemctl", "daemon-reload"])
        _atomic_json(
            marker,
            {
                "ok": True,
                "safe_code": "S12_1_ROLLBACK_GREEN",
                "count": 1,
                "credentials_preserved": True,
            },
        )
    _sync_repository_filesystem(APPLICATION_ROOT)
    _sync_repository_filesystem(CONTROL_ROOT)
    _durable_unlink(BARRIER_MARKER)


def rollback_once(
    backup: Path,
    index: dict[str, Any],
    expected_release_state: dict[str, Any] | None = None,
) -> None:
    marker = backup / "rollback-complete.json"
    if marker.exists():
        raise S12ControlError("S12_1_ROLLBACK_DUPLICATE_RED")
    active_state, sub_state = _rollback_unit_state()
    if active_state != "inactive":
        stopped = _run(["systemctl", "stop", UNIT_NAME], check=False)
        if stopped.returncode != 0:
            raise S12ControlError("S12_1_ROLLBACK_STOP_RED")
        active_state, sub_state = _rollback_unit_state()
    if active_state != "inactive" or sub_state != "dead":
        raise S12ControlError("S12_1_ROLLBACK_STOP_RED")
    _restore_public_nginx_backup(backup, index)
    progress = _load_rollback_progress(backup)
    phase = progress.get("phase") if progress is not None else None
    if phase == ROLLBACK_PHASE_REPOSITORIES_RESTORED:
        if BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
            _recover_repository_barrier_only()
        _finalize_rollback(backup, index)
        return
    if phase == ROLLBACK_PHASE_STARTED and not _repository_barriers_are_installed():
        raise S12ControlError("S12_1_ROLLBACK_PROGRESS_RED")
    path_records = {
        APPLICATION_ROOT: index["application"],
        CONTROL_ROOT: index["control"],
    }
    parent_record = index.get("repository_parent")
    if not isinstance(parent_record, dict):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    _recorded_parent_metadata(parent_record, require_xattr=False)
    worktree_barrier = _ensure_barrier_journal(path_records, parent_record)
    with _serialized_repository_recovery(
        records=path_records,
        parent_record=parent_record,
        worktree_barrier=worktree_barrier,
        preserve_on_error=True,
        allow_journaled_transition=True,
    ) as git_directories:
        if expected_release_state is not None:
            if progress is None:
                _validate_release_repository_states(
                    expected_release_state, git_directories, path_records
                )
        _perform_restore_under_barrier(
            backup, index, git_directories, progress, path_records
        )
    _finalize_rollback(backup, index)


def _bare_root_git(git_directory: Path, *arguments: str) -> str:
    completed = _run(
        [
            *_isolated_root_git_prefix(git_directory),
            f"--git-dir={git_directory}",
            *arguments,
        ]
    )
    if completed.stderr.strip():
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    return completed.stdout.strip()


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        payload = os.pread(descriptor, 1024 * 1024, offset)
        if not payload:
            return digest.hexdigest()
        digest.update(payload)
        offset += len(payload)


def _write_private_backup_blob(path: Path, payload: bytes) -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        digest = hashlib.sha256(payload).hexdigest()
    except OSError:
        raise S12ControlError("S12_1_BACKUP_TRACKED_PATHS_RED") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _fsync_directory(path.parent)
    return digest


def _read_private_backup_blob(
    path: Path, expected_digest: object, safe_code: str
) -> bytes:
    if (
        not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
    ):
        raise S12ControlError(safe_code)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        metadata = path.lstat()
        expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 1 <= opened.st_size <= 32 * 1024 * 1024
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise OSError
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(payload)))
            if not chunk:
                raise OSError
            payload.extend(chunk)
        result = bytes(payload)
        if hashlib.sha256(result).hexdigest() != expected_digest:
            raise OSError
        return result
    except OSError:
        raise S12ControlError(safe_code) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _path_digest(path: bytes) -> bytes:
    return hashlib.sha256(b"TU1NZ_S12_1_PATH\0" + path).digest()


def _path_ancestors(path: bytes) -> set[bytes]:
    parts = path.split(b"/")
    return {b"/".join(parts[:index]) for index in range(1, len(parts))}


def _tracked_path_hash_payload(paths: set[bytes]) -> bytes:
    exact = sorted({_path_digest(path) for path in paths})
    ancestors = sorted(
        {_path_digest(ancestor) for path in paths for ancestor in _path_ancestors(path)}
    )
    return (
        TRACKED_PATH_HASH_SCHEMA
        + b"".join(b"E" + digest for digest in exact)
        + b"".join(b"A" + digest for digest in ancestors)
    )


def _parse_tracked_path_hash_payload(
    payload: bytes, safe_code: str
) -> tuple[set[bytes], set[bytes]]:
    if not payload.startswith(TRACKED_PATH_HASH_SCHEMA):
        raise S12ControlError(safe_code)
    records = payload[len(TRACKED_PATH_HASH_SCHEMA):]
    if len(records) % 33:
        raise S12ControlError(safe_code)
    exact: list[bytes] = []
    ancestors: list[bytes] = []
    active = exact
    for offset in range(0, len(records), 33):
        record = records[offset:offset + 33]
        if record[:1] == b"A":
            active = ancestors
        elif record[:1] != b"E" or active is ancestors:
            raise S12ControlError(safe_code)
        active.append(record[1:])
    if exact != sorted(set(exact)) or ancestors != sorted(set(ancestors)):
        raise S12ControlError(safe_code)
    return set(exact), set(ancestors)


def _open_release_input_bundle(
    bundle: Path, digest_environment: str, safe_code: str
) -> tuple[int, str]:
    expected = os.environ.get(digest_environment, "")
    descriptor: int | None = None
    try:
        descriptor = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        parent = bundle.parent.lstat()
        metadata = bundle.lstat()
        if (
            bundle.parent != RELEASE_INPUT_ROOT
            or bundle.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022
            or bundle.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or _sha256_descriptor(descriptor) != expected
        ):
            raise OSError
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise S12ControlError(safe_code) from None
    return descriptor, expected


@contextmanager
def _pinned_release_input_bundles():
    application: tuple[int, str] | None = None
    control: tuple[int, str] | None = None
    try:
        application = _open_release_input_bundle(
            APPLICATION_INPUT_BUNDLE,
            APPLICATION_BUNDLE_DIGEST_ENV,
            "S12_1_APPLICATION_INPUT_BUNDLE_RED",
        )
        control = _open_release_input_bundle(
            CONTROL_INPUT_BUNDLE,
            CONTROL_BUNDLE_DIGEST_ENV,
            "S12_1_CONTROL_INPUT_BUNDLE_RED",
        )
        yield {APPLICATION_ROOT: application, CONTROL_ROOT: control}
    finally:
        if application is not None:
            os.close(application[0])
        if control is not None:
            os.close(control[0])


def _copy_pinned_bundle(
    descriptor: int, destination: Path, expected_digest: str
) -> None:
    output_descriptor: int | None = None
    try:
        output_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        source_descriptor = os.dup(descriptor)
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        with (
            os.fdopen(source_descriptor, "rb") as source,
            os.fdopen(output_descriptor, "wb") as output,
        ):
            output_descriptor = None
            shutil.copyfileobj(source, output, length=1024 * 1024)
            output.flush()
            os.fchmod(output.fileno(), 0o600)
            os.fsync(output.fileno())
        metadata = destination.lstat()
        expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
        if (
            destination.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or _sha256(destination) != expected_digest
        ):
            raise OSError
        _fsync_directory(destination.parent)
    except OSError:
        destination.unlink(missing_ok=True)
        raise S12ControlError("S12_1_FETCH_STAGE_RED") from None
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)


def _prepare_release_fetch_stage(
    pinned_bundles: dict[Path, tuple[int, str]],
) -> dict[Path, Path]:
    if pinned_bundles.keys() != {APPLICATION_ROOT, CONTROL_ROOT}:
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    if FETCH_ROOT.exists() or FETCH_ROOT.is_symlink():
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    try:
        FETCH_ROOT.mkdir(mode=0o700)
        os.chown(FETCH_ROOT, 0, 0)
        os.chmod(FETCH_ROOT, 0o700)
        _fsync_directory(FETCH_ROOT.parent)
    except OSError:
        raise S12ControlError("S12_1_FETCH_STAGE_RED") from None
    application_fetch = FETCH_ROOT / "application.git"
    control_fetch = FETCH_ROOT / "control.git"
    application_bundle = FETCH_ROOT / "application.bundle"
    control_bundle = FETCH_ROOT / "control.bundle"
    application_descriptor, application_digest = pinned_bundles[APPLICATION_ROOT]
    control_descriptor, control_digest = pinned_bundles[CONTROL_ROOT]
    _copy_pinned_bundle(
        application_descriptor, application_bundle, application_digest
    )
    _copy_pinned_bundle(control_descriptor, control_bundle, control_digest)
    for git_directory in (application_fetch, control_fetch):
        _run(
            [
                *_isolated_root_git_prefix(FETCH_ROOT),
                "init",
                "--bare",
                str(git_directory),
            ]
        )
        _validate_root_git_contract(git_directory)
    _verify_git_bundle(APPLICATION_ROOT, application_bundle, application_fetch)
    _verify_git_bundle(CONTROL_ROOT, control_bundle, control_fetch)
    application_heads = _git_bundle_heads(
        APPLICATION_ROOT, application_bundle, application_fetch
    )
    control_heads = _git_bundle_heads(
        CONTROL_ROOT, control_bundle, control_fetch
    )
    if application_heads.get("refs/heads/main") != APPLICATION_COMMIT:
        raise S12ControlError("S12_1_APPLICATION_INPUT_BUNDLE_RED")
    if (
        re.fullmatch(
            r"[0-9a-f]{40}",
            control_heads.get("refs/heads/control-main", ""),
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{40}",
            control_heads.get(f"refs/tags/{FREEZE_TAG}", ""),
        )
        is None
    ):
        raise S12ControlError("S12_1_CONTROL_INPUT_BUNDLE_RED")
    for git_directory, bundle, source, destination in (
        (
            application_fetch,
            application_bundle,
            "refs/heads/main",
            "refs/s12/application-main",
        ),
        (
            control_fetch,
            control_bundle,
            "refs/heads/control-main",
            "refs/s12/control-main",
        ),
        (
            control_fetch,
            control_bundle,
            f"refs/tags/{FREEZE_TAG}",
            f"refs/tags/{FREEZE_TAG}",
        ),
    ):
        _run(
            [
                *_isolated_root_git_prefix(git_directory),
                f"--git-dir={git_directory}",
                "fetch",
                "--no-write-fetch-head",
                "--no-tags",
                "--refmap=",
                str(bundle),
                f"{source}:{destination}",
            ],
            timeout=300,
        )
    return {
        APPLICATION_ROOT: application_fetch,
        CONTROL_ROOT: control_fetch,
    }


def _seal_release_fetch_stage(
    fetch_directories: dict[Path, Path],
) -> None:
    if fetch_directories != {
        APPLICATION_ROOT: FETCH_ROOT / "application.git",
        CONTROL_ROOT: FETCH_ROOT / "control.git",
    }:
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    application_fetch = fetch_directories[APPLICATION_ROOT]
    control_fetch = fetch_directories[CONTROL_ROOT]
    try:
        metadata = FETCH_ROOT.lstat()
        if (
            FETCH_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _active_recovery_git_handle_count((FETCH_ROOT,)) != 0
        ):
            raise OSError
    except OSError:
        raise S12ControlError("S12_1_FETCH_STAGE_RED") from None
    for git_directory in (application_fetch, control_fetch):
        _validate_root_git_contract(git_directory)
    application_commit = _bare_root_git(
        application_fetch, "rev-parse", "refs/s12/application-main"
    )
    application_tree = _bare_root_git(
        application_fetch, "rev-parse", "refs/s12/application-main^{tree}"
    )
    control_commit = _bare_root_git(
        control_fetch, "rev-parse", "refs/s12/control-main"
    )
    tag_target = _bare_root_git(
        control_fetch, "rev-parse", f"refs/tags/{FREEZE_TAG}^{{commit}}"
    )
    tag_object = _bare_root_git(
        control_fetch, "cat-file", "tag", f"refs/tags/{FREEZE_TAG}"
    )
    runtime_digest_bindings = re.findall(
        r"^control_runtime_sha256=([0-9a-f]{64})$", tag_object, re.MULTILINE
    )
    if (
        (application_commit, application_tree)
        != (APPLICATION_COMMIT, APPLICATION_TREE)
        or _bare_root_git(
            control_fetch, "cat-file", "-t", f"refs/tags/{FREEZE_TAG}"
        )
        != "tag"
        or control_commit != tag_target
        or runtime_digest_bindings != [_trusted_controller_digest()]
    ):
        raise S12ControlError("S12_1_FETCH_STAGE_RED")


def _validated_git_paths(
    records: tuple[bytes, ...], safe_code: str
) -> set[bytes]:
    paths: set[bytes] = set()
    for record in records:
        parts = record.split(b"/")
        if (
            record.startswith(b"/")
            or any(part in {b"", b".", b".."} for part in parts)
            or record in paths
        ):
            raise S12ControlError(safe_code)
        paths.add(record)
    return paths


def _tracked_tree_paths(
    root: Path,
    git_directory: Path,
    revision: str,
    safe_code: str,
) -> set[bytes]:
    return _validated_git_paths(
        _bounded_nul_command_records(
            _selected_git_arguments(
                root,
                git_directory,
                "ls-tree",
                "-r",
                "--name-only",
                "-z",
                revision,
            ),
            safe_code,
        ),
        safe_code,
    )


def _ignored_worktree_paths(
    root: Path, git_directory: Path, safe_code: str
) -> set[bytes]:
    return _validated_git_paths(
        _bounded_nul_command_records(
            _selected_git_arguments(
                root,
                git_directory,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
                "--",
                ".",
                f":(exclude){RECOVERY_GIT_DIRECTORY}",
            ),
            safe_code,
        ),
        safe_code,
    )


def _validate_ignored_release_collisions(
    git_directories: dict[Path, Path],
    fetch_directories: dict[Path, Path],
) -> None:
    if git_directories.keys() != {APPLICATION_ROOT, CONTROL_ROOT} or (
        fetch_directories.keys() != {APPLICATION_ROOT, CONTROL_ROOT}
    ):
        raise S12ControlError("S12_1_IGNORED_RELEASE_COLLISION_RED")
    targets = {
        APPLICATION_ROOT: "refs/s12/application-main",
        CONTROL_ROOT: f"refs/tags/{FREEZE_TAG}^{{commit}}",
    }
    for root in (APPLICATION_ROOT, CONTROL_ROOT):
        ignored = _ignored_worktree_paths(
            root,
            git_directories[root],
            "S12_1_IGNORED_RELEASE_COLLISION_RED",
        )
        target_paths = _validated_git_paths(
            _bounded_nul_command_records(
                [
                    *_isolated_root_git_prefix(fetch_directories[root]),
                    f"--git-dir={fetch_directories[root]}",
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "-z",
                    targets[root],
                ],
                "S12_1_IGNORED_RELEASE_COLLISION_RED",
            ),
            "S12_1_IGNORED_RELEASE_COLLISION_RED",
        )
        target_ancestors: set[bytes] = set()
        for path in target_paths:
            target_ancestors.update(_path_ancestors(path))
        for path in ignored:
            ignored_ancestors = _path_ancestors(path)
            if (
                path in target_paths
                or path in target_ancestors
                or not target_paths.isdisjoint(ignored_ancestors)
            ):
                raise S12ControlError("S12_1_IGNORED_RELEASE_COLLISION_RED")


def _sync_repositories(
    git_directories: dict[Path, Path],
    fetch_directories: dict[Path, Path],
) -> tuple[str, str]:
    application_git = git_directories[APPLICATION_ROOT]
    control_git = git_directories[CONTROL_ROOT]
    _run(
        _selected_git_arguments(
            APPLICATION_ROOT,
            application_git,
            "fetch",
            "--no-write-fetch-head",
            "--no-tags",
            "--refmap=",
            str(fetch_directories[APPLICATION_ROOT]),
            "refs/s12/application-main",
        ),
        timeout=300,
    )
    _run(_selected_git_arguments(APPLICATION_ROOT, application_git, "checkout", "main"))
    _run(
        _selected_git_arguments(
            APPLICATION_ROOT, application_git, "merge", "--ff-only", APPLICATION_COMMIT
        )
    )
    _run(
        _selected_git_arguments(
            CONTROL_ROOT,
            control_git,
            "fetch",
            "--no-write-fetch-head",
            "--no-tags",
            "--refmap=",
            str(fetch_directories[CONTROL_ROOT]),
            "refs/s12/control-main",
        ),
        timeout=300,
    )
    _run(
        _selected_git_arguments(
            CONTROL_ROOT,
            control_git,
            "fetch",
            "--no-write-fetch-head",
            "--no-tags",
            "--refmap=",
            str(fetch_directories[CONTROL_ROOT]),
            f"refs/tags/{FREEZE_TAG}:refs/tags/{FREEZE_TAG}",
        ),
        timeout=300,
    )
    target_control = _selected_git(
        CONTROL_ROOT, control_git, "rev-parse", f"{FREEZE_TAG}^{{commit}}"
    )
    _run(_selected_git_arguments(CONTROL_ROOT, control_git, "checkout", "control-main"))
    _run(
        _selected_git_arguments(
            CONTROL_ROOT, control_git, "merge", "--ff-only", target_control
        )
    )
    if _selected_identity(APPLICATION_ROOT, application_git) != (
        APPLICATION_COMMIT,
        APPLICATION_TREE,
    ):
        raise S12ControlError("S12_1_APPLICATION_RELEASE_RED")
    control_sha, control_tree = _selected_identity(CONTROL_ROOT, control_git)
    if control_sha != target_control:
        raise S12ControlError("S12_1_CONTROL_RELEASE_RED")
    return control_sha, control_tree


def _verify_release_freeze() -> None:
    verify = _run(
        [
            sys.executable,
            str(
                RELEASE_CONTROL_ROOT
                / "scripts/tu1nz_adult_commercial_s12_1_freeze.py"
            ),
            "verify-tag",
            "--control-repo", str(RELEASE_CONTROL_ROOT),
            "--application-repo", str(RELEASE_APPLICATION_ROOT),
            "--tag", FREEZE_TAG,
        ]
    )
    if json.loads(verify.stdout).get("ok") is not True:
        raise S12ControlError("S12_1_RUNTIME_FREEZE_RED")


def _provider_application_digest() -> str:
    material = SDK_ID.read_bytes()
    try:
        sdk_id = material.decode("ascii").strip()
    finally:
        material = b""
    if not sdk_id:
        raise S12ControlError("S12_1_CREDENTIAL_METADATA_RED")
    return hashlib.sha256(sdk_id.encode("ascii")).hexdigest()


def runtime_contract(control_sha: str, control_tree: str) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    ended = started + timedelta(minutes=20)
    return {
        "active": True,
        "allowed_method": "AGE_ESTIMATION",
        "application_sha": APPLICATION_COMMIT,
        "application_tree": APPLICATION_TREE,
        "callback_max_body_bytes": 16384,
        "callback_method": "POST",
        "callback_path": "/avs/sandbox/callback",
        "contract_version": CONTRACT_VERSION,
        "control_sha": control_sha,
        "control_tree": control_tree,
        "credential_references": {
            "private_key": str(PRIVATE_KEY),
            "sdk_id": str(SDK_ID),
        },
        "decision": "GO_FOR_SYNTHETIC_YOTI_SANDBOX",
        "environment": "SANDBOX",
        "hard_gates": {
            "adult_media": False,
            "adult_submission": False,
            "community_adult_media": False,
            "controlled_beta": False,
            "external_publishing": False,
            "payments": False,
            "production": False,
            "real_avs": False,
        },
        "network_enabled": True,
        "network_hosts": ["age.yoti.com", "auth.api.yoti.com"],
        "provider": "YOTI",
        "provider_application_digest": _provider_application_digest(),
        "runtime_freeze_tag": FREEZE_TAG,
        "synthetic_subject_only": True,
        "threshold": 18,
        "window_ends_at": ended.isoformat().replace("+00:00", "Z"),
        "window_starts_at": started.isoformat().replace("+00:00", "Z"),
    }


def _atomic_copy(source: Path, destination: Path, mode: int, uid: int, gid: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        parent_descriptor = os.open(
            destination.parent, os.O_RDONLY | os.O_DIRECTORY
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _install_file(source: Path, destination: Path, mode: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise S12ControlError("S12_1_INSTALL_SOURCE_RED")
    _atomic_copy(source, destination, mode, 0, 0)


def _fresh_evidence(path: Path, earliest_mtime_ns: int) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 65536
            or metadata.st_mtime_ns < earliest_mtime_ns
        ):
            raise ValueError
        value = json.loads(path.read_text(encoding="ascii"))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise S12ControlError("S12_1_FRESH_EVIDENCE_RED") from None


def _private_json(path: Path, safe_code: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 131072
        ):
            raise ValueError
        value = json.loads(path.read_text(encoding="ascii"))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise S12ControlError(safe_code) from None


def _load_recovery_backup() -> tuple[Path, dict[str, Any], dict[str, Any]]:
    _validate_secure_directory_chain(BACKUP_ROOT, Path("/"))
    attempt = _private_json(ATTEMPT_MARKER, "S12_1_RECOVERY_MARKER_RED")
    release_repository_state = attempt.get("release_repository_state")
    if (
        attempt.get("attempt") != 1
        or not isinstance(attempt.get("backup"), str)
        or not isinstance(attempt.get("started_at"), str)
        or not attempt["started_at"]
        or (
            release_repository_state is not None
            and (
                not isinstance(release_repository_state, dict)
                or set(release_repository_state) != {"application", "control"}
                or not all(
                    isinstance(release_repository_state.get(key), dict)
                    for key in ("application", "control")
                )
            )
        )
    ):
        raise S12ControlError("S12_1_RECOVERY_MARKER_RED")
    backup = Path(attempt["backup"])
    try:
        metadata = backup.lstat()
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_BACKUP_RED") from None
    if (
        backup.parent != BACKUP_ROOT
        or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-predeploy", backup.name) is None
        or backup.is_symlink()
        or not backup.is_dir()
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise S12ControlError("S12_1_RECOVERY_BACKUP_RED")
    index = _private_json(backup / "restore-index.json", "S12_1_RECOVERY_INDEX_RED")
    if index.get("schema") != BACKUP_SCHEMA:
        raise S12ControlError("S12_1_RECOVERY_INDEX_RED")
    return backup, index, attempt


def _pristine_legacy_orphan_is_releasable(
    records: dict[Path, dict[str, Any]],
    parent_record: dict[str, Any],
    worktree_barrier: dict[Path, dict[Path, dict[str, Any]]] | None,
    schema: str,
    *,
    guarded_git_checks: bool = True,
) -> bool:
    """Recognize a V1 journal left before any repository mutation began."""

    roots = (APPLICATION_ROOT, CONTROL_ROOT)
    if (
        schema != LEGACY_BARRIER_SCHEMA
        or worktree_barrier is not None
        or ATTEMPT_MARKER.exists()
        or ATTEMPT_MARKER.is_symlink()
        or FETCH_ROOT.exists()
        or FETCH_ROOT.is_symlink()
        or set(records) != set(roots)
    ):
        return False
    metadata_paths = _repository_git_metadata_paths(roots)
    if set(metadata_paths) != {root / ".git" for root in roots}:
        return False
    expected_parent = _recorded_parent_metadata(
        parent_record, require_xattr=False
    )
    current_parent = _repository_parent_metadata()
    if expected_parent != (
        current_parent["uid"],
        current_parent["gid"],
        int(current_parent["mode"], 8),
    ):
        return False
    _assert_legacy_repository_parent_xattrs_safe()
    repository_fields = (
        "root_uid", "root_gid", "root_mode",
        "git_uid", "git_gid", "git_mode",
    )
    for root in roots:
        current = _repository_path_metadata(root)
        if any(
            current[field] != records[root].get(field)
            for field in repository_fields
        ):
            return False
        _validate_repository_worktree_contract(
            root,
            records[root],
            allow_journaled_transition=True,
        )
        _assert_legacy_path_xattrs_safe(
            root, "S12_1_RECOVERY_GIT_BARRIER_RED"
        )
        if guarded_git_checks:
            for path in _tracked_worktree_barrier_paths(root):
                _assert_legacy_path_xattrs_safe(
                    path, "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                )
            _validate_root_git_contract(root / ".git")
            _validate_canonical_index(root, root / ".git")
    tracked_paths = (
        _tracked_worktree_regular_paths(roots) if guarded_git_checks else ()
    )

    def assert_no_writer() -> None:
        if (
            _competing_control_sync_count() != 0
            or _active_repository_git_count(roots) != 0
            or _active_recovery_git_handle_count(metadata_paths) != 0
            or _active_tracked_worktree_write_handle_count(tracked_paths) != 0
            or _active_exact_directory_handle_count(DEPLOYMENT_LOCK_ROOT) != 0
        ):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")

    assert_no_writer()
    if guarded_git_checks:
        for root in roots:
            _selected_identity(root, root / ".git")
    assert_no_writer()
    return True


def _successful_result_matches_attempt(attempt: dict[str, Any]) -> bool:
    result_path = STATE_ROOT / "deployment-result.json"
    if not result_path.exists():
        return False
    try:
        result = _private_json(result_path, "S12_1_RECOVERY_RESULT_RED")
    except S12ControlError:
        return False
    return (
        result.get("ok") is True
        and result.get("safe_code") == "S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN"
        and result.get("deployment_count") == 1
        and result.get("backup") == attempt.get("backup")
        and result.get("attempt_started_at") == attempt.get("started_at")
    )


def _recover_repository_barrier_only() -> dict[str, Any]:
    _normalize_barrier_release_backup()
    records, parent_record, existing_worktree_barrier, schema = (
        _load_barrier_journal()
    )
    if _pristine_legacy_orphan_is_releasable(
        records,
        parent_record,
        existing_worktree_barrier,
        schema,
        guarded_git_checks=False,
    ):
        roots = (APPLICATION_ROOT, CONTROL_ROOT)
        metadata_guard: _GitMetadataTransitionGuard | None = None
        worktree_guard: _WorktreeReleaseGuard | None = None
        try:
            metadata_guard = _GitMetadataTransitionGuard(
                _repository_git_metadata_paths(roots),
                allow_root_lock_events=False,
            )
            tracked_paths = tuple(
                path
                for root in roots
                for path in _tracked_worktree_barrier_paths(root)
            )
            worktree_guard = _WorktreeReleaseGuard(
                (DEPLOYMENT_LOCK_ROOT, *roots),
                tracked_paths=tracked_paths,
            )
            if not _pristine_legacy_orphan_is_releasable(
                records, parent_record, existing_worktree_barrier, schema
            ):
                raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
            metadata_guard.assert_unchanged()
            worktree_guard.assert_no_events()
            _sync_repository_filesystem(APPLICATION_ROOT)
            _sync_repository_filesystem(CONTROL_ROOT)
            if not _pristine_legacy_orphan_is_releasable(
                records, parent_record, existing_worktree_barrier, schema
            ):
                raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
            metadata_guard.assert_unchanged()
            worktree_guard.assert_no_events()
            _prepare_barrier_release_backup()
            _durable_unlink(BARRIER_MARKER)
            metadata_guard.assert_unchanged()
            worktree_guard.finalize_release(
                metadata_guard.assert_unchanged,
                metadata_guard.assert_unchanged,
            )
            worktree_guard = None
            metadata_guard.finalize_release()
            metadata_guard = None
            _write_barrier_release_completion()
            _durable_unlink(BARRIER_RELEASE_BACKUP)
        finally:
            if worktree_guard is not None:
                worktree_guard.close()
            if metadata_guard is not None:
                metadata_guard.close()
        return {
            "ok": True,
            "safe_code": "S12_1_ORPHAN_BARRIER_RECOVERED",
            "rollback_count": 0,
        }
    worktree_barrier = _ensure_barrier_journal(records, parent_record)
    with _serialized_repository_recovery(
        records=records,
        parent_record=parent_record,
        worktree_barrier=worktree_barrier,
        allow_journaled_transition=True,
    ):
        _remove_fetch_stage(
            {"fetch_stage": {"path": str(FETCH_ROOT), "present": False}}
        )
    _sync_repository_filesystem(APPLICATION_ROOT)
    _sync_repository_filesystem(CONTROL_ROOT)
    _durable_unlink(BARRIER_MARKER)
    return {
        "ok": True,
        "safe_code": "S12_1_ORPHAN_BARRIER_RECOVERED",
        "rollback_count": 0,
    }


def _recover_locked() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise S12ControlError("S12_1_ROOT_REQUIRED_RED")
    _normalize_barrier_release_backup()
    barrier_present = _barrier_journal_present()
    attempt_present = ATTEMPT_MARKER.exists() or ATTEMPT_MARKER.is_symlink()
    if (
        not barrier_present
        and not attempt_present
        and _barrier_release_completion() is not None
    ):
        result = {
            "ok": True,
            "safe_code": "S12_1_ORPHAN_BARRIER_RECOVERED",
            "rollback_count": 0,
        }
        _atomic_json(STATE_ROOT / "recovery-result.json", result)
        return result
    if barrier_present and not attempt_present:
        result = _recover_repository_barrier_only()
        _atomic_json(STATE_ROOT / "recovery-result.json", result)
        return result
    backup, index, attempt = _load_recovery_backup()
    if _successful_result_matches_attempt(attempt):
        raise S12ControlError("S12_1_RECOVERY_AFTER_SUCCESS_FORBIDDEN_RED")
    completed = backup / "rollback-complete.json"
    if completed.exists():
        marker = _private_json(completed, "S12_1_RECOVERY_RESULT_RED")
        if marker.get("safe_code") != "S12_1_ROLLBACK_GREEN" or marker.get("count") != 1:
            raise S12ControlError("S12_1_RECOVERY_RESULT_RED")
        if _barrier_journal_present():
            _recover_repository_barrier_only()
        safe_code = "S12_1_RECOVERY_ALREADY_COMPLETE"
    else:
        rollback_once(backup, index, attempt.get("release_repository_state"))
        safe_code = "S12_1_INTERRUPTED_DEPLOYMENT_RECOVERED"
    result = {"ok": True, "safe_code": safe_code, "rollback_count": 1}
    _atomic_json(STATE_ROOT / "recovery-result.json", result)
    return result


def recover() -> dict[str, Any]:
    with _exclusive_deployment_lock():
        return _recover_locked()


def _deploy_locked() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise S12ControlError("S12_1_ROOT_REQUIRED_RED")
    if STATE_ROOT.exists() and (
        STATE_ROOT.is_symlink()
        or not STATE_ROOT.is_dir()
        or STATE_ROOT.stat().st_uid != 0
        or STATE_ROOT.stat().st_gid != 0
        or stat.S_IMODE(STATE_ROOT.stat().st_mode) != 0o700
    ):
        raise S12ControlError("S12_1_RUNTIME_STATE_RED")
    _normalize_barrier_release_backup()
    if _barrier_journal_present() and not (
        ATTEMPT_MARKER.exists() or ATTEMPT_MARKER.is_symlink()
    ):
        _recover_repository_barrier_only()
        raise S12ControlError("S12_1_ORPHAN_BARRIER_RECOVERED")
    read_only_preflight()
    initial_active, initial_sub = _rollback_unit_state()
    if initial_active != "inactive" or initial_sub != "dead":
        raise S12ControlError("S12_1_PREDEPLOY_RUNTIME_UNIT_RED")
    if ATTEMPT_MARKER.exists() or ATTEMPT_MARKER.is_symlink():
        raise S12ControlError("S12_1_SECOND_DEPLOYMENT_FORBIDDEN_RED")
    if FETCH_ROOT.exists() or FETCH_ROOT.is_symlink():
        raise S12ControlError("S12_1_FETCH_STAGE_RED")
    _ensure_private_directory_durable(STATE_ROOT, Path("/"))
    path_records = {
        APPLICATION_ROOT: _repository_path_metadata(APPLICATION_ROOT),
        CONTROL_ROOT: _repository_path_metadata(CONTROL_ROOT),
    }
    parent_record = _repository_parent_metadata()
    backup: Path | None = None
    index: dict[str, Any] | None = None
    attempt_started_at = ""
    mutation_started = False
    release_repository_state: dict[str, Any] | None = None
    repository_sync_failure: BaseException | None = None
    try:
        worktree_barrier = _write_barrier_journal(
            path_records, parent_record
        )
        with _pinned_release_input_bundles() as pinned_bundles:
            with _serialized_repository_recovery(
                records=path_records,
                parent_record=parent_record,
                worktree_barrier=worktree_barrier,
                preserve_on_error=True,
            ) as git_directories:
                fetch_directories = _prepare_release_fetch_stage(pinned_bundles)
                _seal_release_fetch_stage(fetch_directories)
                _validate_ignored_release_collisions(
                    git_directories, fetch_directories
                )
                backup, index = create_backup(
                    git_directories,
                    path_records,
                    parent_record,
                )
                _validate_backup_snapshot(backup, index, git_directories)
                _validate_ignored_release_collisions(
                    git_directories, fetch_directories
                )
                attempt_started_at = datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                )
                _atomic_json(
                    ATTEMPT_MARKER,
                    {
                        "attempt": 1,
                        "backup": str(backup),
                        "started_at": attempt_started_at,
                    },
                )
                _write_rollback_progress(backup, ROLLBACK_PHASE_STARTED)
                mutation_started = True
                try:
                    control_sha, control_tree = _sync_repositories(
                        git_directories, fetch_directories
                    )
                    release_repository_state = _release_repository_states(
                        git_directories, path_records
                    )
                    _atomic_json(
                        ATTEMPT_MARKER,
                        {
                            "attempt": 1,
                            "backup": str(backup),
                            "started_at": attempt_started_at,
                            "release_repository_state": release_repository_state,
                        },
                    )
                    _create_immutable_release_stage(
                        git_directories,
                        control_sha,
                        control_tree,
                    )
                    _remove_fetch_stage(index)
                    _durable_unlink(_rollback_progress_path(backup))
                except BaseException as error:
                    repository_sync_failure = error
                    _perform_restore_under_barrier(
                        backup,
                        index,
                        git_directories,
                        _load_rollback_progress(backup),
                        path_records,
                    )
            if repository_sync_failure is not None:
                _finalize_rollback(backup, index)
                raise repository_sync_failure
        _sync_repository_filesystem(APPLICATION_ROOT)
        _sync_repository_filesystem(CONTROL_ROOT)
        _durable_unlink(BARRIER_MARKER)
        _verify_release_freeze()
        _atomic_json(RUNTIME_CONTRACT, runtime_contract(control_sha, control_tree))
        os.chown(RUNTIME_CONTRACT, 0, 0)
        _install_file(
            RELEASE_CONTROL_ROOT / "systemd" / UNIT_NAME,
            UNIT_PATH,
            0o644,
        )
        if _sha256(UNIT_PATH) != _sha256(
            RELEASE_CONTROL_ROOT / "systemd" / UNIT_NAME
        ):
            raise S12ControlError("S12_1_INSTALLED_UNIT_RED")
        _install_file(
            RELEASE_CONTROL_ROOT / "nginx/current/wantmeseen.s12-1-acceptance.conf",
            NGINX_SITE,
            0o644,
        )
        if NGINX_ENABLED.is_symlink():
            if os.readlink(NGINX_ENABLED) not in {
                str(NGINX_SITE), "../sites-available/wantmeseen.conf"
            }:
                raise S12ControlError("S12_1_NGINX_LINK_RED")
        elif NGINX_ENABLED.exists():
            _install_file(NGINX_SITE, NGINX_ENABLED, 0o644)
        else:
            _durable_symlink(str(NGINX_SITE), NGINX_ENABLED)
        _run(["systemctl", "daemon-reload"])
        if (
            _runtime_unit_dropin_count() != 0
            or _systemctl_property(UNIT_NAME, "DropInPaths")
        ):
            raise S12ControlError("S12_1_RUNTIME_UNIT_DROPIN_RED")
        if _systemctl_property(UNIT_NAME, "FragmentPath") != str(UNIT_PATH):
            raise S12ControlError("S12_1_RUNTIME_UNIT_FRAGMENT_RED")
        if _runtime_unit_enablement_state() != "static":
            raise S12ControlError("S12_1_RUNTIME_UNIT_ENABLEMENT_RED")
        _run(["nginx", "-t"])
        _run(["systemctl", "reload", "nginx.service"])
        _verify_immutable_release_stage(control_sha, control_tree)
        release_environment = _release_environment_record()
        for path in (
            STATE_ROOT / "acceptance.json",
            STATE_ROOT / "final-state.json",
            STATE_ROOT / "deployment-result.json",
        ):
            _durable_unlink(path)
        evidence_not_before_ns = time.time_ns()
        start = _run(["systemctl", "start", UNIT_NAME], check=False, timeout=900)
        if start.returncode != 0:
            raise S12ControlError("S12_1_RUNTIME_ACCEPTANCE_RED")
        if _systemctl_property(UNIT_NAME, "Result") != "success":
            raise S12ControlError("S12_1_RUNTIME_ACCEPTANCE_RED")
        evidence = _fresh_evidence(
            STATE_ROOT / "acceptance.json", evidence_not_before_ns
        )
        if (
            evidence.get("safe_code") != "S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN"
            or evidence.get("hard_gates_closed") is not True
            or evidence.get("runtime_active") is not False
        ):
            raise S12ControlError("S12_1_RUNTIME_ACCEPTANCE_RED")
        final_state = _fresh_evidence(
            STATE_ROOT / "final-state.json", evidence_not_before_ns
        )
        if (
            final_state.get("safe_code") != "S12_RUNTIME_CONTROLLED_INACTIVE"
            or final_state.get("hard_gates_closed") is not True
            or final_state.get("runtime_active") is not False
            or final_state.get("callback") != "INACTIVE"
        ):
            raise S12ControlError("S12_1_SAFE_STOP_RED")
        _restore_file(index["files"]["nginx_site"], backup / "nginx-site.before", NGINX_SITE)
        _restore_file(
            index["files"]["nginx_enabled"],
            backup / "nginx-enabled.before",
            NGINX_ENABLED,
        )
        _run(["nginx", "-t"])
        _run(["systemctl", "reload", "nginx.service"])
        _durable_unlink(RUNTIME_CONTRACT)
        read_only_preflight(immutable_release_allowed=True)
        result = {
            "ok": True,
            "safe_code": "S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN",
            "backup": str(backup),
            "attempt_started_at": attempt_started_at,
            "deployment_count": 1,
            "rollback_count": 0,
            "runtime": "CONTROLLED_INACTIVE",
            "callback": "INACTIVE",
            "s11": "UNCHANGED_GREEN",
            "public_wms": "GREEN",
            "runtime_environment_sha256": release_environment["venv_sha256"],
            "hard_gates_closed": True,
        }
        _atomic_json(STATE_ROOT / "deployment-result.json", result)
        return result
    except BaseException:
        if repository_sync_failure is not None:
            pass
        elif mutation_started and backup is not None and index is not None:
            rollback_once(backup, index, release_repository_state)
        elif _barrier_journal_present():
            _recover_repository_barrier_only()
        raise


def deploy() -> dict[str, Any]:
    with _exclusive_deployment_lock():
        return _deploy_locked()


def simulator() -> dict[str, Any]:
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
    from scripts.tu1nz_adult_commercial_s12_1_simulator import run_simulator

    return run_simulator()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("verify-source", "simulate", "preflight", "deploy", "recover")
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.operation in {"deploy", "recover"}:
            if os.geteuid() != 0:
                raise S12ControlError("S12_1_ROOT_REQUIRED_RED")
            _trusted_controller_digest()
        if arguments.operation == "verify-source":
            result = validate_source_contract()
        elif arguments.operation == "simulate":
            result = simulator()
        elif arguments.operation == "preflight":
            result = read_only_preflight(
                immutable_release_allowed=ATTEMPT_MARKER.exists()
            )
        elif arguments.operation == "recover":
            result = recover()
        else:
            result = deploy()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (S12ControlError, OSError, ValueError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {"ok": False, "safe_code": getattr(error, "safe_code", "S12_1_CONTROL_RED")},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
