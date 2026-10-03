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
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence


APPLICATION_COMMIT = "93555d8a141caf8ace33522f9340d30bfc47d2bb"
APPLICATION_TREE = "1e8a644115127818f394b6f9d24f31826e04ecba"
FREEZE_TAG = "s12-yoti-sandbox-runtime-freeze-r13"
FOLLOWUP_SLOT = "r13-followup-1"
FOLLOWUP_RED = "S12_1_FOLLOWUP_AUTHORIZATION_RED"
FOLLOWUP_PARENT = {
    "attempt": "30189b22f290361e901ac4f6b0af95ebc75424014ff190fb86cc9600c5ab680c",
    "index": "18fad15bfc806ad1359648fc06353678ca78380a7924e30024050af726ce196e",
    "r12_original": "8e2bb8ec334584d2a87e7b1d5b0f01fcf9463ed37281510fa56a9e49d89250ae",
}
ACTIVE_ATTEMPT: dict[str, Any] | None = None
MATERIALIZATION_RECORDS: dict | None = None
MATERIALIZATION_GUARDS: _R13GuardStack | None = None
GIT_WRITER_SCOPE: _R13GitWriters | None = None
MATERIALIZATION_RED = "S12_1_MATERIALIZATION_CONTRACT_RED"
CONTRACT_VERSION = "tu1nz-s12-yoti-sandbox-runtime-v1"
BACKUP_SCHEMA = "TU1NZ_S12_1_RUNTIME_BACKUP_V8"
BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V3"
R12_BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V4"
R12_CONTRACT_SHA256 = "97794cddc84a5d9a0ddd6600236aee5f8c8c79013089ef9b20fb01060ca8e00f"
R12_RED = "S12_1_R12_METADATA_RECONCILIATION_RED"
XATTR_BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V2"
LEGACY_BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V1"
BARRIER_RELEASE_COMPLETION_SCHEMA = "TU1NZ_S12_1_BARRIER_RELEASE_COMPLETE_V1"
BARRIER_JOURNAL_MAX_BYTES = 1024 * 1024
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
        "followup_admission": {
            "slot": FOLLOWUP_SLOT,
            "authority": "PROTECTED_HUMAN_GRANT_AND_CLOSED_R12_RECOVERY",
            "historical_marker_preserved": True,
            "consumption": "DURABLE_BEFORE_DEPLOY_NO_RETRY",
        },
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
            or not 1 <= metadata.st_size <= BARRIER_JOURNAL_MAX_BYTES
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
        set(value) != ({"schema", "completed_at", "journal_sha256"}
                       | ({"attempt_binding"} if ACTIVE_ATTEMPT is not None else set()))
        or value.get("schema") != BARRIER_RELEASE_COMPLETION_SCHEMA
        or not isinstance(value.get("completed_at"), str)
        or not value["completed_at"]
        or not isinstance(value.get("journal_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["journal_sha256"]) is None
        or (ACTIVE_ATTEMPT is not None and value.get("attempt_binding") != ACTIVE_ATTEMPT)
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return value


def _barrier_json(path: Path) -> dict[str, Any]:
    return _private_json(
        path,
        "S12_1_REPOSITORY_BARRIER_JOURNAL_RED",
        maximum=BARRIER_JOURNAL_MAX_BYTES,
    )


def _atomic_barrier_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if not 1 <= len(encoded) <= BARRIER_JOURNAL_MAX_BYTES:
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    _atomic_json(path, payload)


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
            **({"attempt_binding": ACTIVE_ATTEMPT} if ACTIVE_ATTEMPT is not None else {}),
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
    if GIT_WRITER_SCOPE is not None:
        GIT_WRITER_SCOPE.check()
        selected = GIT_WRITER_SCOPE.command(arguments)
        if selected is not None:
            completed = GIT_WRITER_SCOPE.run(selected, timeout, input_text=input_text)
            if check and completed.returncode:
                raise S12ControlError("S12_1_CONTROL_COMMAND_RED")
            return completed
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
        completed = _git_process(arguments)
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


def _git_process(arguments, *, timeout=120, stdin=None, stdout=None, text=False):
    """Binary/streaming Git helpers share the epoch router, without a bypass."""
    if GIT_WRITER_SCOPE is not None:
        selected = GIT_WRITER_SCOPE.command(arguments)
        if selected is None:
            GIT_WRITER_SCOPE.fail()
        return GIT_WRITER_SCOPE.run(selected,timeout,stdin=stdin,stdout=stdout,text=text)
    return subprocess.run(list(arguments),check=False,stdin=stdin,
        stdout=stdout or subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,text=text)


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
            completed = _git_process(
                _selected_git_arguments(
                    root, git_directory, "bundle", "create", "-", *revisions
                ),
                stdout=output,
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
            completed = _git_process(
                _selected_git_arguments(
                    root, git_directory, "bundle", "verify", "/dev/stdin"
                ),
                stdin=input_stream,
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
            completed = _git_process(
                _selected_git_arguments(
                    root, git_directory, "bundle", "list-heads", "/dev/stdin"
                ),
                stdin=input_stream,
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
    *,
    control_freeze_ref: str | None = None,
) -> dict[str, dict[str, Any]]:
    selected_freeze_ref = (
        f"refs/tags/{FREEZE_TAG}"
        if control_freeze_ref is None
        else control_freeze_ref
    )
    if not isinstance(selected_freeze_ref, str) or re.fullmatch(
        r"refs/tags/s12-yoti-sandbox-runtime-freeze-r[1-9][0-9]{0,8}",
        selected_freeze_ref,
    ) is None:
        raise S12ControlError("S12_1_RELEASE_REPOSITORY_STATE_RED")

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
            (selected_freeze_ref,),
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
    # A later reviewed recovery controller must validate the exact reference
    # selected by the durable snapshot's controller, not its own newer tag.
    # All refs, ref targets, identity, index and reflogs remain compared.
    managed_refs = expected["control"].get("managed_refs")
    if (
        expected["application"].get("managed_refs") != {}
        or not isinstance(managed_refs, dict)
        or len(managed_refs) != 1
    ):
        raise S12ControlError("S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED")
    control_freeze_ref, target = next(iter(managed_refs.items()))
    if (
        not isinstance(control_freeze_ref, str)
        or re.fullmatch(
            r"refs/tags/s12-yoti-sandbox-runtime-freeze-r[1-9][0-9]{0,8}",
            control_freeze_ref,
        ) is None
        or (
            target is not None
            and (
                not isinstance(target, str)
                or re.fullmatch(r"[0-9a-f]{40}", target) is None
            )
        )
    ):
        raise S12ControlError("S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED")
    try:
        current = _release_repository_states(
            git_directories,
            path_records,
            control_freeze_ref=control_freeze_ref,
        )
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
        **({"attempt_binding": ACTIVE_ATTEMPT} if ACTIVE_ATTEMPT is not None else {}),
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
    if (owner_access & ~group_access) or (owner_access & ~other_access):
        # The group-class mode bits represent the ACL mask, not access granted
        # to the owning group.  A single named-user ACL below carries the
        # former owner's exact read/execute class without relying on NSS group
        # enumeration or making a GID an authorization capability.
        restricted = (restricted & ~0o070) | (
            (owner_access | group_access) << 3
        )
    return restricted


def _root_git_same_inode_transition_mode(
    current_mode: int, recorded_mode: int
) -> bool:
    """Accept only an index-executable-stable mode re-sealable exactly."""

    current_owner_executable = bool(current_mode & stat.S_IXUSR)
    recorded_owner_executable = bool(recorded_mode & stat.S_IXUSR)
    execute_classes_consistent = (
        not current_mode & 0o011 or current_owner_executable
    ) and (not recorded_mode & 0o011 or recorded_owner_executable)
    return (
        current_owner_executable == recorded_owner_executable
        and execute_classes_consistent
        and (current_mode == recorded_mode or not current_mode & 0o022)
    )


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
    if not (
        (owner_access & ~group_access) or (owner_access & ~other_access)
    ):
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


def _chmod_mutated_worktree_barrier_owner_acl(
    mode: int, uid: int, *, kind: str, current_mode: int
) -> bytes | None:
    """Return the exact generated ACL after a root-Git chmod transition."""

    acl = _worktree_barrier_owner_acl(mode, uid, kind=kind)
    if acl is None:
        return None
    header = struct.Struct("<I")
    entry = struct.Struct("<HHI")
    entries = []
    for offset in range(header.size, len(acl), entry.size):
        tag, permissions, identifier = entry.unpack_from(acl, offset)
        if tag == 0x01:
            permissions = (current_mode >> 6) & 0o7
        elif tag == 0x10:
            permissions = (current_mode >> 3) & 0o7
        elif tag == 0x20:
            permissions = current_mode & 0o7
        entries.append(entry.pack(tag, permissions, identifier))
    return header.pack(2) + b"".join(entries)


def _worktree_chmod_mutated_owner_acl_transition(
    path: Path, record: dict[str, Any], current_mode: int
) -> bool:
    """Prove a chmod-only mutation of the exact generated owner ACL."""

    try:
        expected = _chmod_mutated_worktree_barrier_owner_acl(
            int(record["mode"], 8),
            record["uid"],
            kind=record["kind"],
            current_mode=current_mode,
        )
        if expected is None or not hasattr(os, "getxattr"):
            return False
        actual = os.getxattr(
            path,
            "system.posix_acl_access",
            follow_symlinks=False,
        )
        return actual == expected and (
            _worktree_path_xattr_fingerprint(
                path, barrier_acl=expected
            )
            == record["xattr_fingerprint"]
        )
    except (KeyError, OSError, TypeError, ValueError, S12ControlError):
        return False


def _assert_post_chown_acl_preserves_access(
    path: Path,
    uid: int,
    required_access: int,
    target_mask: int,
    target_other: int,
    safe_code: str,
    *,
    reject_access_acl: bool = False,
    allow_mode_group_access: bool = False,
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
            # Worktree barriers require public or named-UID access. Repository
            # namespace locks retain their reviewed group contract explicitly.
            effective_access = (
                target_mask if allow_mode_group_access else target_other
            )
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
        if named_users:
            if required_access & ~(named_users[0] & target_mask):
                raise OSError
        else:
            possible_group_classes = [
                permissions & target_mask
                for tag, permissions, _identifier in entries
                if tag in {0x04, 0x08}
            ]
            if any(
                required_access & ~effective_access
                for effective_access in (
                    *possible_group_classes,
                    target_other,
                )
            ):
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
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                try:
                    acl_state, _locked_mode = _worktree_locked_acl_state(
                        path, record
                    )
                except S12ControlError:
                    if (
                        metadata.st_uid != record["uid"]
                        or metadata.st_gid != record["gid"]
                    ):
                        raise
                    # A reverse transition may already have restored the
                    # recorded owner and removed its temporary ACL.
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
                    _assert_no_security_capability(path)
                else:
                    raise OSError
                mode = stat.S_IMODE(metadata.st_mode)
                if metadata.st_uid != 0 or mode & 0o022:
                    raise OSError
                existing = root_records.get(path)
                if ACTIVE_ATTEMPT is not None and (existing is None or
                        (metadata.st_dev,metadata.st_ino) != (existing["device"],existing["inode"])):
                    # Follow-up objects must have a prospective binding. The
                    # legacy root-Git fallback is not authority for R13.
                    raise S12ControlError(MATERIALIZATION_RED)
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
            journal = _barrier_json(BARRIER_MARKER)
            journal["worktree_write_barrier"] = _worktree_barrier_payload(
                roots, records
            )
            _atomic_barrier_json(BARRIER_MARKER, journal)
        _lock_worktree_write_barrier(records)
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
                if (metadata.st_dev, metadata.st_ino) != (
                    record["device"],
                    record["inode"],
                ):
                    # Root Git may also have replaced a journaled path.  The
                    # old inode cannot be re-sealed; defer the current inode
                    # to the tracked-path pass below, which accepts only a
                    # root-owned, single-link regular file or directory that
                    # is already closed to group/other writers.
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
                    in {base_restricted_mode, generated_restricted_mode}
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
                current_mode = stat.S_IMODE(metadata.st_mode)
                root_transition = (
                    metadata.st_dev == record["device"]
                    and metadata.st_ino == record["inode"]
                    and metadata.st_uid == 0
                    and metadata.st_gid == record["gid"]
                    and _root_git_same_inode_transition_mode(
                        current_mode, mode
                    )
                )
                chmod_mutated_owner_acl_transition = (
                    root_transition
                    and _worktree_chmod_mutated_owner_acl_transition(
                        path, record, current_mode
                    )
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
                    _state, expected_locked_mode = (
                        _worktree_locked_acl_state(path, record)
                    )
                    if stat.S_IMODE(metadata.st_mode) == expected_locked_mode:
                        continue
                if owner_acl_transition:
                    source_acl = None
                    restricted_mode = generated_restricted_mode
                elif chmod_mutated_owner_acl_transition:
                    source_acl = None
                    restricted_mode = generated_restricted_mode
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
                    try:
                        _state, locked_mode = _worktree_locked_acl_state(
                            path, record
                        )
                    except S12ControlError:
                        raise S12ControlError(
                            "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
                        ) from None
                    if stat.S_IMODE(metadata.st_mode) == locked_mode:
                        expected_mode = locked_mode
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
                elif (
                    metadata.st_uid == record["uid"]
                    and stat.S_IMODE(metadata.st_mode)
                    in {
                        base_restricted_mode,
                        generated_restricted_mode,
                        *(
                            {original_mode}
                            if not original_mode & 0o022
                            else set()
                        ),
                    }
                ):
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
                        if metadata.st_uid != target_uid:
                            raise
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

    def finalize_release(self, relocated_paths: Sequence[Path] | None = None) -> None:
        """Cross an ordered watch barrier while a journal backup remains."""

        if relocated_paths is None:
            self.assert_unchanged()
        else:
            # Atomic exchange retains the watched directory inodes. Compare
            # against the pre-exchange baseline, never baseline exposed paths.
            self.assert_quarantined_unchanged(relocated_paths)
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
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary("PREDEPLOY_BARRIER_CAPTURE")
    worktree_barrier = _capture_worktree_write_barrier(roots, records)
    _atomic_barrier_json(
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
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary("PREATTEMPT_BARRIER_JOURNALED")
    return worktree_barrier


def _load_barrier_journal() -> tuple[
    dict[Path, dict[str, Any]],
    dict[str, Any],
    dict[Path, dict[Path, dict[str, Any]]] | None,
    str,
]:
    journal = _barrier_json(BARRIER_MARKER)
    repositories = journal.get("repositories")
    parent_record = journal.get("repository_parent")
    if (
        journal.get("schema")
        not in {
            BARRIER_SCHEMA,
            R12_BARRIER_SCHEMA,
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
    if journal_schema in {BARRIER_SCHEMA, R12_BARRIER_SCHEMA, XATTR_BARRIER_SCHEMA}:
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
        if journal_schema in {BARRIER_SCHEMA, R12_BARRIER_SCHEMA}:
            expected_record_keys.add("root_xattr_fingerprint")
        if set(record) != expected_record_keys:
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        _recorded_path_metadata(record, "root")
        _recorded_path_metadata(record, "git")
        if journal_schema in {BARRIER_SCHEMA, R12_BARRIER_SCHEMA}:
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
    journal_keys = set(journal)
    if journal_schema == R12_BARRIER_SCHEMA:
        _r12_validate_lineage(journal)
        journal_keys.remove("r12_metadata_reconciliation")
    if journal_keys not in (
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
            if schema not in {BARRIER_SCHEMA, R12_BARRIER_SCHEMA}:
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
        journal = _barrier_json(BARRIER_MARKER)
        journal["schema"] = R12_BARRIER_SCHEMA if schema == R12_BARRIER_SCHEMA else BARRIER_SCHEMA
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
        _atomic_barrier_json(BARRIER_MARKER, journal)
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
            allow_mode_group_access=True,
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
            allow_mode_group_access=True,
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
    # This owner outlives both the yielded body and its release cleanup. Only
    # an already-installed release guard may take over its event history.
    with _r13_guard_scope() as guards:
        with _serialized_repository_recovery_guarded(
            roots, records, parent_record, worktree_barrier, preserve_on_error,
            allow_journaled_transition, materialization_guards=guards,
        ) as barriers:
            yield barriers


@contextmanager
def _serialized_repository_recovery_guarded(
    roots: Sequence[Path] | None = None,
    records: dict[Path, dict[str, Any]] | None = None,
    parent_record: dict[str, Any] | None = None,
    worktree_barrier: dict[Path, dict[Path, dict[str, Any]]] | None = None,
    preserve_on_error: bool = False,
    allow_journaled_transition: bool = False,
    *,
    materialization_guards: _R13GuardStack,
):
    selected_roots = tuple(roots or (APPLICATION_ROOT, CONTROL_ROOT))
    metadata_paths = _repository_git_metadata_paths(selected_roots)
    transition_guard = _GitMetadataTransitionGuard(
        tuple(path for path in metadata_paths if not _is_recovery_guard(path))
    )
    selected_records: dict[Path, dict[str, Any]] = records or {}
    selected_worktree_barrier = worktree_barrier
    barriers: dict[Path, Path] = {}
    parent_locked = False
    transition_started = False
    completed = False
    git_handoff_guard: _GitMetadataTransitionGuard | None = None
    try:
        # Check a quiet interrupted epoch before any lock chmod/chown can
        # alter ctime. The new live stream then owns those declared transitions.
        writers = _r13_git_writers(selected_roots)
        transition_guard.assert_unchanged()
        if writers is not None:
            materialization_guards.retain(_r13_initial_worktree_guards(selected_roots, writers))
        tracked_paths = _tracked_worktree_regular_paths(
            selected_roots,
            allow_missing=allow_journaled_transition,
        )
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
        # Establish attributed, filesystem-wide coverage while the initial
        # recursive quarantine guard still owns the mutation history.
        if writers is not None:
            writers.directories = dict(barriers)
            writers.check()
        transition_guard.assert_quarantined_unchanged(tuple(barriers.values()))
        transition_guard.close()
        for git_directory in barriers.values():
            _validate_root_git_contract(git_directory)
        for root, git_dir in barriers.items():
            _clear_stale_git_locks(root, git_dir)
        global MATERIALIZATION_RECORDS, MATERIALIZATION_GUARDS
        previous_materialization = MATERIALIZATION_RECORDS
        previous_guards = MATERIALIZATION_GUARDS
        # Retain both allocation and successor watches across repositories,
        # immutable staging and the complete post-yield audit. Snapshot equality
        # alone must not erase an intervening foreign writer's event history.
        try:
            MATERIALIZATION_RECORDS = selected_worktree_barrier
            MATERIALIZATION_GUARDS = materialization_guards
            try:
                if ACTIVE_ATTEMPT is not None:
                    materialization_guards.assert_quiet()
                    _r13_boundary('REPOSITORY_BODY_ENTERED')
                yield barriers
                if ACTIVE_ATTEMPT is not None:
                    # Authorized Git writes have finished. Watch the complete
                    # quarantined metadata tree before exposing it, including
                    # deep refs/objects not covered by worktree/root watches.
                    if writers is None:
                        raise S12ControlError(GIT_WRITER_RED)
                    writers.check()
                    git_handoff_guard = _GitMetadataTransitionGuard(
                        tuple(barriers.values())
                    )
                    materialization_guards.callback(git_handoff_guard.close)
                    _r13_audit_materialized(selected_roots)
                # Legacy Git may normalize a journaled inode's mode. R13 only
                # accepts its prospectively bound objects; the guards above
                # remain live throughout the final identity checks.
                _lock_worktree_write_barrier(
                    selected_worktree_barrier,
                    allow_missing=allow_journaled_transition,
                )
                tracked_paths = _tracked_worktree_regular_paths(selected_roots)
                _assert_worktree_write_barrier(
                    selected_roots, selected_worktree_barrier
                )
                if _active_tracked_worktree_write_handle_count(tracked_paths) != 0:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
                materialization_guards.assert_quiet()
                for root, git_directory in barriers.items():
                    _selected_identity(root, git_directory)
                if _active_tracked_worktree_write_handle_count(tracked_paths) != 0:
                    raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
            finally:
                MATERIALIZATION_RECORDS = previous_materialization
                MATERIALIZATION_GUARDS = previous_guards
        except BaseException:
            # Leave the watches installed through fail-closed cleanup too.
            raise
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
                if ACTIVE_ATTEMPT is not None and GIT_WRITER_SCOPE is not None:
                    # Rename changes the selector, not the inode authority.
                    # Subsequent read-only audit commands use the live name
                    # while the same filesystem stream and handles persist.
                    GIT_WRITER_SCOPE.directories = {r:r/'.git' for r in selected_roots}
                release_guard: _WorktreeReleaseGuard | None = None
                release_quiescence: _GuardedHandleQuiescence | None = None
                release_attributes = None
                try:
                    if ACTIVE_ATTEMPT is not None and completed:
                        _r13_boundary("RELEASE_BARRIERS_EXCHANGED")
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
                        p for p in materialization_guards.paths
                        if p.exists() and not p.is_symlink()
                    )
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
                        if ACTIVE_ATTEMPT is not None:
                            # The final namespace permission/attribute handoff
                            # includes the parent, not just its repositories.
                            release_paths.add(DEPLOYMENT_LOCK_ROOT)
                    release_guard = _WorktreeReleaseGuard(
                        selected_roots,
                        tuple(release_paths),
                    )
                    if ACTIVE_ATTEMPT is not None:
                        release_attributes = _R12AttributeGuard(tuple(
                            p for p in release_paths if p.exists() and not p.is_symlink()
                        ), event_mask=0xFCE)
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
                    if git_handoff_guard is not None:
                        git_handoff_guard.finalize_release(tuple(
                            root / ".git" for root in selected_roots
                        ))
                    # Both watch sets overlap here. Drain/check the retained
                    # attributed history before any release metadata changes.
                    materialization_guards.close()
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
                    if ACTIVE_ATTEMPT is not None:
                        _r13_boundary("RELEASE_ATTRIBUTES_RESTORED")
                    release_guard.accept_release_attributes()

                    def validate_final_release() -> None:
                        release_quiescence.assert_quiesced()
                        if release_attributes is not None:
                            release_attributes.assert_quiet()
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
                            if ACTIVE_ATTEMPT is None:
                                _assert_hard_locked_repository_parent(parent_record)
                            elif _repository_parent_metadata() != parent_record:
                                raise S12ControlError("S12_1_REPOSITORY_PARENT_RED")
                        if release_attributes is not None:
                            release_attributes.assert_quiet()
                        if ACTIVE_ATTEMPT is not None:
                            writers.check()
                            _r13_boundary("RELEASE_SHUTDOWN")
                            release_attributes.assert_quiet()
                            writers.check()

                    if ACTIVE_ATTEMPT is not None and parent_locked:
                        # Restore while permission, attributed and filesystem
                        # guards still overlap. IN_IGNORED shutdown follows
                        # this last declared mutation, never precedes it.
                        _restore_repository_parent(parent_record)
                        _r13_boundary("RELEASE_PARENT_RESTORED")
                        release_guard.accept_release_attributes()
                        release_attributes.assert_quiet()
                        writers.check()

                    release_guard.finalize_release(
                        validate_final_release,
                        validate_release_shutdown,
                    )
                    release_guard = None
                    if release_attributes is not None:
                        release_attributes.assert_quiet()
                    if ACTIVE_ATTEMPT is not None:
                        # Attributed release guards still cover all existing
                        # directories while the writer epoch drains and retires.
                        _r13_retire_git_writers()
                        if release_attributes is not None:
                            release_attributes.assert_quiet()
                    if parent_locked:
                        if ACTIVE_ATTEMPT is None:
                            _restore_repository_parent(parent_record)
                        parent_locked = False
                except S12ControlError:
                    cleanup_failed = True
                    try:
                        if ACTIVE_ATTEMPT is not None:
                            for root in selected_roots:
                                if _barrier_path_present(_r13_location(root)):
                                    _r13_poison(_r13_location(root))
                        if parent_locked:
                            _lock_repository_parent(parent_record)
                        for root in selected_roots:
                            _lock_repository_root(root, selected_records[root])
                        for root in selected_roots:
                            _lock_repository_git_metadata(
                                root, selected_records[root]
                            )
                        if ACTIVE_ATTEMPT is not None:
                            for root in selected_roots:
                                _install_repository_recovery_barrier(
                                    root, selected_records[root]
                                )
                        # A failed writer epoch can never admit another Git
                        # reader. R13 already prospectively bound every new
                        # tracked path in selected_worktree_barrier; reseal
                        # that closed set without a fresh index enumeration.
                        # Reinstall Git barriers first so a failed worktree
                        # reseal cannot leave released Git namespaces behind.
                        _reseal_released_worktree_contract(
                            selected_roots,
                            selected_records,
                            selected_worktree_barrier,
                            include_current=completed and ACTIVE_ATTEMPT is None,
                        )
                    except S12ControlError:
                        pass
                finally:
                    if release_attributes is not None:
                        release_attributes.close()
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
                arguments = git_arguments("bundle", operation, "/dev/stdin")
                completed = _git_process(arguments,timeout=300,stdin=input_stream)
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
    managed_refs = record.get("managed_refs", {})
    # Restore the authenticated backup's finite freeze ref, not this newer
    # controller's tag. Never extend this to arbitrary refs or floating names.
    if not isinstance(managed_refs, dict) or len(managed_refs) > 1 or any(
        not isinstance(reference, str)
        or re.fullmatch(r"refs/tags/s12-yoti-sandbox-runtime-freeze-r[1-9][0-9]{0,8}", reference) is None
        or (target is not None and (not isinstance(target, str)
            or re.fullmatch(r"[0-9a-f]{40}", target) is None))
        for reference, target in managed_refs.items()
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    if (
        detached is not (branch is None)
        or (
            branch is not None
            and (not isinstance(branch, str) or branch.startswith("-"))
        )
    ):
        raise S12ControlError("S12_1_BACKUP_REPOSITORY_STATE_RED")
    _seed_repository_from_bundle(root, git_arguments, bundle, record)
    if ACTIVE_ATTEMPT is not None:
        _r13_materialize_undo(root, git_directory)
        _run(git_arguments("read-tree", commit))
        _run(git_arguments("update-ref", "--no-deref", "HEAD", commit))
    else:
        _run(git_arguments("checkout", "--force", "--detach", commit))
        _run(git_arguments(*clean_arguments))
    _run(git_arguments("branch", "-f", release_branch, release_branch_tip))
    if branch is not None:
        if branch != release_branch:
            _run(git_arguments("branch", "-f", branch, commit))
        if ACTIVE_ATTEMPT is not None:
            _run(git_arguments("symbolic-ref", "HEAD", "refs/heads/"+branch))
        else:
            _run(git_arguments("checkout", "--force", branch))
            _run(git_arguments(*clean_arguments))
    for reference, target in sorted(managed_refs.items()):
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
    # Use the same narrow quarantine-directory exclusion as every other
    # guarded identity check. Unrelated untracked paths still fail closed.
    identity = _selected_identity(root, git_directory)
    if identity != (commit, record["tree"]):
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
    if ACTIVE_ATTEMPT is not None:
        release = ACTIVE_ATTEMPT["release"]
        if (control_commit != release["control_commit"]
                or _bare_root_git(control_fetch, "rev-parse", f"refs/tags/{FREEZE_TAG}") != release["tag_object"]
                or _bare_root_git(control_fetch, "rev-parse", "refs/s12/control-main^{tree}") != release["control_tree"]):
            raise S12ControlError(FOLLOWUP_RED)


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
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary('APPLICATION_FETCHED')
        _r13_materialize(APPLICATION_ROOT, application_git, APPLICATION_COMMIT, "main")
    else:
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
    if ACTIVE_ATTEMPT is not None:
        _r13_materialize(CONTROL_ROOT, control_git, target_control, "control-main")
    else:
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


def _private_json(
    path: Path, safe_code: str, *, maximum: int = 131072
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
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
    if ACTIVE_ATTEMPT is not None and (
        attempt.get("attempt_binding") != ACTIVE_ATTEMPT
        or index.get("attempt_binding") != ACTIVE_ATTEMPT
    ):
        raise S12ControlError("S12_1_FOLLOWUP_RECOVERY_BINDING_RED")
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
        and (ACTIVE_ATTEMPT is None or result.get("attempt_binding") == ACTIVE_ATTEMPT)
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
    # Retain the pre-attempt journal until the bound release completion is
    # durable. Normalization recovers interrupted unlink/completion steps.
    _prepare_barrier_release_backup()
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary("PREATTEMPT_RELEASE_BACKED_UP")
    _durable_unlink(BARRIER_MARKER)
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary("PREATTEMPT_RELEASE_UNLINKED")
    _write_barrier_release_completion()
    if ACTIVE_ATTEMPT is not None:
        _r13_boundary("PREATTEMPT_RELEASE_COMPLETED")
    _durable_unlink(BARRIER_RELEASE_BACKUP)
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
    if ACTIVE_ATTEMPT is not None:
        _ensure_private_directory_durable(STATE_ROOT, Path("/"))
        _r13_boundary("FOLLOWUP_NAMESPACE_CREATED")
        _r13_begin_attempt_observation()
        _r13_boundary("PREDEPLOY_PREFLIGHT")
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
    release_observation: _GitMetadataTransitionGuard | None = None
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
                        **({"attempt_binding": ACTIVE_ATTEMPT} if ACTIVE_ATTEMPT is not None else {}),
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
                    if ACTIVE_ATTEMPT is not None:
                        _r13_boundary("REPOSITORIES_MATERIALIZED")
                    release_repository_state = _release_repository_states(
                        git_directories, path_records
                    )
                    _atomic_json(
                        ATTEMPT_MARKER,
                        {
                            "attempt": 1,
                            **({"attempt_binding": ACTIVE_ATTEMPT} if ACTIVE_ATTEMPT is not None else {}),
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
                    if ACTIVE_ATTEMPT is not None:
                        # Install before the filesystem writer epoch retires.
                        # This immutable subtree admits NO mutations (including
                        # controller/root writes); ordinary runtime reads need
                        # no writer grant. Creation of any new child is RED.
                        release_observation = _GitMetadataTransitionGuard(
                            (RELEASE_ROOT,), allow_root_lock_events=False
                        )
                        if GIT_WRITER_SCOPE is None:
                            raise S12ControlError(GIT_WRITER_RED)
                        GIT_WRITER_SCOPE.check()
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
        if release_observation is not None:
            _r13_boundary("RELEASE_TREE_PREVERIFY")
            release_observation.assert_unchanged()
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
        if release_observation is not None:
            _r13_boundary("RELEASE_TREE_PREACTIVATION")
            release_observation.assert_unchanged()
        start = _run(["systemctl", "start", UNIT_NAME], check=False, timeout=900)
        if release_observation is not None:
            _r13_boundary("RELEASE_TREE_ACTIVATED")
            release_observation.assert_unchanged()
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
        if release_observation is not None:
            _r13_boundary("RELEASE_TREE_FINAL_AUDIT")
            # The existing ordered IN_IGNORED shutdown checks queued history
            # through the final inactive/public audit. No release execution
            # follows this boundary. Process loss never resumes activation:
            # the consumed attempt can only enter canonical recovery.
            release_observation.finalize_release()
        result = {
            "ok": True,
            "safe_code": "S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN",
            **({"attempt_binding": ACTIVE_ATTEMPT} if ACTIVE_ATTEMPT is not None else {}),
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
        # Observation failure must NOT poison the global Git executor and
        # thereby prevent systemctl stop or the verified backup rollback.
        # Abort this immutable epoch before the authorized release removal.
        if release_observation is not None:
            release_observation.close()
        if repository_sync_failure is not None:
            pass
        elif mutation_started and backup is not None and index is not None:
            rollback_once(backup, index, release_repository_state)
        elif _barrier_journal_present():
            _recover_repository_barrier_only()
        raise
    finally:
        if release_observation is not None:
            release_observation.close()


def deploy() -> dict[str, Any]:
    with _exclusive_deployment_lock():
        return _deploy_locked()


def simulator() -> dict[str, Any]:
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
    from scripts.tu1nz_adult_commercial_s12_1_simulator import run_simulator

    return run_simulator()


def _r12_xattr_fingerprint(path: Path, identity: dict, attrs: dict) -> str:
    """Bind a specified identity; callers must never relabel this as history."""
    payload = bytearray()
    for name, value_hex in sorted(attrs.items(), key=lambda item: os.fsencode(item[0])):
        name_bytes, value = os.fsencode(name), bytes.fromhex(value_hex)
        if name == "system.posix_acl_access":
            value = _normalize_posix_acl_mode_entries(value)
        payload.extend(len(name_bytes).to_bytes(8, "big") + name_bytes)
        payload.extend(len(value).to_bytes(8, "big") + value)
    return hashlib.sha256(
        b"present\0" + os.fsencode(path) + b"\0"
        + str(identity["device"]).encode() + b":"
        + str(identity["inode"]).encode() + b"\0" + payload + b"\0"
    ).hexdigest()


def _r12_stat(fd: int) -> dict:
    metadata = os.fstat(fd)
    kind = ("directory" if stat.S_ISDIR(metadata.st_mode) else
            "regular" if stat.S_ISREG(metadata.st_mode) else "invalid")
    if kind == "invalid" or (kind == "regular" and metadata.st_nlink != 1):
        raise S12ControlError(R12_RED)
    return dict(device=metadata.st_dev, inode=metadata.st_ino, kind=kind,
                uid=metadata.st_uid, gid=metadata.st_gid,
                mode=f"{stat.S_IMODE(metadata.st_mode):04o}", links=metadata.st_nlink)


def _r12_birth(fd: int) -> list[int]:
    # statx(AT_EMPTY_PATH): a second, kernel-provided identity binding for
    # crash/resume. An unsupported birth time is NOT silently downgraded.
    library = ctypes.CDLL(None, use_errno=True)
    function = library.statx
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_uint, ctypes.c_void_p]
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(256)
    if function(fd, b"", 0x1000 | 0x100, 0x800, buffer) != 0:
        raise S12ControlError(R12_RED)
    if not struct.unpack_from("=I", buffer.raw)[0] & 0x800:
        raise S12ControlError(R12_RED)
    seconds, nanoseconds = struct.unpack_from("=qI", buffer.raw, 80)
    if seconds <= 0 or nanoseconds >= 1_000_000_000:
        raise S12ControlError(R12_RED)
    return [seconds, nanoseconds]


def _r12_attrs(fd: int) -> dict[str, str]:
    names = sorted(os.listxattr(fd))
    if any(name not in {"system.posix_acl_access", "system.posix_acl_default"}
           for name in names):
        raise S12ControlError(R12_RED)
    values = {name: os.getxattr(fd, name).hex() for name in names}
    if names != sorted(os.listxattr(fd)):
        raise S12ControlError(R12_RED)
    return values


def _r12_open(path: Path, *, inspect_symlink: bool = False) -> int:
    # Pin each ancestor; never follow a symlink, including an inspected leaf.
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = next_fd
        return os.open(path.name, (os.O_PATH if inspect_symlink else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
                       | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def _r12_snapshot(path: Path, fd: int, content: str | None) -> dict:
    before = os.fstat(fd)
    value = dict(metadata=_r12_stat(fd), birth=_r12_birth(fd), xattrs=_r12_attrs(fd))
    if content is not None and _sha256_descriptor(fd) != content:
        raise S12ControlError(R12_RED)
    after = os.fstat(fd)
    fresh = _r12_open(path)
    try:
        if _r12_stat(fresh) != value["metadata"] or _r12_birth(fresh) != value["birth"]:
            raise S12ControlError(R12_RED)
    finally:
        os.close(fresh)
    for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"):
        if getattr(before, field) != getattr(after, field):
            raise S12ControlError(R12_RED)
    return value


def _r12_chmod_attrs(attrs: dict, mode: int) -> dict:
    copied = dict(attrs)
    name = "system.posix_acl_access"
    if name in copied:
        raw = bytes.fromhex(copied[name])
        _normalize_posix_acl_mode_entries(raw)  # validate framing
        entries = list(struct.iter_unpack("<HHI", raw[4:]))
        has_mask = any(tag == 0x10 for tag, _, _ in entries)
        changed = {1: (mode >> 6) & 7, 0x10 if has_mask else 4: (mode >> 3) & 7,
                   0x20: mode & 7}
        copied[name] = (raw[:4] + b"".join(struct.pack("<HHI", tag,
                         changed.get(tag, permissions), identifier)
                         for tag, permissions, identifier in entries)).hex()
    return copied


def _r12_plan(entry: dict, observed: dict) -> list[dict]:
    """Finite syscall-boundary states, saved BEFORE the first metadata write."""
    states = [json.loads(json.dumps(observed))]
    def add(operation, value):
        states.append(dict(metadata=dict(value["metadata"]), birth=value["birth"],
                           xattrs=dict(value["xattrs"]), operation=operation))
    current = json.loads(json.dumps(observed))
    current["metadata"].update(uid=0, gid=entry["target"]["gid"])
    add("chown", current)
    if entry["historical_record"] is None:
        if "system.posix_acl_default" in current["xattrs"]:
            del current["xattrs"]["system.posix_acl_default"]
            add("remove_default_acl", current)
        acl = _worktree_barrier_owner_acl(int(entry["target"]["mode"], 8),
                  entry["target"]["uid"], kind=current["metadata"]["kind"])
        if acl is None:
            raise S12ControlError(R12_RED)
        current["xattrs"]["system.posix_acl_access"] = acl.hex()
        entries = list(struct.iter_unpack("<HHI", acl[4:]))
        bits = {tag: permissions for tag, permissions, _ in entries if tag in {1, 0x10, 0x20}}
        mode = (int(current["metadata"]["mode"], 8) & 0o7000) | bits[1] << 6 | bits[0x10] << 3 | bits[0x20]
        current["metadata"]["mode"] = f"{mode:04o}"
        add("set_access_acl", current)
    mode = int(entry["target"]["mode"], 8) & ~0o222
    current["xattrs"] = _r12_chmod_attrs(current["xattrs"], mode)
    current["metadata"]["mode"] = f"{mode:04o}"
    add("chmod", current)
    return states


class _R12AttributeGuard:
    """PID-attributed FAN_ATTRIB events complement the existing open barrier.

    Inotify alone cannot distinguish our fchmod from a competing owner's
    chmod. Attribute events from ANY other TID (including root) are RED.
    """
    def __init__(self, paths: Sequence[Path], *, event_mask: int = 4):
        self.fd = None
        self.event_mask = event_mask
        library = ctypes.CDLL(None, use_errno=True)
        init = library.fanotify_init
        init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        init.restype = ctypes.c_int
        descriptor = init(0x303, os.O_RDONLY | os.O_CLOEXEC)
        if descriptor < 0:
            raise S12ControlError(R12_RED)
        self.fd = descriptor
        mark = library.fanotify_mark
        mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                         ctypes.c_int, ctypes.c_char_p]
        mark.restype = ctypes.c_int
        try:
            for path in sorted(set(paths), key=os.fsencode):
                mask = event_mask | (0x48000000 if path.is_dir() else 0)
                if mark(descriptor, 1, mask, -100, os.fsencode(path)) != 0:
                    raise S12ControlError(R12_RED)
            self.assert_quiet()
        except BaseException:
            self.close()
            raise

    def assert_quiet(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            offset = 0
            while offset < len(data):
                size, version, _, metadata_size, mask, fd, pid = struct.unpack_from("=IBBHQii", data, offset)
                if fd >= 0:
                    os.close(fd)
                if size < 24 or offset + size > len(data) or metadata_size != 24 or version != 3:
                    raise S12ControlError(R12_RED)
                if mask & ~(self.event_mask | 0x40000000) or pid != threading.get_native_id():
                    raise S12ControlError(R12_RED)
                offset += size

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _r12_load_contract(path: Path) -> dict:
    # Digest pins the ENTIRE finite schema and all 254 entries; no arbitrary
    # supplied JSON can expand paths, owners, modes or accepted xattrs.
    raw = _read_private_backup_blob(path, R12_CONTRACT_SHA256, R12_RED)
    value = json.loads(raw)
    if value["schema"] != "TU1NZ_S12_1_R12_METADATA_CONTRACT_V1":
        raise S12ControlError(R12_RED)
    return value


def _r12_validate_lineage(journal: dict, *, completing_abort: bool = False) -> None:
    if not completing_abort and _barrier_path_present(STATE_ROOT / "repository-barrier.r12-abort.json"):
        raise S12ControlError("S12_1_R12_ABORT_FINALIZATION_REQUIRED")
    lineage = journal.get("r12_metadata_reconciliation")
    if not isinstance(lineage, dict) or set(lineage) != {
        "contract_sha256", "original_journal_sha256", "ledger_sha256"
    } or lineage["contract_sha256"] != R12_CONTRACT_SHA256:
        raise S12ControlError(R12_RED)
    original = STATE_ROOT / "repository-barrier.r12-original.json"
    _read_private_backup_blob(original, lineage["original_journal_sha256"], R12_RED)
    ledger = json.loads(_read_private_backup_blob(
        STATE_ROOT / "repository-barrier.r12-bindings.json", lineage["ledger_sha256"], R12_RED))
    if (ledger.get("schema") != "TU1NZ_S12_1_R12_BINDINGS_V1"
            or ledger.get("phase") != "SEALED"
            or ledger.get("contract_sha256") != R12_CONTRACT_SHA256
            or ledger.get("original_journal_sha256") != lineage["original_journal_sha256"]
            or ledger.get("historical_continuity") is not False):
        raise S12ControlError(R12_RED)


def _r12_abort(contract: dict) -> None:
    """Durably terminate, not retry, a detected violation.

    Keep the published V4/SEALED pair hash-consistent until V3 is restored.
    The receipt blocks V4 consumption and any reconciliation retry across
    interruption of this sequence. Only journal finalization may resume.
    """
    receipt_path = STATE_ROOT / "repository-barrier.r12-abort.json"
    original_sha = contract["protected_inputs"]["repository-barrier.json"]
    receipt = dict(schema="TU1NZ_S12_1_R12_ABORT_V1", contract_sha256=R12_CONTRACT_SHA256,
                   original_journal_sha256=original_sha, historical_continuity=False)
    original_path = STATE_ROOT / "repository-barrier.r12-original.json"
    _read_private_backup_blob(original_path, original_sha, R12_RED)
    if _barrier_path_present(receipt_path):
        if _barrier_json(receipt_path) != receipt:
            raise S12ControlError(R12_RED)
    else:
        _atomic_barrier_json(receipt_path, receipt)
    if _sha256(BARRIER_MARKER) != original_sha:
        journal = _barrier_json(BARRIER_MARKER)
        if journal.get("schema") != R12_BARRIER_SCHEMA:
            raise S12ControlError(R12_RED)
        _r12_validate_lineage(journal, completing_abort=True)
        if journal["r12_metadata_reconciliation"]["original_journal_sha256"] != original_sha:
            raise S12ControlError(R12_RED)
        _atomic_copy(original_path, BARRIER_MARKER, 0o600, 0, 0)
        _read_private_backup_blob(BARRIER_MARKER, original_sha, R12_RED)
    ledger_path = STATE_ROOT / "repository-barrier.r12-bindings.json"
    ledger = _barrier_json(ledger_path)
    if (ledger.get("schema") != "TU1NZ_S12_1_R12_BINDINGS_V1"
            or ledger.get("contract_sha256") != R12_CONTRACT_SHA256
            or ledger.get("original_journal_sha256") != original_sha
            or ledger.get("phase") not in {"PREPARED", "SEALED", "ABORTED"}):
        raise S12ControlError(R12_RED)
    ledger["phase"] = "ABORTED"
    _atomic_barrier_json(ledger_path, ledger)


def _r12_validate_git(contract: dict, index: dict, backup: Path) -> dict:
    """Bind HEAD/index to the approved release, not an observed index baseline."""
    selected = {}
    for key, root in (("application", APPLICATION_ROOT), ("control", CONTROL_ROOT)):
        git_directory = _repository_recovery_git_directory(root)
        commit = contract["release_commits"][key]
        if _selected_git(root, git_directory, "for-each-ref", "--format=%(refname)", "refs/replace/"):
            raise S12ControlError(R12_RED)
        if _selected_git(root, git_directory, "rev-parse", "HEAD") != commit:
            raise S12ControlError(R12_RED)
        _validate_canonical_index(root, git_directory)
        tree = _bounded_nul_command_records(_selected_git_arguments(
            root, git_directory, "ls-tree", "-r", "-z", commit), R12_RED)
        staged = _bounded_nul_command_records(_selected_git_arguments(
            root, git_directory, "ls-files", "--stage", "-z", "--"), R12_RED)
        expected = []
        names = set()
        for item in tree:
            prefix, separator, name = item.partition(b"\t")
            fields = prefix.split(b" ")
            if (not separator or len(fields) != 3 or fields[0] not in {b"100644", b"100755", b"120000"}
                    or fields[1] != b"blob" or re.fullmatch(rb"[0-9a-f]{40}", fields[2]) is None):
                raise S12ControlError(R12_RED)
            _validated_git_paths((name,), R12_RED)
            if name in names:
                raise S12ControlError(R12_RED)
            names.add(name)
            selected[root / os.fsdecode(name)] = (fields[0].decode(), fields[2].decode())
            expected.append(fields[0] + b" " + fields[2] + b" 0\t" + name)
        if sorted(expected) != sorted(staged):
            raise S12ControlError(R12_RED)
        record = index[key]
        bundle = backup / (key + ".bundle")
        _verify_git_bundle(root, bundle, git_directory)
        if _git_bundle_heads(root, bundle, git_directory).get("HEAD") != record["commit"]:
            raise S12ControlError(R12_RED)
        if _selected_git(root, git_directory, "rev-parse", record["commit"] + "^{tree}") != record["tree"]:
            raise S12ControlError(R12_RED)
        original_paths = _tracked_path_hash_payload(_tracked_tree_paths(
            root, git_directory, record["commit"], R12_RED))
        if original_paths != _read_private_backup_blob(backup / (key + ".tracked-path-hashes"),
                record["tracked_path_hashes_sha256"], R12_RED):
            raise S12ControlError(R12_RED)
    return selected


def _r12_scope_snapshot(paths: set[Path], selected: dict) -> dict:
    """Stable content/identity/metadata evidence across watch installation.

    ctime is included so a write or metadata change restored before the second
    snapshot is still a violation. Missing names and symlinks are explicit.
    Present indexed contents must match canonical Git blobs, not current bytes
    adopted as a new release baseline. This is not historical metadata proof.
    """
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    result = {}
    for path in sorted(paths | set(selected), key=os.fsencode):
        try:
            before = path.lstat()
        except FileNotFoundError:
            result[path] = None
            continue
        symlink = stat.S_ISLNK(before.st_mode)
        fd = _r12_open(path, inspect_symlink=symlink)
        try:
            opened = os.fstat(fd)
            identity = tuple(getattr(before, key) for key in fields)
            if tuple(getattr(opened, key) for key in fields) != identity:
                raise S12ControlError(R12_RED)
            attrs = _stable_xattr_payload(path, before)
            birth = _r12_birth(fd)
            blob = None
            if symlink:
                link = os.fsencode(os.readlink(path))
                blob = hashlib.sha1(b"blob " + str(len(link)).encode() + b"\0" + link).hexdigest()
            elif stat.S_ISREG(before.st_mode):
                if before.st_nlink != 1:
                    raise S12ControlError(R12_RED)
                digest = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
                while chunk := os.read(fd, 1024 * 1024):
                    digest.update(chunk)
                blob = digest.hexdigest()
            elif not stat.S_ISDIR(before.st_mode):
                raise S12ControlError(R12_RED)
            if path in selected:
                mode, expected_blob = selected[path]
                if (blob != expected_blob or symlink != (mode == "120000")
                        or (not symlink and bool(before.st_mode & 0o100) != (mode == "100755"))):
                    raise S12ControlError(R12_RED)
            if (tuple(getattr(os.fstat(fd), key) for key in fields) != identity
                    or tuple(getattr(path.lstat(), key) for key in fields) != identity):
                raise S12ControlError(R12_RED)
            result[path] = (identity, birth, attrs, blob)
        finally:
            os.close(fd)
    return result


def _r12_index_guard_paths(roots: Sequence[Path]) -> set[Path]:
    """Guard every index name, including absent names and symlink parents.

    A missing inode cannot be marked; its nearest existing ancestor detects
    creation. Never follow an index symlink into an unrelated object. Its
    directory entry is watched through its parent instead. Intermediate
    symlinks and non-directory components are ambiguous and fail closed.
    """
    guarded = set(roots)
    for root in roots:
        names = _bounded_nul_command_records(_selected_git_arguments(
            root, _repository_recovery_git_directory(root), "ls-files", "-z", "--"), R12_RED)
        seen = set()
        for name in names:
            parts = name.split(b"/")
            if name.startswith(b"/") or any(p in {b"", b".", b".."} for p in parts) or name in seen:
                raise S12ControlError(R12_RED)
            seen.add(name)
            path = root
            for position, part in enumerate(parts):
                path = path / os.fsdecode(part)
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    break  # The already included ancestor watches creation.
                except OSError:
                    raise S12ControlError(R12_RED) from None
                if position < len(parts) - 1:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise S12ControlError(R12_RED)
                    guarded.add(path)
                elif stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode):
                    guarded.add(path)
                elif not stat.S_ISLNK(metadata.st_mode):
                    raise S12ControlError(R12_RED)
    return guarded


def _r12_reconcile_locked(contract_path: Path) -> dict:
    """Explicit future maintenance entrypoint: seals only; NEVER runs recovery.

    Called under the existing exclusive deployment flock. Historical evidence
    is immutable. Even after success both Git guards stay installed.
    """
    if os.geteuid() != 0 or sys.platform != "linux":
        raise S12ControlError(R12_RED)
    contract = _r12_load_contract(contract_path)
    roots = (APPLICATION_ROOT, CONTROL_ROOT)
    if contract["roots"] != dict(application=str(roots[0]), control=str(roots[1])):
        raise S12ControlError(R12_RED)
    by_name = dict(zip(("application", "control"), roots))
    original_path = STATE_ROOT / "repository-barrier.r12-original.json"
    ledger_path = STATE_ROOT / "repository-barrier.r12-bindings.json"
    original_sha = contract["protected_inputs"]["repository-barrier.json"]
    backup = BACKUP_ROOT / contract["backup_name"]
    for private in (STATE_ROOT, backup):
        _validate_secure_directory_chain(private, Path("/"))
    for name, path in (("deployment-attempted.json", ATTEMPT_MARKER),
                       ("restore-index.json", backup / "restore-index.json")):
        _read_private_backup_blob(path, contract["protected_inputs"][name], R12_RED)
    if _barrier_path_present(STATE_ROOT / "repository-barrier.r12-abort.json"):
        _r12_abort(contract)
        raise S12ControlError("S12_1_R12_ABORTED_NO_RETRY")
    journal = _barrier_json(BARRIER_MARKER)
    if journal["schema"] == R12_BARRIER_SCHEMA:
        _r12_validate_lineage(journal)
        # A completed transaction is never reapplied and is not stale health
        # evidence. The next, separately authorized recovery must revalidate.
        raise S12ControlError("S12_1_R12_ALREADY_SEALED_RECOVERY_PREFLIGHT_REQUIRED")
    original_raw = _read_private_backup_blob(BARRIER_MARKER, original_sha, R12_RED)
    records, parent_record, worktree, schema = _load_barrier_journal()
    if schema != BARRIER_SCHEMA or worktree is None:
        raise S12ControlError(R12_RED)
    for root in (*roots, DEPLOYMENT_LOCK_ROOT):
        metadata = root.lstat()
        if root.is_symlink() or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise S12ControlError(R12_RED)
    _assert_repository_parent_xattrs(parent_record)
    for root in roots:
        _assert_repository_root_xattrs(root, records[root])
    index = _private_json(backup / "restore-index.json", R12_RED)
    for key in ("application", "control"):
        record = index[key]
        for suffix, field in ((".bundle", "bundle_sha256"),
                              (".tracked-path-hashes", "tracked_path_hashes_sha256")):
            _read_private_backup_blob(backup / (key + suffix), record[field], R12_RED)
        if _reflog_tree_digest(backup / (key + ".reflogs")) != record["reflog_snapshot_sha256"]:
            raise S12ControlError(R12_RED)
    # This is a narrowly bound repair of an existing quarantine, not a path
    # to take ownership of an unguarded checkout.
    for expected in contract["guards"]:
        path = by_name[expected["repository"]] / expected["name"]
        fd = _r12_open(path)
        try:
            if _r12_stat(fd) != expected["metadata"]:
                raise S12ControlError(R12_RED)
        finally:
            os.close(fd)
    entries = sorted(contract["entries"], key=lambda e: (len(Path(e["path"]).parts), e["repository"], e["path"]))
    paths = [by_name[e["repository"]] / e["path"] for e in entries]
    metadata_paths = _repository_git_metadata_paths(roots)
    git_installation_snapshot = (
        _git_metadata_transition_fingerprint(metadata_paths),
        _r12_scope_snapshot(set(metadata_paths), {}),
    )
    selected = _r12_validate_git(contract, index, backup)
    index_guarded = _r12_index_guard_paths(roots)
    tracked = _tracked_worktree_regular_paths(roots, allow_missing=True)
    if (_competing_control_sync_count() or _active_repository_git_count(roots)
            or _active_recovery_git_handle_count(metadata_paths)
            or _active_tracked_worktree_write_handle_count(tracked)):
        raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
    # Point-in-time scans are insufficient: a writer can open an unrelated
    # tracked name after them. Include existing ancestors of absent entries
    # and symlink entries too; regular present files alone are insufficient.
    guarded = set(paths) | index_guarded
    for path in tuple(guarded - set(roots)):
        root = next(root for root in roots if root in path.parents)
        guarded.update(parent for parent in path.parents if parent == root or root in parent.parents)
    installation_snapshot = _r12_scope_snapshot(guarded, selected)
    guard = None
    git_guard = None
    attrs_guard = None
    quiescence = None
    descriptors = []
    try:
        git_guard = _GitMetadataTransitionGuard(tuple(
            path for path in metadata_paths if not _is_recovery_guard(path)),
            allow_root_lock_events=False)
        guard = _WorktreeReleaseGuard(roots, tuple(guarded))
        attrs_guard = _R12AttributeGuard(tuple(guarded))
        quiescence = _GuardedHandleQuiescence(tuple(guarded), roots)
        quiescence.acquire()
        if (_git_metadata_transition_fingerprint(metadata_paths),
                _r12_scope_snapshot(set(metadata_paths), {})) != git_installation_snapshot:
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        if (_r12_validate_git(contract, index, backup) != selected
                or _r12_scope_snapshot(guarded, selected) != installation_snapshot):
            raise S12ControlError(R12_RED)
        if _r12_index_guard_paths(roots) != index_guarded:
            raise S12ControlError(R12_RED)
        git_guard.assert_unchanged()
        if _active_tracked_worktree_write_handle_count(tracked):
            raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")
        for path in paths:
            descriptors.append(_r12_open(path))
        if ledger_path.exists() or ledger_path.is_symlink():
            ledger = _barrier_json(ledger_path)
            _read_private_backup_blob(original_path, original_sha, R12_RED)
            if (ledger.get("schema") != "TU1NZ_S12_1_R12_BINDINGS_V1"
                    or ledger.get("contract_sha256") != R12_CONTRACT_SHA256
                    or ledger.get("original_journal_sha256") != original_sha
                    or ledger.get("phase") not in {"PREPARED", "SEALED"}
                    or ledger.get("historical_continuity") is not False
                    or len(ledger.get("bindings", [])) != len(entries)):
                raise S12ControlError(R12_RED)
        else:
            bindings = []
            for entry, path, fd in zip(entries, paths, descriptors):
                root = by_name[entry["repository"]]
                old = worktree[root].get(path)
                if old != entry["historical_record"]:
                    raise S12ControlError(R12_RED)
                current = _r12_snapshot(path, fd, entry["content_sha256"])
                if current["metadata"] != entry["admission"] or current["xattrs"] != entry["admission_xattrs"]:
                    raise S12ControlError(R12_RED)
                if old is not None and _r12_xattr_fingerprint(path, old, entry["target"]["xattrs"]) != old["xattr_fingerprint"]:
                    raise S12ControlError(R12_RED)
                successor = dict(entry["target"])
                successor.pop("xattrs")
                successor.update(kind=current["metadata"]["kind"], device=current["metadata"]["device"], inode=current["metadata"]["inode"],
                                 xattr_fingerprint=_r12_xattr_fingerprint(path, current["metadata"], entry["target"]["xattrs"]))
                bindings.append(dict(path=str(path), provenance=entry["provenance"], historical_record=old,
                                     successor=successor, states=_r12_plan(entry, current), step=0, intent=None))
            guard.assert_no_events()
            attrs_guard.assert_quiet()
            quiescence.assert_quiesced()
            if original_path.exists() or original_path.is_symlink():
                _read_private_backup_blob(original_path, original_sha, R12_RED)
            else:
                _write_private_backup_blob(original_path, original_raw)
            ledger = dict(schema="TU1NZ_S12_1_R12_BINDINGS_V1", phase="PREPARED",
                          contract_sha256=R12_CONTRACT_SHA256, original_journal_sha256=original_sha,
                          historical_continuity=False, bindings=bindings)
            _atomic_barrier_json(ledger_path, ledger)
        # Bind the ledger to the exact admission contract again on resume.
        for entry, path, fd, binding in zip(entries, paths, descriptors, ledger["bindings"]):
            if binding["path"] != str(path) or binding["historical_record"] != entry["historical_record"]:
                raise S12ControlError(R12_RED)
            initial = binding["states"][0]
            if initial["metadata"] != entry["admission"] or initial["xattrs"] != entry["admission_xattrs"] or binding["states"] != _r12_plan(entry, initial):
                raise S12ControlError(R12_RED)
            expected_successor = dict(entry["target"])
            expected_successor.pop("xattrs")
            expected_successor.update(kind=initial["metadata"]["kind"],
                device=initial["metadata"]["device"], inode=initial["metadata"]["inode"],
                xattr_fingerprint=_r12_xattr_fingerprint(path, initial["metadata"], entry["target"]["xattrs"]))
            if binding["successor"] != expected_successor or binding["provenance"] != entry["provenance"]:
                raise S12ControlError(R12_RED)
            states = binding["states"]
            while True:
                step = binding["step"]
                if (type(step) is not int or not 0 <= step < len(states)
                        or (binding["intent"] is not None and (
                            type(binding["intent"]) is not int or binding["intent"] != step + 1))):
                    raise S12ControlError(R12_RED)
                actual = _r12_snapshot(path, fd, entry["content_sha256"])
                expected = {k:v for k,v in states[step].items() if k != "operation"}
                if actual != expected:
                    pending = binding["intent"]
                    if pending is None or pending >= len(states) or actual != {k:v for k,v in states[pending].items() if k != "operation"}:
                        raise S12ControlError(R12_RED)
                    binding.update(step=pending, intent=None)
                    _atomic_barrier_json(ledger_path, ledger)
                    continue
                if step == len(states) - 1:
                    break
                binding["intent"] = step + 1
                _atomic_barrier_json(ledger_path, ledger)
                quiescence.assert_quiesced()
                attrs_guard.assert_quiet()
                guard.accept_release_attributes()
                operation = states[step + 1]["operation"]
                if operation == "chown":
                    os.fchown(fd, 0, entry["target"]["gid"])
                elif operation == "remove_default_acl":
                    os.removexattr(fd, "system.posix_acl_default")
                elif operation == "set_access_acl":
                    os.setxattr(fd, "system.posix_acl_access", bytes.fromhex(states[step + 1]["xattrs"]["system.posix_acl_access"]))
                elif operation == "chmod":
                    os.fchmod(fd, int(states[step + 1]["metadata"]["mode"], 8))
                else:
                    raise S12ControlError(R12_RED)
                os.fsync(fd)
                guard.accept_release_attributes()
                attrs_guard.assert_quiet()
                after = _r12_snapshot(path, fd, entry["content_sha256"])
                if after != {k:v for k,v in states[step + 1].items() if k != "operation"}:
                    raise S12ControlError(R12_RED)
                binding.update(step=step + 1, intent=None)
                _atomic_barrier_json(ledger_path, ledger)
            worktree[by_name[entry["repository"]]][path] = binding["successor"]
        for entry, path, fd, binding in zip(entries, paths, descriptors, ledger["bindings"]):
            if _r12_snapshot(path, fd, entry["content_sha256"]) != {k:v for k,v in binding["states"][-1].items() if k != "operation"}:
                raise S12ControlError(R12_RED)
            _assert_worktree_path_xattrs(path, binding["successor"], barrier_locked=True)
        attrs_guard.assert_quiet()
        guard.assert_no_events()
        git_guard.assert_unchanged()
        quiescence.assert_quiesced()
        ledger["phase"] = "SEALED"
        _atomic_barrier_json(ledger_path, ledger)
        journal["schema"] = R12_BARRIER_SCHEMA
        journal["r12_metadata_reconciliation"] = dict(contract_sha256=R12_CONTRACT_SHA256,
            original_journal_sha256=original_sha, ledger_sha256=_sha256(ledger_path))
        journal["worktree_write_barrier"] = _worktree_barrier_payload(roots, worktree)
        _atomic_barrier_json(BARRIER_MARKER, journal)
        guard.finalize_release(git_guard.assert_unchanged, quiescence.assert_quiesced)
        attrs_guard.assert_quiet()
        return dict(ok=True, safe_code="S12_1_R12_METADATA_SEALED", bound_paths=len(entries),
                    historical_continuity=False, recovery_started=False, git_guards_released=False)
    except Exception:
        # A detected violation is not an interruption-resume candidate. Poison
        # it only AFTER restoring V3, so V4 never references a rewritten ledger.
        if ledger_path.exists() and "ledger" in locals():
            _r12_abort(contract)
        raise
    finally:
        for fd in descriptors:
            os.close(fd)
        if guard is not None:
            guard.close()
        if attrs_guard is not None:
            attrs_guard.close()
        if git_guard is not None:
            git_guard.close()
        if quiescence is not None:
            quiescence.close()


def reconcile_metadata(contract_path: Path) -> dict:
    with _exclusive_deployment_lock():
        return _r12_reconcile_locked(contract_path)


def _r13_boundary(name: str) -> None:
    """Fault-injection boundary; production never retries activation."""


def _r13_tree(root: Path, git: Path, revision: str) -> dict[bytes, tuple[str, str]]:
    entries = {}
    for raw in _bounded_nul_command_records(_selected_git_arguments(
            root, git, "ls-tree", "-r", "-z", revision), MATERIALIZATION_RED):
        header, name = raw.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        _validated_git_paths((name,), MATERIALIZATION_RED)
        if mode not in {"100644", "100755", "120000"} or kind != "blob" or name in entries:
            raise S12ControlError(MATERIALIZATION_RED)
        entries[name] = (mode, oid)
    return entries


def _r13_snapshot(path: Path) -> dict | None:
    if not _barrier_path_present(path):
        return None
    meta = path.lstat()
    link = stat.S_ISLNK(meta.st_mode)
    fd = _r12_open(path, inspect_symlink=link)
    try:
        if link:
            if meta.st_nlink != 1:
                raise S12ControlError(MATERIALIZATION_RED)
            return dict(device=meta.st_dev, inode=meta.st_ino, birth=_r12_birth(fd),
                        kind="symlink", uid=meta.st_uid, gid=meta.st_gid,
                        mode="0777", content=os.fsencode(os.readlink(path)).hex(), attrs={})
        value = _r12_snapshot(path, fd, None)
        metadata = value["metadata"]
        metadata.pop("links")  # directory nlink changes only through bound child moves
        return dict(**metadata, birth=value["birth"], attrs=value["xattrs"],
                    content=_sha256_descriptor(fd) if metadata["kind"] == "regular" else None)
    finally:
        os.close(fd)


def _r13_location(root: Path) -> Path:
    if root not in {APPLICATION_ROOT, CONTROL_ROOT} or ACTIVE_ATTEMPT is None:
        raise S12ControlError(MATERIALIZATION_RED)
    return STATE_ROOT/"materialization"/("application" if root == APPLICATION_ROOT else "control")


def _r13_preflight_storage() -> None:
    """Reject a predictable EXDEV before consuming the sole follow-up slot."""
    parent=STATE_ROOT/"attempts"/FOLLOWUP_SLOT/"materialization"
    while not _barrier_path_present(parent):
        parent=parent.parent
    metadata=parent.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=0
            or stat.S_IMODE(metadata.st_mode)&0o022
            or any(root.lstat().st_dev!=metadata.st_dev for root in (APPLICATION_ROOT,CONTROL_ROOT))):
        raise S12ControlError("S12_1_MATERIALIZATION_FILESYSTEM_RED")


def _r13_load(root: Path) -> tuple[Path, dict]:
    tx = _r13_location(root)
    _validate_secure_directory_chain(tx, Path("/"))
    value = _private_json(tx/"journal.json", MATERIALIZATION_RED, maximum=32*1024*1024)
    if (set(value) - {"unsafe"} != {"schema","attempt_binding","root","phase",
                "historical_continuity","entries","old_commit","target_commit","branch",
                "parents","private_parents"}
            or value.get("schema") != "TU1NZ_S12_1_MATERIALIZATION_V1"
            or value.get("attempt_binding") != ACTIVE_ATTEMPT or value.get("root") != str(root)
            or value.get("phase") not in {"PREPARING", "READY", "APPLYING", "APPLIED", "UNDOING", "UNDONE"}
            or value.get("historical_continuity") is not False or "unsafe" in value
            or not isinstance(value.get("entries"), list)):
        raise S12ControlError(MATERIALIZATION_RED)
    key = "application" if root == APPLICATION_ROOT else "control"
    _,index,_ = _load_recovery_backup()
    uid,gid,_ = _recorded_path_metadata(index[key], "root")
    if (value["old_commit"] != index[key]["commit"]
            or value["target_commit"] != ACTIVE_ATTEMPT["release"][key+"_commit"]
            or value["branch"] != ("main" if key=="application" else "control-main")):
        raise S12ControlError(MATERIALIZATION_RED)
    names = []
    for entry in value["entries"]:
        if (not isinstance(entry,dict) or set(entry) != {"path_hex","git_mode","blob",
                "before","before_record","after","after_record","policy","step"}
                or entry["git_mode"] not in {None,"directory","100644","100755","120000"}
                or not isinstance(entry["path_hex"],str)
                or re.fullmatch(r"(?:[0-9a-f]{2})+",entry["path_hex"]) is None
                or entry["step"] not in {"PREPARED","BOUND","RETIRE_INTENT","PUBLISH_INTENT",
                                        "APPLIED","WITHDRAW_INTENT","RESTORE_INTENT","UNDONE"}
                or entry["policy"] != dict(uid=uid,gid=gid,mode=_r13_mode(entry["git_mode"]))
                or (entry["git_mode"] in {None,"directory"} and entry["blob"] is not None)
                or (entry["git_mode"] not in {None,"directory"} and
                    (not isinstance(entry["blob"],str) or re.fullmatch(r"[0-9a-f]{40}",entry["blob"]) is None))):
            raise S12ControlError(MATERIALIZATION_RED)
        name = bytes.fromhex(entry["path_hex"])
        _validated_git_paths((name,), MATERIALIZATION_RED)
        if name.split(b"/")[0] in {b".git", os.fsencode(RECOVERY_GIT_DIRECTORY)}:
            raise S12ControlError(MATERIALIZATION_RED)
        names.append(name)
    if len(set(names)) != len(names):
        raise S12ControlError(MATERIALIZATION_RED)
    git = _repository_recovery_git_directory(root)
    before,after = _r13_tree(root,git,value["old_commit"]),_r13_tree(root,git,value["target_commit"])
    old_dirs = set().union(*(_path_ancestors(n) for n in before))
    new_dirs = set().union(*(_path_ancestors(n) for n in after)) - old_dirs
    expected = {n: after.get(n,(None,None)) for n in before.keys() | after.keys()
                if before.get(n)!=after.get(n)}
    expected.update({n:("directory",None) for n in new_dirs})
    if {bytes.fromhex(e["path_hex"]):(e["git_mode"],e["blob"]) for e in value["entries"]} != expected:
        raise S12ControlError(MATERIALIZATION_RED)
    expected_parents = {b""}
    for name in expected:
        expected_parents.update(_path_ancestors(name) - new_dirs)
    if (not isinstance(value["parents"],dict) or set(value["parents"])!={n.hex() for n in expected_parents}
            or not isinstance(value["private_parents"],dict) or set(value["private_parents"])!={".","new","old"}):
        raise S12ControlError(MATERIALIZATION_RED)
    return tx, value


def _r13_mode(mode: str | None) -> str:
    return {"directory":"2770","120000":"0777","100755":"0770"}.get(mode,"0660")


def _r13_save(tx: Path, value: dict) -> None:
    _atomic_json(tx/"journal.json", value)


def _r13_assert_parents(root: Path, tx: Path, value: dict) -> None:
    for name, binding in value["parents"].items():
        if _r13_snapshot(root/os.fsdecode(bytes.fromhex(name))) != binding:
            raise S12ControlError(MATERIALIZATION_RED)
    for name,binding in value["private_parents"].items():
        if _r13_snapshot(tx/name) != binding:
            raise S12ControlError(MATERIALIZATION_RED)
    # A newly published directory is itself a bound parent. No same-content
    # replacement of an ancestor may redirect a subsequent child move.
    for entry in value["entries"]:
        if entry["git_mode"]=="directory" and entry["after"] is not None:
            path=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
            current=_r13_snapshot(path)
            if current is not None and current!=entry["after"]:
                raise S12ControlError(MATERIALIZATION_RED)


def _r13_audit_materialized(roots: Sequence[Path]) -> None:
    for root in roots:
        if not _barrier_path_present(_r13_location(root)):
            continue
        tx,value=_r13_load(root)
        if value["phase"] not in {"APPLIED","UNDONE"}:
            raise S12ControlError(MATERIALIZATION_RED)
        _r13_assert_parents(root,tx,value)
        for i,entry in enumerate(value["entries"]):
            path=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
            if _r13_snapshot(path) != entry["after" if value["phase"]=="APPLIED" else "before"]:
                raise S12ControlError(MATERIALIZATION_RED)
            if value["phase"]=="APPLIED" and (
                    _r13_snapshot(tx/"old"/str(i))!=entry["before"]
                    or _barrier_path_present(tx/"new"/str(i))):
                raise S12ControlError(MATERIALIZATION_RED)
    _r13_boundary("MATERIALIZATION_AUDITED")


GIT_WRITER_RED = "S12_1_GIT_WRITER_CONTRACT_RED"

# Executed by an isolated interpreter, not preexec_fn in a threaded controller.
# The O_PATH descriptor is the prospectively bound metadata inode. Landlock
# grants no worktree/backup/outside writes and is inherited by every new task.
_GIT_WRITER_BOOTSTRAP = r'''
import ctypes,json,os,signal,struct,sys
c=ctypes.CDLL(None,use_errno=True)
fd=int(sys.argv[1]); args=json.loads(sys.argv[2]); env=json.loads(sys.argv[3])
if c.prctl(1,signal.SIGKILL,0,0,0)<0 or os.getppid()!=int(sys.argv[4]): os._exit(125)
if os.uname().machine not in ('x86_64','aarch64') or c.syscall(444,0,0,1)<3: os._exit(125)
rules=ctypes.create_string_buffer(struct.pack('=Q',0x7ff2))
rs=c.syscall(444,ctypes.byref(rules),8,0)
rule=ctypes.create_string_buffer(struct.pack('=Qi',0x71b2 if sys.argv[8]=='STAGE_WRITE' else 0x61b2,fd))
if rs<0: os._exit(125)
if sys.argv[8]!='READ_ONLY' and c.syscall(445,rs,1,ctypes.byref(rule),0)<0: os._exit(125)
null_fd=int(sys.argv[5])
null_rule=ctypes.create_string_buffer(struct.pack('=Qi',2,null_fd))
if c.syscall(445,rs,1,ctypes.byref(null_rule),0)<0: os._exit(125)
if c.prctl(38,1,0,0,0)<0 or c.syscall(446,rs,0)<0: os._exit(125)
os.close(rs); os.close(fd); os.close(null_fd); os.close(int(sys.argv[6]))
if c.ptrace(0,0,0,0)<0: os._exit(125)
os.kill(os.getpid(),signal.SIGSTOP)
git_fd=int(sys.argv[7]); os.set_inheritable(git_fd,False)
os.execve(git_fd,args,env)
'''


def _r13_fid_events(data: bytes) -> list[tuple[int, int, tuple[bytes, ...], bytes]]:
    """Decode only opaque identities, never retain unrelated names/content."""
    events = []
    offset = 0
    while offset < len(data):
        if len(data)-offset < 24:
            raise S12ControlError(GIT_WRITER_RED)
        size, version, reserved, header, mask, fd, tid = struct.unpack_from('=IBBHQii', data, offset)
        if fd >= 0:
            os.close(fd)
        if (version != 3 or reserved or header != 24 or size < 24
                or offset+size > len(data) or fd != -1 or tid <= 0
                or mask & ~0x40000FCE or not mask & 0xFCE):
            raise S12ControlError(GIT_WRITER_RED)
        end, pos = offset+size, offset+24
        parents, targets = [], []
        while pos < end:
            if end-pos < 20:
                raise S12ControlError(GIT_WRITER_RED)
            kind, pad, length = struct.unpack_from('=BBH', data, pos)
            count, handle_type = struct.unpack_from('=Ii', data, pos+12)
            if (kind not in (1,2,3) or pad or length < 20+count or pos+length > end
                    or not 0 < count <= 128 or handle_type <= 0):
                raise S12ControlError(GIT_WRITER_RED)
            key = data[pos+4:pos+12] + struct.pack('=i',handle_type) + data[pos+20:pos+20+count]
            if kind == 1:
                targets.append(key)
            else:
                parents.append(key)
            if kind == 2 and b'\0' not in data[pos+20+count:pos+length]:
                raise S12ControlError(GIT_WRITER_RED)
            pos += length
        if pos != end or len(targets) > 1 or not (targets or parents):
            raise S12ControlError(GIT_WRITER_RED)
        events.append((tid, mask, tuple(parents), targets[0] if targets else b''))
        offset = end
    return events


class _R13GitWriters:
    """One finite, journaled writer epoch; no ancestry-only or root exemption.

    Filesystem marks precede inventory and never need a recursive watch-add.
    Ptrace stops fork/clone/exec/exit before admitting or retiring each task.
    Queued events are drained before PID reuse can confer another task's grant.
    """
    def __init__(self, roots: Sequence[Path], *, validation_binding: dict | None = None):
        self.roots = tuple(roots)
        self.validation_only = validation_binding is not None
        binding = validation_binding if self.validation_only else ACTIVE_ATTEMPT
        self.directories = {r:_repository_recovery_git_directory(r) or r/'.git' for r in roots}
        self.controller_tid = threading.get_native_id()
        self.fd = None
        self.failed = False
        self.members: dict[bytes, Path] = {}
        self.worktree_members: set[bytes] = set()
        self.pending: list[tuple] = []
        self.tasks: dict[int, dict] = {}
        self.operation = None
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.journal = STATE_ROOT/(FOLLOWUP_SLOT+'.validation.json' if self.validation_only
                                   else 'git-writer-scope.json')
        self.value = dict(schema='TU1NZ_S12_1_GIT_WRITER_V1', attempt_binding=binding,
                          phase='QUIET', sequence=0, tasks=[], operation=None,history=[])
        if self.validation_only:
            self.value['purpose'] = 'PARENT_VALIDATION_READ_ONLY'
        try:
            if (sys.platform != 'linux' or os.geteuid() != 0 or binding is None
                    or (self.validation_only and (ACTIVE_ATTEMPT is not None
                        or self.roots != (APPLICATION_ROOT,CONTROL_ROOT)))
                    or os.uname().machine not in {'x86_64','aarch64'}
                    or len({p.stat().st_dev for p in self.directories.values()}) != 1):
                raise S12ControlError(GIT_WRITER_RED)
            # REPORT_TID + DFID_NAME_TARGET; filesystem (not inode/mount) marks
            # observe new nested directories from their creation onward.
            self.fd = self.libc.fanotify_init(0x1f03, os.O_RDONLY|os.O_CLOEXEC)
            if self.fd < 0:
                self.fd = None
                raise S12ControlError(GIT_WRITER_RED)
            first = next(iter(self.directories.values()))
            if self.libc.fanotify_mark(self.fd, 0x101, ctypes.c_uint64(0x40000FCE),
                                      -100, os.fsencode(first)) < 0:
                raise S12ControlError(GIT_WRITER_RED)
            # The filesystem stream already exists before enumerating ANY
            # worktree/index name or invoking Git. It covers existing inodes,
            # absent/new names and reverted writes during inventory itself.
            for root in self.roots:
                key = self.handle(root)
                self.members[key] = root
                self.worktree_members.add(key)
            _r13_boundary('GIT_WRITER_INVENTORY')
            for root in self.roots:
                for base,dirs,files in os.walk(root,followlinks=False):
                    if Path(base) == root:
                        dirs[:] = [n for n in dirs if n not in ('.git',RECOVERY_GIT_DIRECTORY)]
                    for p in (Path(base),*(Path(base)/n for n in dirs+files)):
                        if p.lstat().st_dev != first.stat().st_dev:
                            raise S12ControlError(GIT_WRITER_RED)
                        key = self.handle(p)
                        self.members[key] = root
                        self.worktree_members.add(key)
            for root,directory in self.directories.items():
                for base,dirs,files in os.walk(directory, followlinks=False):
                    for p in (Path(base), *(Path(base)/n for n in dirs+files)):
                        if p.is_symlink() or p.stat().st_dev != first.stat().st_dev:
                            raise S12ControlError(GIT_WRITER_RED)
                        self.members[self.handle(p)] = root
            self.check()
            # Fixed Linux installation contract; discovering this path must
            # not execute an as-yet unbound Git binary. Unsupported layouts
            # fail closed. Git children receive this exact GIT_EXEC_PATH.
            exec_path = Path('/usr/lib/git-core')
            _validate_secure_directory_chain(exec_path,Path('/'))
            self.image_paths = {'bootstrap':Path('/proc/self/exe'),
                                'git':Path('/usr/bin/git'),'shell':Path('/bin/sh'),
                                'git-core':exec_path/'git','upload-pack':exec_path/'git-upload-pack'}
            self.images = {name:self.executable(path) for name,path in self.image_paths.items()}
            self.value['images'] = self.images
            if _barrier_path_present(self.journal):
                old = _private_json(self.journal, GIT_WRITER_RED, maximum=4*1024*1024)
                if (old.get('schema') != self.value['schema'] or old.get('attempt_binding') != binding
                        or old.get('purpose') != self.value.get('purpose')
                        or old.get('phase') != 'QUIET' or old.get('tasks') != []
                        or old.get('images') != self.images or type(old.get('sequence')) is not int
                        or not 0 <= old['sequence'] <= 1024 or not isinstance(old.get('history'),list)
                        or len(old['history']) != old['sequence']
                        or old.get('fingerprint') != self.fingerprint()):
                    raise S12ControlError(GIT_WRITER_RED)
                if self.validation_only and (
                        old.get('observer_baseline') != _r13_observer_baseline(self.roots)
                        or any(not isinstance(op,dict) or op.get('access_profile')!='READ_ONLY'
                               or 'stdout' in op or not isinstance(op.get('task_history'),list)
                               or any(not isinstance(task,dict) or task.get('exited') is not True
                                      for task in op['task_history']) for op in old['history'])):
                    raise S12ControlError(GIT_WRITER_RED)
                self.value['sequence'] = old['sequence']
                self.value['history'] = old.get('history',[])
                if 'observer_baseline' in old:
                    self.value['observer_baseline'] = old['observer_baseline']
            elif self.validation_only or (self.roots == (APPLICATION_ROOT, CONTROL_ROOT)
                  and not _barrier_journal_present()
                  and not _barrier_path_present(ATTEMPT_MARKER)):
                # Prospective, observed checkpoint, NOT historical provenance.
                # Preserve it across read-only commands; never replace it with
                # current metadata when recovering an observer-only namespace.
                self.value['observer_baseline'] = _r13_observer_baseline(self.roots)
            self.check()
            self.checkpoint()
        except BaseException:
            self.close(aborted=True)
            raise

    def handle(self, path: Path, *, descriptor=False) -> bytes:
        raw = ctypes.create_string_buffer(136)
        struct.pack_into('=I',raw,0,128)
        mount = ctypes.c_int()
        fs = ctypes.create_string_buffer(256)
        if (self.libc.name_to_handle_at(-100, os.fsencode(path), raw, ctypes.byref(mount),
                                       0x400 if descriptor else 0) < 0
                or self.libc.statfs(os.fsencode(path), fs) < 0):
            raise S12ControlError(GIT_WRITER_RED)
        count,kind = struct.unpack_from('=Ii',raw)
        if not 0 < count <= 128 or kind <= 0:
            raise S12ControlError(GIT_WRITER_RED)
        # Linux x86_64/aarch64 statfs: seven native 64-bit fields before fsid.
        return fs.raw[56:64] + struct.pack('=i',kind) + raw.raw[8:8+count]

    def fingerprint(self):
        paths = tuple(self.directories.values())
        # Unlike the live quarantine-transition digest, interruption evidence
        # must also bind root ctime: transient create/unlink at the root cannot
        # disappear just because no descendant remains in the final tree.
        roots = []
        for path in paths:
            meta = path.lstat()
            roots.append([meta.st_dev,meta.st_ino,meta.st_mode,meta.st_uid,meta.st_gid,
                          meta.st_nlink,meta.st_mtime_ns,meta.st_ctime_ns])
        return dict(tree=_git_metadata_transition_fingerprint(paths),roots=roots)

    def fail(self, reason=None):
        self.failed = True
        if reason is not None:
            self.value.setdefault('failure_reason',reason)
        self.value['phase'] = 'FAILED'
        _atomic_json(self.journal,self.value)
        for root in (() if self.validation_only else self.roots):
            if _barrier_path_present(_r13_location(root)):
                _r13_poison(_r13_location(root))
        error = S12ControlError(GIT_WRITER_RED)
        if 'failure_reason' in self.value:
            error.add_note(self.value['failure_reason'])
        raise error

    def check(self):
        if self.failed or self.fd is None:
            raise S12ControlError(GIT_WRITER_RED)
        try:
            while True:
                try:
                    data = os.read(self.fd,65536)
                except BlockingIOError:
                    break
                if not data:
                    self.fail()
                for tid,mask,parents,target in _r13_fid_events(data):
                    # Capture authority at receipt, not when a future parent
                    # event finally classifies this opaque object as in-scope.
                    actor = 'controller' if tid == self.controller_tid else self.tasks.get(tid,{}).get('root')
                    self.pending.append((actor,mask,parents,target))
                if len(self.pending) > 262144:
                    self.fail()
            # A child event may precede its parent's CREATE in another task.
            # Retain unclassified events for the epoch and compute closure.
            changed = True
            while changed:
                changed = False
                remaining = []
                for actor,mask,parents,target in self.pending:
                    roots = {self.members[k] for k in (*parents,target) if k in self.members}
                    if not roots:
                        remaining.append((actor,mask,parents,target))
                        continue
                    if len(roots) != 1:
                        self.fail()
                    root = roots.pop()
                    worktree = any(k in getattr(self,'worktree_members',()) for k in (*parents,target))
                    if actor != 'controller' and (worktree or actor != str(root)):
                        self.fail('FOREIGN_WORKTREE_EVENT' if worktree else 'FOREIGN_METADATA_EVENT')
                    if target and target not in self.members:
                        # New identity has an observed parent association,
                        # not a later equal-content/inode-owner inference.
                        if not any(p in self.members for p in parents):
                            self.fail()
                        self.members[target] = root
                        if worktree:
                            self.worktree_members.add(target)
                        changed = True
                self.pending = remaining
        except (OSError,ValueError,struct.error,S12ControlError):
            self.fail()

    def checkpoint(self):
        self.check()
        if any(actor not in (None,'controller') for actor,_,_,_ in self.pending):
            self.fail()
        if self.tasks:
            self.fail()
        fingerprint = self.fingerprint()
        self.check()
        self.value.update(phase='QUIET',tasks=[],operation=None,fingerprint=fingerprint)
        _atomic_json(self.journal,self.value)
        # Serialization/fsync is still inside the observed epoch. Do not
        # discard events queued during that last I/O when close() retires it.
        self.check()

    def command(self, arguments):
        argv = list(arguments)
        env = dict(item.split('=',1) for item in _isolated_root_git_prefix(self.roots[0])[2:8])
        env['GIT_EXEC_PATH'] = '/usr/lib/git-core'
        for root,directory in self.directories.items():
            prefix = _recovery_git_arguments(root,directory)
            if argv[:len(prefix)] != prefix:
                continue
            suffix = argv[len(prefix):]
            if not suffix:
                self.fail()
            return root, argv[8:], env
        # Every remaining Git invocation also enters ptrace/Landlock. These
        # finite auxiliary roles operate only on controller-owned fetch or
        # immutable-stage namespaces, never widen a live-worktree grant.
        if argv[:6] == _isolated_root_git_prefix(self.roots[0])[:6] and argv[6:7] == ['/usr/bin/git']:
            suffix = argv[7:]
            if (len(suffix)==7 and suffix[:3]==['config','--no-includes','--file']
                    and suffix[4:]==['--null','--name-only','--list']):
                return self.roots[0],argv[6:],env
            self.fail()
        if argv[:8] != _isolated_root_git_prefix(self.roots[0])[:8]:
            # Unknown/wrapped Git is never silently run through subprocess.
            if any(Path(item).name == 'git' for item in argv):
                self.fail()
            return None
        for context in (FETCH_ROOT, FETCH_ROOT/'application.git', FETCH_ROOT/'control.git',
                        *self.directories.values(), RELEASE_STAGING_ROOT/'application',
                        RELEASE_STAGING_ROOT/'control', RELEASE_APPLICATION_ROOT, RELEASE_CONTROL_ROOT,
                        *self.roots):
            prefix = _isolated_root_git_prefix(context)
            if argv[:len(prefix)] != prefix:
                continue
            suffix = argv[len(prefix):]
            if suffix[:2] == ['init','--bare'] and context == FETCH_ROOT:
                if len(suffix)!=3 or Path(suffix[2]) not in (FETCH_ROOT/'application.git',FETCH_ROOT/'control.git'):
                    self.fail()
                return FETCH_ROOT,argv[8:],env
            if suffix[:3] == ['clone','--no-local','--no-checkout'] and context in self.directories.values():
                root = next(r for r,d in self.directories.items() if d == context)
                destination = RELEASE_STAGING_ROOT/('application' if root==APPLICATION_ROOT else 'control')
                if suffix != ['clone','--no-local','--no-checkout',str(context),str(destination)]:
                    self.fail()
                return RELEASE_STAGING_ROOT,argv[8:],env
            if suffix[:1] == [f'--git-dir={context}'] and context in (FETCH_ROOT/'application.git',FETCH_ROOT/'control.git'):
                return FETCH_ROOT,argv[8:],env
            if suffix[:2] == ['-C',str(context)] and context in (
                    RELEASE_STAGING_ROOT/'application',RELEASE_STAGING_ROOT/'control',
                    RELEASE_APPLICATION_ROOT,RELEASE_CONTROL_ROOT):
                return RELEASE_STAGING_ROOT if context.is_relative_to(RELEASE_STAGING_ROOT) else self.roots[0],argv[8:],env
        # Bundle helpers select a bare fetch directory with its application
        # safe.directory context rather than the bare directory as context.
        for root,key in ((APPLICATION_ROOT,'application'),(CONTROL_ROOT,'control')):
            prefix = _recovery_git_arguments(root,FETCH_ROOT/(key+'.git'))
            if argv[:len(prefix)] == prefix:
                return FETCH_ROOT,argv[8:],env
        self.fail()

    def access_profile(self, root, argv):
        args = argv[1:]
        while args and (args[0] in ('-c','-C') or args[0].startswith(('--git-dir=','--work-tree='))):
            args = args[2:] if args[0] in ('-c','-C') else args[1:]
        if not args:
            self.fail()
        verb = args[0]
        readonly = verb in {'status','rev-parse','merge-base','ls-tree','ls-files','cat-file',
                           'for-each-ref','show-ref','config','diff','diff-index'}
        readonly |= verb=='symbolic-ref' and ('--quiet' in args or '--short' in args)
        readonly |= verb=='bundle' and args[1:2] in (['verify'],['list-heads'],['create'])
        if not readonly and verb not in {'fetch','read-tree','update-ref','branch','symbolic-ref',
                                        'bundle','init','clone','checkout','hash-object','pack-objects'}:
            self.fail()
        if verb in {'init','clone','checkout'} and root not in (FETCH_ROOT,RELEASE_STAGING_ROOT):
            self.fail()
        if readonly: return 'READ_ONLY'
        # Git init probes symlink support in its new bare metadata directory;
        # denying that probe silently persists core.symlinks=false. Permit it
        # only for the finite staging initialization/checkout roles, not for a
        # live repository's metadata writer.
        return 'STAGE_WRITE' if root==RELEASE_STAGING_ROOT or verb=='init' else 'BOUND_WRITE'
        return None

    def ptrace(self, request, tid, data=0):
        result = self.libc.ptrace(request,tid,ctypes.c_void_p(),ctypes.c_void_p(data))
        if result < 0:
            raise S12ControlError(GIT_WRITER_RED)
        return result

    @staticmethod
    def executable(path):
        before = path.stat()
        digest = _sha256(path)
        after = path.stat()
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or any(getattr(before,k) != getattr(after,k) for k in fields)):
            raise S12ControlError(GIT_WRITER_RED)
        return dict(metadata=[getattr(before,k) for k in fields],sha256=digest)

    def bind(self, tid, root, parent):
        self.check()  # No queued event may inherit this new PID's authority.
        fields = Path(f'/proc/{tid}/stat').read_text().rsplit(')',1)[1].split()
        if (tid in self.tasks or fields[0] not in {'t','T'} or len(self.tasks) >= 256
                or len(self.operation['task_history']) >= 2048
                or fields[2:4] != [str(self.operation['session'])]*2
                or (parent is None and self.executable(Path(f'/proc/{tid}/exe')) != self.images['bootstrap'])):
            self.fail()
        record = dict(tid=tid,start=fields[19],root=str(root),parent=parent,exited=False)
        self.tasks[tid] = record
        self.operation['task_history'].append(record)
        self.value['tasks'] = list(self.tasks.values())
        _atomic_json(self.journal,self.value)

    def run(self, selected, timeout, *, input_text=None, stdin=None, stdout=None, text=True):
        # Bundle restore also calls this directly; a failed epoch must never
        # gain a fresh subprocess merely by avoiding the ordinary _run router.
        self.check()
        root,argv,env = selected
        if self.tasks or self.operation is not None or input_text is not None:
            self.fail()
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot_id) is None:
            self.fail()
        profile = self.access_profile(root,argv)
        if self.validation_only and (profile!='READ_ONLY' or stdout is not None
                                     or root not in self.roots):
            self.fail()
        directory = self.directories[root] if root in self.directories else root
        if root not in self.directories:
            if root not in (FETCH_ROOT,RELEASE_STAGING_ROOT):
                self.fail()
            _validate_secure_directory_chain(directory,Path('/'))
            for base,dirs,files in os.walk(directory,followlinks=False):
                for p in (Path(base),*(Path(base)/n for n in dirs+files)):
                    self.members[self.handle(p)] = root
            self.check()
        directory_fd = null_fd = bootstrap_fd = git_fd = None
        try:
            # Execute the actual running interpreter through a held descriptor,
            # never resolve sys.executable again at spawn. The live interpreter
            # is text-busy; replacement of its pathname cannot replace this
            # inode. Pin metadata/digest before intent and verify at ptrace stop.
            bootstrap_fd = os.open('/proc/self/exe',os.O_RDONLY|os.O_CLOEXEC)
            bootstrap_path = Path(f'/proc/self/fd/{bootstrap_fd}')
            if self.executable(bootstrap_path) != self.images['bootstrap']:
                self.fail()
            git_fd = os.open(self.image_paths['git'],os.O_RDONLY|os.O_CLOEXEC)
            git_path = Path(f'/proc/self/fd/{git_fd}')
            if self.executable(git_path) != self.images['git']:
                self.fail()
            directory_fd = os.open(directory,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW)
            null_fd = os.open('/dev/null',os.O_PATH|os.O_NOFOLLOW)
            null = os.fstat(null_fd)
            if (not stat.S_ISCHR(null.st_mode) or null.st_uid != 0 or null.st_gid != 0
                    or null.st_rdev != os.makedev(1,3) or null.st_nlink != 1):
                self.fail()
            current_images = {name:self.executable(path) for name,path in self.image_paths.items()}
            allowed_git,allowed_shell = self.images['git'],self.images['shell']
            if current_images != self.images:
                self.fail()
            self.operation = dict(root=str(root),argv=argv,git=allowed_git,shell=allowed_shell,boot_id=boot_id,
                                  access_profile=profile,
                                  isolation='new-private-session',
                                  namespace=self.handle(directory).hex(),bootstrap_sha256=
                                  hashlib.sha256(_GIT_WRITER_BOOTSTRAP.encode()).hexdigest(),task_history=[],
                                  null_device=[null.st_dev,null.st_ino,null.st_rdev])
            if stdout is not None:
                output = os.fstat(stdout.fileno())
                if (not stat.S_ISREG(output.st_mode) or output.st_uid!=0
                        or output.st_nlink!=1 or stat.S_IMODE(output.st_mode)!=0o600):
                    self.fail()
                self.operation['stdout'] = [output.st_dev,output.st_ino,output.st_mode,output.st_uid]
                output_handle = self.handle(Path(f'/proc/self/fd/{stdout.fileno()}'),descriptor=True)
                if output_handle in self.worktree_members:
                    self.fail()
                self.members[output_handle] = root
                self.operation['stdout_handle'] = output_handle.hex()
                self.check()
            if self.value['sequence'] >= 1024:
                self.fail()
            self.value.update(phase='RUNNING',sequence=self.value['sequence']+1,operation=self.operation,tasks=[])
            _atomic_json(self.journal,self.value)  # Intent before spawning any writer.
        except BaseException:
            for descriptor in (git_fd,bootstrap_fd,null_fd,directory_fd):
                if descriptor is not None: os.close(descriptor)
            raise
        process = None
        pending = {}
        buffers = {}
        try:
            _r13_boundary('GIT_WRITER_INTENT')
            if self.executable(bootstrap_path) != self.images['bootstrap']:
                self.fail()
            process = subprocess.Popen([str(bootstrap_path),'-I','-S','-B','-c',_GIT_WRITER_BOOTSTRAP,
                str(directory_fd),json.dumps(argv),json.dumps(env),str(os.getpid()),str(null_fd),str(bootstrap_fd),
                str(git_fd),profile],stdin=stdin or subprocess.DEVNULL,
                stdout=stdout or subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(directory_fd,null_fd,bootstrap_fd,git_fd),close_fds=True,
                start_new_session=True,env={'HOME':'/','PATH':'/usr/bin:/bin'})
            pending[process.pid] = None
            self.operation['session'] = process.pid
            buffers = {stream:bytearray() for stream in (process.stdout,process.stderr) if stream is not None}
            for stream in buffers:
                os.set_blocking(stream.fileno(),False)
            deadline = time.monotonic()+timeout
            initial = True
            while pending:
                if time.monotonic() >= deadline:
                    self.fail()
                progress = False
                for tid in tuple(pending):
                    event = os.waitid(os.P_PID,tid,os.WSTOPPED|os.WEXITED|os.WNOHANG|os.WNOWAIT|0x40000000)
                    if event is None:
                        continue
                    progress = True
                    # A stop does not retire the PID. Capture a kernel-stopped
                    # newborn for cleanup BEFORE any fallible event check;
                    # it receives no writer grant until bind() below. Otherwise
                    # a failure at the parent's fork stop can strand a tracee
                    # absent from pending. Exits still drain before PID release.
                    if event.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED):
                        self.check()
                        _,status = os.waitpid(tid,os.WNOHANG|0x40000000)
                    else:
                        _,status = os.waitpid(tid,os.WNOHANG|0x40000000)
                        if os.WIFSTOPPED(status) and status >> 16 in (1,2,3):
                            child = ctypes.c_ulong()
                            self.ptrace(0x4201,tid,ctypes.addressof(child))
                            if child.value in pending or not child.value:
                                self.fail()
                            pending[child.value] = tid
                            _r13_boundary('GIT_WRITER_FORK')
                        self.check()
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                        pending.pop(tid)
                        if tid in self.tasks:
                            self.tasks[tid]['exited'] = True
                        self.tasks.pop(tid,None)
                        if tid == process.pid:
                            process.returncode = os.waitstatus_to_exitcode(status)
                        if initial:
                            self.fail()
                        continue
                    if not os.WIFSTOPPED(status):
                        self.fail()
                    kind,stop = status >> 16,os.WSTOPSIG(status)
                    if tid not in self.tasks:
                        self.bind(tid,root,pending[tid])
                        # EXITKILL; fork/vfork/clone, exec and pre-exit stops.
                        self.ptrace(0x4200,tid,0x0010005e)
                        initial = False
                        _r13_boundary('GIT_WRITER_BOUND')
                    elif kind in (1,2,3):
                        pass  # Newborn is already held in pending, not admitted.
                    elif kind == 4:
                        actual = self.executable(Path(f'/proc/{tid}/exe'))
                        args = Path(f'/proc/{tid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                        if actual not in (allowed_git,self.images['git-core']):
                            # Git's local transport uses this one shell bridge;
                            # never authorize a shell merely by its ancestry.
                            sources = [a for a in argv if a.startswith(str(FETCH_ROOT)+'/') or a in
                                       {str(d) for d in self.directories.values()}]
                            expected = [b'/bin/sh',b'-c']
                            scripts = {os.fsencode("git-upload-pack '"+p+"'") for p in sources
                                       if not any(c in p for c in "'\n\r")}
                            # prepare_shell_cmd supplies the same string as $0;
                            # admit only that exact four-element argv, no "$@".
                            upload_pack = (actual == self.images['upload-pack'] and len(args)==2
                                and args[0]==b'git-upload-pack' and args[1] in {os.fsencode(p) for p in sources})
                            shell_bridge = (actual == allowed_shell and args[:2] == expected and len(args)==4
                                and args[2] in scripts and args[3] == args[2])
                            if not (upload_pack or shell_bridge):
                                self.fail()
                        self.tasks[tid]['executable'] = actual
                        _atomic_json(self.journal,self.value)
                        _r13_boundary('GIT_WRITER_EXEC')
                    elif kind not in (0,6):
                        self.fail()
                    self.ptrace(7,tid,0 if kind or stop in (signal.SIGSTOP,signal.SIGTRAP) else stop)
                for stream,buffer in buffers.items():
                    try:
                        chunk = os.read(stream.fileno(),65536)
                    except BlockingIOError:
                        continue
                    buffer.extend(chunk)
                    if len(buffer) > 32*1024*1024:
                        self.fail()
                if not progress:
                    select.select([self.fd,*[s.fileno() for s in buffers]],[],[],0.005)
                self.check()
            for stream,buffer in buffers.items():
                while True:
                    chunk = os.read(stream.fileno(),65536)
                    if not chunk: break
                    buffer.extend(chunk)
            if stdout is not None:
                output = os.fstat(stdout.fileno())
                if ([output.st_dev,output.st_ino,output.st_mode,output.st_uid] != self.operation['stdout']
                        or output.st_nlink!=1):
                    self.fail()
            self.value['history'].append(self.operation)
            self.operation = None
            self.checkpoint()
            def result(stream):
                if stream is None: return None
                payload = bytes(buffers[stream])
                return payload.decode('utf-8') if text else payload
            return subprocess.CompletedProcess(argv,process.returncode,
                result(process.stdout),result(process.stderr))
        except BaseException:
            self.value['phase'] = 'FAILED'
            self.failed = True
            # A failed disk/journal write must not skip live-writer cleanup.
            # The last durable RUNNING intent still denies any resumed grant.
            journal_error = None
            try: _atomic_json(self.journal,self.value)
            except BaseException as error: journal_error = error
            if process is not None:
                # Private session membership is a cleanup fence, NEVER writer
                # authority. An outside process cannot join this session.
                # An unreaped owned task proves the group ID is not recycled.
                # Kill its entire group before reaping: another stopped parent
                # may have a newborn whose fork notification is not yet read.
                session_owned = False
                for tid in pending:
                    try:
                        fields = Path(f'/proc/{tid}/stat').read_text().rsplit(')',1)[1].split()
                        if fields[2:4] == [str(process.pid)]*2:
                            session_owned = True
                            break
                    except (FileNotFoundError,ProcessLookupError): pass
                if session_owned:
                    try: os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                # Only unreaped children/tracees still own these kernel PIDs.
                # A completed leader's numeric PID is never a cleanup target.
                for tid in pending:
                    try: os.kill(tid,signal.SIGKILL)
                    except ProcessLookupError: pass
                # Never detach a writer or silently grant a retry.
                for tid in pending:
                    try:
                        while True:
                            _,status = os.waitpid(tid,0x40000000)
                            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                                if tid == process.pid:
                                    process.returncode = os.waitstatus_to_exitcode(status)
                                break
                            self.ptrace(7,tid,signal.SIGKILL)
                    except (ChildProcessError,S12ControlError): pass
                if session_owned:
                    # Reap even an unadmitted tracee; waitpid's group filter
                    # plus the private session excludes unrelated children.
                    while True:
                        try:
                            tid,status = os.waitpid(-process.pid,0x40000000)
                            if os.WIFSTOPPED(status): self.ptrace(7,tid,signal.SIGKILL)
                        except ChildProcessError: break
            if journal_error is not None:
                raise journal_error
            raise
        finally:
            os.close(directory_fd)
            os.close(null_fd)
            os.close(bootstrap_fd)
            os.close(git_fd)
            for stream in buffers: stream.close()

    def close(self, *, aborted=False):
        if self.fd is not None:
            try:
                if not aborted:
                    self.checkpoint()
            finally:
                os.close(self.fd)
                self.fd = None


def _r13_git_writers(roots: Sequence[Path]) -> _R13GitWriters | None:
    global GIT_WRITER_SCOPE
    if ACTIVE_ATTEMPT is None:
        return None
    if GIT_WRITER_SCOPE is None:
        GIT_WRITER_SCOPE = _R13GitWriters(roots)
    elif set(GIT_WRITER_SCOPE.roots) != set(roots):
        raise S12ControlError(GIT_WRITER_RED)
    GIT_WRITER_SCOPE.check()
    return GIT_WRITER_SCOPE


def _r13_retire_git_writers():
    global GIT_WRITER_SCOPE
    if GIT_WRITER_SCOPE is not None:
        GIT_WRITER_SCOPE.close()
        GIT_WRITER_SCOPE = None


def _r13_observer_baseline(roots: Sequence[Path]) -> dict:
    fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
    metadata=[path.lstat() for path in (DEPLOYMENT_LOCK_ROOT, *roots)]
    return dict(tree=_git_metadata_transition_fingerprint(roots),
                roots=[[getattr(value, field) for field in fields] for value in metadata])


def _r13_begin_attempt_observation():
    """Observe before preflight/index capture, including recovery prefixes."""
    roots = (APPLICATION_ROOT, CONTROL_ROOT)
    writers = _r13_git_writers(roots)
    if writers is None or MATERIALIZATION_GUARDS is None:
        raise S12ControlError(GIT_WRITER_RED)
    MATERIALIZATION_GUARDS.retain(_r13_initial_worktree_guards(roots, writers))


class _R13GuardStack(ExitStack):
    def __init__(self):
        super().__init__()
        self.checks: list[Callable] = []
        self.paths: set[Path] = set()
        self.failed = False

    def retain(self, context):
        if self.failed:
            raise S12ControlError(MATERIALIZATION_RED)
        self.assert_quiet()
        check = self.enter_context(context)
        self.checks.append(check)
        return check

    def assert_quiet(self):
        if self.failed:
            raise S12ControlError(MATERIALIZATION_RED)
        for check in self.checks:
            check()

    def close(self):
        try:
            super().close()
        except BaseException:
            self.failed = True
            raise
        # Canonical rollback has a second serialized finalization phase. Only
        # after a verified handoff may it start a fresh watch set; closed file
        # descriptors and their callbacks must not masquerade as live guards.
        self.checks.clear()
        self.paths.clear()


@contextmanager
def _r13_guard_scope():
    global MATERIALIZATION_GUARDS, GIT_WRITER_SCOPE
    if MATERIALIZATION_GUARDS is not None:
        yield MATERIALIZATION_GUARDS
        return
    with _R13GuardStack() as guards:
        MATERIALIZATION_GUARDS = guards
        try:
            yield guards
        finally:
            if GIT_WRITER_SCOPE is not None:
                GIT_WRITER_SCOPE.close(aborted=True)
                GIT_WRITER_SCOPE = None
            MATERIALIZATION_GUARDS = None


@contextmanager
def _r13_initial_worktree_guards(roots: Sequence[Path], writers: _R13GitWriters):
    # Both existing worktrees must be watched before fetch preparation, backup
    # or the first Git writer, not first baselined by each later materializer.
    attrs = None
    try:
        paths = _r12_index_guard_paths(roots)
        before = _r12_scope_snapshot(paths,{})
        attrs = _R12AttributeGuard(tuple(paths),event_mask=0xFCE)
        if _r12_scope_snapshot(paths,{}) != before:
            writers.fail()
        if MATERIALIZATION_GUARDS is not None:
            MATERIALIZATION_GUARDS.paths.update(paths)
        def check():
            try: attrs.assert_quiet()
            except S12ControlError: writers.fail()
        check()
        yield check
        check()
    except S12ControlError:
        writers.fail()
    finally:
        if attrs is not None: attrs.close()


@contextmanager
def _r13_guards(root: Path, tx: Path, value: dict):
    if MATERIALIZATION_GUARDS is None:
        with _r13_guard_context(root, tx, value) as check:
            yield check
        return
    check = MATERIALIZATION_GUARDS.retain(_r13_guard_context(root, tx, value))
    try:
        yield check
        check()
    except S12ControlError:
        _r13_poison(tx)
        raise


def _r13_poison(tx: Path) -> None:
    # A retained guard can outlive a legitimate rollback using another loaded
    # journal instance. Preserve the latest durable phase/steps when poisoning.
    value = _private_json(tx/"journal.json", MATERIALIZATION_RED, maximum=32*1024*1024)
    value["unsafe"] = True
    _r13_save(tx, value)


@contextmanager
def _r13_guard_context(root: Path, tx: Path, value: dict):
    paths = _r12_index_guard_paths((root,)) | {tx, tx/"new", tx/"old"}
    for i, entry in enumerate(value["entries"]):
        path = root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
        paths.add(path)
        paths.update(p for p in path.parents if p == root or root in p.parents)
        paths.update((tx/"new"/str(i), tx/"old"/str(i)))
    # The PID-attributed notification group rejects even reverted mutations by
    # another root thread. The permission group fences opens; ptrace quiesces
    # already-held descriptors. Neither payload equality nor uid proves origin.
    before = _r12_scope_snapshot(paths, {})
    if MATERIALIZATION_GUARDS is not None:
        MATERIALIZATION_GUARDS.paths.update(paths)
    existing = tuple(p for p in paths if p.exists() and not p.is_symlink())
    open_guard = attrs = quiet = None
    try:
        open_guard = _WorktreeReleaseGuard((root,), existing)
        attrs = _R12AttributeGuard(existing, event_mask=0xFCE)
        quiet = _GuardedHandleQuiescence(existing, (root,))
        quiet.acquire()
        if _r12_scope_snapshot(paths, {}) != before:
            raise S12ControlError(MATERIALIZATION_RED)
        def check():
            quiet.assert_quiesced()
            open_guard._assert_fanotify_quiet()
            attrs.assert_quiet()
            _r13_assert_parents(root,tx,value)
        check()
        yield check
        check()
    except S12ControlError:
        # A detected competing mutation is NOT a recoverable simulated crash.
        # Keep the claim and barriers; never legitimize a reverted write later.
        _r13_poison(tx)
        raise
    finally:
        if quiet is not None:
            quiet.close()
        if open_guard is not None:
            open_guard.close()
        if attrs is not None:
            attrs.close()


def _r13_move(source: Path, target: Path, expected: dict, check: Callable) -> None:
    check()
    if _r13_snapshot(source) != expected or _barrier_path_present(target):
        raise S12ControlError(MATERIALIZATION_RED)
    if expected["kind"]=="directory" and any(source.iterdir()):
        raise S12ControlError(MATERIALIZATION_RED)
    source_parent = _r12_open(source.parent)
    target_parent = _r12_open(target.parent)
    try:
        operation = ctypes.CDLL(None, use_errno=True).renameat2
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        if operation(source_parent, os.fsencode(source.name), target_parent, os.fsencode(target.name), 1):
            raise S12ControlError(MATERIALIZATION_RED)  # RENAME_NOREPLACE; no clobber fallback
        os.fsync(source_parent); os.fsync(target_parent)
    finally:
        os.close(source_parent); os.close(target_parent)
    if _r13_snapshot(target) != expected or _barrier_path_present(source):
        raise S12ControlError(MATERIALIZATION_RED)
    check()


def _r13_publish_records(root: Path, value: dict, *, undo: bool) -> None:
    global MATERIALIZATION_RECORDS
    journal = _barrier_json(BARRIER_MARKER)
    loaded = _parse_worktree_barrier_payload(
        journal["worktree_write_barrier"], (APPLICATION_ROOT, CONTROL_ROOT))
    records = MATERIALIZATION_RECORDS if MATERIALIZATION_RECORDS is not None else loaded
    for entry in value["entries"]:
        path = root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
        record = entry["before_record"] if undo else entry.get("after_record")
        if record is None:
            records[root].pop(path, None)
        else:
            records[root][path] = record
    journal["worktree_write_barrier"] = _worktree_barrier_payload(
        (APPLICATION_ROOT, CONTROL_ROOT), records)
    _atomic_barrier_json(BARRIER_MARKER, journal)


def _r13_materialize(root: Path, git: Path, target: str, branch: str) -> None:
    if MATERIALIZATION_RECORDS is None or _selected_branch_or_none(root, git) != branch:
        raise S12ControlError(MATERIALIZATION_RED)
    old, _ = _selected_identity(root, git)
    if _run(_selected_git_arguments(root, git, "merge-base", "--is-ancestor", old, target), check=False).returncode:
        raise S12ControlError(MATERIALIZATION_RED)
    tx = _r13_location(root)
    if _barrier_path_present(tx):
        raise S12ControlError("S12_1_MATERIALIZATION_REPLAY_RED")
    before, after = _r13_tree(root, git, old), _r13_tree(root, git, target)
    initial_paths = _r12_index_guard_paths((root,))
    initial_snapshot = _r12_scope_snapshot(initial_paths,
        {root/os.fsdecode(name): binding for name,binding in before.items()})
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    new_dirs = set()
    for name in after:
        for ancestor in _path_ancestors(name):
            path = root/os.fsdecode(ancestor)
            if not _barrier_path_present(path):
                new_dirs.add(ancestor)
            elif not path.is_dir() or path.is_symlink():
                raise S12ControlError(MATERIALIZATION_RED)  # finite contract: no directory/type swaps
            elif path not in MATERIALIZATION_RECORDS[root]:
                raise S12ControlError(MATERIALIZATION_RED)  # no adoption of unknown empty directories
    names = sorted(new_dirs, key=lambda n:(n.count(b"/"),n)) + sorted(changed)
    repo = _barrier_json(BARRIER_MARKER)["repositories"]["application" if root==APPLICATION_ROOT else "control"]
    uid, gid, _ = _recorded_path_metadata(repo, "root")
    entries = []
    for name in names:
        path = root/os.fsdecode(name)
        mode, oid = ("directory", None) if name in new_dirs else after.get(name, (None,None))
        current = _r13_snapshot(path)
        if name not in before and current is not None:
            raise S12ControlError(MATERIALIZATION_RED)
        entries.append(dict(path_hex=name.hex(), git_mode=mode, blob=oid, before=current,
            before_record=MATERIALIZATION_RECORDS[root].get(path), after=None, after_record=None,
            policy=dict(uid=uid,gid=gid,mode=_r13_mode(mode)),
            step="PREPARED"))
    _ensure_private_directory_durable(tx, Path("/"))
    if tx.stat().st_dev != root.stat().st_dev:
        raise S12ControlError(MATERIALIZATION_RED)
    for name in ("new", "old"):
        _ensure_private_directory_durable(tx/name, Path("/"))
        if os.listxattr(tx/name):
            raise S12ControlError(MATERIALIZATION_RED)
    parents = {root}
    for name in names:
        parents.update(root/os.fsdecode(n) for n in _path_ancestors(name) if n not in new_dirs)
    value = dict(schema="TU1NZ_S12_1_MATERIALIZATION_V1", root=str(root), attempt_binding=ACTIVE_ATTEMPT,
                 old_commit=old, target_commit=target, branch=branch, historical_continuity=False,
                 phase="PREPARING", entries=entries,
                 parents={(b"" if p==root else os.fsencode(p.relative_to(root))).hex():_r13_snapshot(p) for p in parents},
                 private_parents={n:_r13_snapshot(tx/n) for n in (".","new","old")})
    _r13_save(tx,value)  # policies + finite path set precede every allocation
    with _r13_guards(root,tx,value) as allocation_check:
        if _r12_scope_snapshot(initial_paths,
                {root/os.fsdecode(name): binding for name,binding in before.items()}) != initial_snapshot:
            raise S12ControlError(MATERIALIZATION_RED)
        _r13_allocate_and_apply(root,git,tx,value,allocation_check)


def _r13_allocate_and_apply(root: Path, git: Path, tx: Path, value: dict,
                           allocation_check: Callable) -> None:
    entries = value["entries"]
    old, target = value["old_commit"], value["target_commit"]
    for i, entry in enumerate(entries):
        allocation_check()
        if entry["git_mode"] is None:
            continue
        stage = tx/"new"/str(i)
        mode = entry["git_mode"]
        if mode == "directory":
            stage.mkdir(mode=0o700)
        else:
            completed = _git_process(_selected_git_arguments(root,git,"cat-file","blob",entry["blob"]))
            if completed.returncode or completed.stderr:
                raise S12ControlError(MATERIALIZATION_RED)
            blob = completed.stdout
            if len(blob)>32*1024*1024 or hashlib.sha1(b"blob "+str(len(blob)).encode()+b"\0"+blob).hexdigest()!=entry["blob"]:
                raise S12ControlError(MATERIALIZATION_RED)
            if mode == "120000":
                link=os.fsdecode(blob)
                destination=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
                if os.path.isabs(link) or not (destination.parent/link).resolve().is_relative_to(root):
                    raise S12ControlError(MATERIALIZATION_RED)
                stage.symlink_to(link)
            else:
                _write_private_backup_blob(stage,blob)
        _r13_boundary("OBJECT_ALLOCATED")
        # Existing quarantine contracts fence a symlink by its parents, not by
        # chmod/chown of the link. Allocate it at the declared maintenance UID
        # under the private parent; later release must not invent a new state.
        os.chown(stage,entry["policy"]["uid"] if mode=="120000" else 0,
                 entry["policy"]["gid"],follow_symlinks=False)
        if mode != "120000":
            if os.listxattr(stage):
                raise S12ControlError(MATERIALIZATION_RED)
            fd = _r12_open(stage)
            try:
                identity = _r12_stat(fd)
            finally:
                os.close(fd)
            destination=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
            record=dict(kind=identity["kind"],device=identity["device"],inode=identity["inode"],
                        **entry["policy"],xattr_fingerprint=_r12_xattr_fingerprint(destination,identity,{}))
            _install_worktree_barrier_owner_acl(stage,record)
            os.chmod(stage,int(record["mode"],8)&~0o222)
            entry["after_record"]=record
            fd=_r12_open(stage)
            try:os.fsync(fd)
            finally:os.close(fd)
        _r13_boundary("OBJECT_METADATA_SET")
        entry["after"]=_r13_snapshot(stage)
        _fsync_directory(stage.parent)
        allocation_check()  # reject foreign creation/replacement before binding
        entry["step"]="BOUND"
        _r13_save(tx,value)  # identity + kernel birth time bound before publication
        _r13_boundary("OBJECT_BOUND")
    value["phase"]="READY";_r13_save(tx,value)
    # Add marks on the newly allocated inodes before they enter the worktree.
    # Keep the allocation guard continuously held across this watch handoff.
    with _r13_guards(root,tx,value) as publication_check:
        def check():
            allocation_check()
            publication_check()
        value["phase"]="APPLYING";_r13_save(tx,value)
        for i,entry in enumerate(entries):
            path=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
            if entry["before"] is not None:
                entry["step"]="RETIRE_INTENT";_r13_save(tx,value);_r13_boundary("RETIRE_INTENT")
                _r13_move(path,tx/"old"/str(i),entry["before"],check)
                _r13_boundary("RETIRED")
            if entry["after"] is not None:
                entry["step"]="PUBLISH_INTENT";_r13_save(tx,value);_r13_boundary("PUBLISH_INTENT")
                _r13_move(tx/"new"/str(i),path,entry["after"],check)
                _r13_boundary("PUBLISHED")
            entry["step"]="APPLIED";_r13_save(tx,value)
        _r13_publish_records(root,value,undo=False)
        _r13_boundary("RECORDS_PUBLISHED")
        # Git updates only its already quarantined metadata. It never creates
        # live worktree objects or propagates a default ACL in this contract.
        _run(_selected_git_arguments(root,git,"read-tree",target))
        _r13_boundary("INDEX_UPDATED")
        _run(_selected_git_arguments(root,git,"update-ref","HEAD",target,old))
        _run(_selected_git_arguments(root,git,"update-ref","ORIG_HEAD",old))
        _r13_boundary("REF_UPDATED")
        if _selected_identity(root,git)[0] != target:
            raise S12ControlError(MATERIALIZATION_RED)
        check();value["phase"]="APPLIED";_r13_save(tx,value)


def _r13_materialize_undo(root: Path, git: Path) -> None:
    tx = _r13_location(root)
    if not _barrier_path_present(tx):
        return
    tx,value = _r13_load(root)
    if value["phase"]=="UNDONE":
        return
    with _r13_guards(root,tx,value) as check:
        value["phase"]="UNDOING";_r13_save(tx,value)
        for i in reversed(range(len(value["entries"]))):
            entry=value["entries"][i]
            path=root/os.fsdecode(bytes.fromhex(entry["path_hex"]))
            current=_r13_snapshot(path)
            stage=_r13_snapshot(tx/"new"/str(i)) if entry["after"] is not None else None
            retired=_r13_snapshot(tx/"old"/str(i))
            if current==entry["before"]:
                allowed={"PREPARED","BOUND","RETIRE_INTENT","RESTORE_INTENT","UNDONE"}
                if entry["before"] is None:
                    allowed|={"PUBLISH_INTENT","WITHDRAW_INTENT","APPLIED"}
                if entry["step"] not in allowed or retired is not None or stage!=entry["after"]:
                    raise S12ControlError(MATERIALIZATION_RED)
            elif current==entry["after"] and entry["after"] is not None:
                if (entry["step"] not in {"PUBLISH_INTENT","APPLIED","WITHDRAW_INTENT"}
                        or stage is not None or retired!=entry["before"]):
                    raise S12ControlError(MATERIALIZATION_RED)
            elif current is None:
                if (entry["step"] not in {"RETIRE_INTENT","PUBLISH_INTENT","APPLIED","WITHDRAW_INTENT","RESTORE_INTENT"}
                        or stage!=entry["after"] or retired!=entry["before"]):
                    raise S12ControlError(MATERIALIZATION_RED)
            else:
                raise S12ControlError(MATERIALIZATION_RED)
            if entry["after"] is not None and current==entry["after"]:
                entry["step"]="WITHDRAW_INTENT";_r13_save(tx,value);_r13_boundary("WITHDRAW_INTENT")
                _r13_move(path,tx/"new"/str(i),entry["after"],check)
                _r13_boundary("WITHDRAWN");current=None
            if entry["before"] is not None and current is None:
                entry["step"]="RESTORE_INTENT";_r13_save(tx,value);_r13_boundary("RESTORE_INTENT")
                _r13_move(tx/"old"/str(i),path,entry["before"],check)
                _r13_boundary("RESTORED");current=entry["before"]
            if current!=entry["before"]:
                raise S12ControlError(MATERIALIZATION_RED)
            entry["step"]="UNDONE";_r13_save(tx,value)
        _run(_selected_git_arguments(root,git,"read-tree",value["old_commit"]))
        _run(_selected_git_arguments(root,git,"update-ref","HEAD",value["old_commit"]))
        _r13_publish_records(root,value,undo=True)
        check();value["phase"]="UNDONE";_r13_save(tx,value)


def _r13_recover_pending() -> None:
    if ACTIVE_ATTEMPT is None:
        return
    existing=[root for root in (CONTROL_ROOT,APPLICATION_ROOT) if _barrier_path_present(_r13_location(root))]
    loaded = {root:_r13_load(root) for root in existing}
    if not any(value["phase"] not in {"APPLIED","UNDONE"} for _,value in loaded.values()):
        return
    _,_,attempt = _load_recovery_backup()
    roots=(APPLICATION_ROOT,CONTROL_ROOT)
    metadata=_repository_git_metadata_paths(roots)
    # This prefix only closes pre-activation/interrupted rollback states.
    # Canonical recovery's safety admission must precede its first move too.
    if (not _repository_barriers_are_installed()
            or _successful_result_matches_attempt(attempt)
            or _rollback_unit_state() != ("inactive","dead")
            or _competing_control_sync_count()
            or _active_repository_git_count(roots)
            or _active_recovery_git_handle_count(metadata)
            or _active_tracked_worktree_write_handle_count(
                _tracked_worktree_regular_paths(roots,allow_missing=True))):
        for tx,value in loaded.values():
            value["unsafe"]=True
            _r13_save(tx,value)
        raise S12ControlError(MATERIALIZATION_RED)
    # Pending undo and canonical recovery share this epoch. No stop/rebaseline
    # between the first undo write and the later serialized protection handoff.
    transition = _GitMetadataTransitionGuard(tuple(metadata))
    try:
        writers = _r13_git_writers(roots)
        transition.assert_unchanged()
        if writers is None or MATERIALIZATION_GUARDS is None:
            raise S12ControlError(GIT_WRITER_RED)
        MATERIALIZATION_GUARDS.retain(_r13_initial_worktree_guards(roots,writers))
    finally:
        transition.close()
    for root in existing:
        git=_recovery_git_path(root)
        _validate_root_git_contract(git)
        _r13_materialize_undo(root,git)
    _r13_boundary("PENDING_MATERIALIZATION_UNDONE")


def _followup_authorization(path: Path, digest: str, *, recovering: bool) -> dict:
    """An out-of-band, root-provisioned HUMAN grant; a freeze is not a grant."""
    if os.geteuid() != 0 or path != PRIVATE_ROOT / "authorizations" / (FOLLOWUP_SLOT + ".json"):
        raise S12ControlError(FOLLOWUP_RED)
    _validate_secure_directory_chain(path.parent, Path("/"))
    if path.lstat().st_gid != 0:
        raise S12ControlError(FOLLOWUP_RED)
    value = json.loads(_read_private_backup_blob(path, digest, FOLLOWUP_RED))
    if not isinstance(value, dict) or set(value) != {
        "schema", "slot", "human_authorization_sha256", "acknowledgment",
        "authorized_at", "expires_at", "release", "parent_proof",
    }:
        raise S12ControlError(FOLLOWUP_RED)
    release = value["release"]
    parent = value["parent_proof"]
    if (value["schema"] != "TU1NZ_S12_1_FOLLOWUP_AUTHORIZATION_V1"
            or value["slot"] != FOLLOWUP_SLOT
            or value["acknowledgment"] != "AUTHORIZE_ONE_SYNTHETIC_SANDBOX_DEPLOYMENT_AFTER_RECOVERY"
            or not isinstance(value["human_authorization_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["human_authorization_sha256"]) is None
            or value["human_authorization_sha256"] == "0" * 64
            or type(value["authorized_at"]) is not int or type(value["expires_at"]) is not int
            or not 0 < value["expires_at"] - value["authorized_at"] <= 86400
            or (not recovering and not value["authorized_at"] <= time.time() < value["expires_at"])
            or not isinstance(release, dict) or set(release) != {
                "tag", "tag_object", "control_commit", "control_tree",
                "application_commit", "application_tree", "controller_sha256",
                "application_bundle_sha256", "control_bundle_sha256"}
            or not isinstance(parent, dict) or set(parent) != {
                "attempt", "index", "rollback", "progress", "recovery", "r12_original", "r12_ledger"}):
        raise S12ControlError(FOLLOWUP_RED)
    for field, size in {"tag_object":40,"control_commit":40,"control_tree":40,
            "application_commit":40,"application_tree":40,"controller_sha256":64,
            "application_bundle_sha256":64,"control_bundle_sha256":64}.items():
        if not isinstance(release[field], str) or re.fullmatch(r"[0-9a-f]{" + str(size) + "}",release[field]) is None:
            raise S12ControlError(FOLLOWUP_RED)
    if (release["tag"] != FREEZE_TAG
            or release["application_commit"] != APPLICATION_COMMIT
            or release["application_tree"] != APPLICATION_TREE
            or release["controller_sha256"] != _trusted_controller_digest()
            or any(not isinstance(v,str) or re.fullmatch(r"[0-9a-f]{64}",v) is None for v in parent.values())
            or any(parent[key] != value for key,value in FOLLOWUP_PARENT.items())):
        raise S12ControlError(FOLLOWUP_RED)
    if not recovering and (
        release["application_bundle_sha256"] != os.environ.get(APPLICATION_BUNDLE_DIGEST_ENV)
        or release["control_bundle_sha256"] != os.environ.get(CONTROL_BUNDLE_DIGEST_ENV)
    ):
        raise S12ControlError(FOLLOWUP_RED)
    return value


def _followup_validate_parent(binding: dict) -> None:
    """Supervise validation without adopting or rewriting an attempt journal.

    The fixed audit is bound to the explicit grant, not to the legacy attempt.
    Its read-only lifetime records survive interruption; RUNNING/FAILED cannot
    be re-admitted. This does not consume or renew the deployment permission.
    """
    global GIT_WRITER_SCOPE
    if GIT_WRITER_SCOPE is not None or ACTIVE_ATTEMPT is not None:
        raise S12ControlError(GIT_WRITER_RED)
    _validate_secure_directory_chain(STATE_ROOT,Path('/'))
    writers=_R13GitWriters((APPLICATION_ROOT,CONTROL_ROOT),validation_binding=binding)
    GIT_WRITER_SCOPE=writers
    try:
        _r13_boundary('FOLLOWUP_VALIDATION_READY')
        _followup_parent_closed(binding['parent_proof'])
        read_only_preflight()
        _r13_boundary('FOLLOWUP_VALIDATION_COMPLETE')
        writers.check()
        if writers.value['observer_baseline']!=_r13_observer_baseline(writers.roots):
            writers.fail()
        _r13_retire_git_writers()
    finally:
        writers.close(aborted=True)
        GIT_WRITER_SCOPE=None


def _followup_parent_closed(proof: dict) -> None:
    """No stale result alone can authorize a follow-up. Revalidate the chain."""
    _validate_secure_directory_chain(STATE_ROOT, Path("/"))
    backup,index,attempt = _load_recovery_backup()
    paths = dict(attempt=ATTEMPT_MARKER,index=backup/"restore-index.json",
        rollback=backup/"rollback-complete.json",progress=backup/"rollback-progress.json",
        recovery=STATE_ROOT/"recovery-result.json",r12_original=STATE_ROOT/"repository-barrier.r12-original.json",
        r12_ledger=STATE_ROOT/"repository-barrier.r12-bindings.json")
    values = {key:json.loads(_read_private_backup_blob(path,proof[key],FOLLOWUP_RED)) for key,path in paths.items()}
    if any(not isinstance(value,dict) for value in values.values()):
        raise S12ControlError(FOLLOWUP_RED)
    ledger=values["r12_ledger"]
    if (values["rollback"].get("safe_code") != "S12_1_ROLLBACK_GREEN"
            or values["rollback"].get("ok") is not True or values["rollback"].get("count") != 1
            or values["recovery"].get("safe_code") not in {
                "S12_1_INTERRUPTED_DEPLOYMENT_RECOVERED", "S12_1_RECOVERY_ALREADY_COMPLETE"}
            or values["recovery"].get("ok") is not True or values["recovery"].get("rollback_count") != 1
            or ledger.get("schema") != "TU1NZ_S12_1_R12_BINDINGS_V1"
            or ledger.get("phase") != "SEALED" or ledger.get("historical_continuity") is not False
            or ledger.get("contract_sha256") != R12_CONTRACT_SHA256
            or ledger.get("original_journal_sha256") != proof["r12_original"]
            or values["r12_original"].get("schema") != BARRIER_SCHEMA
            or _successful_result_matches_attempt(attempt)
            or any(_barrier_path_present(path) for path in (
                BARRIER_MARKER,BARRIER_RELEASE_BACKUP,STATE_ROOT/"repository-barrier.r12-abort.json",
                STATE_ROOT/"deployment-result.json"))):
        raise S12ControlError("S12_1_FOLLOWUP_PARENT_NOT_CLOSED_RED")
    progress=_load_rollback_progress(backup)
    if progress is None or progress["phase"] != ROLLBACK_PHASE_REPOSITORIES_RESTORED:
        raise S12ControlError("S12_1_FOLLOWUP_PARENT_NOT_CLOSED_RED")
    if any(_barrier_path_present(_recovery_git_path(root)) or _is_recovery_guard(root/".git")
           for root in (APPLICATION_ROOT,CONTROL_ROOT)):
        raise S12ControlError("S12_1_FOLLOWUP_PARENT_NOT_CLOSED_RED")
    if _rollback_unit_state() != ("inactive","dead"):
        raise S12ControlError("S12_1_FOLLOWUP_PARENT_NOT_CLOSED_RED")
    for key in ("application","control"):
        record=index[key]
        for suffix,field in ((".bundle","bundle_sha256"),(".tracked-path-hashes","tracked_path_hashes_sha256")):
            _read_private_backup_blob(backup/(key+suffix),record[field],FOLLOWUP_RED)
        if _reflog_tree_digest(backup/(key+".reflogs")) != record["reflog_snapshot_sha256"]:
            raise S12ControlError(FOLLOWUP_RED)
    roots=(APPLICATION_ROOT,CONTROL_ROOT)
    _validate_release_repository_states(progress["repository_state"],
        {root:root/".git" for root in roots},
        {root:index[key] for root,key in zip(roots,("application","control"))})
    for root,key in zip(roots,("application","control")):
        _validate_repository_worktree_contract(root,index[key])
    if (_competing_control_sync_count() or _active_repository_git_count(roots)
            or _active_recovery_git_handle_count(tuple(root/".git" for root in roots))
            or _active_tracked_worktree_write_handle_count(_tracked_worktree_regular_paths(roots))):
        raise S12ControlError("S12_1_RECOVERY_GIT_ACTIVE_RED")


@contextmanager
def _followup_namespace(binding: dict):
    """One fixed finite slot; no caller-supplied filesystem paths or counters."""
    names=("STATE_ROOT","BACKUP_ROOT","ATTEMPT_MARKER","BARRIER_MARKER",
           "BARRIER_RELEASE_BACKUP","BARRIER_RELEASE_COMPLETION","ACTIVE_ATTEMPT")
    previous={name:globals()[name] for name in names}
    if ACTIVE_ATTEMPT is not None:
        raise S12ControlError(FOLLOWUP_RED)
    state=STATE_ROOT/"attempts"/FOLLOWUP_SLOT
    globals().update(STATE_ROOT=state,BACKUP_ROOT=BACKUP_ROOT/FOLLOWUP_SLOT,
        ATTEMPT_MARKER=state/"deployment-attempted.json",BARRIER_MARKER=state/"repository-barrier.json",
        BARRIER_RELEASE_BACKUP=state/"repository-barrier.release-backup.json",
        BARRIER_RELEASE_COMPLETION=state/"repository-barrier.release-complete.json",ACTIVE_ATTEMPT=binding)
    try:
        yield
    finally:
        globals().update(previous)


def followup(path: Path, digest: str, *, recovering: bool = False) -> dict:
    with _exclusive_deployment_lock():
        authorization=_followup_authorization(path,digest,recovering=recovering)
        binding=dict(slot=FOLLOWUP_SLOT,authorization_sha256=digest,
                     parent_classification="INTERRUPTED_DEPLOYMENT_RECOVERED_R12_NONHISTORICAL_BINDINGS",
                     release=authorization["release"],parent_proof=authorization["parent_proof"])
        claim=STATE_ROOT/(FOLLOWUP_SLOT+".consumed.json")
        closure=STATE_ROOT/(FOLLOWUP_SLOT+".closed-without-deployment.json")
        receipt=dict(schema="TU1NZ_S12_1_FOLLOWUP_CONSUMED_V1",attempt_binding=binding)
        if recovering:
            _validate_secure_directory_chain(STATE_ROOT,Path("/"))
            if _private_json(claim,FOLLOWUP_RED) != receipt:
                raise S12ControlError(FOLLOWUP_RED)
            namespace=STATE_ROOT/"attempts"/FOLLOWUP_SLOT
            no_namespace=not _barrier_path_present(namespace)
            no_backup=not _barrier_path_present(BACKUP_ROOT/FOLLOWUP_SLOT)
            empty_namespace=False
            observer_only=False
            if not no_namespace:
                _validate_secure_directory_chain(namespace,Path("/"))
                metadata=namespace.lstat()
                private=(metadata.st_gid==0 and stat.S_IMODE(metadata.st_mode)==0o700
                         and not os.listxattr(namespace))
                names={entry.name for entry in namespace.iterdir()}
                empty_namespace=private and not names
                observer_only=private and names=={'git-writer-scope.json'}
            if no_backup and observer_only:
                _followup_validate_parent(binding)
                with _followup_namespace(binding), _r13_guard_scope():
                    journal=STATE_ROOT/'git-writer-scope.json'
                    original=_private_json(journal,FOLLOWUP_RED,maximum=4*1024*1024)
                    roots=(APPLICATION_ROOT,CONTROL_ROOT)
                    if (original.get('attempt_binding')!=binding
                            or original.get('phase')!='QUIET'
                            or original.get('tasks')!=[] or original.get('operation') is not None
                            or not isinstance(original.get('history'),list)
                            or any(not isinstance(op,dict) or op.get('access_profile')!='READ_ONLY'
                                   or 'stdout' in op or not isinstance(op.get('task_history'),list)
                                   or any(not isinstance(task,dict) or task.get('exited') is not True
                                          for task in op['task_history'])
                                   for op in original['history'])
                            or original.get('observer_baseline')!=_r13_observer_baseline(roots)):
                        raise S12ControlError(FOLLOWUP_RED)
                    original_digest=_sha256(journal)
                    # Resume only observation, never a command or activation.
                    # The constructor checks image identities, Git ctimes,
                    # sequence/history consistency and installs a fresh stream.
                    writers=_r13_git_writers(roots)
                    if (_sha256(journal)!=original_digest
                            or original['observer_baseline']!=_r13_observer_baseline(roots)):
                        writers.fail()
                    writers.check()
                    result=dict(ok=True,safe_code='S12_1_FOLLOWUP_OBSERVER_ONLY_CLOSED',
                                deployment_count=0,rollback_count=0,attempt_binding=binding,
                                observer_journal_sha256=original_digest,
                                observation_continuity='NOT_ASSERTED_ACROSS_INTERRUPTION')
                    parent_guard=_R12AttributeGuard((DEPLOYMENT_LOCK_ROOT,),event_mask=0xFCE)
                    try:
                        if _barrier_path_present(closure):
                            if _private_json(closure,FOLLOWUP_RED)!=result:
                                raise S12ControlError(FOLLOWUP_RED)
                        else:
                            _r13_boundary('FOLLOWUP_OBSERVER_CLOSURE_BEFORE_WRITE')
                            _atomic_json(closure,result)
                            _r13_boundary('FOLLOWUP_OBSERVER_CLOSURE_WRITTEN')
                        if original['observer_baseline']!=_r13_observer_baseline(roots):
                            writers.fail()
                        writers.check()
                        parent_guard.assert_quiet()
                        _r13_retire_git_writers()
                        parent_guard.assert_quiet()
                        if (_sha256(journal)!=original_digest
                                or {entry.name for entry in STATE_ROOT.iterdir()}!={'git-writer-scope.json'}):
                            raise S12ControlError(FOLLOWUP_RED)
                    finally:
                        parent_guard.close()
                    return result
            if no_backup and (no_namespace or empty_namespace):
                _followup_validate_parent(binding)
                # Do not adopt or write into the possibly unbound mkdir result.
                # The fixed consumed-slot parent owns this idempotent closure;
                # an empty namespace is retained without an origin assertion.
                result=dict(ok=True,safe_code="S12_1_FOLLOWUP_CONSUMED_WITHOUT_DEPLOYMENT",
                            deployment_count=0,rollback_count=0,attempt_binding=binding,
                            namespace_provenance="NOT_ASSERTED_RETAINED_IF_PRESENT")
                if _barrier_path_present(closure):
                    if _private_json(closure,FOLLOWUP_RED)!=result:
                        raise S12ControlError(FOLLOWUP_RED)
                    return result
                _r13_boundary("FOLLOWUP_EARLY_CLOSURE_BEFORE_WRITE")
                _atomic_json(closure,result)
                _r13_boundary("FOLLOWUP_EARLY_CLOSURE_WRITTEN")
                return result
            with _followup_namespace(binding), _r13_guard_scope() as guards:
                # Recovery never invokes deploy, admission, or activation.
                _r13_begin_attempt_observation()
                _r13_recover_pending()
                guards.assert_quiet()
                result=_recover_locked()
                result={**result,"attempt_binding":binding}
                _atomic_json(STATE_ROOT/"recovery-result.json",result)
                return result
        if _barrier_path_present(claim):
            raise S12ControlError("S12_1_FOLLOWUP_ALREADY_CONSUMED_RED")
        if any(_barrier_path_present(p) for p in (
            STATE_ROOT/"attempts"/FOLLOWUP_SLOT,BACKUP_ROOT/FOLLOWUP_SLOT,closure)):
            raise S12ControlError(FOLLOWUP_RED)
        _followup_validate_parent(binding)
        _r13_preflight_storage()
        # O_EXCL, file fsync, parent fsync: even a crash/partial claim consumes
        # this one slot. No implicit retry and no deletion/reset operation.
        _write_private_backup_blob(claim,json.dumps(receipt,sort_keys=True,separators=(",",":")).encode())
        with _followup_namespace(binding), _r13_guard_scope():
            return _deploy_locked()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("verify-source", "simulate", "preflight", "deploy", "recover", "reconcile-metadata")
    )
    parser.add_argument("--metadata-contract", type=Path)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--authorization-sha256")
    arguments = parser.parse_args(argv)
    try:
        if (arguments.operation == "reconcile-metadata") != (arguments.metadata_contract is not None):
            raise S12ControlError(R12_RED)
        if (arguments.authorization is None) != (arguments.authorization_sha256 is None):
            raise S12ControlError(FOLLOWUP_RED)
        if arguments.authorization is not None and arguments.operation not in {"deploy","recover"}:
            raise S12ControlError(FOLLOWUP_RED)
        if arguments.operation == "deploy" and arguments.authorization is None:
            raise S12ControlError("S12_1_FOLLOWUP_AUTHORIZATION_REQUIRED_RED")
        if arguments.operation in {"deploy", "recover", "reconcile-metadata"}:
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
            if arguments.authorization is not None:
                result=followup(arguments.authorization,arguments.authorization_sha256,recovering=True)
            elif _barrier_path_present(STATE_ROOT/(FOLLOWUP_SLOT+".consumed.json")):
                raise S12ControlError("S12_1_FOLLOWUP_RECOVERY_TARGET_REQUIRED_RED")
            else:
                result = recover()
        elif arguments.operation == "reconcile-metadata":
            result = reconcile_metadata(arguments.metadata_contract)
        else:
            result = followup(arguments.authorization,arguments.authorization_sha256)
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
