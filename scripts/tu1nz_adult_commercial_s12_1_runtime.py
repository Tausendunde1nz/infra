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
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence


APPLICATION_COMMIT = "93555d8a141caf8ace33522f9340d30bfc47d2bb"
APPLICATION_TREE = "1e8a644115127818f394b6f9d24f31826e04ecba"
FREEZE_TAG = "s12-yoti-sandbox-runtime-freeze-r4"
CONTRACT_VERSION = "tu1nz-s12-yoti-sandbox-runtime-v1"
BACKUP_SCHEMA = "TU1NZ_S12_1_RUNTIME_BACKUP_V7"
BARRIER_SCHEMA = "TU1NZ_S12_1_REPOSITORY_BARRIER_V1"
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
    }


def _repository_backup_state(
    root: Path,
    release_branch: str,
    managed_refs: Sequence[str] = (),
    *,
    git_directory: Path | None = None,
    path_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_path_metadata = path_metadata or _repository_path_metadata(root)
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
) -> tuple[Path, ...]:
    """Resolve regular index entries without treating runtime-only files as protected."""

    tracked: list[Path] = []
    for root in roots:
        for path, metadata in _tracked_worktree_index_entries(root):
            if stat.S_ISREG(metadata.st_mode):
                tracked.append(path)
    return tuple(tracked)


def _tracked_worktree_index_entries(
    root: Path,
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


def _tracked_worktree_barrier_paths(root: Path) -> tuple[Path, ...]:
    """Return tracked regular entries and every directory needed to reach them."""

    protected: set[Path] = set()
    for path, metadata in _tracked_worktree_index_entries(root):
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
                else:
                    raise OSError
                if (metadata.st_uid, metadata.st_gid) != (
                    expected_uid,
                    expected_gid,
                ):
                    raise OSError
                entries[path] = {
                    "kind": kind,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
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


def _parse_worktree_barrier_payload(
    payload: Any,
    roots: Sequence[Path],
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
            if not isinstance(raw, dict) or set(raw) != {
                "path_hex",
                "kind",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
            }:
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
            ):
                raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
            path = root / relative
            if path in entries:
                raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
            entries[path] = {
                name: raw[name]
                for name in ("kind", "device", "inode", "uid", "gid", "mode")
            }
        parsed[root] = entries
    return parsed


def _lock_worktree_write_barrier(
    records: dict[Path, dict[Path, dict[str, Any]]],
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
                restricted_mode = mode & ~0o222
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
                    and stat.S_IMODE(metadata.st_mode) == restricted_mode
                )
                actual_kind = (
                    "directory"
                    if stat.S_ISDIR(metadata.st_mode)
                    else "regular"
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    else "invalid"
                )
                resumed = (
                    actual_kind in {"directory", "regular"}
                    and metadata.st_uid == 0
                    and not stat.S_IMODE(metadata.st_mode) & 0o022
                )
                if actual_kind != expected_kind or not (
                    original or locked or resumed
                ):
                    raise OSError
                if original:
                    os.chmod(path, restricted_mode, follow_symlinks=False)
                    os.chown(path, 0, record["gid"], follow_symlinks=False)
                    os.chmod(path, restricted_mode, follow_symlinks=False)
            # New target paths created by a previously interrupted root Git
            # checkout are absent from the durable pre-mutation record. They
            # are safe to resume only when root-owned and already closed to
            # group/other writers. Their root-only write bit remains intact so
            # the final ownership restore releases their canonical Git mode.
            for path in _tracked_worktree_barrier_paths(root):
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
            for path in _tracked_worktree_barrier_paths(root):
                metadata = path.lstat()
                record = recorded_paths.get(path)
                if record is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (record["device"], record["inode"]):
                    expected_gid = record["gid"]
                else:
                    expected_gid = metadata.st_gid
                if (
                    metadata.st_uid != 0
                    or metadata.st_gid != expected_gid
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
                os.chown(
                    path,
                    record["uid"],
                    record["gid"],
                    follow_symlinks=False,
                )
                os.chmod(path, int(record["mode"], 8), follow_symlinks=False)
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
    _IN_ISDIR = 0x40000000
    _ROOT_LOCK_EVENTS = 0x00000004 | 0x00000800  # ATTRIB | MOVE_SELF

    def __init__(self, paths: Sequence[Path]):
        self.paths = tuple(paths)
        self.descriptor: int | None = None
        self.root_watches: set[int] = set()
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
                    watch in self.root_watches
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

    def close(self) -> None:
        if self.descriptor is not None:
            try:
                os.close(self.descriptor)
            finally:
                self.descriptor = None


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
    return {
        "root": str(root),
        **{
            key: record[key]
            for key in (
                "root_uid", "root_gid", "root_mode",
                "git_uid", "git_gid", "git_mode",
            )
        },
    }


def _recorded_parent_metadata(record: dict[str, Any]) -> tuple[int, int, int]:
    uid = record.get("uid")
    gid = record.get("gid")
    mode = record.get("mode")
    if (
        record.get("path") != str(DEPLOYMENT_LOCK_ROOT)
        or type(uid) is not int
        or type(gid) is not int
        or not isinstance(mode, str)
        or re.fullmatch(r"[0-7]{4}", mode) is None
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    return uid, gid, int(mode, 8)


def _metadata_barrier_mode(mode: int) -> int:
    """Remove namespace mutation while retaining every prior traversal class."""

    restricted = mode & ~0o222
    if restricted & 0o050 != 0o050:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED")
    return restricted


def _write_barrier_journal(
    records: dict[Path, dict[str, Any]], parent_record: dict[str, Any]
) -> dict[Path, dict[Path, dict[str, Any]]]:
    if BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    if set(records) != {APPLICATION_ROOT, CONTROL_ROOT}:
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    _recorded_parent_metadata(parent_record)
    roots = (APPLICATION_ROOT, CONTROL_ROOT)
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
    return worktree_barrier


def _load_barrier_journal() -> tuple[
    dict[Path, dict[str, Any]],
    dict[str, Any],
    dict[Path, dict[Path, dict[str, Any]]] | None,
]:
    journal = _private_json(
        BARRIER_MARKER, "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
    )
    repositories = journal.get("repositories")
    parent_record = journal.get("repository_parent")
    if (
        journal.get("schema") != BARRIER_SCHEMA
        or not isinstance(journal.get("created_at"), str)
        or not journal["created_at"]
        or not isinstance(repositories, dict)
        or set(repositories) != {"application", "control"}
        or not isinstance(parent_record, dict)
    ):
        raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
    _recorded_parent_metadata(parent_record)
    records: dict[Path, dict[str, Any]] = {}
    for key, root in (
        ("application", APPLICATION_ROOT),
        ("control", CONTROL_ROOT),
    ):
        item = repositories.get(key)
        if not isinstance(item, dict) or item.get("root") != str(root):
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        record = {name: value for name, value in item.items() if name != "root"}
        if set(record) != {
            "root_uid", "root_gid", "root_mode",
            "git_uid", "git_gid", "git_mode",
        }:
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        _recorded_path_metadata(record, "root")
        _recorded_path_metadata(record, "git")
        records[root] = record
    raw_worktree_barrier = journal.get("worktree_write_barrier")
    worktree_barrier = (
        None
        if raw_worktree_barrier is None
        else _parse_worktree_barrier_payload(
            raw_worktree_barrier,
            (APPLICATION_ROOT, CONTROL_ROOT),
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
    return records, parent_record, worktree_barrier


def _ensure_barrier_journal(
    records: dict[Path, dict[str, Any]], parent_record: dict[str, Any]
) -> dict[Path, dict[Path, dict[str, Any]]]:
    if BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
        recorded_repositories, recorded_parent, worktree_barrier = (
            _load_barrier_journal()
        )
        if recorded_repositories != records or recorded_parent != parent_record:
            raise S12ControlError("S12_1_REPOSITORY_BARRIER_JOURNAL_RED")
        if worktree_barrier is not None:
            return worktree_barrier
        # A legacy R3 orphan never mutated Worktree children. Upgrade its
        # private journal durably before installing the new write barrier.
        worktree_barrier = _capture_worktree_write_barrier(
            (APPLICATION_ROOT, CONTROL_ROOT), records
        )
        journal = _private_json(
            BARRIER_MARKER, "S12_1_REPOSITORY_BARRIER_JOURNAL_RED"
        )
        journal["worktree_write_barrier"] = _worktree_barrier_payload(
            (APPLICATION_ROOT, CONTROL_ROOT), worktree_barrier
        )
        _atomic_json(BARRIER_MARKER, journal)
        return worktree_barrier
    return _write_barrier_journal(records, parent_record)


def _lock_repository_parent(record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    expected_uid, expected_gid, expected_mode = _recorded_parent_metadata(record)
    restricted_mode = _metadata_barrier_mode(expected_mode)
    try:
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
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (original or locked or restricted)
        ):
            raise OSError
        if original:
            os.chmod(DEPLOYMENT_LOCK_ROOT, restricted_mode)
        if original or restricted:
            os.chown(DEPLOYMENT_LOCK_ROOT, 0, expected_gid)
            os.chmod(DEPLOYMENT_LOCK_ROOT, restricted_mode)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != restricted_mode
        ):
            raise OSError
        _fsync_directory(DEPLOYMENT_LOCK_ROOT.parent)
    except OSError:
        raise S12ControlError("S12_1_REPOSITORY_PARENT_RED") from None


def _restore_repository_parent(record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    uid, gid, mode = _recorded_parent_metadata(record)
    restricted_mode = _metadata_barrier_mode(mode)
    try:
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
        if (
            DEPLOYMENT_LOCK_ROOT.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (locked or restricted)
        ):
            raise OSError
        if locked:
            os.chown(DEPLOYMENT_LOCK_ROOT, uid, gid)
        os.chmod(DEPLOYMENT_LOCK_ROOT, mode)
        metadata = DEPLOYMENT_LOCK_ROOT.lstat()
        if (
            metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise OSError
        _fsync_directory(DEPLOYMENT_LOCK_ROOT.parent)
    except OSError:
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
                        allowed_owners.add((0, 0))
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
        if (
            root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or not (original or locked or restricted)
        ):
            raise OSError
        if original:
            os.chmod(root, restricted_mode)
        if original or restricted:
            os.chown(root, 0, expected_gid)
            os.chmod(root, restricted_mode)
        metadata = root.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != restricted_mode
        ):
            raise OSError
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


def _restore_repository_path_metadata(root: Path, record: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        return
    root_uid, root_gid, root_mode = _recorded_path_metadata(record, "root")
    git_uid, git_gid, git_mode = _recorded_path_metadata(record, "git")
    git_directory = root / ".git"
    try:
        _chown_tree(
            root,
            root_uid,
            root_gid,
            {".git", RECOVERY_GIT_DIRECTORY},
        )
        _chown_tree(git_directory, git_uid, git_gid)
        os.chmod(git_directory, git_mode)
        os.chown(git_directory, git_uid, git_gid)
        os.chown(root, root_uid, root_gid)
        os.chmod(root, root_mode)
        _fsync_directory(root.parent)
    except OSError:
        raise S12ControlError("S12_1_RECOVERY_GIT_BARRIER_RED") from None


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
    tracked_paths = _tracked_worktree_regular_paths(selected_roots)
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
        _lock_worktree_write_barrier(selected_worktree_barrier)
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
            selected_roots, selected_worktree_barrier
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
                try:
                    if completed:
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
                    _restore_worktree_write_barrier(
                        selected_worktree_barrier
                    )
                    for root in reversed(selected_roots):
                        _restore_repository_path_metadata(
                            root, selected_records[root]
                        )
                except S12ControlError:
                    cleanup_failed = True
            if parent_locked:
                try:
                    _restore_repository_parent(parent_record)
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
    _recorded_parent_metadata(parent_record)
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
    _recorded_parent_metadata(parent_record)
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
    records, parent_record, _ = _load_barrier_journal()
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
    barrier_present = BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink()
    attempt_present = ATTEMPT_MARKER.exists() or ATTEMPT_MARKER.is_symlink()
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
        if BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
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
    if (
        (BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink())
        and not (ATTEMPT_MARKER.exists() or ATTEMPT_MARKER.is_symlink())
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
        elif BARRIER_MARKER.exists() or BARRIER_MARKER.is_symlink():
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
