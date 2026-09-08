#!/usr/bin/env python3
"""Backup-first recovery for the S10.2D-R7 aggregate rollback gap.

The target release added COMMUNITY_CTA to a shared aggregate JSON file.  The
source release intentionally accepts only LANDING_VIEW and TELEGRAM_CTA.  This
tool preserves the original bytes and the forward-only aggregate entries,
then restores a source-compatible view without touching database or user data.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Mapping


APPLICATION_ROOT = Path("/opt/tu1nz_repos/adult-publishing-core")
CONTROL_ROOT = Path("/opt/tu1nz_repos/control")
BACKUP_PARENT = Path("/opt/tu1nz_repos/backups")
RECOVERY_PREFIX = BACKUP_PARENT / "commercial-s10-2d-r7-aggregate-recovery"
AGGREGATE_PATH = Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json")

SOURCE_SHA = "f9747088a31ec6c671e82de24e293ebdec99f717"
SOURCE_TREE = "7defedef032f6af38bbce0165eb6c2bdec327df7"
SOURCE_EVENTS = frozenset({"LANDING_VIEW", "TELEGRAM_CTA"})
FORWARD_EVENTS = frozenset({"COMMUNITY_CTA"})
ALL_EVENTS = SOURCE_EVENTS | FORWARD_EVENTS
MAX_AGGREGATE_BYTES = 8 * 1024 * 1024

SERVICES = (
    "tu1nz-adult-public-s8-landing.service",
    "tu1nz-adult-public-s8-telegram.service",
    "tu1nz-adult-public-s10-wms.service",
)
GREEN_SERVICES = (
    "tu1nz-adult-public-s7.service",
    *SERVICES,
    "nginx.service",
)
TIMERS = (
    "tu1nz-adult-public-s9-audience.timer",
    "tu1nz-adult-public-s9-nurture.timer",
    "tu1nz-adult-public-s9-report.timer",
    "tu1nz-adult-public-s9-health.timer",
    "tu1nz-adult-public-s10-health.timer",
)
HEALTH_SERVICES = (
    "tu1nz-adult-public-s8-health.service",
    "tu1nz-adult-public-s9-health.service",
    "tu1nz-adult-public-s10-health.service",
)
HEALTH_START_SETTLE_DELAYS_SECONDS = (0, 5, 15, 30)
RECOVERY_WORKERS = (
    "tu1nz-adult-public-s8-health.service",
    "tu1nz-adult-public-s8-probe.service",
    "tu1nz-adult-public-s9-audience.service",
    "tu1nz-adult-public-s9-nurture.service",
    "tu1nz-adult-public-s9-report.service",
    "tu1nz-adult-public-s9-health.service",
    "tu1nz-adult-public-s10-health.service",
)
ADULT_RUNTIMES = (
    "tu1nz-adult-commercial-s0.service",
    "tu1nz-adult-commercial-s3.service",
    "tu1nz-adult-commercial-s3-s3-1.service",
    "tu1nz-adult-commercial-s4.service",
)

SOURCE_HASHES = {
    Path("/etc/tu1nz/adult-commercial-s7-public.json"): "f4e2b473905f6c82afe2ad6473989604e47f26eff70356db74da6fd49af50214",
    Path("/etc/tu1nz/adult-commercial-s8-landing.json"): "f8b7215b35d7d871cbc775f5b35c0469dfb047a29c1cf56789373a70dad76469",
    Path("/etc/tu1nz/adult-commercial-s9-growth.json"): "274677854b3067cf970f103fc3f541f31e4244df017f9bbcaa0da0c707aa2bf5",
    Path("/etc/tu1nz/adult-commercial-s8-public-telegram.json"): "7879bf2ddb503d4b16d5095773166bbeb6d7ffc507f18da5502394c8c7a71d55",
    Path("/etc/tu1nz/adult-commercial-s8-copy.json"): "35050d02636630c23b7c97ae0184945b4587695f9a121e908f5f638bd668bd01",
    Path("/etc/tu1nz/adult-commercial-s10-wms.json"): "675fdb138014b06094549183a55f916829a0ba5a8fb6c999039278ded1fe5698",
    Path("/etc/tu1nz/adult-commercial-s10-wms-copy.json"): "f995929dd9fe037fcc469e2c0573607f1d90fc757a76df89ef51d0f59c899fdc",
    Path("/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json"): "7879bf2ddb503d4b16d5095773166bbeb6d7ffc507f18da5502394c8c7a71d55",
    Path("/etc/systemd/system/tu1nz-adult-public-s8-telegram.service"): "2a83f8ccb2945315d98191831cc2c0059d14a30122e23f5db149f90ea308deee",
    Path("/etc/systemd/system/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf"): "2eaa68ace7a2ed4259be422cb7908eb5994735691c265d20935ca4d354d9565a",
    Path("/etc/systemd/system/tu1nz-adult-public-s8-health.service"): "24c6d544bd12a93b8631da8fa017cc50e45432f5c9ca736359fe5f8c304f4d88",
    Path("/etc/systemd/system/tu1nz-adult-public-s10-wms.service"): "7016f1b110d5b87ec9455d588bf9ca502be419b3b95162a4441fc0d6187a3939",
    Path("/etc/systemd/system/tu1nz-adult-public-s10-health.service"): "6fa111959f26a2cea7a37f5251dfe4d130aa4b64bd89963fc220afe366969eb1",
    Path("/etc/systemd/system/tu1nz-adult-public-s9-health.service.d/s10-wms.conf"): "4d9506b2e9ad1bee5f30f57f50680b77705c0c0e1bdc7e2047483d5f1220d81b",
    Path("/usr/local/bin/tu1nz_adult_public_s8_health.py"): "2f3f82209c4c61fb617f74c9a094ab095af5eee2c3007fc19d2b3b68d9e02f4f",
    Path("/usr/local/bin/tu1nz_adult_public_s10_1_health.py"): "84eaae51dd3a208516788b183b2f5ec41609751b126870799fba48d477fc84ea",
}

TARGET_ONLY_PATHS = (
    Path("/etc/tu1nz/adult-commercial-s10-2d-community.json"),
    Path("/etc/tu1nz/adult-commercial-s10-2d-community-copy.json"),
    Path("/etc/systemd/system/tu1nz-adult-public-s10-2d-rotate.service"),
)

PUBLIC_PAGES = (
    "https://wantmeseen.com/",
    "https://wantmeseen.com/privacy",
    "https://wantmeseen.com/terms",
    "https://wantmeseen.com/imprint",
)
HEALTH_URLS = (
    "http://127.0.0.1:18110/health",
    "https://wantmeseen.com/health",
)
BOUNDARY_KEYS = (
    "adult_content",
    "media_intake",
    "identity_documents",
    "real_avs",
    "payments",
    "external_publishing",
    "controlled_beta",
    "production",
)


class RecoveryError(Exception):
    """Expected fail-closed recovery error containing only a safe code."""


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise RecoveryError(safe_code)


def sha256_bytes(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("AGGREGATE_DUPLICATE_KEY")
        result[key] = value
    return result


def parse_aggregate(material: bytes) -> dict[str, int]:
    """Parse the bounded aggregate state without accepting duplicate keys."""

    require(len(material) <= MAX_AGGREGATE_BYTES, "AGGREGATE_SIZE_RED")
    try:
        decoded = material.decode("ascii")
        payload = json.loads(decoded, object_pairs_hook=_unique_object)
    except RecoveryError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise RecoveryError("AGGREGATE_JSON_RED") from None
    require(isinstance(payload, dict), "AGGREGATE_SHAPE_RED")
    result: dict[str, int] = {}
    for key, value in payload.items():
        require(isinstance(key, str), "AGGREGATE_KEY_RED")
        require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "AGGREGATE_COUNT_RED")
        parts = key.split("|")
        require(len(parts) == 4 and all(parts), "AGGREGATE_KEY_RED")
        try:
            dt.date.fromisoformat(parts[0])
        except ValueError:
            raise RecoveryError("AGGREGATE_DATE_RED") from None
        require(parts[1] in ALL_EVENTS, "AGGREGATE_EVENT_RED")
        require(all(len(part) <= 64 for part in parts[1:]), "AGGREGATE_DIMENSION_RED")
        result[key] = value
    return result


def partition_aggregate(payload: Mapping[str, int]) -> tuple[dict[str, int], dict[str, int]]:
    source: dict[str, int] = {}
    forward: dict[str, int] = {}
    for key, value in payload.items():
        event = key.split("|")[1]
        if event in SOURCE_EVENTS:
            source[key] = value
        elif event in FORWARD_EVENTS:
            forward[key] = value
        else:  # defensive even if parse_aggregate already checked the event
            raise RecoveryError("AGGREGATE_EVENT_RED")
    require(bool(forward), "FORWARD_AGGREGATE_NOT_PRESENT")
    require(len(source) + len(forward) == len(payload), "AGGREGATE_PARTITION_RED")
    require(sum(source.values()) + sum(forward.values()) == sum(payload.values()), "AGGREGATE_CONSERVATION_RED")
    return source, forward


def _run(arguments: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RecoveryError("COMMAND_EXECUTION_RED") from None


def _git_value(root: Path, expression: str) -> str:
    completed = _run(["/usr/sbin/runuser", "-u", "chatops", "--", "/usr/bin/git", "-C", str(root), "rev-parse", expression])
    require(completed.returncode == 0, "GIT_STATE_RED")
    return completed.stdout.strip()


def _git_clean(root: Path) -> bool:
    completed = _run(["/usr/sbin/runuser", "-u", "chatops", "--", "/usr/bin/git", "-C", str(root), "status", "--porcelain=v1"])
    return completed.returncode == 0 and completed.stdout == ""


def _unit_value(unit: str, property_name: str) -> str:
    completed = _run(["/usr/bin/systemctl", "show", unit, "-p", property_name, "--value"])
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _systemctl(*arguments: str, safe_code: str, timeout: int = 95) -> None:
    completed = _run(["/usr/bin/systemctl", *arguments], timeout=timeout)
    require(completed.returncode == 0, safe_code)


def _reset_failed_if_needed(unit: str, *, safe_code: str) -> None:
    """Reset systemd failure state only when the unit is actually failed."""

    if _unit_value(unit, "ActiveState") == "failed":
        _systemctl("reset-failed", unit, safe_code=safe_code)


def _start_health_with_settle(unit: str) -> None:
    """Bound health start retries while a newly started poller becomes ready."""

    for delay in HEALTH_START_SETTLE_DELAYS_SECONDS:
        if delay:
            time.sleep(delay)
        _reset_failed_if_needed(unit, safe_code="HEALTH_SERVICE_RESET_RED")
        completed = _run(["/usr/bin/systemctl", "start", unit], timeout=95)
        if completed.returncode == 0:
            return
    raise RecoveryError("HEALTH_SERVICE_START_RED")


def _regular_metadata(path: Path, *, expected_uid: int | None = None) -> os.stat_result:
    require(path.is_absolute() and not path.is_symlink(), "PATH_UNSAFE")
    try:
        metadata = path.lstat()
    except OSError:
        raise RecoveryError("PATH_MISSING") from None
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "PATH_UNSAFE")
    if expected_uid is not None:
        require(metadata.st_uid == expected_uid, "AGGREGATE_OWNER_RED")
    require(stat.S_IMODE(metadata.st_mode) == 0o600, "AGGREGATE_MODE_RED")
    return metadata


def _read_exact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            current = path.lstat()
            require(
                stat.S_ISREG(opened.st_mode)
                and opened.st_nlink == 1
                and (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino),
                "PATH_UNSAFE",
            )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                material = stream.read(MAX_AGGREGATE_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError:
        raise RecoveryError("AGGREGATE_READ_RED") from None
    require(len(material) <= MAX_AGGREGATE_BYTES, "AGGREGATE_SIZE_RED")
    return material


def _write_new(path: Path, material: bytes, *, uid: int, gid: int, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags, mode)
        created = True
        try:
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, uid, gid)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(material)
                stream.flush()
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise RecoveryError("BACKUP_WRITE_RED") from None


def _atomic_replace(path: Path, material: bytes, *, uid: int, gid: int, mode: int) -> None:
    temporary = path.with_name(path.name + ".s10-2d-r7-recovery.tmp")
    require(not temporary.exists() and not temporary.is_symlink(), "TEMPORARY_PATH_OCCUPIED")
    _write_new(temporary, material, uid=uid, gid=gid, mode=mode)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise RecoveryError("AGGREGATE_REPLACE_RED") from None


def _write_evidence(path: Path, value: object) -> None:
    _write_new(path, canonical_json(value) + b"\n", uid=0, gid=0)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise RecoveryError("BACKUP_DIRECTORY_SYNC_RED") from None


def _normalize_private_directory(path: Path, *, expected_uid: int, expected_gid: int) -> None:
    """Remove only an inherited setgid bit from an otherwise private directory."""

    require(path.is_dir() and not path.is_symlink(), "RECOVERY_PREFIX_UNSAFE")
    metadata = path.lstat()
    require(
        metadata.st_uid == expected_uid
        and metadata.st_gid == expected_gid
        and stat.S_IMODE(metadata.st_mode) in {0o700, 0o2700},
        "RECOVERY_PREFIX_UNSAFE",
    )
    if stat.S_IMODE(metadata.st_mode) == 0o2700:
        try:
            os.chmod(path, 0o700)
        except OSError:
            raise RecoveryError("RECOVERY_PREFIX_NORMALIZE_RED") from None
    require(stat.S_IMODE(path.lstat().st_mode) == 0o700, "RECOVERY_PREFIX_NORMALIZE_RED")


def _prepare_recovery_prefix() -> None:
    """Create or narrowly normalize the root-only backup prefix."""

    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(BACKUP_PARENT.is_dir() and not BACKUP_PARENT.is_symlink(), "BACKUP_PARENT_UNSAFE")
    try:
        if not RECOVERY_PREFIX.exists():
            os.mkdir(RECOVERY_PREFIX, 0o700)
            os.chown(RECOVERY_PREFIX, 0, 0)
        _normalize_private_directory(RECOVERY_PREFIX, expected_uid=0, expected_gid=0)
        _fsync_directory(RECOVERY_PREFIX)
        _fsync_directory(BACKUP_PARENT)
    except RecoveryError:
        raise
    except OSError:
        raise RecoveryError("RECOVERY_PREFIX_CREATE_RED") from None


def _validate_control_binding(control_sha: str, control_tree: str) -> None:
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", control_sha)), "CONTROL_SHA_INVALID")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", control_tree)), "CONTROL_TREE_INVALID")
    for root in (APPLICATION_ROOT, CONTROL_ROOT):
        require(root.is_dir() and not root.is_symlink() and (root / ".git").is_dir(), "REPOSITORY_PATH_UNSAFE")
        require(_git_clean(root), "REPOSITORY_DIRTY")
    require(_git_value(CONTROL_ROOT, "HEAD") == control_sha, "CONTROL_SHA_MISMATCH")
    require(_git_value(CONTROL_ROOT, "HEAD^{tree}") == control_tree, "CONTROL_TREE_MISMATCH")
    require(_git_value(APPLICATION_ROOT, "HEAD") == SOURCE_SHA, "APPLICATION_SOURCE_MISMATCH")
    require(_git_value(APPLICATION_ROOT, "HEAD^{tree}") == SOURCE_TREE, "APPLICATION_TREE_MISMATCH")


def _validate_source_surface() -> None:
    for path, expected_hash in SOURCE_HASHES.items():
        metadata = path.lstat() if path.exists() else None
        require(metadata is not None and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and not path.is_symlink(), "SOURCE_SURFACE_PATH_RED")
        require(sha256_bytes(_read_exact(path)) == expected_hash, "SOURCE_SURFACE_HASH_RED")
    require(all(not path.exists() and not path.is_symlink() for path in TARGET_ONLY_PATHS), "TARGET_SURFACE_PRESENT")
    exec_start = _unit_value("tu1nz-adult-public-s8-telegram.service", "ExecStart")
    require("tu1nz_public_s8.runtime" in exec_start, "SOURCE_EXECSTART_RED")
    require("--community-contract" not in exec_start and "--community-copy" not in exec_start, "TARGET_EXECSTART_PRESENT")


def _validate_recovery_path(recovery_dir: Path, *, must_exist: bool) -> None:
    require(recovery_dir.is_absolute(), "RECOVERY_PATH_UNSAFE")
    require(recovery_dir.parent == RECOVERY_PREFIX, "RECOVERY_PATH_UNSAFE")
    require(bool(re.fullmatch(r"\d{8}T\d{6}Z", recovery_dir.name)), "RECOVERY_NAME_INVALID")
    require(BACKUP_PARENT.is_dir() and not BACKUP_PARENT.is_symlink(), "BACKUP_PARENT_UNSAFE")
    if RECOVERY_PREFIX.exists() or RECOVERY_PREFIX.is_symlink():
        require(RECOVERY_PREFIX.is_dir() and not RECOVERY_PREFIX.is_symlink(), "RECOVERY_PREFIX_UNSAFE")
        prefix_metadata = RECOVERY_PREFIX.lstat()
        require(
            prefix_metadata.st_uid == 0
            and prefix_metadata.st_gid == 0
            and stat.S_IMODE(prefix_metadata.st_mode) == 0o700,
            "RECOVERY_PREFIX_UNSAFE",
        )
    if must_exist:
        require(recovery_dir.is_dir() and not recovery_dir.is_symlink(), "RECOVERY_DIRECTORY_MISSING")
        metadata = recovery_dir.lstat()
        require(
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "RECOVERY_DIRECTORY_UNSAFE",
        )
    else:
        require(not recovery_dir.exists() and not recovery_dir.is_symlink(), "RECOVERY_DIRECTORY_EXISTS")


def _validate_quiescent_state() -> None:
    require(_unit_value("tu1nz-adult-public-s7.service", "ActiveState") == "active", "S7_NOT_ACTIVE")
    require(_unit_value("nginx.service", "ActiveState") == "active", "NGINX_NOT_ACTIVE")
    for service in SERVICES:
        require(_unit_value(service, "ActiveState") in {"inactive", "failed"}, "AGGREGATE_WRITER_ACTIVE")
    require(_unit_value("tu1nz-adult-public-s10-2d-rotate.service", "ActiveState") in {"", "inactive", "failed"}, "TARGET_ROTATION_ACTIVE")


def _load_current_aggregate() -> tuple[bytes, dict[str, int], os.stat_result]:
    try:
        chatops = pwd.getpwnam("chatops")
    except KeyError:
        raise RecoveryError("CHATOPS_IDENTITY_MISSING") from None
    require(AGGREGATE_PATH.parent.is_dir() and not AGGREGATE_PATH.parent.is_symlink(), "AGGREGATE_PARENT_UNSAFE")
    temporary = AGGREGATE_PATH.with_name(AGGREGATE_PATH.name + ".s10-2d-r7-recovery.tmp")
    require(not temporary.exists() and not temporary.is_symlink(), "TEMPORARY_PATH_OCCUPIED")
    metadata = _regular_metadata(AGGREGATE_PATH, expected_uid=chatops.pw_uid)
    require(metadata.st_gid == chatops.pw_gid, "AGGREGATE_GROUP_RED")
    material = _read_exact(AGGREGATE_PATH)
    payload = parse_aggregate(material)
    partition_aggregate(payload)
    return material, payload, metadata


def preflight(control_sha: str, control_tree: str, recovery_dir: Path) -> dict[str, object]:
    _validate_control_binding(control_sha, control_tree)
    _validate_source_surface()
    _validate_recovery_path(recovery_dir, must_exist=False)
    _validate_quiescent_state()
    material, payload, _metadata = _load_current_aggregate()
    source, forward = partition_aggregate(payload)
    return {
        "ok": True,
        "safe_code": "S10_2D_R7_AGGREGATE_RECOVERY_PREFLIGHT_GREEN",
        "original_sha256": sha256_bytes(material),
        "source_entries": len(source),
        "source_total": sum(source.values()),
        "forward_entries": len(forward),
        "forward_total": sum(forward.values()),
        "adult_media": False,
        "avs": False,
        "payments": False,
        "publishing": False,
    }


def _create_backup(recovery_dir: Path, material: bytes, payload: Mapping[str, int], metadata: os.stat_result, control_sha: str, control_tree: str) -> dict[str, object]:
    source, forward = partition_aggregate(payload)
    try:
        os.mkdir(recovery_dir, 0o700)
        os.chown(recovery_dir, 0, 0)
        _normalize_private_directory(recovery_dir, expected_uid=0, expected_gid=0)
    except OSError:
        raise RecoveryError("RECOVERY_DIRECTORY_CREATE_RED") from None

    original_path = recovery_dir / "landing-aggregates.original.json"
    source_path = recovery_dir / "landing-aggregates.source-compatible.json"
    forward_path = recovery_dir / "landing-aggregates.forward-only.json"
    source_material = canonical_json(source)
    forward_material = canonical_json(forward)
    _write_new(original_path, material, uid=0, gid=0)
    _write_new(source_path, source_material, uid=0, gid=0)
    _write_new(forward_path, forward_material, uid=0, gid=0)
    evidence = {
        "schema": "tu1nz-s10-2d-r7-aggregate-recovery-v1",
        "control_commit": control_sha,
        "control_tree": control_tree,
        "application_commit": SOURCE_SHA,
        "application_tree": SOURCE_TREE,
        "original_sha256": sha256_bytes(material),
        "source_sha256": sha256_bytes(source_material),
        "forward_sha256": sha256_bytes(forward_material),
        "original_entries": len(payload),
        "original_total": sum(payload.values()),
        "source_entries": len(source),
        "source_total": sum(source.values()),
        "forward_entries": len(forward),
        "forward_total": sum(forward.values()),
        "original_uid": metadata.st_uid,
        "original_gid": metadata.st_gid,
        "original_mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "conservation_green": len(source) + len(forward) == len(payload) and sum(source.values()) + sum(forward.values()) == sum(payload.values()),
        "database_mutation": False,
        "user_data_present": False,
        "adult_media": False,
        "avs": False,
        "payments": False,
        "publishing": False,
    }
    _write_evidence(recovery_dir / "evidence.json", evidence)
    checksum_lines = "".join(
        f"{sha256_bytes(path.read_bytes())}  {path.name}\n"
        for path in (original_path, source_path, forward_path, recovery_dir / "evidence.json")
    ).encode("ascii")
    _write_new(recovery_dir / "SHA256SUMS", checksum_lines, uid=0, gid=0)
    # Persist both file entries and every newly created directory entry before
    # the live aggregate can be replaced.
    _fsync_directory(recovery_dir)
    _fsync_directory(RECOVERY_PREFIX)
    _fsync_directory(BACKUP_PARENT)
    return evidence


def _http_json(url: str, *, timeout: int = 10) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"User-Agent": "tu1nz-control-health/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            require(response.status == 200, "HTTP_STATUS_RED")
            body = response.read(65537)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        raise RecoveryError("HTTP_REQUEST_RED") from None
    require(len(body) <= 65536, "HEALTH_BODY_SIZE_RED")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise RecoveryError("HEALTH_JSON_RED") from None
    require(isinstance(payload, dict), "HEALTH_SHAPE_RED")
    return payload


def _http_status(url: str, *, redirects: bool = True) -> int:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
            return None

    opener = urllib.request.build_opener() if redirects else urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "tu1nz-control-health/1"})
    try:
        with opener.open(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, urllib.error.URLError):
        raise RecoveryError("HTTP_REQUEST_RED") from None


def _timer_has_future(unit: str) -> bool:
    for property_name in ("NextElapseUSecRealtime", "NextElapseUSecMonotonic"):
        value = _unit_value(unit, property_name)
        if value not in {"", "0", "infinity"}:
            return True
    return False


def _verify_runtime_green() -> None:
    for service in GREEN_SERVICES:
        require(_unit_value(service, "ActiveState") == "active", "SERVICE_NOT_ACTIVE")
        require(_unit_value(service, "NRestarts") == "0", "SERVICE_RESTARTED")
    for timer in TIMERS:
        enabled = _run(["/usr/bin/systemctl", "is-enabled", timer])
        require(enabled.returncode == 0 and enabled.stdout.strip() == "enabled", "TIMER_NOT_ENABLED")
        require(_unit_value(timer, "ActiveState") == "active", "TIMER_NOT_ACTIVE")
        require(_unit_value(timer, "SubState") == "waiting" and _timer_has_future(timer), "TIMER_NO_FUTURE_RUN")
    for service in ADULT_RUNTIMES:
        require(_unit_value(service, "ActiveState") in {"", "inactive", "failed"}, "ADULT_RUNTIME_OPEN")
    for service in HEALTH_SERVICES:
        require(_unit_value(service, "Result") == "success", "HEALTH_SERVICE_RESULT_RED")
        require(_unit_value(service, "ExecMainStatus") == "0", "HEALTH_SERVICE_STATUS_RED")
    for url in HEALTH_URLS:
        health = _http_json(url)
        require(health.get("ok") is True, "HEALTH_NOT_OK")
        require(health.get("brand") == "Want Me Seen" and health.get("mode") == "SFW_PUBLIC_EARLY_ACCESS", "HEALTH_IDENTITY_RED")
        require(all(health.get(key) is False for key in BOUNDARY_KEYS), "PRODUCT_BOUNDARY_RED")
    for url in PUBLIC_PAGES:
        require(_http_status(url) == 200, "PUBLIC_PAGE_RED")
    require(_http_status("https://wantmeseen.de/", redirects=False) == 308, "GERMAN_REDIRECT_RED")


def _verify_recovered_files(recovery_dir: Path) -> dict[str, object]:
    evidence_path = recovery_dir / "evidence.json"
    evidence = json.loads(_read_exact(evidence_path).decode("ascii"))
    require(isinstance(evidence, dict) and evidence.get("schema") == "tu1nz-s10-2d-r7-aggregate-recovery-v1", "EVIDENCE_RED")
    evidence_files = (
        recovery_dir / "landing-aggregates.original.json",
        recovery_dir / "landing-aggregates.source-compatible.json",
        recovery_dir / "landing-aggregates.forward-only.json",
        evidence_path,
        recovery_dir / "SHA256SUMS",
    )
    for path in evidence_files:
        metadata = _regular_metadata(path, expected_uid=0)
        require(metadata.st_gid == 0, "EVIDENCE_GROUP_RED")
    original = _read_exact(evidence_files[0])
    source = _read_exact(evidence_files[1])
    forward = _read_exact(evidence_files[2])
    require(sha256_bytes(original) == evidence.get("original_sha256"), "ORIGINAL_BACKUP_HASH_RED")
    require(sha256_bytes(source) == evidence.get("source_sha256"), "SOURCE_BACKUP_HASH_RED")
    require(sha256_bytes(forward) == evidence.get("forward_sha256"), "FORWARD_BACKUP_HASH_RED")
    source_payload = parse_aggregate(source)
    require(all(key.split("|")[1] in SOURCE_EVENTS for key in source_payload), "SOURCE_AGGREGATE_EVENT_RED")
    forward_payload = parse_aggregate(forward)
    require(all(key.split("|")[1] in FORWARD_EVENTS for key in forward_payload), "FORWARD_AGGREGATE_EVENT_RED")
    current_payload = parse_aggregate(_read_exact(AGGREGATE_PATH))
    require(all(key.split("|")[1] in SOURCE_EVENTS for key in current_payload), "RECOVERED_AGGREGATE_EVENT_RED")
    require(
        all(current_payload.get(key, -1) >= value for key, value in source_payload.items()),
        "RECOVERED_AGGREGATE_REGRESSION_RED",
    )
    return evidence


def verify(control_sha: str, control_tree: str, recovery_dir: Path) -> dict[str, object]:
    _validate_control_binding(control_sha, control_tree)
    _validate_source_surface()
    _validate_recovery_path(recovery_dir, must_exist=True)
    try:
        chatops = pwd.getpwnam("chatops")
    except KeyError:
        raise RecoveryError("CHATOPS_IDENTITY_MISSING") from None
    metadata = _regular_metadata(AGGREGATE_PATH, expected_uid=chatops.pw_uid)
    require(metadata.st_gid == chatops.pw_gid, "AGGREGATE_GROUP_RED")
    evidence = _verify_recovered_files(recovery_dir)
    _verify_runtime_green()
    return {
        "ok": True,
        "safe_code": "S10_2D_R7_SOURCE_PUBLIC_RECOVERY_GREEN",
        "recovery": recovery_dir.name,
        "original_sha256": evidence["original_sha256"],
        "source_sha256": evidence["source_sha256"],
        "forward_sha256": evidence["forward_sha256"],
        "source_entries": evidence["source_entries"],
        "source_total": evidence["source_total"],
        "forward_entries": evidence["forward_entries"],
        "forward_total": evidence["forward_total"],
        "database_mutation": False,
        "adult_media": False,
        "avs": False,
        "payments": False,
        "publishing": False,
    }


def _quiesce_automation() -> None:
    for timer in TIMERS:
        _systemctl("stop", timer, safe_code="FAIL_CLOSED_TIMER_STOP_RED")
        require(_unit_value(timer, "ActiveState") in {"inactive", "failed"}, "FAIL_CLOSED_TIMER_ACTIVE")
    for service in RECOVERY_WORKERS:
        _systemctl("stop", service, safe_code="FAIL_CLOSED_WORKER_STOP_RED")
        require(_unit_value(service, "ActiveState") in {"inactive", "failed"}, "FAIL_CLOSED_WORKER_ACTIVE")
    for service in SERVICES:
        _systemctl("stop", service, safe_code="FAIL_CLOSED_STOP_RED")
        require(_unit_value(service, "ActiveState") in {"inactive", "failed"}, "FAIL_CLOSED_SERVICE_ACTIVE")


def _restore_original_fail_closed(recovery_dir: Path) -> None:
    _quiesce_automation()
    try:
        evidence = json.loads(_read_exact(recovery_dir / "evidence.json").decode("ascii"))
        original = _read_exact(recovery_dir / "landing-aggregates.original.json")
        require(sha256_bytes(original) == evidence.get("original_sha256"), "ORIGINAL_BACKUP_HASH_RED")
        _atomic_replace(
            AGGREGATE_PATH,
            original,
            uid=int(evidence["original_uid"]),
            gid=int(evidence["original_gid"]),
            mode=int(str(evidence["original_mode"]), 8),
        )
        restored = AGGREGATE_PATH.lstat()
        require(sha256_bytes(_read_exact(AGGREGATE_PATH)) == evidence.get("original_sha256"), "ORIGINAL_RESTORE_HASH_RED")
        require(
            restored.st_uid == int(evidence["original_uid"])
            and restored.st_gid == int(evidence["original_gid"])
            and stat.S_IMODE(restored.st_mode) == int(str(evidence["original_mode"]), 8),
            "ORIGINAL_RESTORE_METADATA_RED",
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise RecoveryError("ORIGINAL_RESTORE_RED") from None


def recover(control_sha: str, control_tree: str, recovery_dir: Path) -> dict[str, object]:
    _prepare_recovery_prefix()
    preflight(control_sha, control_tree, recovery_dir)
    material, payload, metadata = _load_current_aggregate()
    source, _forward = partition_aggregate(payload)
    evidence = _create_backup(recovery_dir, material, payload, metadata, control_sha, control_tree)
    replacement_attempted = False
    try:
        _quiesce_automation()
        require(sha256_bytes(_read_exact(AGGREGATE_PATH)) == evidence["original_sha256"], "AGGREGATE_CHANGED_AFTER_BACKUP")
        replacement_attempted = True
        _atomic_replace(
            AGGREGATE_PATH,
            canonical_json(source),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=stat.S_IMODE(metadata.st_mode),
        )
        current = _read_exact(AGGREGATE_PATH)
        require(sha256_bytes(current) == evidence["source_sha256"], "RECOVERED_AGGREGATE_HASH_RED")
        for service in SERVICES:
            _reset_failed_if_needed(service, safe_code="SERVICE_RESET_RED")
            _systemctl("start", service, safe_code="SOURCE_SERVICE_START_RED")
        for timer in TIMERS:
            _systemctl("start", timer, safe_code="TIMER_START_RED")
        for service in HEALTH_SERVICES:
            _start_health_with_settle(service)
        last_error = "SOURCE_RUNTIME_NOT_SETTLED"
        for attempt in range(60):
            try:
                _verify_runtime_green()
                return verify(control_sha, control_tree, recovery_dir)
            except RecoveryError as error:
                last_error = str(error)
                if attempt == 59:
                    raise RecoveryError(last_error)
                time.sleep(1)
    except RecoveryError:
        if replacement_attempted:
            _restore_original_fail_closed(recovery_dir)
        raise
    except Exception:
        if replacement_attempted:
            _restore_original_fail_closed(recovery_dir)
        raise RecoveryError("UNEXPECTED_RECOVERY_ERROR") from None
    raise RecoveryError("SOURCE_RUNTIME_NOT_SETTLED")


def restore_original(control_sha: str, control_tree: str, recovery_dir: Path) -> dict[str, object]:
    _validate_control_binding(control_sha, control_tree)
    _validate_source_surface()
    _validate_recovery_path(recovery_dir, must_exist=True)
    _restore_original_fail_closed(recovery_dir)
    evidence = json.loads(_read_exact(recovery_dir / "evidence.json").decode("ascii"))
    require(sha256_bytes(_read_exact(AGGREGATE_PATH)) == evidence.get("original_sha256"), "ORIGINAL_RESTORE_HASH_RED")
    return {
        "ok": True,
        "safe_code": "S10_2D_R7_AGGREGATE_ORIGINAL_RESTORED_FAIL_CLOSED",
        "recovery": recovery_dir.name,
        "public_services_active": False,
        "database_mutation": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "recover", "verify", "restore-original"))
    parser.add_argument("control_sha")
    parser.add_argument("control_tree")
    parser.add_argument("recovery_dir", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    action: Callable[[str, str, Path], dict[str, object]] = {
        "preflight": preflight,
        "recover": recover,
        "verify": verify,
        "restore-original": restore_original,
    }[arguments.action]
    try:
        result = action(arguments.control_sha, arguments.control_tree, arguments.recovery_dir)
    except RecoveryError as error:
        print(canonical_json({"ok": False, "safe_code": str(error)}).decode("ascii"))
        return 2
    except Exception:
        print('{"ok":false,"safe_code":"UNEXPECTED_RECOVERY_ERROR"}')
        return 2
    print(canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
