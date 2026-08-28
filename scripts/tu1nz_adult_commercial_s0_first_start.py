#!/usr/bin/env python3
"""M4.24 controlled, network-free first-start acceptance transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import grp
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FirstStartFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
CONTROL_SHA = "8c4e8992a60c215295cf9d0c400afcd9a931f883"
CONTROL_TREE = "5a5274f7ea5dd639880935170f3fd3673497955b"
ARCHIVE_NAME = "tu1nz_system_backup_20260828T16-50-53Z.tar.gz"
ARCHIVE_SHA256 = "b96f9efb304b2898758539516d842d27574307de82cbfb49229692ab8c9bcbd7"
MANIFEST_SHA256 = "2a3dc857205f9cff262edd686bc6db13d799c1e5de8aea954a8f50b9420cdc54"
UNIT_SHA256 = "ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3"
UNIT = "tu1nz-adult-commercial-s0.service"
S1_UNIT = "tu1nz-adult-publishing-s1.service"
BACKUP_SERVICE = "tu1nz_encrypted_backup.service"
BACKUP_TIMER = "tu1nz_encrypted_backup.timer"
RUNTIME_USER = "tu1nz-adult-commercial-s0"
RUNTIME_GROUP = "tu1nz-adult-commercial-s0"
DATABASE = "tu1nz_adult_commercial_s0"
BASE = Path("/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial")
APPLICATION = BASE / "application" / APPLICATION_SHA
CONTROL = BASE / "control" / CONTROL_SHA
VENV = BASE / "venv" / APPLICATION_SHA
CONFIG = Path("/etc/tu1nz/adult-publishing/staging-s0-commercial")
STATE = Path("/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial")
MANIFEST = CONFIG / "release-manifest.json"
STATE_FILE = STATE / "state.json"
STATUS_FILE = STATE / "runtime-status.json"
LOCK_FILE = STATE / "runtime.lock"
INSTALLED_UNIT = Path("/etc/systemd/system") / UNIT
ARCHIVE = Path("/opt/tu1nz_repos/backups/encrypted-system") / ARCHIVE_NAME
RESTORE_ROOT = Path(
    "/opt/tu1nz_repos/backups/m4-23-commercial-s0-restore/20260828T16-50-53Z"
)
EVIDENCE_PARENT = Path("/opt/tu1nz_repos/backups/m4-24-commercial-s0-first-start")
CANONICAL_CONTROL = Path("/opt/tu1nz_repos/control")
CONTRACT = (
    CANONICAL_CONTROL
    / "manifests"
    / "adult-publishing-commercial-first-start.m4-24.json"
)
AUTHORIZATION_GATE = (
    CANONICAL_CONTROL / "scripts" / "tu1nz_adult_commercial_first_start_gate.py"
)
SYSTEMCTL = "/bin/systemctl"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
RUNUSER = "/usr/sbin/runuser"
PSQL = "/usr/bin/psql"
GIT = "/usr/bin/git"
TAILSCALE = "/usr/bin/tailscale"
JOURNALCTL = "/usr/bin/journalctl"
HEALTH = VENV / "bin" / "tu1nz-commercial-candidate-health"
RELEASE_GATE = CONTROL / "scripts" / "tu1nz_adult_commercial_s0_release_gate.py"
READY_TIMEOUT_SECONDS = 60
STOP_TIMEOUT_SECONDS = 45
HEALTH_MAXIMUM_AGE_SECONDS = 90
MIN_ROOT_AVAILABLE_BYTES = 1024 * 1024 * 1024
MIN_MEMORY_AVAILABLE_KIB = 512 * 1024
ALLOWED_FAILED_UNITS = {"tu1nz-doc.service"}
SAFE_STATUS_KEYS = {
    "checked_at",
    "commercial_contract_version",
    "environment",
    "last_synchronized_at",
    "outbound_providers_enabled",
    "postgres_major",
    "projected_submissions",
    "service",
    "started_at",
    "state",
    "synthetic_data_only",
    "version",
}


DATABASE_SNAPSHOT_SQL = """
SELECT json_build_object(
  'table_count', (SELECT count(*) FROM pg_tables WHERE schemaname = 'public'),
  'function_count', (SELECT count(*) FROM pg_proc WHERE proname LIKE 'tu1nz_%'),
  'creators', (SELECT count(*) FROM creators),
  'policy_versions', (SELECT count(*) FROM policy_versions),
  'country_policy_rules', (SELECT count(*) FROM country_policy_rules),
  'platform_policy_rules', (SELECT count(*) FROM platform_policy_rules),
  'integration_accounts', (SELECT count(*) FROM integration_accounts),
  'publication_destinations', (SELECT count(*) FROM publication_destinations),
  'business_rows',
      (SELECT count(*) FROM adult_verification_events)
    + (SELECT count(*) FROM adult_verifications)
    + (SELECT count(*) FROM audit_events)
    + (SELECT count(*) FROM command_receipts)
    + (SELECT count(*) FROM commercial_dispatch_entitlements)
    + (SELECT count(*) FROM consent_events)
    + (SELECT count(*) FROM consent_invites)
    + (SELECT count(*) FROM credit_transactions)
    + (SELECT count(*) FROM depicted_persons)
    + (SELECT count(*) FROM external_identities)
    + (SELECT count(*) FROM external_identity_aliases)
    + (SELECT count(*) FROM integration_event_receipts)
    + (SELECT count(*) FROM media_assets)
    + (SELECT count(*) FROM moderation_decisions)
    + (SELECT count(*) FROM payment_attempts)
    + (SELECT count(*) FROM payment_intent_events)
    + (SELECT count(*) FROM payment_intents)
    + (SELECT count(*) FROM payment_provider_event_receipts)
    + (SELECT count(*) FROM payments)
    + (SELECT count(*) FROM platform_dispatch_events)
    + (SELECT count(*) FROM platform_dispatches)
    + (SELECT count(*) FROM platform_provider_receipts)
    + (SELECT count(*) FROM policy_decisions)
    + (SELECT count(*) FROM policy_evaluations)
    + (SELECT count(*) FROM publication_entitlement_events)
    + (SELECT count(*) FROM publication_entitlements)
    + (SELECT count(*) FROM publications)
    + (SELECT count(*) FROM safety_complaint_events)
    + (SELECT count(*) FROM safety_complaints)
    + (SELECT count(*) FROM submission_intake_sessions)
    + (SELECT count(*) FROM submission_state_events)
    + (SELECT count(*) FROM submissions)
    + (SELECT count(*) FROM takedowns)
)::text;
"""


def fail(code: str, detail: str) -> None:
    raise FirstStartFailure(code, detail)


def command(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
    }
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail("COMMAND_EXECUTION_FAILED", str(error))
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        fail("COMMAND_REJECTED", detail)
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        fail("ROOT_REQUIRED", "first-start controls require root")


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        fail("UNSAFE_FILE", str(path))
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, label: str, maximum_bytes: int = 1024 * 1024) -> Any:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_nlink != 1
        or path.stat().st_size > maximum_bytes
    ):
        fail("UNSAFE_JSON", label)
    try:
        return json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail("INVALID_JSON", label + ": " + str(error))


def write_private(path: Path, material: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path: Path, payload: object) -> None:
    material = (
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    write_private(path, material)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def systemctl_state(unit: str) -> dict[str, str]:
    result = command(
        [
            SYSTEMCTL,
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--property=NRestarts",
            "--property=ExecMainStartTimestampMonotonic",
        ]
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def active_state(unit: str) -> str:
    result = command([SYSTEMCTL, "is-active", unit], check=False)
    return result.stdout.strip() or "unknown"


def enabled_state(unit: str) -> str:
    result = command([SYSTEMCTL, "is-enabled", unit], check=False)
    return result.stdout.strip() or "unknown"


def git_value(repository: Path, *arguments: str) -> str:
    return command(
        [GIT, "-c", "safe.directory=" + str(repository), "-C", str(repository), *arguments]
    ).stdout.strip()


def verify_clean_release(repository: Path, expected_sha: str, expected_tree: str) -> None:
    if git_value(repository, "rev-parse", "HEAD") != expected_sha:
        fail("RELEASE_SHA_MISMATCH", str(repository))
    if git_value(repository, "rev-parse", "HEAD^{tree}") != expected_tree:
        fail("RELEASE_TREE_MISMATCH", str(repository))
    if git_value(repository, "status", "--porcelain", "--ignored"):
        fail("RELEASE_NOT_CLEAN", str(repository))
    command([GIT, "-c", "safe.directory=" + str(repository), "-C", str(repository), "fsck", "--full"])


def verify_canonical_contract(contract: Path) -> None:
    if contract.absolute() != CONTRACT:
        fail("NONCANONICAL_CONTRACT", str(contract))
    if not CANONICAL_CONTROL.is_dir() or CANONICAL_CONTROL.is_symlink():
        fail("CANONICAL_CONTROL_UNSAFE", str(CANONICAL_CONTROL))
    if git_value(CANONICAL_CONTROL, "status", "--porcelain"):
        fail("CANONICAL_CONTROL_DIRTY", str(CANONICAL_CONTROL))
    if git_value(CANONICAL_CONTROL, "symbolic-ref", "--short", "HEAD") != "control-main":
        fail("CANONICAL_CONTROL_BRANCH_MISMATCH", "control-main required")
    if git_value(CANONICAL_CONTROL, "rev-parse", "HEAD") != git_value(
        CANONICAL_CONTROL, "rev-parse", "origin/control-main"
    ):
        fail("CANONICAL_CONTROL_NOT_SYNCED", "origin/control-main mismatch")


def validate_contract(contract: Path, *, require_approved: bool) -> None:
    verify_canonical_contract(contract)
    arguments = [str(AUTHORIZATION_GATE), "--contract", str(contract)]
    if require_approved:
        arguments.append("--require-approved")
    result = command(arguments, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or "first-start authorization rejected"
        fail("FIRST_START_AUTHORIZATION_REJECTED", detail)


def database_snapshot() -> dict[str, int]:
    result = command(
        [
            RUNUSER,
            "-u",
            "postgres",
            "--",
            PSQL,
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--dbname=" + DATABASE,
            "--command",
            DATABASE_SNAPSHOT_SQL,
        ]
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as error:
        fail("DATABASE_SNAPSHOT_INVALID", str(error))
    if not isinstance(payload, dict) or any(
        isinstance(value, bool) or not isinstance(value, int) for value in payload.values()
    ):
        fail("DATABASE_SNAPSHOT_INVALID", "integer count object required")
    return payload


def verify_initial_database(snapshot: dict[str, int]) -> None:
    expected = {
        "table_count": 39,
        "function_count": 21,
        "creators": 1,
        "policy_versions": 1,
        "country_policy_rules": 1,
        "platform_policy_rules": 3,
        "integration_accounts": 3,
        "publication_destinations": 3,
        "business_rows": 0,
    }
    if snapshot != expected:
        fail("DATABASE_NOT_SYNTHETIC_EMPTY", json.dumps(snapshot, sort_keys=True))


def verify_empty_state() -> str:
    payload = read_json(STATE_FILE, "commercial state")
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "creator_verifications",
            "processed_updates",
            "product_events",
            "submissions",
            "terms_acceptances",
            "version",
        }
        or payload["version"] != 2
        or payload["product_events"] != []
        or any(
            payload[field] != {}
            for field in (
                "creator_verifications",
                "processed_updates",
                "submissions",
                "terms_acceptances",
            )
        )
    ):
        fail("STATE_NOT_SYNTHETIC_EMPTY", str(STATE_FILE))
    return sha256_file(STATE_FILE)


def verify_manifest() -> None:
    if sha256_file(MANIFEST) != MANIFEST_SHA256:
        fail("MANIFEST_DIGEST_MISMATCH", str(MANIFEST))
    payload = read_json(MANIFEST, "release manifest")
    expected = {
        "application_sha": APPLICATION_SHA,
        "control_sha": CONTROL_SHA,
        "archive_name": ARCHIVE_NAME,
        "archive_sha256": ARCHIVE_SHA256,
        "external_providers_enabled": False,
        "network_enabled": False,
        "real_media_enabled": False,
        "real_payment_enabled": False,
        "synthetic_data_only": True,
        "synthetic_publishers_only": True,
        "telegram_intake_enabled": False,
    }
    if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in expected.items()):
        fail("MANIFEST_BOUNDARY_MISMATCH", str(MANIFEST))


def verify_unit() -> dict[str, str]:
    if sha256_file(INSTALLED_UNIT) != UNIT_SHA256:
        fail("UNIT_DIGEST_MISMATCH", str(INSTALLED_UNIT))
    if sha256_file(CONTROL / "systemd" / UNIT) != UNIT_SHA256:
        fail("VERSIONED_UNIT_DIGEST_MISMATCH", str(CONTROL))
    text = INSTALLED_UNIT.read_text(encoding="ascii")
    for required in (
        "PrivateNetwork=yes",
        "IPAddressDeny=any",
        "RestrictAddressFamilies=AF_UNIX",
    ):
        if required not in text:
            fail("UNIT_NETWORK_GUARD_MISSING", required)
    if "[Install]" in text or "WantedBy=" in text:
        fail("UNIT_ENABLEMENT_PRESENT", str(INSTALLED_UNIT))
    command([SYSTEMD_ANALYZE, "verify", str(INSTALLED_UNIT)])
    security = command(
        [SYSTEMD_ANALYZE, "security", "--offline=yes", str(INSTALLED_UNIT)]
    ).stdout
    if re.search(r"Overall exposure level.*0\.6 SAFE", security) is None:
        fail("UNIT_SECURITY_RATING_MISMATCH", "0.6 SAFE required")
    state = systemctl_state(UNIT)
    if (
        state.get("LoadState") != "loaded"
        or state.get("ActiveState") != "inactive"
        or state.get("SubState") != "dead"
        or state.get("UnitFileState") != "static"
        or enabled_state(UNIT) != "static"
    ):
        fail("UNIT_NOT_STOPPED_STATIC", json.dumps(state, sort_keys=True))
    return state


def verify_services() -> None:
    if active_state(S1_UNIT) != "active":
        fail("S1_NOT_ACTIVE", S1_UNIT)
    if active_state(BACKUP_TIMER) != "active":
        fail("BACKUP_TIMER_NOT_ACTIVE", BACKUP_TIMER)
    if active_state(BACKUP_SERVICE) == "active":
        fail("BACKUP_SERVICE_BUSY", BACKUP_SERVICE)
    failed = command([SYSTEMCTL, "--failed", "--no-legend", "--plain"]).stdout
    failed_units = {line.split()[0] for line in failed.splitlines() if line.split()}
    if failed_units - ALLOWED_FAILED_UNITS:
        fail("UNEXPECTED_FAILED_UNIT", ",".join(sorted(failed_units)))
    timers = command([SYSTEMCTL, "list-timers", "--all", "--no-legend"]).stdout
    if UNIT in timers:
        fail("COMMERCIAL_TIMER_PRESENT", UNIT)


def process_references() -> list[int]:
    references: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            material = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
        if b"tu1nz-commercial-runtime-candidate" in material:
            references.append(int(entry.name))
    return references


def cron_references() -> list[str]:
    needles = (b"staging-s0-commercial", b"tu1nz-adult-commercial-s0")
    roots = [Path("/etc/crontab"), Path("/etc/cron.d"), Path("/var/spool/cron")]
    found: list[str] = []
    for root in roots:
        paths = [root] if root.is_file() else list(root.rglob("*")) if root.is_dir() else []
        for path in paths:
            try:
                if path.is_file() and not path.is_symlink() and any(
                    needle in path.read_bytes() for needle in needles
                ):
                    found.append(str(path))
            except (OSError, PermissionError):
                continue
    return sorted(found)


def docker_mount_references() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        return []
    identifiers = command([docker, "ps", "--quiet"]).stdout.split()
    if not identifiers:
        return []
    output = command(
        [
            docker,
            "inspect",
            "--format",
            "{{range .Mounts}}{{.Source}}|{{.Destination}}{{println}}{{end}}",
            *identifiers,
        ]
    ).stdout
    return [line for line in output.splitlines() if "staging-s0-commercial" in line]


def open_file_references() -> list[str]:
    lsof = shutil.which("lsof")
    if lsof is None:
        return []
    result = command([lsof, "-Fn", "+D", str(BASE)], check=False, timeout=30)
    if result.returncode not in {0, 1}:
        fail("OPEN_FILE_CHECK_FAILED", result.stderr.strip())
    return sorted({line for line in result.stdout.splitlines() if line.startswith("p")})


def capacity_snapshot() -> dict[str, int]:
    root = os.statvfs("/")
    memory: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            memory[key] = int(value.strip().split()[0])
    snapshot = {
        "root_available_bytes": root.f_bavail * root.f_frsize,
        "memory_available_kib": memory.get("MemAvailable", 0),
        "swap_total_kib": memory.get("SwapTotal", 0),
    }
    if snapshot["root_available_bytes"] < MIN_ROOT_AVAILABLE_BYTES:
        fail("ROOT_CAPACITY_LOW", str(snapshot["root_available_bytes"]))
    if snapshot["memory_available_kib"] < MIN_MEMORY_AVAILABLE_KIB:
        fail("MEMORY_CAPACITY_LOW", str(snapshot["memory_available_kib"]))
    return snapshot


def run_release_gate() -> None:
    result = command(
        [
            str(RELEASE_GATE),
            "--manifest",
            str(MANIFEST),
            "--application-repository",
            str(BASE / "application-current"),
            "--control-repository",
            str(BASE / "control-current"),
            "--application-release-root",
            str(BASE / "application"),
            "--control-release-root",
            str(BASE / "control"),
            "--venv",
            str(BASE / "venv-current"),
            "--configuration-root",
            str(CONFIG),
            "--state-root",
            str(STATE),
            "--installed-unit",
            str(INSTALLED_UNIT),
            "--archive",
            str(ARCHIVE),
            "--runtime-user",
            RUNTIME_USER,
            "--runtime-group",
            RUNTIME_GROUP,
            "--release-user",
            "root",
            "--configuration-user",
            "root",
            "--unit-user",
            "root",
            "--unit-group",
            "root",
            "--require-active",
        ],
        timeout=90,
    )
    if "COMMERCIAL_S0_RELEASE_GATE_OK" not in result.stdout:
        fail("RELEASE_GATE_FAILED", result.stdout.strip())


def technical_preflight(contract: Path) -> dict[str, object]:
    require_root()
    validate_contract(contract, require_approved=False)
    verify_manifest()
    if sha256_file(ARCHIVE) != ARCHIVE_SHA256 or ARCHIVE.stat().st_size != 63734473:
        fail("ARCHIVE_BOUNDARY_MISMATCH", str(ARCHIVE))
    if not RESTORE_ROOT.is_dir() or RESTORE_ROOT.is_symlink():
        fail("RESTORE_EVIDENCE_MISSING", str(RESTORE_ROOT))
    verify_clean_release(APPLICATION, APPLICATION_SHA, APPLICATION_TREE)
    verify_clean_release(
        CONTROL,
        CONTROL_SHA,
        CONTROL_TREE,
    )
    if os.readlink(BASE / "application-current") != "application/" + APPLICATION_SHA:
        fail("APPLICATION_LINK_MISMATCH", str(BASE))
    if os.readlink(BASE / "control-current") != "control/" + CONTROL_SHA:
        fail("CONTROL_LINK_MISMATCH", str(BASE))
    if os.readlink(BASE / "venv-current") != "venv/" + APPLICATION_SHA:
        fail("VENV_LINK_MISMATCH", str(BASE))
    run_release_gate()
    unit_state = verify_unit()
    verify_services()
    if STATUS_FILE.exists() or STATUS_FILE.is_symlink():
        fail("PRIOR_RUNTIME_STATUS_PRESENT", str(STATUS_FILE))
    if LOCK_FILE.exists() or LOCK_FILE.is_symlink():
        fail("PRIOR_RUNTIME_LOCK_PRESENT", str(LOCK_FILE))
    state_sha = verify_empty_state()
    database = database_snapshot()
    verify_initial_database(database)
    processes = process_references()
    if processes:
        fail("COMMERCIAL_PROCESS_PRESENT", ",".join(map(str, processes)))
    cron = cron_references()
    if cron:
        fail("COMMERCIAL_CRON_PRESENT", ",".join(cron))
    mounts = docker_mount_references()
    if mounts:
        fail("COMMERCIAL_CONTAINER_MOUNT_PRESENT", ",".join(mounts))
    open_files = open_file_references()
    if open_files:
        fail("COMMERCIAL_OPEN_FILE_PRESENT", ",".join(open_files))
    tailscale_ip = command([TAILSCALE, "ip", "-4"]).stdout.splitlines()[0].strip()
    if tailscale_ip != "100.121.130.51":
        fail("TAILSCALE_IDENTITY_MISMATCH", tailscale_ip)
    capacity = capacity_snapshot()
    return {
        "archive_sha256": ARCHIVE_SHA256,
        "application_sha": APPLICATION_SHA,
        "canonical_control_sha": git_value(CANONICAL_CONTROL, "rev-parse", "HEAD"),
        "captured_at": utc_now(),
        "contract_sha256": sha256_file(contract),
        "control_sha": CONTROL_SHA,
        "database": database,
        "manifest_sha256": MANIFEST_SHA256,
        "state_sha256": state_sha,
        "tailscale_ipv4": tailscale_ip,
        "unit": unit_state,
        "unit_sha256": UNIT_SHA256,
        **capacity,
    }


def read_runtime_status(expected_state: str) -> dict[str, object]:
    metadata = STATUS_FILE.stat()
    runtime_uid = pwd.getpwnam(RUNTIME_USER).pw_uid
    runtime_gid = grp.getgrnam(RUNTIME_GROUP).gr_gid
    if (
        STATUS_FILE.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail("RUNTIME_STATUS_UNSAFE", str(STATUS_FILE))
    payload = read_json(STATUS_FILE, "runtime status", maximum_bytes=4096)
    if (
        not isinstance(payload, dict)
        or set(payload) != SAFE_STATUS_KEYS
        or payload.get("state") != expected_state
        or payload.get("environment") != "STAGING-S0-COMMERCIAL-CANDIDATE"
        or payload.get("service") != "tu1nz-commercial-runtime-candidate"
        or payload.get("synthetic_data_only") is not True
        or payload.get("outbound_providers_enabled") is not False
        or payload.get("projected_submissions") != 0
    ):
        fail("RUNTIME_STATUS_INVALID", expected_state)
    if metadata.st_uid != runtime_uid or metadata.st_gid != runtime_gid:
        fail(
            "RUNTIME_STATUS_OWNER_MISMATCH",
            str(metadata.st_uid) + ":" + str(metadata.st_gid),
        )
    return payload


def wait_for_runtime_state(expected_state: str, timeout_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "status absent"
    while time.monotonic() < deadline:
        try:
            if STATUS_FILE.exists():
                return read_runtime_status(expected_state)
        except FirstStartFailure as error:
            last_error = str(error)
        time.sleep(1)
    fail("RUNTIME_STATE_TIMEOUT", expected_state + ": " + last_error)


def wait_inactive(timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if active_state(UNIT) == "inactive":
            return
        time.sleep(1)
    fail("UNIT_STOP_TIMEOUT", UNIT)


def safe_evidence_directory(path: Path) -> Path:
    try:
        absolute = path.resolve(strict=True)
    except OSError as error:
        fail("EVIDENCE_DIRECTORY_UNSAFE", str(error))
    try:
        absolute.relative_to(EVIDENCE_PARENT)
    except ValueError:
        fail("EVIDENCE_PATH_OUTSIDE_ROOT", str(path))
    if absolute == EVIDENCE_PARENT:
        fail("RUN_EVIDENCE_DIRECTORY_REQUIRED", str(path))
    if not absolute.is_dir() or absolute.is_symlink():
        fail("EVIDENCE_DIRECTORY_UNSAFE", str(path))
    metadata = absolute.stat()
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("EVIDENCE_DIRECTORY_METADATA_INVALID", str(path))
    return absolute


def create_evidence_directory() -> Path:
    if EVIDENCE_PARENT.exists():
        if EVIDENCE_PARENT.is_symlink() or not EVIDENCE_PARENT.is_dir():
            fail("EVIDENCE_ROOT_UNSAFE", str(EVIDENCE_PARENT))
        metadata = EVIDENCE_PARENT.stat()
        if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
            fail("EVIDENCE_ROOT_METADATA_INVALID", str(EVIDENCE_PARENT))
    else:
        EVIDENCE_PARENT.mkdir(mode=0o700)
    run = EVIDENCE_PARENT / datetime.now(timezone.utc).strftime("%Y%m%dT%H-%M-%SZ")
    run.mkdir(mode=0o700)
    return safe_evidence_directory(run)


def capture_journal(evidence: Path, name: str) -> None:
    result = command(
        [JOURNALCTL, "-u", UNIT, "--no-pager", "--output=short-iso", "-n", "200"],
        check=False,
    )
    write_private(evidence / name, result.stdout.encode("utf-8", errors="replace"))


def capture_runtime_status(evidence: Path, name: str) -> None:
    if STATUS_FILE.is_file() and not STATUS_FILE.is_symlink():
        write_private(evidence / name, STATUS_FILE.read_bytes())


def abort_window(evidence: Path, reason: str) -> None:
    safe_evidence_directory(evidence)
    token = datetime.now(timezone.utc).strftime("%Y%m%dT%H-%M-%SZ")
    state_before = systemctl_state(UNIT)
    if state_before.get("ActiveState") != "inactive":
        command([SYSTEMCTL, "stop", UNIT], check=False, timeout=STOP_TIMEOUT_SECONDS)
    try:
        wait_inactive(STOP_TIMEOUT_SECONDS)
    except FirstStartFailure:
        pass
    capture_runtime_status(evidence, "runtime-status.abort." + token + ".json")
    capture_journal(evidence, "journal.abort." + token + ".log")
    payload = {
        "aborted_at": utc_now(),
        "database_preserved": True,
        "reason": reason,
        "runtime_evidence_preserved": True,
        "state_after": systemctl_state(UNIT),
        "state_before": state_before,
        "unit": UNIT,
    }
    write_json(evidence / ("abort-result." + token + ".json"), payload)


def postcheck(before: dict[str, object]) -> dict[str, object]:
    state = systemctl_state(UNIT)
    if (
        state.get("ActiveState") != "inactive"
        or state.get("SubState") != "dead"
        or state.get("UnitFileState") != "static"
        or enabled_state(UNIT) != "static"
    ):
        fail("POSTCHECK_UNIT_NOT_STOPPED", json.dumps(state, sort_keys=True))
    if state.get("NRestarts") != "0":
        fail("POSTCHECK_RESTART_DETECTED", state.get("NRestarts", "missing"))
    status_payload = read_runtime_status("STOPPED")
    lock_metadata = LOCK_FILE.stat()
    runtime_uid = pwd.getpwnam(RUNTIME_USER).pw_uid
    runtime_gid = grp.getgrnam(RUNTIME_GROUP).gr_gid
    if (
        LOCK_FILE.is_symlink()
        or not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_nlink != 1
        or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        or lock_metadata.st_uid != runtime_uid
        or lock_metadata.st_gid != runtime_gid
    ):
        fail("POSTCHECK_LOCK_UNSAFE", str(LOCK_FILE))
    if verify_empty_state() != before.get("state_sha256"):
        fail("POSTCHECK_STATE_DRIFT", str(STATE_FILE))
    after_database = database_snapshot()
    if after_database != before.get("database"):
        fail("POSTCHECK_DATABASE_DRIFT", json.dumps(after_database, sort_keys=True))
    verify_initial_database(after_database)
    verify_clean_release(APPLICATION, APPLICATION_SHA, APPLICATION_TREE)
    verify_clean_release(CONTROL, CONTROL_SHA, CONTROL_TREE)
    verify_services()
    if process_references():
        fail("POSTCHECK_PROCESS_REMAINS", UNIT)
    return {
        "checked_at": utc_now(),
        "database": after_database,
        "runtime_status": status_payload,
        "state_sha256": before["state_sha256"],
        "unit": state,
    }


def execute_window(contract: Path) -> Path:
    before = technical_preflight(contract)
    validate_contract(contract, require_approved=True)
    if sha256_file(contract) != before.get("contract_sha256"):
        fail("AUTHORIZATION_CHANGED_AFTER_PREFLIGHT", str(contract))
    if git_value(CANONICAL_CONTROL, "rev-parse", "HEAD") != before.get(
        "canonical_control_sha"
    ):
        fail("CONTROL_CHANGED_AFTER_PREFLIGHT", str(CANONICAL_CONTROL))
    evidence = create_evidence_directory()
    write_json(evidence / "preflight.json", before)
    write_private(evidence / "authorization.json", contract.read_bytes())
    start_attempted = False
    completed = False
    try:
        start_attempted = True
        command([SYSTEMCTL, "start", UNIT], timeout=READY_TIMEOUT_SECONDS)
        ready = wait_for_runtime_state("READY", READY_TIMEOUT_SECONDS)
        if active_state(UNIT) != "active":
            fail("UNIT_NOT_ACTIVE_AT_READY", UNIT)
        command(
            [
                RUNUSER,
                "-u",
                RUNTIME_USER,
                "--",
                str(HEALTH),
                "--status-file",
                str(STATUS_FILE),
                "--maximum-age-seconds",
                str(HEALTH_MAXIMUM_AGE_SECONDS),
            ]
        )
        write_json(evidence / "runtime-ready.json", ready)
        command([SYSTEMCTL, "stop", UNIT], timeout=STOP_TIMEOUT_SECONDS)
        wait_inactive(STOP_TIMEOUT_SECONDS)
        wait_for_runtime_state("STOPPED", STOP_TIMEOUT_SECONDS)
        after = postcheck(before)
        write_json(evidence / "postcheck.json", after)
        capture_journal(evidence, "journal.success.log")
        write_json(
            evidence / "acceptance-result.json",
            {
                "completed_at": utc_now(),
                "decision": "GO_NETWORK_FREE_FIRST_START_ACCEPTED_AND_STOPPED",
                "evidence_directory": str(evidence),
                "must_end_stopped": True,
                "unit": UNIT,
            },
        )
        completed = True
        return evidence
    except FirstStartFailure as error:
        if start_attempted:
            abort_window(evidence, error.code + ": " + str(error))
        raise
    finally:
        if start_attempted and not completed and active_state(UNIT) != "inactive":
            command([SYSTEMCTL, "stop", UNIT], check=False, timeout=STOP_TIMEOUT_SECONDS)


def load_before_snapshot(path: Path) -> dict[str, object]:
    try:
        path.absolute().relative_to(EVIDENCE_PARENT)
    except ValueError:
        fail("PRECHECK_EVIDENCE_OUTSIDE_ROOT", str(path))
    payload = read_json(path, "preflight evidence")
    if not isinstance(payload, dict) or payload.get("application_sha") != APPLICATION_SHA:
        fail("PRECHECK_EVIDENCE_INVALID", str(path))
    return payload


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "execute", "postcheck", "abort"))
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--before-snapshot", type=Path)
    parser.add_argument("--evidence-directory", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.mode == "preflight":
            technical_preflight(arguments.contract)
            print("M4_24_TECHNICAL_PREFLIGHT_OK_FIRST_START_NOT_EXECUTED")
        elif arguments.mode == "execute":
            evidence = execute_window(arguments.contract)
            print("M4_24_FIRST_START_ACCEPTED_STOPPED evidence=" + str(evidence))
        elif arguments.mode == "postcheck":
            require_root()
            if arguments.before_snapshot is None:
                fail("BEFORE_SNAPSHOT_REQUIRED", "--before-snapshot")
            before = load_before_snapshot(arguments.before_snapshot)
            postcheck(before)
            print("M4_24_POSTCHECK_OK_STOPPED")
        else:
            require_root()
            if arguments.evidence_directory is None:
                fail("EVIDENCE_DIRECTORY_REQUIRED", "--evidence-directory")
            evidence = safe_evidence_directory(arguments.evidence_directory)
            abort_window(evidence, "manual operator abort")
            print("M4_24_ABORT_COMPLETED_STOPPED evidence=" + str(evidence))
        return 0
    except (FirstStartFailure, OSError, ValueError) as error:
        code = error.code if isinstance(error, FirstStartFailure) else "UNEXPECTED_FAILURE"
        print("M4_24_FIRST_START_BLOCKED code=" + code + " detail=" + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
