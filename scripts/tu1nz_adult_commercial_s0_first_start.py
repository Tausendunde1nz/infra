#!/usr/bin/env python3
"""M4.24 controlled, network-free first-start acceptance transaction."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import grp
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Any, Iterator


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
DOCKER = "/usr/bin/docker"
LSOF = "/usr/bin/lsof"
HEALTH = VENV / "bin" / "tu1nz-commercial-candidate-health"
RELEASE_GATE = CONTROL / "scripts" / "tu1nz_adult_commercial_s0_release_gate.py"
READY_TIMEOUT_SECONDS = 60
STOP_TIMEOUT_SECONDS = 45
HEALTH_MAXIMUM_AGE_SECONDS = 90
MAXIMUM_RUNTIME_SECONDS = 180
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
SENSITIVE_ENV_NAME = re.compile(
    r"(?i)(token|secret|credential|password|api[_-]?key)"
)
SEED_COUNTS = {
    "country_policy_rules": 1,
    "creators": 1,
    "integration_accounts": 3,
    "platform_policy_rules": 3,
    "policy_versions": 1,
    "publication_destinations": 3,
}
BUSINESS_TABLES = (
    "adult_verification_events",
    "adult_verifications",
    "audit_events",
    "command_receipts",
    "commercial_dispatch_entitlements",
    "consent_events",
    "consent_invites",
    "credit_transactions",
    "depicted_persons",
    "external_identities",
    "external_identity_aliases",
    "integration_event_receipts",
    "media_assets",
    "moderation_decisions",
    "payment_attempts",
    "payment_intent_events",
    "payment_intents",
    "payment_provider_event_receipts",
    "payments",
    "platform_dispatch_events",
    "platform_dispatches",
    "platform_provider_receipts",
    "policy_decisions",
    "policy_evaluations",
    "publication_entitlement_events",
    "publication_entitlements",
    "publications",
    "safety_complaint_events",
    "safety_complaints",
    "submission_intake_sessions",
    "submission_state_events",
    "submissions",
    "takedowns",
)
ALL_TABLES = tuple(sorted((*SEED_COUNTS, *BUSINESS_TABLES)))
DATABASE_COUNTS_SQL = (
    "SELECT '__COUNTS__' || json_build_object("
    "'table_count',(SELECT count(*) FROM pg_tables WHERE schemaname='public'),"
    "'function_count',(SELECT count(*) FROM pg_proc WHERE proname LIKE 'tu1nz_%'),"
    "'other_sessions',(SELECT count(*) FROM pg_stat_activity "
    "WHERE datname=current_database() AND pid<>pg_backend_pid()),"
    "'tables',json_build_object("
    + ",".join(
        "'{0}',(SELECT count(*) FROM public.{0})".format(table)
        for table in ALL_TABLES
    )
    + "))::text;"
)
DATABASE_CONTENT_SQL = (
    "SELECT '__CONTENT__' || encode(convert_to(table_name || E'\\t' || row_json,"
    "'UTF8'),'hex') FROM ("
    + " UNION ALL ".join(
        "SELECT '{0}' AS table_name,row_to_json(t)::text AS row_json "
        "FROM public.{0} AS t".format(table)
        for table in ALL_TABLES
    )
    + ") AS rows ORDER BY table_name,row_json;"
)
DATABASE_SCHEMA_SQL = """
SELECT '__SCHEMA__' || encode(convert_to(object_definition, 'UTF8'), 'hex') FROM (
  SELECT 'column|' || table_name || '|' || ordinal_position::text || '|' ||
         column_name || '|' || data_type || '|' || is_nullable || '|' ||
         coalesce(column_default, '') AS object_definition
    FROM information_schema.columns WHERE table_schema = 'public'
  UNION ALL
  SELECT 'constraint|' || conname || '|' || pg_get_constraintdef(oid, true)
    FROM pg_constraint WHERE connamespace = 'public'::regnamespace
  UNION ALL
  SELECT 'index|' || indexname || '|' || indexdef
    FROM pg_indexes WHERE schemaname = 'public'
  UNION ALL
  SELECT 'function|' || oid::text || '|' || pg_get_functiondef(oid)
    FROM pg_proc WHERE proname LIKE 'tu1nz_%'
) AS schema_objects ORDER BY object_definition;
"""
DATABASE_SNAPSHOT_SQL = (
    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
    + DATABASE_COUNTS_SQL
    + "\n"
    + DATABASE_CONTENT_SQL
    + "\n"
    + DATABASE_SCHEMA_SQL
    + "\nCOMMIT;"
)


def fail(code: str, detail: str) -> None:
    raise FirstStartFailure(code, detail)


def command(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": "/root",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
        "TZ": "UTC",
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
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail("UNSAFE_FILE", str(path) + ": " + str(error))
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("UNSAFE_FILE", str(path))
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_safe_bytes(path: Path, label: str, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail("UNSAFE_FILE", label + ": " + str(error))
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum_bytes
        ):
            fail("UNSAFE_FILE", label)
        return handle.read()


def read_json(path: Path, label: str, maximum_bytes: int = 1024 * 1024) -> Any:
    try:
        return json.loads(read_safe_bytes(path, label, maximum_bytes).decode("ascii"))
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
            "--property=Restart",
            "--property=RuntimeMaxUSec",
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
    if git_value(CANONICAL_CONTROL, "status", "--porcelain", "--ignored"):
        fail("CANONICAL_CONTROL_DIRTY", str(CANONICAL_CONTROL))
    if git_value(CANONICAL_CONTROL, "symbolic-ref", "--short", "HEAD") != "control-main":
        fail("CANONICAL_CONTROL_BRANCH_MISMATCH", "control-main required")
    if git_value(CANONICAL_CONTROL, "rev-parse", "HEAD") != git_value(
        CANONICAL_CONTROL, "rev-parse", "origin/control-main"
    ):
        fail("CANONICAL_CONTROL_NOT_SYNCED", "origin/control-main mismatch")


@contextmanager
def contract_execution_lock(contract: Path) -> Iterator[tuple[int, int]]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(contract, flags)
    except OSError as error:
        fail("CONTRACT_LOCK_FAILED", str(error))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("CONTRACT_LOCK_UNSAFE", str(contract))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("FIRST_START_ALREADY_CONTROLLED", str(contract))
        yield (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def file_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("UNSAFE_FILE_IDENTITY", str(path))
    return (metadata.st_dev, metadata.st_ino)


def validate_contract(contract: Path, *, require_approved: bool) -> None:
    verify_canonical_contract(contract)
    arguments = [str(AUTHORIZATION_GATE), "--contract", str(contract)]
    if require_approved:
        arguments.append("--require-approved")
    result = command(arguments, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or "first-start authorization rejected"
        fail("FIRST_START_AUTHORIZATION_REJECTED", detail)


def database_query(sql: str) -> str:
    return command(
        [
            RUNUSER,
            "-u",
            "postgres",
            "--",
            PSQL,
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--quiet",
            "--dbname=" + DATABASE,
            "--command",
            sql,
        ]
    ).stdout.strip()


def database_snapshot() -> dict[str, object]:
    counts: object | None = None
    content_digest = hashlib.sha256()
    schema_digest = hashlib.sha256()
    unexpected: list[str] = []
    for line in database_query(DATABASE_SNAPSHOT_SQL).splitlines():
        if line.startswith("__COUNTS__"):
            if counts is not None:
                fail("DATABASE_SNAPSHOT_INVALID", "duplicate counts")
            try:
                counts = json.loads(line.removeprefix("__COUNTS__"))
            except json.JSONDecodeError as error:
                fail("DATABASE_SNAPSHOT_INVALID", str(error))
        elif line.startswith("__CONTENT__"):
            try:
                content_digest.update(bytes.fromhex(line.removeprefix("__CONTENT__")))
                content_digest.update(b"\n")
            except ValueError:
                fail("DATABASE_SNAPSHOT_INVALID", "invalid content encoding")
        elif line.startswith("__SCHEMA__"):
            try:
                schema_digest.update(bytes.fromhex(line.removeprefix("__SCHEMA__")))
                schema_digest.update(b"\n")
            except ValueError:
                fail("DATABASE_SNAPSHOT_INVALID", "invalid schema encoding")
        elif line.strip():
            unexpected.append(line)
    if unexpected:
        fail("DATABASE_SNAPSHOT_INVALID", "unexpected database output")
    if (
        not isinstance(counts, dict)
        or set(counts)
        != {"function_count", "other_sessions", "table_count", "tables"}
        or isinstance(counts["table_count"], bool)
        or not isinstance(counts["table_count"], int)
        or isinstance(counts["function_count"], bool)
        or not isinstance(counts["function_count"], int)
        or isinstance(counts["other_sessions"], bool)
        or not isinstance(counts["other_sessions"], int)
        or not isinstance(counts["tables"], dict)
        or set(counts["tables"]) != set(ALL_TABLES)
        or any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in counts["tables"].values()
        )
    ):
        fail("DATABASE_SNAPSHOT_INVALID", "exact per-table count object required")
    return {
        **counts,
        "content_sha256": content_digest.hexdigest(),
        "schema_sha256": schema_digest.hexdigest(),
    }


def verify_initial_database(snapshot: dict[str, object]) -> None:
    expected_counts = {**{table: 0 for table in BUSINESS_TABLES}, **SEED_COUNTS}
    if (
        set(snapshot)
        != {
            "content_sha256",
            "function_count",
            "other_sessions",
            "schema_sha256",
            "table_count",
            "tables",
        }
        or snapshot.get("table_count") != 39
        or snapshot.get("function_count") != 21
        or snapshot.get("other_sessions") != 0
        or snapshot.get("tables") != expected_counts
        or not isinstance(snapshot.get("content_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("content_sha256"))) is None
        or not isinstance(snapshot.get("schema_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("schema_sha256"))) is None
    ):
        fail("DATABASE_NOT_SYNTHETIC_EMPTY", json.dumps(snapshot, sort_keys=True))


def verify_empty_state() -> str:
    material = read_safe_bytes(STATE_FILE, "commercial state", 1024 * 1024)
    try:
        payload = json.loads(material.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail("INVALID_JSON", "commercial state: " + str(error))
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
    return hashlib.sha256(material).hexdigest()


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


def systemd_duration_microseconds(value: str) -> int | None:
    if value == "infinity":
        return None
    if value.isdigit():
        return int(value)
    factors = {
        "us": 1,
        "ms": 1_000,
        "s": 1_000_000,
        "min": 60 * 1_000_000,
        "h": 60 * 60 * 1_000_000,
    }
    total = 0.0
    position = 0
    for match in re.finditer(r"([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h)", value):
        if value[position : match.start()].strip():
            return None
        total += float(match.group(1)) * factors[match.group(2)]
        position = match.end()
    if position == 0 or value[position:].strip():
        return None
    return int(total)


def verify_single_start_guard(state: dict[str, str]) -> None:
    runtime_maximum = state.get("RuntimeMaxUSec", "infinity")
    if (
        state.get("Restart") != "no"
        or systemd_duration_microseconds(runtime_maximum)
        != MAXIMUM_RUNTIME_SECONDS * 1_000_000
    ):
        fail(
            "UNIT_SINGLE_START_GUARD_MISSING",
            "Restart=no and RuntimeMaxSec=180 required",
        )


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
        or state.get("NRestarts") != "0"
        or state.get("ExecMainStartTimestampMonotonic") != "0"
    ):
        fail("UNIT_NOT_STOPPED_STATIC", json.dumps(state, sort_keys=True))
    verify_single_start_guard(state)
    return state


def verify_provider_environment_boundary() -> None:
    manager = command([SYSTEMCTL, "show-environment"]).stdout
    for line in manager.splitlines():
        name, separator, _ = line.partition("=")
        if separator and SENSITIVE_ENV_NAME.search(name):
            fail("SENSITIVE_MANAGER_ENVIRONMENT", name)
    effective = command(
        [
            SYSTEMCTL,
            "show",
            UNIT,
            "--property=Environment",
            "--property=EnvironmentFiles",
            "--property=PassEnvironment",
        ]
    ).stdout
    for line in effective.splitlines():
        _, separator, value = line.partition("=")
        if separator and SENSITIVE_ENV_NAME.search(value):
            fail("SENSITIVE_UNIT_ENVIRONMENT", line.partition("=")[0])


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
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            fail("PROCESS_REFERENCE_CHECK_FAILED", entry.name + ": " + str(error))
        if b"tu1nz-commercial-runtime-candidate" in material:
            references.append(int(entry.name))
    return references


def runtime_user_processes() -> list[int]:
    runtime_uid = pwd.getpwnam(RUNTIME_USER).pw_uid
    references: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status_lines = (entry / "status").read_text(encoding="ascii").splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            fail("RUNTIME_PROCESS_CHECK_FAILED", entry.name + ": " + str(error))
        uid_line = next((line for line in status_lines if line.startswith("Uid:")), None)
        if uid_line is None:
            fail("RUNTIME_PROCESS_CHECK_FAILED", entry.name + ": Uid missing")
        if int(uid_line.split()[1]) == runtime_uid:
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
            except OSError as error:
                fail("CRON_REFERENCE_CHECK_FAILED", str(path) + ": " + str(error))
    return sorted(found)


def docker_mount_references() -> list[str]:
    if not Path(DOCKER).is_file():
        fail("DOCKER_INSPECTION_UNAVAILABLE", DOCKER)
    identifiers = command([DOCKER, "ps", "--quiet"]).stdout.split()
    if not identifiers:
        return []
    output = command(
        [
            DOCKER,
            "inspect",
            "--format",
            "{{range .Mounts}}{{.Source}}|{{.Destination}}{{println}}{{end}}",
            *identifiers,
        ]
    ).stdout
    return [line for line in output.splitlines() if "staging-s0-commercial" in line]


def open_file_references() -> list[str]:
    if not Path(LSOF).is_file():
        fail("OPEN_FILE_INSPECTION_UNAVAILABLE", LSOF)
    references: set[str] = set()
    for boundary in (BASE, CONFIG, STATE):
        result = command([LSOF, "-Fn", "+D", str(boundary)], check=False, timeout=30)
        if result.returncode not in {0, 1}:
            fail("OPEN_FILE_CHECK_FAILED", boundary.as_posix())
        references.update(
            line for line in result.stdout.splitlines() if line.startswith("p")
        )
    return sorted(references)


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
    verify_provider_environment_boundary()
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
    runtime_processes = runtime_user_processes()
    if runtime_processes:
        fail("COMMERCIAL_RUNTIME_USER_BUSY", ",".join(map(str, runtime_processes)))
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
    contract_device, contract_inode = file_identity(contract)
    return {
        "archive_sha256": ARCHIVE_SHA256,
        "application_sha": APPLICATION_SHA,
        "canonical_control_sha": git_value(CANONICAL_CONTROL, "rev-parse", "HEAD"),
        "captured_at": utc_now(),
        "contract_sha256": sha256_file(contract),
        "contract_identity": {
            "device": contract_device,
            "inode": contract_inode,
        },
        "control_sha": CONTROL_SHA,
        "database": database,
        "manifest_sha256": MANIFEST_SHA256,
        "state_sha256": state_sha,
        "tailscale_ipv4": tailscale_ip,
        "unit": unit_state,
        "unit_sha256": UNIT_SHA256,
        **capacity,
    }


def parse_status_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        fail("RUNTIME_STATUS_INVALID", label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        fail("RUNTIME_STATUS_INVALID", label)
    if parsed.tzinfo != timezone.utc:
        fail("RUNTIME_STATUS_INVALID", label)
    return parsed


def read_runtime_status(
    expected_state: str,
    minimum_started_at: datetime | None = None,
) -> dict[str, object]:
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
        or type(payload.get("projected_submissions")) is not int
        or payload.get("projected_submissions") != 0
        or type(payload.get("postgres_major")) is not int
        or type(payload.get("version")) is not int
    ):
        fail("RUNTIME_STATUS_INVALID", expected_state)
    if metadata.st_uid != runtime_uid or metadata.st_gid != runtime_gid:
        fail(
            "RUNTIME_STATUS_OWNER_MISMATCH",
            str(metadata.st_uid) + ":" + str(metadata.st_gid),
        )
    started_at = parse_status_timestamp(payload.get("started_at"), "started_at")
    checked_at = parse_status_timestamp(payload.get("checked_at"), "checked_at")
    synchronized = payload.get("last_synchronized_at")
    synchronized_at = (
        None
        if synchronized is None
        else parse_status_timestamp(synchronized, "last_synchronized_at")
    )
    if (
        checked_at < started_at
        or (synchronized_at is not None and not started_at <= synchronized_at <= checked_at)
        or (minimum_started_at is not None and started_at < minimum_started_at)
    ):
        fail("RUNTIME_STATUS_STALE", expected_state)
    return payload


def wait_for_runtime_state(
    expected_state: str,
    timeout_seconds: int,
    minimum_started_at: datetime | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "status absent"
    while time.monotonic() < deadline:
        try:
            if STATUS_FILE.exists():
                return read_runtime_status(expected_state, minimum_started_at)
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
        write_private(
            evidence / name,
            read_safe_bytes(STATUS_FILE, "runtime status", 4096),
        )


def ensure_stopped(failure_code: str) -> tuple[dict[str, str], dict[str, str]]:
    try:
        state_before = systemctl_state(UNIT)
    except FirstStartFailure:
        state_before = {"ActiveState": "unknown", "SubState": "unknown"}
    if state_before.get("ActiveState") != "inactive":
        try:
            command([SYSTEMCTL, "stop", UNIT], check=False, timeout=STOP_TIMEOUT_SECONDS)
        except FirstStartFailure:
            pass
    try:
        wait_inactive(STOP_TIMEOUT_SECONDS)
        state_after = systemctl_state(UNIT)
    except FirstStartFailure as error:
        fail(failure_code, str(error))
    if state_after.get("ActiveState") != "inactive" or state_after.get("SubState") != "dead":
        fail(failure_code, json.dumps(state_after, sort_keys=True))
    return state_before, state_after


def abort_window(
    evidence: Path,
    reason: str,
    before: dict[str, object] | None = None,
) -> None:
    safe_evidence_directory(evidence)
    token = datetime.now(timezone.utc).strftime("%Y%m%dT%H-%M-%SZ")
    stop_failure: FirstStartFailure | None = None
    try:
        state_before, state_after = ensure_stopped("ABORT_STOP_FAILED")
    except FirstStartFailure as error:
        stop_failure = error
        state_before = {"ActiveState": "unknown", "SubState": "unknown"}
        try:
            state_after = systemctl_state(UNIT)
        except FirstStartFailure:
            state_after = {"ActiveState": "unknown", "SubState": "unknown"}

    database_preserved: bool | None = None
    state_preserved: bool | None = None
    invariance_failure: FirstStartFailure | None = None
    if before is not None and stop_failure is None:
        try:
            state_preserved = verify_empty_state() == before.get("state_sha256")
            after_database = database_snapshot()
            database_preserved = after_database == before.get("database")
            if not state_preserved:
                fail("ABORT_STATE_DRIFT", str(STATE_FILE))
            if not database_preserved:
                fail("ABORT_DATABASE_DRIFT", "complete database snapshot changed")
            verify_initial_database(after_database)
        except FirstStartFailure as error:
            invariance_failure = error

    capture_runtime_status(evidence, "runtime-status.abort." + token + ".json")
    capture_journal(evidence, "journal.abort." + token + ".log")
    payload = {
        "aborted_at": utc_now(),
        "database_preserved": database_preserved,
        "reason": reason,
        "runtime_evidence_preserved": True,
        "state_after": state_after,
        "state_before": state_before,
        "state_file_preserved": state_preserved,
        "stop_verified": stop_failure is None,
        "unit": UNIT,
    }
    write_json(evidence / ("abort-result." + token + ".json"), payload)
    if stop_failure is not None:
        raise stop_failure
    if before is None:
        fail("ABORT_SNAPSHOT_REQUIRED", "preflight evidence is required")
    if invariance_failure is not None:
        raise invariance_failure


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
    verify_manifest()
    if sha256_file(ARCHIVE) != before.get("archive_sha256"):
        fail("POSTCHECK_ARCHIVE_DRIFT", str(ARCHIVE))
    if sha256_file(INSTALLED_UNIT) != before.get("unit_sha256"):
        fail("POSTCHECK_UNIT_DRIFT", str(INSTALLED_UNIT))
    if sha256_file(CONTRACT) != before.get("contract_sha256"):
        fail("POSTCHECK_CONTRACT_DRIFT", str(CONTRACT))
    if git_value(CANONICAL_CONTROL, "rev-parse", "HEAD") != before.get(
        "canonical_control_sha"
    ):
        fail("POSTCHECK_CONTROL_DRIFT", str(CANONICAL_CONTROL))
    run_release_gate()
    verify_provider_environment_boundary()
    verify_services()
    if process_references():
        fail("POSTCHECK_PROCESS_REMAINS", UNIT)
    if runtime_user_processes():
        fail("POSTCHECK_RUNTIME_USER_BUSY", RUNTIME_USER)
    return {
        "checked_at": utc_now(),
        "database": after_database,
        "runtime_status": status_payload,
        "state_sha256": before["state_sha256"],
        "unit": state,
    }


STABLE_PREFLIGHT_KEYS = {
    "application_sha",
    "archive_sha256",
    "canonical_control_sha",
    "contract_identity",
    "contract_sha256",
    "control_sha",
    "database",
    "manifest_sha256",
    "state_sha256",
    "tailscale_ipv4",
    "unit",
    "unit_sha256",
}


def verify_prestart_revalidation(
    before: dict[str, object],
    prestart: dict[str, object],
) -> None:
    for key in STABLE_PREFLIGHT_KEYS:
        if before.get(key) != prestart.get(key):
            fail("PRESTART_BOUNDARY_DRIFT", key)


def normalize_execution_failure(error: BaseException) -> FirstStartFailure:
    if isinstance(error, FirstStartFailure):
        return error
    if isinstance(error, KeyboardInterrupt):
        return FirstStartFailure("EXECUTION_INTERRUPTED", "SIGINT")
    return FirstStartFailure(
        "UNEXPECTED_EXECUTION_FAILURE",
        type(error).__name__ + ": " + str(error),
    )


@contextmanager
def execution_signal_guard() -> Iterator[None]:
    prior: dict[signal.Signals, Any] = {}

    def interrupted(signum: int, _frame: FrameType | None) -> None:
        fail("EXECUTION_INTERRUPTED", signal.Signals(signum).name)

    for selected in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        prior[selected] = signal.getsignal(selected)
        signal.signal(selected, interrupted)
    try:
        yield
    finally:
        for selected, handler in prior.items():
            signal.signal(selected, handler)


def execute_window(contract: Path) -> Path:
    with contract_execution_lock(contract) as locked_identity:
        before = technical_preflight(contract)
        validate_contract(contract, require_approved=True)
        if sha256_file(contract) != before.get("contract_sha256"):
            fail("AUTHORIZATION_CHANGED_AFTER_PREFLIGHT", str(contract))
        if file_identity(contract) != locked_identity:
            fail("AUTHORIZATION_REPLACED_AFTER_LOCK", str(contract))
        if git_value(CANONICAL_CONTROL, "rev-parse", "HEAD") != before.get(
            "canonical_control_sha"
        ):
            fail("CONTROL_CHANGED_AFTER_PREFLIGHT", str(CANONICAL_CONTROL))
        evidence = create_evidence_directory()
        write_json(evidence / "preflight.json", before)
        write_private(
            evidence / "authorization.json",
            read_safe_bytes(contract, "authorization", 1024 * 1024),
        )
        prestart = technical_preflight(contract)
        validate_contract(contract, require_approved=True)
        verify_prestart_revalidation(before, prestart)
        if file_identity(contract) != locked_identity:
            fail("AUTHORIZATION_REPLACED_BEFORE_START", str(contract))
        write_json(evidence / "prestart-revalidation.json", prestart)

        start_attempted = False
        stop_verified = False
        signal_context = execution_signal_guard()
        signal_context.__enter__()
        try:
            minimum_started_at = datetime.now(timezone.utc)
            start_attempted = True
            command([SYSTEMCTL, "start", UNIT], timeout=READY_TIMEOUT_SECONDS)
            ready = wait_for_runtime_state(
                "READY",
                READY_TIMEOUT_SECONDS,
                minimum_started_at,
            )
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
            ensure_stopped("CONTROLLED_STOP_FAILED")
            stop_verified = True
            wait_for_runtime_state(
                "STOPPED",
                STOP_TIMEOUT_SECONDS,
                minimum_started_at,
            )
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
            return evidence
        except BaseException as raw_error:
            error = normalize_execution_failure(raw_error)
            if start_attempted:
                try:
                    abort_window(evidence, error.code + ": " + str(error), before)
                    stop_verified = True
                except BaseException as raw_abort_error:
                    raise normalize_execution_failure(raw_abort_error) from error
            raise error
        finally:
            try:
                if start_attempted and not stop_verified:
                    ensure_stopped("FINAL_STOP_FAILED")
            finally:
                signal_context.__exit__(None, None, None)


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
            snapshot = evidence / "preflight.json"
            before = load_before_snapshot(snapshot) if snapshot.is_file() else None
            abort_window(evidence, "manual operator abort", before)
            print("M4_24_ABORT_COMPLETED_STOPPED evidence=" + str(evidence))
        return 0
    except (FirstStartFailure, OSError, TypeError, ValueError) as error:
        code = error.code if isinstance(error, FirstStartFailure) else "UNEXPECTED_FAILURE"
        print("M4_24_FIRST_START_BLOCKED code=" + code + " detail=" + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
