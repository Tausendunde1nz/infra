#!/usr/bin/env python3
"""Fail-closed retained-state classification and reconciliation for S10.2D.

The live adapter keeps Telegram identifiers and exact database rows inside a
root-only backup directory.  Standard output contains aggregate safe codes
only.  Pure helpers are intentionally reusable by the release simulator and
unit tests.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse
import urllib.request


DATABASE = "tu1nz_adult_commercial_s3"
TOKEN_PATH = Path("/etc/tu1nz/adult-commercial-s10-2b-telegram.token")
COMMUNITY = "@WantMeSeenCommunity"
BACKUP_ROOT = Path("/opt/tu1nz_repos/backups/commercial-s10-2d-r8-1-state")
SCHEMA = "tu1nz-s10-2d-r8-1-retained-state-v1"
OWNERSHIP_CLASSES = {
    "INTERNAL_ACCEPTANCE_CONFIRMED",
    "FAILED_RELEASE_TARGET_STATE_CONFIRMED",
}
TECHNICAL_EVIDENCE = "TECHNICAL_ACCEPTANCE"
EXPECTED_RELEASE_ID = "s10-2d-r3-5"
EXPECTED_RUN_ID_SHA256 = "6c2af59919f79ce39c99efa6b3a8de9c318d1e259f3bf383710692daa78bf7d9"
EXPECTED_CUTOVER_STARTED_AT = "2026-09-07T15:37:04.788047Z"
EXPECTED_EVENT_TYPES = {
    "COMMUNITY_JOIN",
    "RULES_ACCEPTED",
    "COMMUNITY_ACTIVE_MEMBER",
}
BACKUP_TABLES = (
    "commercial_s10_2d_runtime_control",
    "commercial_s10_2d_bot_polling_state",
    "commercial_s10_2d_community_members",
    "commercial_s10_2d_community_events",
    "commercial_s10_2d_community_rate_limits",
    "commercial_s10_2d_moderation_events",
    "commercial_s10_2d_moderation_outbox",
    "commercial_s10_2d_latency_samples",
)
PRIVATE_INVENTORY = "retained-state-private.json"
SUMMARY = "retained-state-summary.json"
DATA_DUMP = "retained-state-data.pgdump"
SCHEMA_DUMP = "retained-state-schema.pgdump"
CHECKSUMS = "SHA256SUMS"
RESULT = "reconciliation-result.json"


class StateContractError(ValueError):
    """Stable fail-closed code safe for operator output."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256_bytes(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise StateContractError(safe_code)


def _event_map(inventory: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    events: dict[str, list[dict[str, object]]] = {}
    for event in inventory.get("community_events", []):
        require(isinstance(event, dict), "RETAINED_EVENT_SHAPE_RED")
        event_type = event.get("event_type")
        require(isinstance(event_type, str), "RETAINED_EVENT_SHAPE_RED")
        events.setdefault(event_type, []).append(event)
    return events


def _within_provider_ack_window(sample_at: object, event_at: object) -> bool:
    if not isinstance(sample_at, str) or not isinstance(event_at, str):
        return False
    try:
        sample = datetime.fromisoformat(sample_at.replace("Z", "+00:00"))
        event = datetime.fromisoformat(event_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    delta = (sample - event).total_seconds()
    return 0 <= delta <= 2


def require_manifest_binding(
    inventory: dict[str, object],
    *,
    expected_release_id: str = EXPECTED_RELEASE_ID,
    expected_run_id_sha256: str = EXPECTED_RUN_ID_SHA256,
    expected_cutover_started_at: str = EXPECTED_CUTOVER_STARTED_AT,
) -> None:
    runtime = inventory.get("runtime")
    require(isinstance(runtime, dict), "RETAINED_RUNTIME_CONTROL_RED")
    run_id = runtime.get("run_id")
    require(isinstance(run_id, str), "RETAINED_RUNTIME_BINDING_RED")
    require(runtime.get("release_id") == expected_release_id, "RETAINED_MANIFEST_RELEASE_MISMATCH_RED")
    require(
        sha256_bytes(run_id.encode("ascii")) == expected_run_id_sha256,
        "RETAINED_MANIFEST_RUN_MISMATCH_RED",
    )
    require(
        runtime.get("cutover_started_at") == expected_cutover_started_at,
        "RETAINED_MANIFEST_CUTOVER_MISMATCH_RED",
    )


def classify_retained_state(
    inventory: dict[str, object],
    *,
    ownership_class: str,
    provider: dict[str, object],
) -> dict[str, object]:
    """Prove the exact failed-release acceptance shape without trusting a name."""

    require(ownership_class in OWNERSHIP_CLASSES, "RETAINED_OWNERSHIP_ASSERTION_RED")
    runtime = inventory.get("runtime")
    members = inventory.get("members")
    latency = inventory.get("latency")
    require(isinstance(runtime, dict), "RETAINED_RUNTIME_CONTROL_RED")
    require(isinstance(members, list) and len(members) == 1, "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(isinstance(latency, list) and len(latency) > 0, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
    require(runtime.get("acquisition_ready") is False, "RETAINED_REAL_ACQUISITION_ACTIVE_RED")
    require(runtime.get("baseline_start") is None, "RETAINED_REAL_ACQUISITION_ACTIVE_RED")
    require(runtime.get("readiness") in {"PENDING", "GREEN"}, "RETAINED_RUNTIME_CONTROL_RED")
    release_id = runtime.get("release_id")
    run_id = runtime.get("run_id")
    cutover_started_at = runtime.get("cutover_started_at")
    require(all(isinstance(value, str) and value for value in (release_id, run_id, cutover_started_at)), "RETAINED_RUNTIME_BINDING_RED")

    member = members[0]
    require(isinstance(member, dict), "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(member.get("community_state") == "ACTIVE", "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(member.get("self_attested") is True, "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(member.get("warning_count") == 0 and member.get("ban_state") is False, "MIGRATION_0029_RETAINED_PRODUCT_STATE")

    events = _event_map(inventory)
    require(set(events) == EXPECTED_EVENT_TYPES, "RETAINED_MEMBER_EVENT_OWNERSHIP_RED")
    require(all(len(events[name]) == 1 for name in EXPECTED_EVENT_TYPES), "RETAINED_MEMBER_EVENT_OWNERSHIP_RED")
    subject_id = member.get("subject_id")
    require(all(events[name][0].get("subject_id") == subject_id for name in EXPECTED_EVENT_TYPES), "RETAINED_MEMBER_EVENT_OWNERSHIP_RED")
    join_at = events["COMMUNITY_JOIN"][0].get("occurred_at")
    rules_at = events["RULES_ACCEPTED"][0].get("occurred_at")
    active_at = events["COMMUNITY_ACTIVE_MEMBER"][0].get("occurred_at")
    require(join_at == member.get("joined_at"), "RETAINED_MEMBER_EVENT_OWNERSHIP_RED")
    require(rules_at == active_at == member.get("updated_at"), "RETAINED_MEMBER_EVENT_OWNERSHIP_RED")

    for sample in latency:
        require(isinstance(sample, dict), "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
        require(sample.get("release_id") == release_id, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
        require(sample.get("run_id") == run_id, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
        require(sample.get("cutover_started_at") == cutover_started_at, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
        require(sample.get("evidence_class") == TECHNICAL_EVIDENCE, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
        require(sample.get("source") in {"DIRECT", "COMMUNITY"}, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
    community_samples = [sample for sample in latency if sample.get("source") == "COMMUNITY"]
    require(len(community_samples) == 2, "RETAINED_MEMBER_LATENCY_CORRELATION_RED")
    require(
        any(_within_provider_ack_window(sample.get("occurred_at"), join_at) for sample in community_samples)
        and any(_within_provider_ack_window(sample.get("occurred_at"), rules_at) for sample in community_samples),
        "RETAINED_MEMBER_LATENCY_CORRELATION_RED",
    )

    require(inventory.get("moderation_events") == [], "RETAINED_MODERATION_STATE_RED")
    require(inventory.get("moderation_outbox") == [], "RETAINED_MODERATION_STATE_RED")
    require(inventory.get("rate_limits") == [], "RETAINED_RATE_LIMIT_STATE_RED")
    require(provider.get("is_human") is True, "RETAINED_PROVIDER_IDENTITY_RED")
    require(provider.get("non_privileged") is True, "RETAINED_PROVIDER_PRIVILEGE_RED")
    require(provider.get("status") in {"member", "restricted", "left", "kicked"}, "RETAINED_PROVIDER_STATE_RED")

    return {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_OWNERSHIP_GREEN",
        "ownership_class": ownership_class,
        "community_rows": 1,
        "latency_rows": len(latency),
        "latency_classes": ["FAILED_TARGET_RELEASE"],
        "unknown_rows": 0,
        "name_used_as_proof": False,
        "real_acquisition_active": False,
    }


def retained_preflight(inventory: dict[str, object]) -> dict[str, object]:
    """Validate retained state while preserving legitimate active-product data."""

    runtime = inventory.get("runtime")
    members = inventory.get("members")
    latency = inventory.get("latency")
    require(isinstance(runtime, dict), "RETAINED_RUNTIME_CONTROL_RED")
    require(isinstance(members, list), "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(isinstance(latency, list), "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
    active_product = (
        runtime.get("readiness") == "GREEN"
        and runtime.get("acquisition_ready") is True
        and isinstance(runtime.get("baseline_start"), str)
        and bool(runtime.get("baseline_start"))
    )
    if active_product:
        for sample in latency:
            require(
                isinstance(sample, dict)
                and isinstance(sample.get("release_id"), str)
                and isinstance(sample.get("run_id"), str)
                and sample.get("evidence_class") == TECHNICAL_EVIDENCE,
                "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN",
            )
        return {
            "ok": True,
            "safe_code": "S10_2D_REAL_PRODUCT_STATE_PRESERVED",
            "community_rows": len(members),
            "latency_rows": len(latency),
            "cleanup_permitted": False,
        }
    require(runtime.get("acquisition_ready") is False and runtime.get("baseline_start") is None, "RETAINED_ACQUISITION_STATE_RED")
    require(len(members) == 0, "MIGRATION_0029_RETAINED_PRODUCT_STATE")
    require(len(latency) == 0, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN")
    return {
        "ok": True,
        "safe_code": "S10_2D_CLEAN_CUTOVER_BASELINE_GREEN",
        "community_rows": 0,
        "latency_rows": 0,
        "cleanup_permitted": False,
    }


def reconcile_model(
    inventory: dict[str, object],
    *,
    ownership_class: str,
    provider: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    """Pure state transition used by tests and the release simulator."""

    members = inventory.get("members")
    latency = inventory.get("latency")
    if members == [] and latency == []:
        return inventory, {
            "ok": True,
            "safe_code": "S10_2D_RETAINED_STATE_ALREADY_RECONCILED",
            "idempotent": True,
        }
    proof = classify_retained_state(inventory, ownership_class=ownership_class, provider=provider)
    require(provider.get("status") in {"left", "kicked"}, "RETAINED_PROVIDER_EXIT_REQUIRED")
    updated = dict(inventory)
    updated["members"] = []
    updated["community_events"] = []
    updated["rate_limits"] = []
    updated["moderation_events"] = []
    updated["moderation_outbox"] = []
    updated["latency"] = []
    retained_preflight(updated)
    return updated, {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_STATE_RECONCILED",
        "idempotent": False,
        "ownership_class": proof["ownership_class"],
        "archived_community_rows": proof["community_rows"],
        "archived_latency_rows": proof["latency_rows"],
        "unknown_rows": 0,
    }


def _psql(sql: str, *, database: str) -> str:
    result = subprocess.run(
        [
            "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc",
            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
            f"--dbname={database}",
        ],
        input=sql,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise StateContractError("RETAINED_DATABASE_QUERY_RED")
    return result.stdout.strip()


def _inventory_sql() -> str:
    return r"""
SELECT json_build_object(
  'runtime', (SELECT row_to_json(runtime_row) FROM (
    SELECT target_release_id AS release_id, technical_evidence_run_id::text AS run_id,
           to_char(cutover_started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cutover_started_at,
           pre_acquisition_readiness AS readiness, wms_real_acquisition_ready AS acquisition_ready,
           CASE WHEN real_acquisition_baseline_start IS NULL THEN NULL ELSE to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS baseline_start
    FROM commercial_s10_2d_runtime_control WHERE singleton
  ) runtime_row),
  'members', (SELECT COALESCE(json_agg(row_to_json(member_row) ORDER BY subject_id),'[]'::json) FROM (
    SELECT subject_id::text, telegram_user_id::text, community_state,
           community_18_plus_self_attested AS self_attested, warning_count, ban_state,
           to_char(joined_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS joined_at,
           to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
    FROM commercial_s10_2d_community_members
  ) member_row),
  'community_events', (SELECT COALESCE(json_agg(row_to_json(event_row) ORDER BY occurred_at,event_id),'[]'::json) FROM (
    SELECT event_id::text, event_type, subject_id::text,
           to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at
    FROM commercial_s10_2d_community_events
  ) event_row),
  'rate_limits', (SELECT COALESCE(json_agg(row_to_json(rate_row) ORDER BY subject_id),'[]'::json) FROM (
    SELECT subject_id::text, to_char(window_started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS window_started_at, message_count
    FROM commercial_s10_2d_community_rate_limits
  ) rate_row),
  'moderation_events', (SELECT COALESCE(json_agg(row_to_json(moderation_row) ORDER BY occurred_at,event_id),'[]'::json) FROM (
    SELECT event_id::text, subject_id::text, reason_code, action_code, severe,
           to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at
    FROM commercial_s10_2d_moderation_events
  ) moderation_row),
  'moderation_outbox', (SELECT COALESCE(json_agg(row_to_json(outbox_row) ORDER BY created_at,delivery_id),'[]'::json) FROM (
    SELECT delivery_id::text, subject_id::text, delivery_state, attempt_count,
           to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
    FROM commercial_s10_2d_moderation_outbox
  ) outbox_row),
  'latency', (SELECT COALESCE(json_agg(row_to_json(latency_row) ORDER BY occurred_at,sample_id),'[]'::json) FROM (
    SELECT sample_id::text, source, bot_response_latency_ms, poll_lag_ms,
           handler_duration_ms, send_ack_ms,
           to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at,
           release_id, run_id::text, evidence_class,
           to_char(cutover_started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cutover_started_at
    FROM commercial_s10_2d_latency_samples
  ) latency_row)
);
"""


def live_inventory(database: str) -> dict[str, object]:
    try:
        payload = json.loads(_psql(_inventory_sql(), database=database))
    except (json.JSONDecodeError, TypeError):
        raise StateContractError("RETAINED_DATABASE_INVENTORY_RED") from None
    require(isinstance(payload, dict), "RETAINED_DATABASE_INVENTORY_RED")
    return payload


def _provider_state(inventory: dict[str, object], token_path: Path) -> dict[str, object]:
    members = inventory.get("members")
    require(isinstance(members, list) and len(members) == 1, "RETAINED_PROVIDER_MEMBER_CARDINALITY_RED")
    telegram_user_id = members[0].get("telegram_user_id")
    require(isinstance(telegram_user_id, str) and telegram_user_id.isdigit(), "RETAINED_PROVIDER_IDENTITY_RED")
    require(token_path.is_file() and not token_path.is_symlink(), "RETAINED_PROVIDER_TOKEN_METADATA_RED")
    token_metadata = token_path.stat()
    require(
        token_metadata.st_uid == 0
        and token_metadata.st_gid == 0
        and stat.S_IMODE(token_metadata.st_mode) == 0o600
        and token_metadata.st_nlink == 1,
        "RETAINED_PROVIDER_TOKEN_METADATA_RED",
    )
    token = token_path.read_text(encoding="ascii").strip()
    require(bool(token), "RETAINED_PROVIDER_TOKEN_RED")
    query = urllib.parse.urlencode({"chat_id": COMMUNITY, "user_id": telegram_user_id})
    try:
        with urllib.request.urlopen(
            f"https://api.telegram.org/bot{token}/getChatMember?{query}",
            timeout=20,
        ) as response:
            payload = json.load(response)
    except Exception:
        raise StateContractError("RETAINED_PROVIDER_QUERY_RED") from None
    member = payload.get("result") if payload.get("ok") is True else None
    require(isinstance(member, dict), "RETAINED_PROVIDER_QUERY_RED")
    user = member.get("user")
    require(isinstance(user, dict), "RETAINED_PROVIDER_QUERY_RED")
    status_value = member.get("status")
    status = status_value if status_value in {"member", "restricted", "left", "kicked", "administrator", "creator"} else "unknown"
    return {
        "status": status,
        "is_human": user.get("is_bot") is False,
        "non_privileged": status not in {"administrator", "creator"},
    }


def safe_summary(inventory: dict[str, object], provider: dict[str, object] | None = None) -> dict[str, object]:
    latency = inventory.get("latency") if isinstance(inventory.get("latency"), list) else []
    values = [sample.get("bot_response_latency_ms") for sample in latency if isinstance(sample, dict)]
    integers = [value for value in values if isinstance(value, int)]
    summary: dict[str, object] = {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_STATE_INVENTORY_GREEN",
        "community_rows": len(inventory.get("members", [])) if isinstance(inventory.get("members"), list) else -1,
        "community_events": len(inventory.get("community_events", [])) if isinstance(inventory.get("community_events"), list) else -1,
        "latency_rows": len(latency),
        "latency_min_ms": min(integers) if integers else None,
        "latency_max_ms": max(integers) if integers else None,
        "pending_moderation": sum(1 for row in inventory.get("moderation_outbox", []) if isinstance(row, dict) and row.get("delivery_state") == "PENDING"),
        "identifiers_emitted": False,
    }
    if provider is not None:
        summary["provider_status"] = provider.get("status")
        summary["provider_human_non_privileged"] = provider.get("is_human") is True and provider.get("non_privileged") is True
    return summary


def _require_root() -> None:
    require(os.geteuid() == 0, "RETAINED_ROOT_REQUIRED")


def _require_backup_path(path: Path) -> None:
    try:
        relative = path.resolve().relative_to(BACKUP_ROOT.resolve())
    except ValueError:
        raise StateContractError("RETAINED_BACKUP_PATH_RED") from None
    require(len(relative.parts) == 1 and re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", relative.name) is not None, "RETAINED_BACKUP_PATH_RED")


def _write_new(path: Path, material: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(material)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "RETAINED_BACKUP_WRITE_RED")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _run_dump(path: Path, *, database: str, schema_only: bool) -> None:
    command = ["runuser", "-u", "postgres", "--", "pg_dump", "--format=custom", "--no-owner", "--no-privileges"]
    command.append("--schema-only" if schema_only else "--data-only")
    for table in BACKUP_TABLES:
        command.extend(("--table", f"public.{table}"))
    command.append(database)
    result = subprocess.run(command, capture_output=True, check=False)
    require(result.returncode == 0 and result.stdout, "RETAINED_BACKUP_DUMP_RED")
    _write_new(path, result.stdout)


def create_backup(
    backup_dir: Path,
    *,
    database: str,
    ownership_class: str,
    token_path: Path,
) -> dict[str, object]:
    _require_root()
    _require_backup_path(backup_dir)
    require(not backup_dir.exists(), "RETAINED_BACKUP_ALREADY_EXISTS")
    backup_dir.mkdir(parents=True, mode=0o700)
    os.chown(backup_dir, 0, 0)
    os.chmod(backup_dir, 0o700)
    inventory = live_inventory(database)
    require_manifest_binding(inventory)
    provider = _provider_state(inventory, token_path)
    proof = classify_retained_state(inventory, ownership_class=ownership_class, provider=provider)
    private = {
        "schema": SCHEMA,
        "ownership_class": ownership_class,
        "inventory": inventory,
        "provider": provider,
        "restore_database": database,
    }
    _write_new(backup_dir / PRIVATE_INVENTORY, canonical_json(private) + b"\n")
    _write_new(backup_dir / SUMMARY, canonical_json({**safe_summary(inventory, provider), **proof}) + b"\n")
    _run_dump(backup_dir / DATA_DUMP, database=database, schema_only=False)
    _run_dump(backup_dir / SCHEMA_DUMP, database=database, schema_only=True)
    checksum_lines = []
    for name in (PRIVATE_INVENTORY, SUMMARY, DATA_DUMP, SCHEMA_DUMP):
        checksum_lines.append(f"{sha256_bytes((backup_dir / name).read_bytes())}  {name}\n")
    _write_new(backup_dir / CHECKSUMS, "".join(checksum_lines).encode("ascii"))
    return {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_STATE_BACKUP_GREEN",
        "ownership_class": ownership_class,
        "community_rows": proof["community_rows"],
        "latency_rows": proof["latency_rows"],
        "restore_artifact": DATA_DUMP,
        "identifiers_emitted": False,
    }


def verify_backup(backup_dir: Path) -> dict[str, object]:
    _require_root()
    _require_backup_path(backup_dir)
    require(backup_dir.is_dir() and not backup_dir.is_symlink(), "RETAINED_BACKUP_DIRECTORY_RED")
    metadata = backup_dir.stat()
    require(metadata.st_uid == 0 and metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) == 0o700, "RETAINED_BACKUP_DIRECTORY_METADATA_RED")
    checksum_path = backup_dir / CHECKSUMS
    require(checksum_path.is_file() and not checksum_path.is_symlink(), "RETAINED_BACKUP_CHECKSUM_INDEX_RED")
    checksum_metadata = checksum_path.stat()
    require(
        checksum_metadata.st_uid == 0
        and checksum_metadata.st_gid == 0
        and stat.S_IMODE(checksum_metadata.st_mode) == 0o600,
        "RETAINED_BACKUP_CHECKSUM_INDEX_RED",
    )
    expected: dict[str, str] = {}
    try:
        for line in checksum_path.read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ", 1)
            expected[name] = digest
    except Exception:
        raise StateContractError("RETAINED_BACKUP_CHECKSUM_INDEX_RED") from None
    require(set(expected) == {PRIVATE_INVENTORY, SUMMARY, DATA_DUMP, SCHEMA_DUMP}, "RETAINED_BACKUP_CHECKSUM_INDEX_RED")
    for name, digest in expected.items():
        path = backup_dir / name
        require(path.is_file() and not path.is_symlink(), "RETAINED_BACKUP_FILE_RED")
        file_metadata = path.stat()
        require(file_metadata.st_uid == 0 and file_metadata.st_gid == 0 and stat.S_IMODE(file_metadata.st_mode) == 0o600, "RETAINED_BACKUP_FILE_METADATA_RED")
        require(sha256_bytes(path.read_bytes()) == digest, "RETAINED_BACKUP_HASH_RED")
    for name in (DATA_DUMP, SCHEMA_DUMP):
        listing = subprocess.run(("pg_restore", "--list", str(backup_dir / name)), capture_output=True, check=False)
        require(listing.returncode == 0 and listing.stdout, "RETAINED_BACKUP_RESTORE_ARTIFACT_RED")
    return {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_STATE_BACKUP_VERIFIED",
        "restore_artifact": DATA_DUMP,
        "identifiers_emitted": False,
    }


def _load_private(backup_dir: Path) -> dict[str, object]:
    verify_backup(backup_dir)
    try:
        payload = json.loads((backup_dir / PRIVATE_INVENTORY).read_text(encoding="ascii"))
    except Exception:
        raise StateContractError("RETAINED_BACKUP_PRIVATE_MANIFEST_RED") from None
    require(isinstance(payload, dict) and payload.get("schema") == SCHEMA, "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    return payload


def _quoted_uuid(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f-]{36}", value) is not None, "RETAINED_IDENTIFIER_SHAPE_RED")
    return "'" + value + "'::uuid"


def _quoted_json(value: object) -> str:
    return "'" + canonical_json(value).decode("ascii").replace("'", "''") + "'::jsonb"


def _reconciliation_sql(private: dict[str, object]) -> str:
    inventory = private.get("inventory")
    require(isinstance(inventory, dict), "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    members = inventory.get("members")
    latency = inventory.get("latency")
    events = inventory.get("community_events")
    require(isinstance(members, list) and len(members) == 1, "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    require(isinstance(latency, list) and latency, "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    require(isinstance(events, list), "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    member = members[0]
    require(isinstance(member, dict), "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    subject = _quoted_uuid(member.get("subject_id"))
    telegram = member.get("telegram_user_id")
    require(isinstance(telegram, str) and telegram.isdigit(), "RETAINED_IDENTIFIER_SHAPE_RED")
    sample_ids = ",".join(_quoted_uuid(row.get("sample_id")) for row in latency if isinstance(row, dict))
    event_ids = ",".join(_quoted_uuid(row.get("event_id")) for row in events if isinstance(row, dict))
    require(sample_ids.count("::uuid") == len(latency), "RETAINED_IDENTIFIER_SHAPE_RED")
    require(event_ids.count("::uuid") == len(events), "RETAINED_IDENTIFIER_SHAPE_RED")
    snapshot_sql = _inventory_sql().strip().removesuffix(";")
    expected_snapshot = _quoted_json(inventory)
    return f"""
BEGIN;
LOCK TABLE commercial_s10_2d_runtime_control, commercial_s10_2d_bot_polling_state,
  commercial_s10_2d_community_members, commercial_s10_2d_community_events,
  commercial_s10_2d_community_rate_limits, commercial_s10_2d_moderation_events,
  commercial_s10_2d_moderation_outbox, commercial_s10_2d_latency_samples IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
  IF (SELECT snapshot::jsonb FROM ({snapshot_sql}) AS current_snapshot(snapshot)) <> {expected_snapshot}
  THEN
    RAISE EXCEPTION 'RETAINED_LIVE_STATE_MISMATCH_RED';
  END IF;
END;
$$;
ALTER TABLE commercial_s10_2d_latency_samples DISABLE TRIGGER commercial_s10_2d_latency_append_only;
ALTER TABLE commercial_s10_2d_community_events DISABLE TRIGGER commercial_s10_2d_community_events_append_only;
DELETE FROM commercial_s10_2d_latency_samples WHERE sample_id IN ({sample_ids});
DELETE FROM commercial_s10_2d_community_events WHERE event_id IN ({event_ids});
ALTER TABLE commercial_s10_2d_community_events ENABLE TRIGGER commercial_s10_2d_community_events_append_only;
ALTER TABLE commercial_s10_2d_latency_samples ENABLE TRIGGER commercial_s10_2d_latency_append_only;
DELETE FROM commercial_s10_2d_community_members WHERE subject_id={subject} AND telegram_user_id={telegram};
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM commercial_s10_2d_community_members)
     OR EXISTS (SELECT 1 FROM commercial_s10_2d_community_events)
     OR EXISTS (SELECT 1 FROM commercial_s10_2d_latency_samples)
  THEN
    RAISE EXCEPTION 'RETAINED_POST_STATE_RED';
  END IF;
END;
$$;
COMMIT;
"""


def reconcile_live(backup_dir: Path, *, database: str, token_path: Path) -> dict[str, object]:
    _require_root()
    private = _load_private(backup_dir)
    result_path = backup_dir / RESULT
    current = live_inventory(database)
    if result_path.exists():
        report = retained_preflight(current)
        return {**report, "safe_code": "S10_2D_RETAINED_STATE_ALREADY_RECONCILED", "idempotent": True}
    expected = private.get("inventory")
    ownership_class = private.get("ownership_class")
    require(isinstance(expected, dict) and isinstance(ownership_class, str), "RETAINED_BACKUP_PRIVATE_MANIFEST_RED")
    require_manifest_binding(current)
    require(canonical_json(current) == canonical_json(expected), "RETAINED_LIVE_STATE_MISMATCH_RED")
    provider = _provider_state(current, token_path)
    proof = classify_retained_state(current, ownership_class=ownership_class, provider=provider)
    require(provider.get("status") in {"left", "kicked"}, "RETAINED_PROVIDER_EXIT_REQUIRED")
    _psql(_reconciliation_sql(private), database=database)
    after = live_inventory(database)
    post = retained_preflight(after)
    report = {
        "ok": True,
        "safe_code": "S10_2D_RETAINED_STATE_RECONCILED",
        "ownership_class": proof["ownership_class"],
        "archived_community_rows": proof["community_rows"],
        "archived_latency_rows": proof["latency_rows"],
        "unknown_rows": 0,
        "idempotent": False,
        "future_preflight": post["safe_code"],
        "identifiers_emitted": False,
    }
    _write_new(result_path, canonical_json(report) + b"\n")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inventory", "classify", "preflight", "backup", "verify-backup", "reconcile"))
    parser.add_argument("--database", default=DATABASE)
    parser.add_argument("--token-path", type=Path, default=TOKEN_PATH)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--ownership-class", choices=sorted(OWNERSHIP_CLASSES))
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.action == "inventory":
            inventory = live_inventory(arguments.database)
            report = safe_summary(inventory, _provider_state(inventory, arguments.token_path))
        elif arguments.action == "classify":
            require(arguments.ownership_class is not None, "RETAINED_ARGUMENT_RED")
            inventory = live_inventory(arguments.database)
            require_manifest_binding(inventory)
            report = classify_retained_state(
                inventory,
                ownership_class=arguments.ownership_class,
                provider=_provider_state(inventory, arguments.token_path),
            )
        elif arguments.action == "preflight":
            report = retained_preflight(live_inventory(arguments.database))
        elif arguments.action == "backup":
            require(arguments.backup_dir is not None and arguments.ownership_class is not None, "RETAINED_ARGUMENT_RED")
            report = create_backup(
                arguments.backup_dir,
                database=arguments.database,
                ownership_class=arguments.ownership_class,
                token_path=arguments.token_path,
            )
        elif arguments.action == "verify-backup":
            require(arguments.backup_dir is not None, "RETAINED_ARGUMENT_RED")
            report = verify_backup(arguments.backup_dir)
        else:
            require(arguments.backup_dir is not None, "RETAINED_ARGUMENT_RED")
            report = reconcile_live(arguments.backup_dir, database=arguments.database, token_path=arguments.token_path)
    except StateContractError as error:
        print(canonical_json({"ok": False, "safe_code": str(error)}).decode("ascii"))
        return 2
    except Exception:
        print('{"ok":false,"safe_code":"RETAINED_STATE_UNEXPECTED_RED"}')
        return 2
    print(canonical_json(report).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
