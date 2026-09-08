#!/usr/bin/env python3
"""Fail-closed aggregate backup and rollback projection for S10.2D.

The live file remains the v1 JSON counter map understood by the historical
source application.  Version and ownership metadata live in immutable backup
sidecars so the source payload itself is never made forward-incompatible.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Mapping


AGGREGATE_PATH = Path("/var/lib/tu1nz-adult-public-s9/landing-aggregates.json")
CONTRACT_VERSION = "tu1nz-s10-2d-r7-1-aggregate-contract-v1"
EVENT_SCHEMA_VERSION = "tu1nz-s9-aggregate-events-v1"
SOURCE_RELEASE_ID = "s10-wms-source-f9747088"
TARGET_RELEASE_ID = "s10-2d-r3-5"
SOURCE_EVENTS = frozenset({"LANDING_VIEW", "TELEGRAM_CTA"})
TARGET_TECHNICAL_EVENTS: frozenset[str] = frozenset()
TARGET_PRODUCT_EVENTS = frozenset({"COMMUNITY_CTA"})
KNOWN_EVENTS = SOURCE_EVENTS | TARGET_TECHNICAL_EVENTS | TARGET_PRODUCT_EVENTS
EVENT_CLASSES = {
    **{event: "SOURCE_COMPATIBLE" for event in SOURCE_EVENTS},
    **{event: "TARGET_ONLY_TECHNICAL" for event in TARGET_TECHNICAL_EVENTS},
    **{event: "TARGET_ONLY_PRODUCT" for event in TARGET_PRODUCT_EVENTS},
}
MAX_AGGREGATE_BYTES = 8 * 1024 * 1024

BACKUP_BYTES = "s10-2d-aggregate-before.json"
BACKUP_METADATA = "s10-2d-aggregate-before.metadata.json"
RECONCILIATION_DIRECTORY = "s10-2d-aggregate-reconciliation"
CURRENT_BYTES = "aggregate-current.original.json"
INTAKE_METADATA = "intake.json"
SOURCE_PROJECTION = "aggregate-source-compatible.json"
TARGET_ONLY_ARCHIVE = "aggregate-target-only.json"
RECONCILIATION_EVIDENCE = "evidence.json"
RECONCILIATION_CHECKSUMS = "SHA256SUMS"
RECONCILIATION_FAILURE = "failure.json"


class AggregateContractError(ValueError):
    """Expected failure that exposes only a stable safe code."""


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise AggregateContractError(safe_code)


def sha256_bytes(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AggregateContractError("AGGREGATE_DUPLICATE_KEY_RED")
        result[key] = value
    return result


def parse_aggregate(material: bytes) -> dict[str, int]:
    """Validate the structural v1 counter map without accepting duplicates."""

    require(len(material) <= MAX_AGGREGATE_BYTES, "AGGREGATE_SIZE_RED")
    try:
        payload = json.loads(material.decode("ascii"), object_pairs_hook=_unique_object)
    except AggregateContractError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise AggregateContractError("AGGREGATE_JSON_RED") from None
    require(isinstance(payload, dict), "AGGREGATE_SHAPE_RED")
    result: dict[str, int] = {}
    for key, value in payload.items():
        require(isinstance(key, str), "AGGREGATE_KEY_RED")
        require(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            "AGGREGATE_COUNT_RED",
        )
        parts = key.split("|")
        require(len(parts) == 4 and all(parts), "AGGREGATE_KEY_RED")
        try:
            dt.date.fromisoformat(parts[0])
        except ValueError:
            raise AggregateContractError("AGGREGATE_DATE_RED") from None
        require(all(len(part) <= 64 for part in parts[1:]), "AGGREGATE_DIMENSION_RED")
        result[key] = value
    return result


def classify_aggregate(
    payload: Mapping[str, int],
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    source: dict[str, int] = {}
    technical: dict[str, int] = {}
    product: dict[str, int] = {}
    for key, value in payload.items():
        event = key.split("|")[1]
        if event in SOURCE_EVENTS:
            source[key] = value
        elif event in TARGET_TECHNICAL_EVENTS:
            technical[key] = value
        elif event in TARGET_PRODUCT_EVENTS:
            product[key] = value
        else:
            raise AggregateContractError("AGGREGATE_RECONCILIATION_UNKNOWN_EVENT_RED")
    require(
        len(source) + len(technical) + len(product) == len(payload),
        "AGGREGATE_PARTITION_RED",
    )
    require(
        sum(source.values()) + sum(technical.values()) + sum(product.values())
        == sum(payload.values()),
        "AGGREGATE_CONSERVATION_RED",
    )
    return source, technical, product


def _event_summary(payload: Mapping[str, int]) -> dict[str, dict[str, int]]:
    entries: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    for key, value in payload.items():
        event = key.split("|")[1]
        entries[event] += 1
        totals[event] += value
    return {
        event: {"entries": entries[event], "total": totals[event]}
        for event in sorted(entries)
    }


def _validate_identifier(value: str, safe_code: str) -> None:
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value)), safe_code)


def _regular_metadata(path: Path, *, safe_code: str) -> os.stat_result:
    require(path.is_absolute() and not path.is_symlink(), safe_code)
    try:
        metadata = path.lstat()
    except OSError:
        raise AggregateContractError(safe_code) from None
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, safe_code)
    return metadata


def _read_exact(path: Path, *, safe_code: str = "AGGREGATE_READ_RED") -> bytes:
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
                safe_code,
            )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                material = stream.read(MAX_AGGREGATE_BYTES + 1)
        finally:
            os.close(descriptor)
    except AggregateContractError:
        raise
    except OSError:
        raise AggregateContractError(safe_code) from None
    require(len(material) <= MAX_AGGREGATE_BYTES, "AGGREGATE_SIZE_RED")
    return material


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise AggregateContractError("AGGREGATE_DIRECTORY_SYNC_RED") from None


def _write_new(path: Path, material: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags, mode)
        created = True
        try:
            os.fchmod(descriptor, mode)
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
        raise AggregateContractError("AGGREGATE_EVIDENCE_WRITE_RED") from None


def _write_or_verify(path: Path, material: bytes) -> None:
    if path.exists() or path.is_symlink():
        require(
            _read_exact(path, safe_code="AGGREGATE_EVIDENCE_READ_RED") == material,
            "AGGREGATE_EVIDENCE_DIVERGED",
        )
        return
    _write_new(path, material)


def _atomic_replace(
    path: Path,
    material: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    temporary = path.with_name(path.name + ".s10-2d-r7-1.tmp")
    require(not temporary.exists() and not temporary.is_symlink(), "AGGREGATE_TEMP_PATH_RED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(temporary, flags, mode)
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
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError:
        if created:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise AggregateContractError("AGGREGATE_ATOMIC_REPLACE_RED") from None


def _backup_paths(backup_dir: Path) -> tuple[Path, Path]:
    return backup_dir / BACKUP_BYTES, backup_dir / BACKUP_METADATA


def create_backup(
    aggregate_path: Path,
    backup_dir: Path,
    *,
    target_release_id: str,
    run_id: str,
) -> dict[str, object]:
    _validate_identifier(target_release_id, "AGGREGATE_RELEASE_ID_RED")
    _validate_identifier(run_id, "AGGREGATE_RUN_ID_RED")
    require(backup_dir.is_absolute() and backup_dir.is_dir() and not backup_dir.is_symlink(), "AGGREGATE_BACKUP_PATH_RED")
    metadata = _regular_metadata(aggregate_path, safe_code="AGGREGATE_PATH_RED")
    require(stat.S_IMODE(metadata.st_mode) == 0o600, "AGGREGATE_MODE_RED")
    material = _read_exact(aggregate_path)
    payload = parse_aggregate(material)
    source, technical, product = classify_aggregate(payload)
    require(not technical and not product and source == payload, "CUTOVER_PREFLIGHT_AGGREGATE_NOT_SOURCE_RED")
    bytes_path, metadata_path = _backup_paths(backup_dir)
    require(
        not bytes_path.exists()
        and not bytes_path.is_symlink()
        and not metadata_path.exists()
        and not metadata_path.is_symlink(),
        "AGGREGATE_BACKUP_ALREADY_EXISTS",
    )
    sidecar = {
        "contract_version": CONTRACT_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "source_release_id": SOURCE_RELEASE_ID,
        "target_release_id": target_release_id,
        "run_id": run_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "restore_path": str(aggregate_path),
        "sha256": sha256_bytes(material),
        "size": len(material),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "event_classes": EVENT_CLASSES,
        "event_summary": _event_summary(payload),
        "contains_personal_data": False,
    }
    _write_new(bytes_path, material)
    _write_new(metadata_path, canonical_json(sidecar) + b"\n")
    _fsync_directory(backup_dir)
    return verify_backup(
        aggregate_path,
        backup_dir,
        target_release_id=target_release_id,
        run_id=run_id,
    )


def verify_backup(
    aggregate_path: Path,
    backup_dir: Path,
    *,
    target_release_id: str,
    run_id: str,
) -> dict[str, object]:
    _validate_identifier(target_release_id, "AGGREGATE_RELEASE_ID_RED")
    _validate_identifier(run_id, "AGGREGATE_RUN_ID_RED")
    require(backup_dir.is_absolute() and backup_dir.is_dir() and not backup_dir.is_symlink(), "AGGREGATE_BACKUP_PATH_RED")
    bytes_path, metadata_path = _backup_paths(backup_dir)
    for path in (bytes_path, metadata_path):
        metadata = _regular_metadata(path, safe_code="AGGREGATE_BACKUP_PRESENT_RED")
        require(stat.S_IMODE(metadata.st_mode) == 0o600, "AGGREGATE_BACKUP_MODE_RED")
    material = _read_exact(bytes_path, safe_code="AGGREGATE_BACKUP_READ_RED")
    try:
        sidecar = json.loads(_read_exact(metadata_path, safe_code="AGGREGATE_BACKUP_READ_RED").decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise AggregateContractError("AGGREGATE_BACKUP_METADATA_RED") from None
    require(isinstance(sidecar, dict), "AGGREGATE_BACKUP_METADATA_RED")
    require(sidecar.get("contract_version") == CONTRACT_VERSION, "AGGREGATE_BACKUP_CONTRACT_RED")
    require(sidecar.get("event_schema_version") == EVENT_SCHEMA_VERSION, "AGGREGATE_BACKUP_SCHEMA_RED")
    require(sidecar.get("target_release_id") == target_release_id, "AGGREGATE_BACKUP_RELEASE_RED")
    require(sidecar.get("run_id") == run_id, "AGGREGATE_BACKUP_RUN_RED")
    require(sidecar.get("restore_path") == str(aggregate_path), "AGGREGATE_BACKUP_RESTORE_PATH_RED")
    require(sidecar.get("sha256") == sha256_bytes(material), "AGGREGATE_BACKUP_HASH_RED")
    require(sidecar.get("size") == len(material), "AGGREGATE_BACKUP_SIZE_RED")
    require(sidecar.get("mode") == "0600", "AGGREGATE_BACKUP_ORIGINAL_MODE_RED")
    payload = parse_aggregate(material)
    source, technical, product = classify_aggregate(payload)
    require(not technical and not product and source == payload, "AGGREGATE_BACKUP_SOURCE_EVENT_RED")
    require(sidecar.get("event_summary") == _event_summary(payload), "AGGREGATE_BACKUP_SUMMARY_RED")
    return {
        "ok": True,
        "safe_code": "S10_2D_AGGREGATE_BACKUP_GREEN",
        "aggregate_backup_present": True,
        "aggregate_backup_hash_valid": True,
        "aggregate_backup_mode_valid": True,
        "aggregate_backup_restore_path_valid": True,
        "source_entries": len(source),
        "source_total": sum(source.values()),
    }


def _create_or_load_intake(
    aggregate_path: Path,
    backup_dir: Path,
    *,
    target_release_id: str,
    run_id: str,
) -> tuple[Path, bytes, os.stat_result]:
    reconciliation_dir = backup_dir / RECONCILIATION_DIRECTORY
    live_metadata = _regular_metadata(aggregate_path, safe_code="AGGREGATE_PATH_RED")
    live_material = _read_exact(aggregate_path)
    if not reconciliation_dir.exists() and not reconciliation_dir.is_symlink():
        try:
            os.mkdir(reconciliation_dir, 0o700)
            os.chmod(reconciliation_dir, 0o700)
        except OSError:
            raise AggregateContractError("AGGREGATE_RECONCILIATION_DIRECTORY_RED") from None
        intake = {
            "contract_version": CONTRACT_VERSION,
            "target_release_id": target_release_id,
            "run_id": run_id,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "restore_path": str(aggregate_path),
            "original_sha256": sha256_bytes(live_material),
            "original_size": len(live_material),
            "original_uid": live_metadata.st_uid,
            "original_gid": live_metadata.st_gid,
            "original_mode": format(stat.S_IMODE(live_metadata.st_mode), "04o"),
        }
        _write_new(reconciliation_dir / CURRENT_BYTES, live_material)
        _write_new(reconciliation_dir / INTAKE_METADATA, canonical_json(intake) + b"\n")
        _fsync_directory(reconciliation_dir)
        _fsync_directory(backup_dir)
    require(reconciliation_dir.is_dir() and not reconciliation_dir.is_symlink(), "AGGREGATE_RECONCILIATION_DIRECTORY_RED")
    directory_metadata = reconciliation_dir.lstat()
    require(stat.S_IMODE(directory_metadata.st_mode) == 0o700, "AGGREGATE_RECONCILIATION_DIRECTORY_MODE_RED")
    original = _read_exact(reconciliation_dir / CURRENT_BYTES, safe_code="AGGREGATE_CURRENT_ARCHIVE_RED")
    try:
        intake = json.loads(_read_exact(reconciliation_dir / INTAKE_METADATA, safe_code="AGGREGATE_INTAKE_RED").decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise AggregateContractError("AGGREGATE_INTAKE_RED") from None
    require(isinstance(intake, dict), "AGGREGATE_INTAKE_RED")
    require(intake.get("contract_version") == CONTRACT_VERSION, "AGGREGATE_INTAKE_RED")
    require(intake.get("target_release_id") == target_release_id and intake.get("run_id") == run_id, "AGGREGATE_INTAKE_OWNERSHIP_RED")
    require(intake.get("restore_path") == str(aggregate_path), "AGGREGATE_INTAKE_RESTORE_PATH_RED")
    require(intake.get("original_sha256") == sha256_bytes(original), "AGGREGATE_CURRENT_ARCHIVE_HASH_RED")
    try:
        archived_metadata = os.stat_result(
            (
                int(str(intake.get("original_mode")), 8),
                0,
                0,
                1,
                int(intake.get("original_uid")),
                int(intake.get("original_gid")),
                int(intake.get("original_size")),
                0,
                0,
                0,
            )
        )
    except (TypeError, ValueError):
        raise AggregateContractError("AGGREGATE_INTAKE_RED") from None
    return reconciliation_dir, original, archived_metadata


def _record_reconciliation_failure(
    reconciliation_dir: Path,
    *,
    safe_code: str,
    original: bytes,
) -> None:
    failure = {
        "contract_version": CONTRACT_VERSION,
        "ok": False,
        "safe_code": safe_code,
        "original_sha256": sha256_bytes(original),
        "original_preserved": True,
    }
    _write_or_verify(reconciliation_dir / RECONCILIATION_FAILURE, canonical_json(failure) + b"\n")
    _fsync_directory(reconciliation_dir)


def _source_deltas(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    deltas: Counter[str] = Counter()
    for key, value in before.items():
        require(after.get(key, -1) >= value, "AGGREGATE_SOURCE_COUNT_REGRESSION_RED")
    for key, value in after.items():
        event = key.split("|")[1]
        deltas[event] += value - before.get(key, 0)
    require(all(value >= 0 for value in deltas.values()), "AGGREGATE_SOURCE_COUNT_REGRESSION_RED")
    return dict(sorted(deltas.items()))


def _write_reconciliation(
    reconciliation_dir: Path,
    *,
    original: bytes,
    source: Mapping[str, int],
    technical: Mapping[str, int],
    product: Mapping[str, int],
    before: Mapping[str, int],
    target_release_id: str,
    run_id: str,
) -> tuple[bytes, dict[str, object]]:
    source_material = canonical_json(dict(source))
    target_only = {**technical, **product}
    target_material = canonical_json(target_only)
    evidence = {
        "contract_version": CONTRACT_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "source_release_id": SOURCE_RELEASE_ID,
        "target_release_id": target_release_id,
        "run_id": run_id,
        "original_sha256": sha256_bytes(original),
        "source_projection_sha256": sha256_bytes(source_material),
        "target_only_sha256": sha256_bytes(target_material),
        "original_summary": _event_summary(parse_aggregate(original)),
        "source_summary": _event_summary(source),
        "target_only_summary": _event_summary(target_only),
        "source_deltas_since_backup": _source_deltas(before, source),
        "event_classes": EVENT_CLASSES,
        "conservation_green": len(source) + len(target_only) == len(parse_aggregate(original))
        and sum(source.values()) + sum(target_only.values()) == sum(parse_aggregate(original).values()),
        "contains_personal_data": False,
    }
    files = {
        SOURCE_PROJECTION: source_material,
        TARGET_ONLY_ARCHIVE: target_material,
        RECONCILIATION_EVIDENCE: canonical_json(evidence) + b"\n",
    }
    for name, material in files.items():
        _write_or_verify(reconciliation_dir / name, material)
    checksum_files = {
        CURRENT_BYTES: original,
        INTAKE_METADATA: _read_exact(reconciliation_dir / INTAKE_METADATA),
        **files,
    }
    checksums = "".join(
        f"{sha256_bytes(material)}  {name}\n" for name, material in sorted(checksum_files.items())
    ).encode("ascii")
    _write_or_verify(reconciliation_dir / RECONCILIATION_CHECKSUMS, checksums)
    _fsync_directory(reconciliation_dir)
    return source_material, evidence


def reconcile_for_source(
    aggregate_path: Path,
    backup_dir: Path,
    *,
    target_release_id: str,
    run_id: str,
    after_replace: Callable[[], None] | None = None,
) -> dict[str, object]:
    backup_report = verify_backup(
        aggregate_path,
        backup_dir,
        target_release_id=target_release_id,
        run_id=run_id,
    )
    reconciliation_dir, original, archived_metadata = _create_or_load_intake(
        aggregate_path,
        backup_dir,
        target_release_id=target_release_id,
        run_id=run_id,
    )
    try:
        backup_metadata = json.loads(
            _read_exact(
                backup_dir / BACKUP_METADATA,
                safe_code="AGGREGATE_BACKUP_READ_RED",
            ).decode("ascii")
        )
    except (UnicodeError, json.JSONDecodeError):
        raise AggregateContractError("AGGREGATE_BACKUP_METADATA_RED") from None
    require(isinstance(backup_metadata, dict), "AGGREGATE_BACKUP_METADATA_RED")
    require(
        archived_metadata.st_uid == backup_metadata.get("uid")
        and archived_metadata.st_gid == backup_metadata.get("gid")
        and format(stat.S_IMODE(archived_metadata.st_mode), "04o") == backup_metadata.get("mode"),
        "AGGREGATE_METADATA_DRIFT_RED",
    )
    try:
        current_payload = parse_aggregate(original)
        source, technical, product = classify_aggregate(current_payload)
    except AggregateContractError as error:
        _record_reconciliation_failure(
            reconciliation_dir,
            safe_code=str(error),
            original=original,
        )
        raise
    before_material = _read_exact(backup_dir / BACKUP_BYTES, safe_code="AGGREGATE_BACKUP_READ_RED")
    before_payload = parse_aggregate(before_material)
    source_material, evidence = _write_reconciliation(
        reconciliation_dir,
        original=original,
        source=source,
        technical=technical,
        product=product,
        before=before_payload,
        target_release_id=target_release_id,
        run_id=run_id,
    )
    live_material = _read_exact(aggregate_path)
    live_hash = sha256_bytes(live_material)
    original_hash = sha256_bytes(original)
    source_hash = sha256_bytes(source_material)
    if live_hash not in {original_hash, source_hash}:
        live_payload = parse_aggregate(live_material)
        live_source, live_technical, live_product = classify_aggregate(live_payload)
        require(
            not live_technical and not live_product and live_source == live_payload,
            "AGGREGATE_RECONCILIATION_STATE_DIVERGED",
        )
        _source_deltas(source, live_source)
    replacement_attempted = False
    try:
        if live_hash == original_hash and original_hash != source_hash:
            replacement_attempted = True
            _atomic_replace(
                aggregate_path,
                source_material,
                uid=archived_metadata.st_uid,
                gid=archived_metadata.st_gid,
                mode=stat.S_IMODE(archived_metadata.st_mode),
            )
        if after_replace is not None:
            after_replace()
        installed = _read_exact(aggregate_path)
        installed_payload = parse_aggregate(installed)
        installed_source, installed_technical, installed_product = classify_aggregate(installed_payload)
        require(
            not installed_technical and not installed_product and installed_source == installed_payload,
            "AGGREGATE_SOURCE_PROJECTION_EVENT_RED",
        )
        _source_deltas(source, installed_source)
        if replacement_attempted:
            require(sha256_bytes(installed) == source_hash, "AGGREGATE_SOURCE_PROJECTION_HASH_RED")
    except Exception as error:
        if replacement_attempted:
            try:
                _atomic_replace(
                    aggregate_path,
                    original,
                    uid=archived_metadata.st_uid,
                    gid=archived_metadata.st_gid,
                    mode=stat.S_IMODE(archived_metadata.st_mode),
                )
                require(
                    sha256_bytes(_read_exact(aggregate_path)) == original_hash,
                    "AGGREGATE_ORIGINAL_RESTORE_HASH_RED",
                )
            except Exception:
                raise AggregateContractError("AGGREGATE_ORIGINAL_RESTORE_RED") from None
        if isinstance(error, AggregateContractError):
            raise
        raise AggregateContractError("AGGREGATE_RECONCILIATION_UNEXPECTED_RED") from None
    return {
        "ok": True,
        "safe_code": "S10_2D_AGGREGATE_SOURCE_PROJECTION_GREEN",
        "backup": backup_report["safe_code"],
        "source_entries": len(source),
        "source_total": sum(source.values()),
        "target_only_entries": len(technical) + len(product),
        "target_only_total": sum(technical.values()) + sum(product.values()),
        "target_only_archived": True,
        "original_preserved": True,
        "conservation_green": evidence["conservation_green"],
        "idempotent": not replacement_attempted,
    }


def verify_source_compatible(aggregate_path: Path) -> dict[str, object]:
    payload = parse_aggregate(_read_exact(aggregate_path))
    source, technical, product = classify_aggregate(payload)
    require(not technical and not product and source == payload, "S9_AGGREGATE_STATE_INVALID")
    return {
        "ok": True,
        "safe_code": "S10_2D_SOURCE_AGGREGATE_READABLE_GREEN",
        "source_entries": len(source),
        "source_total": sum(source.values()),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create-backup", "verify-backup", "reconcile", "verify-source"))
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--release-id", default=TARGET_RELEASE_ID)
    parser.add_argument("--run-id")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.action == "verify-source":
            report = verify_source_compatible(AGGREGATE_PATH)
        else:
            require(arguments.backup_dir is not None and arguments.run_id is not None, "AGGREGATE_ARGUMENT_RED")
            operation = {
                "create-backup": create_backup,
                "verify-backup": verify_backup,
                "reconcile": reconcile_for_source,
            }[arguments.action]
            report = operation(
                AGGREGATE_PATH,
                arguments.backup_dir,
                target_release_id=arguments.release_id,
                run_id=arguments.run_id,
            )
    except AggregateContractError as error:
        print(canonical_json({"ok": False, "safe_code": str(error)}).decode("ascii"))
        return 2
    except Exception:
        print('{"ok":false,"safe_code":"AGGREGATE_CONTRACT_UNEXPECTED_RED"}')
        return 2
    print(canonical_json(report).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
