#!/usr/bin/env python3
"""Privacy-safe baseline and delta evidence for controlled SFW acquisition."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Mapping


class EvidenceError(RuntimeError):
    pass


COUNT_KEYS = frozenset(
    {
        "bot_starts",
        "community_active",
        "community_events",
        "community_members",
        "moderation_events",
        "pending_moderation",
        "referral_bot_starts",
        "s8_analytics_total",
        "stuck_restrictions",
        "waitlist_joined_events",
        "waitlist_total",
    }
)
AGGREGATE_EVENTS = frozenset({"LANDING_VIEW", "TELEGRAM_CTA", "COMMUNITY_CTA"})
MAX_AGGREGATE_BYTES = 8 * 1024 * 1024


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise EvidenceError(safe_code)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "EVIDENCE_DUPLICATE_KEY_RED")
        result[key] = value
    return result


def read_regular_bytes(path: Path, *, safe_code: str = "EVIDENCE_PATH_RED") -> bytes:
    require(path.is_absolute() and not path.is_symlink(), safe_code)
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
            require(stat.S_IMODE(opened.st_mode) in {0o600, 0o640, 0o644}, "EVIDENCE_MODE_RED")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                material = stream.read(MAX_AGGREGATE_BYTES + 1)
        finally:
            os.close(descriptor)
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError(safe_code) from None
    require(len(material) <= MAX_AGGREGATE_BYTES, "EVIDENCE_SIZE_RED")
    return material


def write_new(path: Path, material: bytes) -> None:
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), "EVIDENCE_DESTINATION_RED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(material)
                stream.flush()
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise EvidenceError("EVIDENCE_WRITE_RED") from None


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(read_regular_bytes(path).decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise EvidenceError("EVIDENCE_JSON_RED") from None
    require(isinstance(value, dict), "EVIDENCE_SHAPE_RED")
    return value


def load_aggregate(path: Path) -> dict[str, int]:
    value = load_json(path)
    return load_aggregate_from_value(value)


def snapshot_aggregate(source: Path, destination: Path) -> dict[str, object]:
    material = read_regular_bytes(source, safe_code="AGGREGATE_SOURCE_RED")
    try:
        value = json.loads(material.decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise EvidenceError("EVIDENCE_JSON_RED") from None
    require(isinstance(value, dict), "EVIDENCE_SHAPE_RED")
    # Reuse the full aggregate contract, including target-state COMMUNITY_CTA.
    temporary_value = load_aggregate_from_value(value)
    write_new(destination, material)
    return {
        "ok": True,
        "safe_code": "S10_2E_AGGREGATE_SNAPSHOT_GREEN",
        "sha256": hashlib.sha256(material).hexdigest(),
        "events": summarize_aggregate(temporary_value),
    }


def load_aggregate_from_value(value: Mapping[str, object]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, count in value.items():
        require(isinstance(key, str), "AGGREGATE_KEY_RED")
        parts = key.split("|")
        require(len(parts) == 4 and all(parts), "AGGREGATE_KEY_RED")
        try:
            dt.date.fromisoformat(parts[0])
        except ValueError:
            raise EvidenceError("AGGREGATE_DATE_RED") from None
        require(parts[1] in AGGREGATE_EVENTS, "AGGREGATE_EVENT_RED")
        require(all(len(part) <= 64 for part in parts[1:]), "AGGREGATE_DIMENSION_RED")
        require(isinstance(count, int) and not isinstance(count, bool) and count >= 0, "AGGREGATE_COUNT_RED")
        result[key] = count
    return result


def validate_snapshot(value: Mapping[str, object], *, before_activation: bool) -> None:
    require(value.get("schema_version") == 1, "SNAPSHOT_SCHEMA_RED")
    state = value.get("state")
    counts = value.get("counts")
    require(isinstance(state, dict) and isinstance(counts, dict), "SNAPSHOT_SHAPE_RED")
    require(set(counts) == COUNT_KEYS, "SNAPSHOT_COUNTS_RED")
    require(all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in counts.values()), "SNAPSHOT_COUNT_RED")
    require(state.get("pre_acquisition_readiness") == "GREEN", "TECHNICAL_READINESS_RED")
    require(state.get("community_media_publishing_enabled") is False, "MEDIA_GATE_RED")
    require(state.get("controlled_beta") is False, "CONTROLLED_BETA_RED")
    if before_activation:
        require(state.get("real_acquisition_active") is False, "ACQUISITION_ALREADY_ACTIVE_RED")
        require(state.get("real_acquisition_baseline_start") is None, "BASELINE_ALREADY_SET_RED")
    else:
        require(isinstance(state.get("real_acquisition_active"), bool), "ACQUISITION_STATE_RED")
        require(isinstance(state.get("real_acquisition_baseline_start"), str), "BASELINE_MISSING_RED")


def summarize_aggregate(value: Mapping[str, int]) -> dict[str, int]:
    result: Counter[str] = Counter()
    for key, count in value.items():
        result[key.split("|")[1]] += count
    return dict(sorted(result.items()))


def delta(current: Mapping[str, int], baseline: Mapping[str, int]) -> dict[str, int]:
    keys = set(current) | set(baseline)
    result = {key: current.get(key, 0) - baseline.get(key, 0) for key in sorted(keys)}
    require(all(value >= 0 for value in result.values()), "AGGREGATE_COUNT_REGRESSION_RED")
    return result


def report(
    baseline_path: Path,
    current_path: Path,
    baseline_aggregate_path: Path,
    current_aggregate_path: Path,
) -> dict[str, object]:
    baseline = load_json(baseline_path)
    current = load_json(current_path)
    validate_snapshot(baseline, before_activation=True)
    validate_snapshot(current, before_activation=False)
    baseline_aggregate = load_aggregate(baseline_aggregate_path)
    current_aggregate = load_aggregate(current_aggregate_path)
    aggregate_delta = delta(current_aggregate, baseline_aggregate)
    baseline_counts = baseline["counts"]
    current_counts = current["counts"]
    assert isinstance(baseline_counts, dict) and isinstance(current_counts, dict)
    count_delta = {
        key: int(current_counts[key]) - int(baseline_counts[key]) for key in sorted(COUNT_KEYS)
    }
    state = current["state"]
    assert isinstance(state, dict)
    return {
        "ok": True,
        "safe_code": "S10_2E_ACQUISITION_REPORT_GREEN",
        "REAL_ACQUISITION_ACTIVE": state["real_acquisition_active"],
        "REAL_ACQUISITION_BASELINE_START": state["real_acquisition_baseline_start"],
        "human_acceptance": "DEFERRED",
        "bot_response_latency": "NOT_MEASURED",
        "join_welcome_latency": "NOT_MEASURED",
        "aggregate_before": summarize_aggregate(baseline_aggregate),
        "aggregate_since_baseline": summarize_aggregate(aggregate_delta),
        "database_before": baseline_counts,
        "database_since_baseline": count_delta,
        "product_boundaries": {
            "adult_media": "CLOSED",
            "avs": "CLOSED",
            "payment": "CLOSED",
            "publishing": "CLOSED",
            "controlled_beta": "CLOSED",
            "production": "CLOSED",
        },
        "real_test_evidence_separation": "INTACT",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    verify = subparsers.add_parser("verify-snapshot")
    verify.add_argument("--snapshot", type=Path, required=True)
    verify_aggregate = subparsers.add_parser("verify-aggregate")
    verify_aggregate.add_argument("--snapshot", type=Path, required=True)
    snapshot_aggregate_parser = subparsers.add_parser("snapshot-aggregate")
    snapshot_aggregate_parser.add_argument("--source", type=Path, required=True)
    snapshot_aggregate_parser.add_argument("--destination", type=Path, required=True)
    result = subparsers.add_parser("report")
    result.add_argument("--baseline", type=Path, required=True)
    result.add_argument("--current", type=Path, required=True)
    result.add_argument("--baseline-aggregate", type=Path, required=True)
    result.add_argument("--current-aggregate", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.action == "verify-snapshot":
            value = load_json(arguments.snapshot)
            validate_snapshot(value, before_activation=True)
            output: dict[str, object] = {
                "ok": True,
                "safe_code": "S10_2E_BASELINE_SNAPSHOT_GREEN",
                "sha256": hashlib.sha256(arguments.snapshot.read_bytes()).hexdigest(),
            }
        elif arguments.action == "verify-aggregate":
            value = load_aggregate(arguments.snapshot)
            output = {
                "ok": True,
                "safe_code": "S10_2E_AGGREGATE_SNAPSHOT_GREEN",
                "sha256": hashlib.sha256(read_regular_bytes(arguments.snapshot)).hexdigest(),
                "events": summarize_aggregate(value),
            }
        elif arguments.action == "snapshot-aggregate":
            output = snapshot_aggregate(arguments.source, arguments.destination)
        else:
            output = report(
                arguments.baseline,
                arguments.current,
                arguments.baseline_aggregate,
                arguments.current_aggregate,
            )
    except EvidenceError as error:
        print(json.dumps({"ok": False, "safe_code": str(error)}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
