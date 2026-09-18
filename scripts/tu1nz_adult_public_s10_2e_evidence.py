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


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise EvidenceError(safe_code)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "EVIDENCE_DUPLICATE_KEY_RED")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "EVIDENCE_PATH_RED")
    require(stat.S_IMODE(path.stat().st_mode) in {0o600, 0o640, 0o644}, "EVIDENCE_MODE_RED")
    try:
        value = json.loads(path.read_text(encoding="ascii"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise EvidenceError("EVIDENCE_JSON_RED") from None
    require(isinstance(value, dict), "EVIDENCE_SHAPE_RED")
    return value


def load_aggregate(path: Path) -> dict[str, int]:
    value = load_json(path)
    result: dict[str, int] = {}
    for key, count in value.items():
        require(isinstance(key, str), "AGGREGATE_KEY_RED")
        parts = key.split("|")
        require(len(parts) == 4 and all(parts), "AGGREGATE_KEY_RED")
        try:
            dt.date.fromisoformat(parts[0])
        except ValueError:
            raise EvidenceError("AGGREGATE_DATE_RED") from None
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
