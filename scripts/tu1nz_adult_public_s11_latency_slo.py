#!/usr/bin/env python3
"""Read-only S11.1 provenance-aware tri-state latency SLO gate."""

from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import psycopg


CANONICAL_CLASSES = frozenset(
    {"REAL", "INTERNAL_TEST", "SYNTHETIC", "HEALTH", "PROVIDER_PROBE", "UNKNOWN"}
)
PROFILES = {
    "TECHNICAL_RUNTIME_LATENCY": ("INTERNAL_TEST", "DIRECT", "DIRECT_BOT_RESPONSE", "handler_duration_ms"),
    "REAL_USER_DIRECT_LATENCY": ("REAL", "DIRECT", "DIRECT_BOT_RESPONSE", "bot_response_latency_ms"),
    "COMMUNITY_JOIN_LATENCY": ("REAL", "COMMUNITY", "COMMUNITY_JOIN_WELCOME", "bot_response_latency_ms"),
    "MODERATION_LATENCY": ("REAL", "COMMUNITY", "MODERATION", "handler_duration_ms"),
}
MINIMUM_SAMPLES = 5
LIMITS = {"p50_ms": 1000, "p95_ms": 2000, "p99_ms": 5000}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn-file", type=Path)
    parser.add_argument("--reconciliation", type=Path)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="REAL_USER_DIRECT_LATENCY")
    parser.add_argument("--now", type=_timestamp)
    parser.add_argument("--simulate-contract", action="store_true")
    return parser


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _read_private(path: Path, maximum: int) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("S11_1_LATENCY_INPUT_UNSAFE")
    if not 1 <= path.stat().st_size <= maximum:
        raise ValueError("S11_1_LATENCY_INPUT_UNSAFE")
    return path.read_text(encoding="utf-8").strip()


def _reconciliation(path: Path) -> dict[tuple[str, str, int, str], dict[str, str]]:
    payload = json.loads(_read_private(path, 65536))
    if (
        not isinstance(payload, dict)
        or payload.get("version") != "tu1nz-commercial-s11-1-latency-provenance-reconciliation-v1"
        or payload.get("original_rows_mutated") is not False
        or not isinstance(payload.get("release_id"), str)
        or not isinstance(payload.get("assertions"), list)
    ):
        raise ValueError("S11_1_RECONCILIATION_INVALID")
    release = payload["release_id"]
    result = {}
    for item in payload["assertions"]:
        if not isinstance(item, dict) or set(item) != {
            "source", "recorded_at", "bot_response_latency_ms", "evidence_class",
            "sample_type", "interaction_path", "proof",
        }:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if item["evidence_class"] not in CANONICAL_CLASSES:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if item["source"] not in {"DIRECT", "COMMUNITY"}:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if item["sample_type"] not in {
            "DIRECT_BOT_RESPONSE", "COMMUNITY_JOIN_WELCOME",
            "COMMUNITY_INTERACTION", "MODERATION", "UNKNOWN",
        }:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if item["interaction_path"] not in {
            "TELEGRAM_DIRECT", "TELEGRAM_COMMUNITY", "INTERNAL_ACCEPTANCE",
            "SYNTHETIC_FIXTURE", "RUNTIME_HEALTH", "PROVIDER_PROBE", "UNKNOWN",
        }:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if type(item["bot_response_latency_ms"]) is not int or not 0 <= item["bot_response_latency_ms"] <= 300000:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        if not isinstance(item["proof"], str) or not item["proof"]:
            raise ValueError("S11_1_RECONCILIATION_INVALID")
        _timestamp(item["recorded_at"])
        key = (item["source"], item["recorded_at"], item["bot_response_latency_ms"], release)
        if key in result:
            raise ValueError("S11_1_RECONCILIATION_DUPLICATE")
        result[key] = item
    return result


def _has_provenance_columns(connection: psycopg.Connection) -> bool:
    return connection.execute(
        "SELECT count(*)=3 FROM information_schema.columns WHERE table_schema='public' "
        "AND table_name='commercial_s10_2d_latency_samples' "
        "AND column_name IN ('sample_type','recorded_at','interaction_path')"
    ).fetchone()[0]


def _load_samples(
    connection: psycopg.Connection,
    now: datetime,
    reconciliation: dict[tuple[str, str, int, str], dict[str, str]],
) -> list[dict[str, object]]:
    if _has_provenance_columns(connection):
        rows = connection.execute(
            "SELECT source,bot_response_latency_ms,poll_lag_ms,handler_duration_ms,send_ack_ms,"
            "occurred_at,release_id,run_id::text,evidence_class,sample_type,recorded_at,interaction_path "
            "FROM commercial_s10_2d_latency_samples WHERE recorded_at >= %s-INTERVAL '24 hours' "
            "AND recorded_at <= %s ORDER BY recorded_at,sample_id",
            (now, now),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT source,bot_response_latency_ms,poll_lag_ms,handler_duration_ms,send_ack_ms,"
            "occurred_at,release_id,run_id::text,evidence_class,NULL,occurred_at,NULL "
            "FROM commercial_s10_2d_latency_samples WHERE occurred_at >= %s-INTERVAL '24 hours' "
            "AND occurred_at <= %s ORDER BY occurred_at,sample_id",
            (now, now),
        ).fetchall()
    samples = []
    for row in rows:
        recorded_at = row[10].astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        item = {
            "source": row[0],
            "bot_response_latency_ms": row[1],
            "poll_lag_ms": row[2],
            "handler_duration_ms": row[3],
            "send_ack_ms": row[4],
            "recorded_at": recorded_at,
            "release_id": row[6],
            "run_id": row[7],
            "evidence_class": row[8] if row[8] in CANONICAL_CLASSES else "UNKNOWN",
            "sample_type": row[9] or "UNKNOWN",
            "interaction_path": row[11] or "UNKNOWN",
        }
        if row[8] == "TECHNICAL_ACCEPTANCE":
            reconciled = reconciliation.get((row[0], recorded_at, row[1], row[6]))
            if reconciled is not None:
                item.update(
                    evidence_class=reconciled["evidence_class"],
                    sample_type=reconciled["sample_type"],
                    interaction_path=reconciled["interaction_path"],
                )
        samples.append(item)
    return samples


def evaluate(samples: list[dict[str, object]], profile: str) -> dict[str, object]:
    evidence_class, source, sample_type, metric = PROFILES[profile]
    source_rows = [sample for sample in samples if sample["source"] == source]
    unknown = [
        sample for sample in source_rows
        if sample["evidence_class"] == "UNKNOWN"
        or sample["sample_type"] == "UNKNOWN"
        or sample["interaction_path"] == "UNKNOWN"
    ]
    if unknown:
        return _result(profile, "RED", "UNKNOWN_PROVENANCE_FAIL_CLOSED", 0, [])
    relevant = [
        int(sample[metric])
        for sample in source_rows
        if sample["evidence_class"] == evidence_class and sample["sample_type"] == sample_type
    ]
    relevant.sort()
    if len(relevant) < MINIMUM_SAMPLES:
        return _result(profile, "INSUFFICIENT_EVIDENCE", "SAMPLE_FLOOR_NOT_MET", len(relevant), relevant)
    percentiles = {
        "p50_ms": _percentile(relevant, 0.50),
        "p95_ms": _percentile(relevant, 0.95),
        "p99_ms": _percentile(relevant, 0.99),
    }
    state = "GREEN" if all(percentiles[name] < limit for name, limit in LIMITS.items()) else "RED"
    return {
        **_result(profile, state, "THRESHOLDS_MET" if state == "GREEN" else "THRESHOLD_EXCEEDED", len(relevant), relevant),
        **percentiles,
    }


def _result(profile: str, state: str, reason: str, count: int, values: list[int]) -> dict[str, object]:
    return {
        "ok": state == "GREEN",
        "safe_code": f"S11_COMMUNITY_LATENCY_SLO_{state}",
        "profile": profile,
        "state": state,
        "reason": reason,
        "samples": count,
        "minimum_samples": MINIMUM_SAMPLES,
        "metric": PROFILES[profile][3],
        "p50_ms": None,
        "p95_ms": None,
        "p99_ms": None,
        "maximum_ms": max(values) if values else None,
        "limits_ms": LIMITS,
    }


def _percentile(values: list[int], quantile: float) -> int:
    position = (len(values) - 1) * quantile
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return values[lower]
    return round(values[lower] + (values[upper] - values[lower]) * (position - lower))


def simulate_contract() -> dict[str, object]:
    def direct(value: int, evidence: str = "REAL", *, poll: int = 10, handler: int = 20,
               path: str = "TELEGRAM_DIRECT") -> dict[str, object]:
        return {
            "source": "DIRECT",
            "bot_response_latency_ms": value,
            "poll_lag_ms": poll,
            "handler_duration_ms": handler,
            "send_ack_ms": 15,
            "evidence_class": evidence,
            "sample_type": "DIRECT_BOT_RESPONSE",
            "interaction_path": path,
        }

    real_green = [direct(value) for value in (220, 260, 300, 340, 380)]
    internal = [direct(19079, "INTERNAL_TEST", poll=18720, handler=172,
                       path="INTERNAL_ACCEPTANCE") for _ in range(5)]
    health = [direct(100, "HEALTH", path="RUNTIME_HEALTH") for _ in range(5)]
    synthetic = [direct(50, "SYNTHETIC", path="SYNTHETIC_FIXTURE") for _ in range(10)]
    cases = {
        "A": evaluate(real_green + [direct(19079)], "REAL_USER_DIRECT_LATENCY")["state"],
        "B": evaluate(real_green[:4], "REAL_USER_DIRECT_LATENCY")["state"],
        "C": evaluate(real_green, "REAL_USER_DIRECT_LATENCY")["state"],
        "D": evaluate(internal, "REAL_USER_DIRECT_LATENCY")["state"],
        "E": evaluate(health, "REAL_USER_DIRECT_LATENCY")["state"],
        "F": evaluate(real_green[:3] + synthetic, "REAL_USER_DIRECT_LATENCY")["state"],
        "G_REAL": evaluate([direct(19079, poll=18720, handler=172) for _ in range(5)],
                           "REAL_USER_DIRECT_LATENCY")["state"],
        "G_TECHNICAL": evaluate(internal, "TECHNICAL_RUNTIME_LATENCY")["state"],
        "H": evaluate([direct(200, "UNKNOWN", path="UNKNOWN")],
                      "REAL_USER_DIRECT_LATENCY")["state"],
    }
    expected = {
        "A": "RED", "B": "INSUFFICIENT_EVIDENCE", "C": "GREEN",
        "D": "INSUFFICIENT_EVIDENCE", "E": "INSUFFICIENT_EVIDENCE",
        "F": "INSUFFICIENT_EVIDENCE", "G_REAL": "RED",
        "G_TECHNICAL": "GREEN", "H": "RED",
    }
    return {
        "ok": cases == expected,
        "safe_code": (
            "S11_1_LATENCY_CONTRACT_SIMULATOR_GREEN"
            if cases == expected else "S11_1_LATENCY_CONTRACT_SIMULATOR_RED"
        ),
        "cases": cases,
    }


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.simulate_contract:
        if arguments.dsn_file is not None or arguments.reconciliation is not None:
            raise ValueError("S11_1_LATENCY_ARGUMENT_RED")
        result = simulate_contract()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["ok"] is True else 2
    if arguments.dsn_file is None or arguments.reconciliation is None:
        raise ValueError("S11_1_LATENCY_ARGUMENT_RED")
    now = arguments.now or datetime.now(timezone.utc)
    reconciliation = _reconciliation(arguments.reconciliation)
    dsn = _read_private(arguments.dsn_file, 8192)
    with psycopg.connect(dsn) as connection:
        samples = _load_samples(connection, now, reconciliation)
    print(json.dumps(evaluate(samples, arguments.profile), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, psycopg.Error, json.JSONDecodeError):
        print('{"ok":false,"safe_code":"S11_COMMUNITY_LATENCY_SLO_READER_RED","state":"RED"}')
        raise SystemExit(2)
