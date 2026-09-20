#!/usr/bin/env python3
"""Privacy-safe S11.2 Canary evaluation and promotion decision gate."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import psycopg
except ModuleNotFoundError:
    class _PsycopgUnavailable:
        class Error(Exception):
            pass

        Connection = Any

        @staticmethod
        def connect(*_args: Any, **_kwargs: Any) -> Any:
            raise ValueError("S11_2_PSYCOPG_UNAVAILABLE")

    psycopg = _PsycopgUnavailable()


MINIMUM_SAMPLES = 5
LIMITS_MS = {"p50_ms": 1000, "p95_ms": 2000, "p99_ms": 5000}
RELEASE_STATES = {"S11_DISABLED", "S11_CANARY", "S11_FULL"}
PROMOTION_STATES = {
    "NOT_STARTED",
    "CANARY_COLLECTING_EVIDENCE",
    "CANARY_READY_FOR_PROMOTION",
    "CANARY_RED",
    "CANARY_INSUFFICIENT_REAL_VOLUME",
    "FULL_RELEASE",
}


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _private_text(path: Path, maximum_bytes: int) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("S11_2_INPUT_UNSAFE")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum_bytes
    ):
        raise ValueError("S11_2_INPUT_UNSAFE")
    return path.read_text(encoding="utf-8").strip()


def _percentile(values: list[int], quantile: float) -> int:
    position = (len(values) - 1) * quantile
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return values[lower]
    return round(values[lower] + (values[upper] - values[lower]) * (position - lower))


def _profile(values: list[int], name: str) -> dict[str, Any]:
    if any(type(value) is not int or not 0 <= value <= 300000 for value in values):
        raise ValueError("S11_2_LATENCY_VALUE_INVALID")
    ordered = sorted(values)
    result: dict[str, Any] = {
        "profile": name,
        "samples": len(ordered),
        "minimum_samples": MINIMUM_SAMPLES,
        "p50_ms": None,
        "p95_ms": None,
        "p99_ms": None,
        "maximum_ms": max(ordered) if ordered else None,
        "limits_ms": LIMITS_MS,
    }
    if len(ordered) < MINIMUM_SAMPLES:
        return {**result, "state": "INSUFFICIENT_EVIDENCE", "reason": "SAMPLE_FLOOR_NOT_MET"}
    percentiles = {
        "p50_ms": _percentile(ordered, 0.50),
        "p95_ms": _percentile(ordered, 0.95),
        "p99_ms": _percentile(ordered, 0.99),
    }
    state = (
        "GREEN"
        if all(percentiles[key] < limit for key, limit in LIMITS_MS.items())
        else "RED"
    )
    return {
        **result,
        **percentiles,
        "state": state,
        "reason": "THRESHOLDS_MET" if state == "GREEN" else "THRESHOLD_EXCEEDED",
    }


def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    required = {
        "release_state",
        "promotion_state",
        "now",
        "evidence_start",
        "horizon_at",
        "session_cap",
        "admitted_count",
        "technical_values_ms",
        "real_values_ms",
        "new_unknown_count",
        "historical_unknown_count",
        "experience_sessions",
        "product_event_count",
        "hard_gates_green",
    }
    if set(payload) != required:
        raise ValueError("S11_2_GATE_PAYLOAD_INVALID")
    release_state = payload["release_state"]
    promotion_state = payload["promotion_state"]
    if release_state not in RELEASE_STATES or promotion_state not in PROMOTION_STATES:
        raise ValueError("S11_2_GATE_STATE_INVALID")
    now = _timestamp(payload["now"])
    evidence_start = (
        None if payload["evidence_start"] is None else _timestamp(payload["evidence_start"])
    )
    horizon_at = None if payload["horizon_at"] is None else _timestamp(payload["horizon_at"])
    for name in (
        "session_cap",
        "admitted_count",
        "new_unknown_count",
        "historical_unknown_count",
        "experience_sessions",
        "product_event_count",
    ):
        if type(payload[name]) is not int or payload[name] < 0:
            raise ValueError("S11_2_GATE_COUNT_INVALID")
    if not 1 <= payload["session_cap"] <= 10 or payload["admitted_count"] > payload["session_cap"]:
        raise ValueError("S11_2_CANARY_CAP_INVALID")
    if type(payload["hard_gates_green"]) is not bool:
        raise ValueError("S11_2_HARD_GATE_INVALID")
    technical = _profile(payload["technical_values_ms"], "S11_CANARY_TECHNICAL_LATENCY")
    real = _profile(payload["real_values_ms"], "S11_CANARY_REAL_USER_LATENCY")
    base = {
        "release_state": release_state,
        "promotion_state": promotion_state,
        "now": _iso(now),
        "evidence_start": _iso(evidence_start),
        "horizon_at": _iso(horizon_at),
        "session_cap": payload["session_cap"],
        "admitted_count": payload["admitted_count"],
        "historical_unknown_count": payload["historical_unknown_count"],
        "new_unknown_count": payload["new_unknown_count"],
        "experience_sessions": payload["experience_sessions"],
        "product_event_count": payload["product_event_count"],
        "technical_latency": technical,
        "real_latency": real,
    }
    if release_state == "S11_FULL":
        if promotion_state != "FULL_RELEASE":
            raise ValueError("S11_2_FULL_STATE_INVALID")
        return {
            **base,
            "ok": payload["hard_gates_green"],
            "decision": "FULL_RELEASE",
            "reason": "FULL_RELEASE_HEALTHY" if payload["hard_gates_green"] else "HARD_GATE_RED",
            "transition": None,
        }
    if release_state == "S11_DISABLED":
        if promotion_state not in {
            "NOT_STARTED", "CANARY_RED", "CANARY_INSUFFICIENT_REAL_VOLUME"
        }:
            raise ValueError("S11_2_DISABLED_STATE_INVALID")
        return {
            **base,
            "ok": promotion_state == "NOT_STARTED" and payload["hard_gates_green"],
            "decision": promotion_state,
            "reason": "CANARY_NOT_STARTED" if promotion_state == "NOT_STARTED" else "CANARY_TERMINAL",
            "transition": None,
        }
    if evidence_start is None or horizon_at is None:
        raise ValueError("S11_2_CANARY_WINDOW_MISSING")
    if horizon_at != evidence_start + timedelta(hours=24) or now < evidence_start:
        raise ValueError("S11_2_CANARY_WINDOW_INVALID")
    if not payload["hard_gates_green"]:
        decision, reason, transition = "CANARY_RED", "HARD_GATE_RED", "CANARY_RED"
    elif payload["new_unknown_count"]:
        decision, reason, transition = (
            "CANARY_RED", "NEW_UNKNOWN_PROVENANCE_FAIL_CLOSED", "CANARY_RED"
        )
    elif technical["state"] != "GREEN":
        decision, reason, transition = (
            "CANARY_RED", "TECHNICAL_RUNTIME_LATENCY_NOT_GREEN", "CANARY_RED"
        )
    elif real["state"] == "RED":
        decision, reason, transition = "CANARY_RED", real["reason"], "CANARY_RED"
    elif real["state"] == "GREEN":
        decision, reason, transition = (
            "CANARY_READY_FOR_PROMOTION", "REAL_USER_LATENCY_GREEN", "PROMOTE_FULL"
        )
    elif now >= horizon_at:
        decision, reason, transition = (
            "CANARY_INSUFFICIENT_REAL_VOLUME",
            "CANARY_HORIZON_REACHED_BELOW_SAMPLE_FLOOR",
            "CANARY_INSUFFICIENT_REAL_VOLUME",
        )
    elif payload["admitted_count"] >= payload["session_cap"]:
        decision, reason, transition = (
            "CANARY_INSUFFICIENT_REAL_VOLUME",
            "CANARY_SESSION_CAP_REACHED_BELOW_SAMPLE_FLOOR",
            "CANARY_INSUFFICIENT_REAL_VOLUME",
        )
    else:
        decision, reason, transition = (
            "CANARY_COLLECTING_EVIDENCE", "REAL_USER_SAMPLE_FLOOR_NOT_MET", None
        )
    return {
        **base,
        "ok": decision in {"CANARY_COLLECTING_EVIDENCE", "CANARY_READY_FOR_PROMOTION"},
        "decision": decision,
        "reason": reason,
        "transition": transition,
    }


def _runtime_payload(connection: psycopg.Connection, now: datetime, hard_gates: bool) -> dict[str, Any]:
    row = connection.execute(
        "SELECT release_state,promotion_state,canary_evidence_start,canary_horizon_at,"
        "canary_session_cap,canary_release_id "
        "FROM commercial_s11_runtime_control WHERE singleton"
    ).fetchone()
    if row is None:
        raise ValueError("S11_2_CONTROL_ROW_MISSING")
    (
        release_state,
        promotion_state,
        evidence_start,
        horizon_at,
        session_cap,
        canary_release_id,
    ) = row
    if release_state != "S11_DISABLED" and not canary_release_id:
        raise ValueError("S11_2_RELEASE_BINDING_MISSING")
    epoch_start = evidence_start or now
    epoch_end = min(now, horizon_at) if horizon_at is not None else now
    samples = connection.execute(
        "SELECT evidence_class,sample_type,interaction_path,bot_response_latency_ms,"
        "handler_duration_ms FROM commercial_s10_2d_latency_samples "
        "WHERE source='DIRECT' AND release_id=%s "
        "AND recorded_at >= %s AND recorded_at <= %s "
        "ORDER BY recorded_at,sample_id",
        (canary_release_id, epoch_start, epoch_end),
    ).fetchall()
    technical_values = [
        value[4]
        for value in samples
        if value[0] == "INTERNAL_TEST"
        and value[1] == "S11_CANARY_RESPONSE"
        and value[2] == "INTERNAL_ACCEPTANCE"
    ]
    real_values = [
        value[3]
        for value in samples
        if value[0] == "REAL"
        and value[1] == "S11_CANARY_RESPONSE"
        and value[2] == "TELEGRAM_DIRECT"
    ]
    new_unknown = sum(
        value[0] in {"UNKNOWN", "TECHNICAL_ACCEPTANCE"}
        or value[1] == "UNKNOWN"
        or value[2] == "UNKNOWN"
        for value in samples
    )
    historical_unknown = connection.execute(
        "SELECT count(*) FROM commercial_s10_2d_latency_samples "
        "WHERE source='DIRECT' AND release_id=%s AND recorded_at < %s AND "
        "(evidence_class IN ('UNKNOWN','TECHNICAL_ACCEPTANCE') "
        "OR sample_type='UNKNOWN' OR interaction_path='UNKNOWN')",
        (canary_release_id, epoch_start),
    ).fetchone()[0]
    admitted = connection.execute(
        "SELECT COALESCE(max(admitted_count),0) FROM commercial_s11_canary_admission_counters "
        "WHERE evidence_epoch_start=%s",
        (evidence_start,),
    ).fetchone()[0] if evidence_start is not None else 0
    sessions = connection.execute(
        "SELECT count(*) FROM commercial_s11_experience_sessions "
        "WHERE evidence_epoch_start=%s",
        (evidence_start,),
    ).fetchone()[0] if evidence_start is not None else 0
    events = connection.execute(
        "SELECT count(*) FROM commercial_s11_product_events "
        "WHERE occurred_at >= %s AND evidence_class='REAL_ACQUISITION'",
        (epoch_start,),
    ).fetchone()[0]
    return {
        "release_state": release_state,
        "promotion_state": promotion_state,
        "now": _iso(now),
        "evidence_start": _iso(evidence_start),
        "horizon_at": _iso(horizon_at),
        "session_cap": session_cap,
        "admitted_count": admitted,
        "technical_values_ms": technical_values,
        "real_values_ms": real_values,
        "new_unknown_count": new_unknown,
        "historical_unknown_count": historical_unknown,
        "experience_sessions": sessions,
        "product_event_count": events,
        "hard_gates_green": hard_gates,
    }


def simulate_contract() -> dict[str, Any]:
    start = "2026-01-01T00:00:00Z"
    before_horizon = "2026-01-01T12:00:00Z"
    after_horizon = "2026-01-02T00:00:01Z"

    def fixture(real: list[int], **overrides: Any) -> dict[str, Any]:
        payload = {
            "release_state": "S11_CANARY",
            "promotion_state": "CANARY_COLLECTING_EVIDENCE",
            "now": before_horizon,
            "evidence_start": start,
            "horizon_at": "2026-01-02T00:00:00Z",
            "session_cap": 10,
            "admitted_count": len(real),
            "technical_values_ms": [100, 110, 120, 130, 140],
            "real_values_ms": real,
            "new_unknown_count": 0,
            "historical_unknown_count": 3,
            "experience_sessions": len(real),
            "product_event_count": len(real),
            "hard_gates_green": True,
        }
        payload.update(overrides)
        return payload

    cases = {
        "A": evaluate(fixture([]))["decision"],
        "B": evaluate(fixture([200, 250, 300, 350]))["decision"],
        "C": evaluate(fixture([200, 250, 300, 350, 400]))["decision"],
        "D": evaluate(fixture([200, 250, 300, 350, 6000]))["decision"],
        "E": evaluate(fixture([200, 250, 300, 350, 400], historical_unknown_count=6))["decision"],
        "F": evaluate(fixture([], new_unknown_count=1))["decision"],
        "G": evaluate(fixture([], hard_gates_green=False))["decision"],
        "H": evaluate(fixture([], technical_values_ms=[100]))["decision"],
        "I": evaluate(fixture([], now=after_horizon))["decision"],
        "J": evaluate(fixture([200, 250, 300, 350, 400]))["transition"],
        "CAP": evaluate(fixture([], admitted_count=10))["decision"],
    }
    expected = {
        "A": "CANARY_COLLECTING_EVIDENCE",
        "B": "CANARY_COLLECTING_EVIDENCE",
        "C": "CANARY_READY_FOR_PROMOTION",
        "D": "CANARY_RED",
        "E": "CANARY_READY_FOR_PROMOTION",
        "F": "CANARY_RED",
        "G": "CANARY_RED",
        "H": "CANARY_RED",
        "I": "CANARY_INSUFFICIENT_REAL_VOLUME",
        "J": "PROMOTE_FULL",
        "CAP": "CANARY_INSUFFICIENT_REAL_VOLUME",
    }
    return {
        "ok": cases == expected,
        "safe_code": "S11_2_CANARY_SIMULATOR_GREEN" if cases == expected else "S11_2_CANARY_SIMULATOR_RED",
        "cases": cases,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulate-contract", action="store_true")
    mode.add_argument("--input", type=Path)
    mode.add_argument("--dsn-file", type=Path)
    parser.add_argument("--now", type=_timestamp)
    parser.add_argument("--hard-gates-green", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.simulate_contract:
        result = simulate_contract()
    elif arguments.input is not None:
        result = evaluate(json.loads(_private_text(arguments.input, 65536)))
    else:
        assert arguments.dsn_file is not None
        dsn = _private_text(arguments.dsn_file, 8192)
        now = arguments.now or datetime.now(timezone.utc)
        with psycopg.connect(dsn) as connection:
            result = evaluate(_runtime_payload(connection, now, arguments.hard_gates_green))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, psycopg.Error) as error:
        print(
            json.dumps(
                {"ok": False, "safe_code": type(error).__name__},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        raise SystemExit(2) from None
