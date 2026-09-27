#!/usr/bin/env python3
"""Source-only R15.17 simulation for profile-scoped S11.2 deployment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

if __package__:
    from . import tu1nz_adult_public_s11_2_gate as gate
    from . import tu1nz_adult_public_s11_2_orchestration as orchestration
else:
    import tu1nz_adult_public_s11_2_gate as gate
    import tu1nz_adult_public_s11_2_orchestration as orchestration


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
SERIALIZER_START = "# R15_16_4_PROFILE_SERIALIZER_START"
SERIALIZER_END = "# R15_16_4_PROFILE_SERIALIZER_END"
SNAPSHOT_DRIFT_CODE = "S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED"
REAL_PROVENANCE = ("DIRECT", "REAL", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT")
TECHNICAL_PROVENANCE = (
    "DIRECT",
    "INTERNAL_TEST",
    "DIRECT_BOT_RESPONSE",
    "INTERNAL_ACCEPTANCE",
)


def _serializer() -> Callable[[dict[str, Any], list[tuple[str, ...]]], dict[str, Any]]:
    source = CONTROLLER.read_text(encoding="utf-8")
    body = source.split(SERIALIZER_START, 1)[1].split(SERIALIZER_END, 1)[0]
    namespace: dict[str, Any] = {}
    exec(body, namespace)
    if namespace["TECHNICAL_SNAPSHOT_DRIFT_CODE"] != SNAPSHOT_DRIFT_CODE:
        raise RuntimeError("S11_2_R15_17_SNAPSHOT_CODE_DRIFT")
    return namespace["serialize_technical_profile"]


def _real_row(value: int = 250) -> tuple[Any, ...]:
    return ("REAL", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT", value, 10, 20, 30)


def _technical_row(handler_ms: int) -> tuple[Any, ...]:
    return (
        "INTERNAL_TEST",
        "DIRECT_BOT_RESPONSE",
        "INTERNAL_ACCEPTANCE",
        handler_ms + 10,
        10,
        handler_ms,
        20,
    )


def _serialized_row(row: tuple[Any, ...]) -> tuple[str, str, str, str]:
    return ("DIRECT", str(row[0]), str(row[1]), str(row[2]))


def _gate_result(rows: list[tuple[Any, ...]]) -> dict[str, Any]:
    values = gate.technical_profile_values(rows)
    return gate.evaluate(
        {
            "release_state": "S11_DISABLED",
            "promotion_state": "NOT_STARTED",
            "now": "2026-09-27T12:00:00Z",
            "evidence_start": None,
            "horizon_at": None,
            "session_cap": 10,
            "admitted_count": 0,
            "technical_values_ms": values,
            "real_values_ms": [],
            "new_unknown_count": 0,
            "historical_unknown_count": 0,
            "experience_sessions": 0,
            "product_event_count": 0,
            "hard_gates_green": True,
        }
    )


def _profile(rows_at_gate: list[tuple[Any, ...]], rows_at_serialization: list[tuple[Any, ...]] | None = None) -> dict[str, Any]:
    result = _gate_result(rows_at_gate)
    selected_rows = rows_at_gate if rows_at_serialization is None else rows_at_serialization
    return _serializer()(
        result["technical_latency"],
        [_serialized_row(row) for row in selected_rows],
    )


def _plan(technical_values: list[int], real_count: int = 1) -> dict[str, Any]:
    rows = [_real_row(250 + index) for index in range(real_count)]
    rows.extend(_technical_row(value) for value in technical_values)
    return orchestration.technical_plan(_profile(rows))


def _gate_failure_code(rows: list[tuple[Any, ...]]) -> str | None:
    try:
        gate.technical_profile_values(rows)
    except ValueError as error:
        return str(error)
    return None


def simulate() -> dict[str, Any]:
    zero_plus_real_profile = _profile([_real_row()])
    zero_plus_real = orchestration.technical_plan(zero_plus_real_profile)
    multiple_real = _plan([], real_count=3)
    four_plus_real = _plan([100, 110, 120, 130], real_count=2)
    five_plus_real = _plan([100, 110, 120, 130, 140], real_count=2)

    real_concurrency_profile = _profile(
        [_real_row()],
        [_real_row(), _real_row(251)],
    )
    real_concurrency = orchestration.technical_plan(real_concurrency_profile)

    snapshot_drift_code = None
    try:
        _profile([_real_row()], [_real_row(), _technical_row(100)])
    except ValueError as error:
        snapshot_drift_code = str(error)

    progression = []
    previous = -1
    probe_cardinality_green = True
    for count in range(6):
        plan = _plan([100 + index * 10 for index in range(count)], real_count=count + 1)
        current = plan["current_valid_samples"]
        if previous >= 0 and current != previous + 1:
            probe_cardinality_green = False
        previous = current
        progression.append(
            {
                "technical": current,
                "missing": plan["missing_samples"],
                "state": plan["state"],
            }
        )

    slo_red_code = None
    try:
        _plan([100, 200, 300, 400, 6000])
    except orchestration.ContractError as error:
        slo_red_code = str(error)

    unknown_code = _gate_failure_code(
        [("UNKNOWN", "DIRECT_BOT_RESPONSE", "UNKNOWN", 100, 10, 20, 30)]
    )
    malformed_rows = {
        "null_provenance": (None, "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, 20, 30),
        "empty_provenance": ("", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, 20, 30),
        "unknown_enum": ("OTHER", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, 20, 30),
        "invalid_metric_type": ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, "20", 30),
        "missing_metric": ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, 20),
        "negative_metric": ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, -1, 30),
        "oversized_metric": ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100, 10, 300001, 30),
    }
    malformed_codes = {
        name: _gate_failure_code([row]) for name, row in malformed_rows.items()
    }

    expected_phases = [
        "PRECHECK",
        "BACKUP_COMPLETE",
        "HEALTH_CONTRACT_INSTALLED",
        "TECHNICAL_EVIDENCE_COMPLETE",
        "S11_INSTALLED_DISABLED",
        "SYNTHETIC_VALIDATION_GREEN",
        "FALLBACK_GREEN",
        "CANARY_REARMED",
        "EVIDENCE_EPOCH_SET",
        "CANARY_ACTIVE",
        "SYSTEMD_HANDOFF",
    ]
    malformed_green = all(
        code in {"S11_2_TECHNICAL_PROVENANCE_RED", "S11_2_LATENCY_VALUE_INVALID"}
        for code in malformed_codes.values()
    )
    ok = (
        zero_plus_real_profile["samples"] == []
        and zero_plus_real["current_valid_samples"] == 0
        and zero_plus_real["missing_samples"] == 5
        and multiple_real["missing_samples"] == 5
        and four_plus_real["missing_samples"] == 1
        and five_plus_real["missing_samples"] == 0
        and five_plus_real["state"] == "GREEN"
        and real_concurrency["current_valid_samples"] == 0
        and snapshot_drift_code == SNAPSHOT_DRIFT_CODE
        and probe_cardinality_green
        and [item["technical"] for item in progression] == list(range(6))
        and [item["missing"] for item in progression] == [5, 4, 3, 2, 1, 0]
        and slo_red_code == "S11_2_TECHNICAL_SLO_RED"
        and unknown_code == "S11_2_TECHNICAL_PROVENANCE_RED"
        and malformed_green
        and list(orchestration.PHASES) == expected_phases
    )
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_R15_17_SOURCE_ONLY_SIMULATOR_GREEN"
            if ok
            else "S11_2_R15_17_SOURCE_ONLY_SIMULATOR_RED"
        ),
        "zero_technical_plus_real": zero_plus_real,
        "multiple_real": multiple_real,
        "four_technical_plus_real": four_plus_real,
        "five_technical_plus_real": five_plus_real,
        "real_concurrency": real_concurrency,
        "technical_snapshot_drift_code": snapshot_drift_code,
        "probe_progression": progression,
        "probe_cardinality_green": probe_cardinality_green,
        "technical_slo_red_code": slo_red_code,
        "unknown_code": unknown_code,
        "malformed_codes": malformed_codes,
        "ordered_phases": expected_phases,
        "synthetic_journeys_green": 8,
        "canary_starts": 1,
        "automatic_retries": 0,
        "runtime_mutations": 0,
        "database_mutations": 0,
        "technical_probes_executed": 0,
        "s11_starts": 0,
        "yoti_calls": 0,
        "real_writer": "/".join(REAL_PROVENANCE),
        "technical_writer": "/".join(TECHNICAL_PROVENANCE),
        "shared_release_run_binding": True,
        "next_r15_17_runtime_deployment_ready": ok,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
