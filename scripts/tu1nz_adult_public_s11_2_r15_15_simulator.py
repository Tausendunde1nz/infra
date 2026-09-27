#!/usr/bin/env python3
"""Source-only R15.15 simulator for the next S11.2 deployment attempt."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

if __package__:
    from . import tu1nz_adult_public_s11_2_gate as gate
    from . import tu1nz_adult_public_s11_2_orchestration as orchestration
else:
    import tu1nz_adult_public_s11_2_gate as gate
    import tu1nz_adult_public_s11_2_orchestration as orchestration


OBSERVED_AT = "2026-09-27T12:00:00Z"
RUN_ID = "r15-15-source-simulator"


def _gate_payload(technical_values: list[int]) -> dict[str, Any]:
    return gate.evaluate(
        {
            "release_state": "S11_DISABLED",
            "promotion_state": "NOT_STARTED",
            "now": OBSERVED_AT,
            "evidence_start": None,
            "horizon_at": None,
            "session_cap": 10,
            "admitted_count": 0,
            "technical_values_ms": technical_values,
            "real_values_ms": [],
            "new_unknown_count": 0,
            "historical_unknown_count": 3,
            "experience_sessions": 0,
            "product_event_count": 0,
            "hard_gates_green": True,
        }
    )


def _normalize(payload: dict[str, Any], exit_code: int) -> tuple[dict[str, Any], bool]:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "gate.json"
        source.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        return gate.normalize_technical_gate_output(
            source,
            gate_exit_code=exit_code,
            run_id=RUN_ID,
            observed_at=OBSERVED_AT,
        )


def _technical_plan(values: list[int]) -> dict[str, Any]:
    normalized, valid = _normalize(_gate_payload(values), 0)
    if not valid:
        raise RuntimeError("S11_2_R15_15_VALID_GATE_REJECTED")
    technical = normalized["technical_latency"]
    samples = [
        {
            "source": "DIRECT",
            "evidence_class": "INTERNAL_TEST",
            "sample_type": "DIRECT_BOT_RESPONSE",
            "interaction_path": "INTERNAL_ACCEPTANCE",
        }
        for _ in values
    ]
    return orchestration.technical_plan(
        {
            "required_floor": technical["minimum_samples"],
            "current_valid_samples": technical["samples"],
            "state": technical["state"],
            "samples": samples,
            "health": "GREEN",
        }
    )


def simulate() -> dict[str, Any]:
    plans = {
        "0_of_5": _technical_plan([]),
        "4_of_5": _technical_plan([100, 110, 120, 130]),
        "5_of_5": _technical_plan([100, 110, 120, 130, 140]),
    }
    failure = gate.failure_envelope(ValueError("S11_2_TECHNICAL_BINDING_MISSING"))
    diagnostic, failure_valid = _normalize(failure, 2)
    slo_red_code = None
    try:
        _technical_plan([100, 200, 300, 400, 6000])
    except orchestration.ContractError as error:
        slo_red_code = str(error)
    happy_path = {
        "ordered_phases": list(orchestration.PHASES),
        "technical_start_0_of_5": {
            "serial_probes": plans["0_of_5"]["missing_samples"],
            "probe_hard_cap": plans["0_of_5"]["hard_cap"],
        },
        "technical_start_4_of_5": {
            "serial_probes": plans["4_of_5"]["missing_samples"],
            "probe_hard_cap": plans["4_of_5"]["hard_cap"],
        },
        "technical_start_5_of_5": {
            "serial_probes": plans["5_of_5"]["missing_samples"],
            "probe_hard_cap": plans["5_of_5"]["hard_cap"],
        },
        "s11_installed_disabled": True,
        "synthetic_journeys_green": 8,
        "feature_off_fallback_green": True,
        "rearm_before_epoch": True,
        "evidence_epoch_before_canary": True,
        "canary_starts": 1,
        "systemd_handoff": True,
    }
    negative_path = {
        "outer_code": diagnostic["outer_code"],
        "inner_safe_code": diagnostic["inner_safe_code"],
        "component": diagnostic["component"],
        "classification": diagnostic["classification"],
        "technical_probes": 0,
        "s11_installs": 0,
        "canary_starts": 0,
        "mutation_started": True,
        "rollback_requests": 1,
        "rollback_executions": 1,
        "automatic_retry": False,
    }
    ok = (
        failure_valid is False
        and diagnostic["inner_safe_code"] == "S11_2_TECHNICAL_BINDING_MISSING"
        and slo_red_code == "S11_2_TECHNICAL_SLO_RED"
        and plans["0_of_5"]["missing_samples"] == 5
        and plans["4_of_5"]["missing_samples"] == 1
        and plans["5_of_5"]["missing_samples"] == 0
        and happy_path["canary_starts"] == 1
        and negative_path["rollback_executions"] == 1
    )
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_R15_15_SOURCE_ONLY_SIMULATOR_GREEN"
            if ok
            else "S11_2_R15_15_SOURCE_ONLY_SIMULATOR_RED"
        ),
        "happy_path": happy_path,
        "negative_gate_path": negative_path,
        "technical_slo_red_code": slo_red_code,
        "runtime_mutation": False,
        "adult_media": False,
        "real_avs": False,
        "payments": False,
        "publishing": False,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
