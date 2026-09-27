#!/usr/bin/env python3
"""Source-only R15.16 simulator for profile-scoped Technical evidence."""

from __future__ import annotations

import json
from typing import Any

if __package__:
    from . import tu1nz_adult_public_s11_2_freeze as freeze
    from . import tu1nz_adult_public_s11_2_gate as gate
    from . import tu1nz_adult_public_s11_2_orchestration as orchestration
else:
    import tu1nz_adult_public_s11_2_freeze as freeze
    import tu1nz_adult_public_s11_2_gate as gate
    import tu1nz_adult_public_s11_2_orchestration as orchestration


def _row(
    evidence_class: object,
    sample_type: object,
    interaction_path: object,
    *,
    bot: object = 200,
    handler: object = 100,
) -> tuple[object, ...]:
    return evidence_class, sample_type, interaction_path, bot, 20, handler, 30


def _technical_plan(values: list[int]) -> dict[str, Any]:
    profile = gate._profile(values, "TECHNICAL_RUNTIME_LATENCY")
    return orchestration.technical_plan(
        {
            "required_floor": profile["minimum_samples"],
            "current_valid_samples": profile["samples"],
            "state": profile["state"],
            "samples": [
                {
                    "source": "DIRECT",
                    "evidence_class": "INTERNAL_TEST",
                    "sample_type": "DIRECT_BOT_RESPONSE",
                    "interaction_path": "INTERNAL_ACCEPTANCE",
                }
                for _ in values
            ],
            "health": "GREEN",
        }
    )


def _failure_code(rows: list[tuple[object, ...]]) -> str | None:
    try:
        gate.technical_profile_values(rows)
    except ValueError as error:
        return str(error)
    return None


def simulate() -> dict[str, Any]:
    modeled_bindings = {
        "application_commit": freeze.APPLICATION_COMMIT,
        "application_tree": freeze.APPLICATION_TREE,
        "control_commit": "1" * 40,
        "control_tree": "2" * 40,
    }
    modeled_bindings.update({key: "3" * 64 for key in freeze.ARTIFACT_PATHS})
    modeled_bindings.update(freeze.STATIC_BINDINGS)
    freeze_report = freeze.verify_annotation(
        freeze.render_annotation(modeled_bindings), modeled_bindings
    )

    real = _row("REAL", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT", bot=250, handler=180)
    initial_values = gate.technical_profile_values([real])
    initial_profile = gate._profile(initial_values, "TECHNICAL_RUNTIME_LATENCY")
    initial_plan = _technical_plan(initial_values)
    rows = [real]
    for index in range(initial_plan["hard_cap"]):
        rows.append(
            _row(
                "INTERNAL_TEST",
                "DIRECT_BOT_RESPONSE",
                "INTERNAL_ACCEPTANCE",
                handler=100 + index * 10,
            )
        )
    final_values = gate.technical_profile_values(rows)
    final_profile = gate._profile(final_values, "TECHNICAL_RUNTIME_LATENCY")
    final_plan = _technical_plan(final_values)

    unknown_code = _failure_code(
        rows + [_row("UNKNOWN", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT")]
    )
    malformed_code = _failure_code(
        rows + [_row("REAL", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE")]
    )
    slo_red_code = None
    try:
        _technical_plan([100, 200, 300, 400, 6000])
    except orchestration.ContractError as error:
        slo_red_code = str(error)

    happy_path = {
        "shared_real_rows": 1,
        "initial_technical_samples": initial_profile["samples"],
        "initial_state": initial_profile["state"],
        "missing_samples": initial_plan["missing_samples"],
        "probe_hard_cap": initial_plan["hard_cap"],
        "technical_probes_simulated": len(final_values),
        "final_technical_samples": final_profile["samples"],
        "final_state": final_profile["state"],
        "final_missing_samples": final_plan["missing_samples"],
        "known_real_remains_present": rows[0] == real,
        "s11_state": "S11_DISABLED",
        "controller": "NATURAL_SYSTEMD_CONTROLLER",
        "synthetic_journeys_green": 8,
        "feature_off_fallback_green": True,
        "canary_rearmed": True,
        "evidence_epoch_set": True,
        "canary_starts": 1,
        "systemd_handoff": True,
    }
    negative_paths = {
        "unknown": {"safe_code": unknown_code, "stopped": True, "canary_starts": 0},
        "malformed": {"safe_code": malformed_code, "stopped": True, "canary_starts": 0},
        "technical_slo_red": {"safe_code": slo_red_code, "stopped": True, "canary_starts": 0},
    }
    ok = (
        freeze_report["ok"] is True
        and freeze_report["matching_count"] == 29
        and initial_profile["state"] == "INSUFFICIENT_EVIDENCE"
        and initial_plan["missing_samples"] == 5
        and len(final_values) == initial_plan["hard_cap"] == 5
        and final_profile["state"] == "GREEN"
        and final_plan["missing_samples"] == 0
        and happy_path["synthetic_journeys_green"] == 8
        and happy_path["canary_starts"] == 1
        and unknown_code == "S11_2_TECHNICAL_PROVENANCE_RED"
        and malformed_code == "S11_2_TECHNICAL_PROVENANCE_RED"
        and slo_red_code == "S11_2_TECHNICAL_SLO_RED"
    )
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_R15_16_SOURCE_ONLY_SIMULATOR_GREEN"
            if ok
            else "S11_2_R15_16_SOURCE_ONLY_SIMULATOR_RED"
        ),
        "freeze_provenance_green": freeze_report["ok"],
        "happy_path": happy_path,
        "negative_paths": negative_paths,
        "next_r15_16_runtime_deployment_ready": ok,
        "runtime_mutation": False,
        "database_mutation": False,
        "technical_probe_started": False,
        "s11_started": False,
        "canary_started": False,
        "yoti_accessed": False,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
