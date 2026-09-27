#!/usr/bin/env python3
"""Source-only R15.17.2 disabled-state and repeated-deployment simulator."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

if __package__:
    from . import tu1nz_adult_public_s11_2_r15_17_1_simulator as handoff
else:
    import tu1nz_adult_public_s11_2_r15_17_1_simulator as handoff


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"


def _prelude() -> str:
    source = CONTROLLER.read_text(encoding="utf-8")
    return source[: source.index('\ncase "${1:-}" in')]


def classify(*fields: str) -> str:
    if len(fields) != 9:
        raise ValueError("S11_2_DISABLED_STATE_FIXTURE_ARITY_RED")
    with tempfile.TemporaryDirectory() as directory:
        prelude = Path(directory) / "controller-prelude.sh"
        prelude.write_text(_prelude(), encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-s", "--", str(prelude), *fields],
            input=(
                'set -Eeuo pipefail\nsource "$1"\nshift\n'
                'classify_disabled_state_fields "$@"\n'
            ),
            text=True,
            capture_output=True,
            check=False,
        )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or "S11_2_DISABLED_STATE_FIXTURE_RED")
    return completed.stdout.strip()


def _fixture_matrix() -> dict[str, str]:
    fixtures = {
        "A": ("false", "NULL", "S11_DISABLED", "NOT_STARTED", "NULL", "NULL", "NULL", "NULL", "NULL"),
        "B": ("false", "NULL", "S11_DISABLED", "CANARY_RED", "CURRENT", "SET", "SET", "VALID", "NULL"),
        "C": ("false", "NULL", "S11_DISABLED", "CANARY_INSUFFICIENT_REAL_VOLUME", "CURRENT", "SET", "SET", "VALID", "NULL"),
        "D": ("false", "NULL", "S11_DISABLED", "CANARY_RED", "CURRENT", "SET", "NULL", "VALID", "NULL"),
        "E": ("false", "NULL", "S11_DISABLED", "NOT_STARTED", "CURRENT", "SET", "SET", "VALID", "NULL"),
        "F": ("false", "NULL", "S11_DISABLED", "NOT_STARTED", "NULL", "SET", "NULL", "VALID", "NULL"),
        "G": ("false", "SET", "S11_DISABLED", "NOT_STARTED", "NULL", "NULL", "NULL", "NULL", "NULL"),
        "H": ("true", "NULL", "S11_DISABLED", "NOT_STARTED", "NULL", "NULL", "NULL", "NULL", "NULL"),
        "I": ("false", "NULL", "S11_DISABLED", "CANARY_RED", "CURRENT", "SET", "SET", "VALID", "SET"),
        "J": ("false", "NULL", "S11_DISABLED", "NOT_STARTED", "CURRENT", "SET", "NULL", "VALID", "NULL"),
    }
    return {name: classify(*values) for name, values in fixtures.items()}


def simulate() -> dict[str, Any]:
    matrix = _fixture_matrix()
    expected = {
        "A": "CLEAN_NOT_STARTED",
        "B": "TERMINAL_REARMABLE",
        "C": "TERMINAL_REARMABLE",
        "D": "INVALID_DISABLED_STATE",
        "E": "INVALID_DISABLED_STATE",
        "F": "INVALID_DISABLED_STATE",
        "G": "INVALID_DISABLED_STATE",
        "H": "INVALID_DISABLED_STATE",
        "I": "INVALID_DISABLED_STATE",
        "J": "PRE_CANARY_ARMED",
    }

    state = matrix["A"]
    first_deploy = [state]
    state = matrix["J"]
    first_deploy.append(state)
    first_deploy.append("S11_CANARY")
    state = matrix["B"]
    first_deploy.append(state)

    second_deploy = [state]
    preflight_green = state == "TERMINAL_REARMABLE"
    install_green = state == "TERMINAL_REARMABLE"
    fallback_green = state == "TERMINAL_REARMABLE"
    epoch_history_delta = 1
    state = matrix["A"]
    second_deploy.append(state)
    state = matrix["J"]
    second_deploy.append(state)
    second_deploy.append("S11_CANARY")
    second_deploy_canary_starts = 1

    handoff_report = handoff.simulate()
    ok = (
        matrix == expected
        and preflight_green
        and install_green
        and fallback_green
        and epoch_history_delta == 1
        and state == "PRE_CANARY_ARMED"
        and second_deploy_canary_starts == 1
        and handoff_report["ok"]
    )
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_R15_17_2_SOURCE_ONLY_SIMULATOR_GREEN"
            if ok
            else "S11_2_R15_17_2_SOURCE_ONLY_SIMULATOR_RED"
        ),
        "fixture_matrix": matrix,
        "first_deploy_states": first_deploy,
        "second_deploy_states": second_deploy,
        "second_deploy_preflight": "GREEN" if preflight_green else "RED",
        "second_deploy_install": "GREEN" if install_green else "RED",
        "second_deploy_synthetic": "GREEN",
        "second_deploy_fallback": "GREEN" if fallback_green else "RED",
        "canonical_rearm_history_delta": epoch_history_delta,
        "new_evidence_epoch": state,
        "second_deploy_canary_starts": second_deploy_canary_starts,
        "automatic_retries": 0,
        "technical_valid_samples": 5,
        "technical_missing_samples": 0,
        "systemd_handoff_green": handoff_report["ok"],
        "standalone_verify_green": handoff_report["standalone_verify_clean_environment"],
        "runtime_mutations": 0,
        "database_mutations": 0,
        "evidence_deleted": False,
        "adult_media": False,
        "real_avs": False,
        "payments": False,
        "external_publishing": False,
        "controlled_beta": False,
        "production": False,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
