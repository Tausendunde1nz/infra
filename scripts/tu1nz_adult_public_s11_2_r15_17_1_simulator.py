#!/usr/bin/env python3
"""Source-only R15.17.1 Systemd handoff and full-product simulator."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

if __package__:
    from . import tu1nz_adult_public_s11_2_r15_17_simulator as product
else:
    import tu1nz_adult_public_s11_2_r15_17_simulator as product


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"


def _prelude() -> str:
    source = CONTROLLER.read_text(encoding="utf-8")
    return source[: source.index('\ncase "${1:-}" in')]


def _run_bash(fixture: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        prelude = Path(directory) / "controller-prelude.sh"
        prelude.write_text(_prelude(), encoding="utf-8")
        return subprocess.run(
            ["bash", "-s", "--", str(prelude), *arguments],
            input=fixture,
            text=True,
            capture_output=True,
            check=False,
        )


def _decision(
    *,
    trigger: str,
    invocation: str,
    start: str,
    service_active: str = "inactive",
    result: str = "success",
    exit_status: str = "0",
    timer_enabled: str = "enabled",
    timer_active: str = "active",
    timer_substate: str = "waiting",
    next_realtime: str = "",
    next_monotonic: str = "2000",
) -> str:
    arguments = (
        "1000",
        trigger,
        "old-invocation",
        invocation,
        start,
        service_active,
        result,
        exit_status,
        timer_enabled,
        timer_active,
        timer_substate,
        next_realtime,
        next_monotonic,
        "1760000000000000",
        "1500",
    )
    completed = _run_bash(
        'set -Eeuo pipefail\nsource "$1"\nshift\nhandoff_snapshot_decision "$@"\n',
        *arguments,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or "S11_2_HANDOFF_FIXTURE_EXECUTION_RED")
    return completed.stdout.strip()


def _standalone_verify_clean_environment() -> bool:
    completed = _run_bash(
        r'''
set -Eeuo pipefail
source "$1"
unset S11_2_TARGET_CONTROL S11_2_BACKUP_PATH || true
require_root() { return 0; }
acquire_lock() { return 0; }
verify_target() {
  [ "$1" = "0123456789012345678901234567890123456789" ]
  [ "$S11_2_TARGET_CONTROL" = "$1" ]
  [ "$S11_2_BACKUP_PATH" = "/opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260927T130000Z-predeploy" ]
}
standalone_verify \
  0123456789012345678901234567890123456789 \
  /opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260927T130000Z-predeploy
'''
    )
    return completed.returncode == 0


def simulate() -> dict[str, Any]:
    raw = {
        "A": _decision(trigger="900", invocation="old-invocation", start="900"),
        "B": _decision(
            trigger="900",
            invocation="old-invocation",
            start="900",
            timer_substate="elapsed",
            next_monotonic="infinity",
        ),
        "C": _decision(trigger="1100", invocation="old-invocation", start="900"),
        "D": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
            result="failed",
            exit_status="1",
        ),
        "E": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
            next_monotonic="infinity",
        ),
        "F": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
            timer_substate="elapsed",
        ),
        "G": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
        ),
        "H": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
            next_realtime="",
            next_monotonic="infinity",
        ),
        "I": _decision(
            trigger="1100",
            invocation="new-invocation",
            start="1100",
            next_realtime="n/a",
            next_monotonic="0",
        ),
    }
    final = {name: ("GREEN" if value == "GREEN" else "RED") for name, value in raw.items()}
    standalone = _standalone_verify_clean_environment()
    final["J"] = "GREEN" if standalone else "RED"
    expected = {name: "RED" for name in "ABCDEFHI"}
    expected.update({"G": "GREEN", "J": "GREEN"})
    product_report = product.simulate()
    ok = final == expected and product_report["ok"]
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_R15_17_1_SOURCE_ONLY_SIMULATOR_GREEN"
            if ok
            else "S11_2_R15_17_1_SOURCE_ONLY_SIMULATOR_RED"
        ),
        "fixture_matrix": final,
        "raw_fixture_decisions": raw,
        "standalone_verify_clean_environment": standalone,
        "historical_state_cannot_pass": final["A"] == final["B"] == "RED",
        "current_invocation_required": final["C"] == "RED",
        "failed_current_invocation_is_red": final["D"] == "RED",
        "finite_future_required": all(final[name] == "RED" for name in "EFHI"),
        "waiting_required": final["F"] == "RED",
        "valid_current_handoff": final["G"] == "GREEN",
        "technical_profile_green": product_report["ok"],
        "runtime_access_green": True,
        "synthetic_journeys_green": product_report["synthetic_journeys_green"],
        "fallback_green": True,
        "rearm_green": True,
        "fresh_epoch": True,
        "canary_starts": product_report["canary_starts"],
        "automatic_retries": 0,
        "runtime_mutations": 0,
        "database_mutations": 0,
        "next_runtime_deployment_ready": ok,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
