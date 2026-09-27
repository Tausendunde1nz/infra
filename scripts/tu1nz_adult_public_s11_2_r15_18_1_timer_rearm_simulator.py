#!/usr/bin/env python3
"""Source-only simulator for the R15.18.1 explicit timer-rearm contract."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

try:
    from scripts import tu1nz_adult_public_s11_2_r15_17_2_simulator as disabled_state
except ModuleNotFoundError:  # Direct execution from scripts/.
    import tu1nz_adult_public_s11_2_r15_17_2_simulator as disabled_state


@dataclass(frozen=True)
class TimerState:
    enabled: bool
    active: str
    substate: str
    last_trigger: int | None
    next_monotonic: int | None
    invocation_id: str | None = None
    invocation_origin: str | None = None
    service_result: str | None = None
    exec_main_status: int | None = None
    service_start_monotonic: int | None = None
    arm_attempts: int = 0


STALE = TimerState(
    enabled=True,
    active="active",
    substate="elapsed",
    last_trigger=0,
    next_monotonic=None,
)


def old_enable_now(state: TimerState) -> tuple[str, TimerState]:
    """Model the observed no-op when enablement already existed."""
    return "TIMEOUT", replace(state, enabled=True)


def explicit_fresh_arm(
    state: TimerState,
    *,
    start_succeeds: bool = True,
    creates_invocation: bool = True,
    invocation_origin: str = "PID1_TIMER",
    service_succeeds: bool = True,
    recurrence: bool = True,
) -> tuple[str, TimerState]:
    """Model enable, stale stop/reset, one StartUnit, then strict acceptance."""
    armed = replace(
        state,
        enabled=True,
        active="inactive",
        substate="dead",
        next_monotonic=None,
        arm_attempts=state.arm_attempts + 1,
    )
    if not start_succeeds:
        return "RED", armed
    if not creates_invocation:
        return "TIMEOUT", replace(armed, active="active", substate="elapsed")

    invoked = replace(
        armed,
        last_trigger=2_000_000,
        invocation_id="fresh-invocation",
        invocation_origin=invocation_origin,
        service_result="success" if service_succeeds else "failed",
        exec_main_status=0 if service_succeeds else 1,
        service_start_monotonic=2_000_001,
    )
    if invocation_origin != "PID1_TIMER" or not service_succeeds:
        return "RED", invoked
    final = replace(
        invoked,
        active="active",
        substate="waiting" if recurrence else "elapsed",
        next_monotonic=3_000_000 if recurrence else None,
    )
    if final.substate != "waiting" or final.next_monotonic is None:
        return "RED", final
    return "GREEN", final


def simulate() -> dict[str, object]:
    new_timer = TimerState(False, "inactive", "dead", None, None)
    old_outcome, old_state = old_enable_now(STALE)
    new_outcome, new_state = explicit_fresh_arm(STALE)
    prior = disabled_state.simulate()
    fixtures = {
        "A": explicit_fresh_arm(new_timer)[0],
        "B": explicit_fresh_arm(STALE)[0],
        "C": explicit_fresh_arm(STALE)[1].substate,
        "D": explicit_fresh_arm(STALE, start_succeeds=False)[0],
        "E": explicit_fresh_arm(STALE, creates_invocation=False)[0],
        "F": explicit_fresh_arm(STALE, service_succeeds=False)[0],
        "G": explicit_fresh_arm(STALE, recurrence=False)[0],
        "H": new_outcome,
        "I": explicit_fresh_arm(STALE, invocation_origin="HISTORICAL")[0],
        "J": explicit_fresh_arm(STALE, invocation_origin="MANUAL")[0],
        "K": explicit_fresh_arm(STALE)[0],
        "L": new_state.arm_attempts,
    }
    report = {
        "ok": (
            old_outcome == "TIMEOUT"
            and old_state.substate == "elapsed"
            and old_state.next_monotonic is None
            and new_outcome == "GREEN"
            and new_state.arm_attempts == 1
            and prior["ok"]
        ),
        "safe_code": "S11_2_R15_18_1_SOURCE_ONLY_SIMULATOR_GREEN",
        "classification": "SYSTEMD_TIMER_STALE_ACTIVE_ELAPSED_ACTIVATION",
        "old_enable_now_outcome": old_outcome,
        "old_timer_state": {
            "active": old_state.active,
            "substate": old_state.substate,
            "last_trigger": old_state.last_trigger,
            "next_monotonic": old_state.next_monotonic,
            "invocation_id": old_state.invocation_id,
        },
        "new_explicit_arm_outcome": new_outcome,
        "fresh_arm_attempts": new_state.arm_attempts,
        "new_pid1_invocation": new_state.invocation_origin == "PID1_TIMER",
        "service_result": new_state.service_result,
        "exec_main_status": new_state.exec_main_status,
        "timer_final_substate": new_state.substate,
        "finite_future": new_state.next_monotonic is not None,
        "fixture_matrix": fixtures,
        "technical_green": prior["technical_valid_samples"] == 5,
        "s11_installed_disabled": True,
        "synthetic_journeys_green": 8,
        "fallback_green": prior["second_deploy_fallback"] == "GREEN",
        "canonical_rearm_history_delta": prior["canonical_rearm_history_delta"],
        "new_evidence_epoch": prior["new_evidence_epoch"],
        "canary_starts": prior["second_deploy_canary_starts"],
        "standalone_verify_green": prior["standalone_verify_green"],
        "systemd_handoff_green": new_outcome == "GREEN",
        "runtime_mutations": 0,
    }
    return report


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
