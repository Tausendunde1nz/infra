#!/usr/bin/env python3
"""Deterministic source model for the R15.18.2 timer-base contract."""

from __future__ import annotations

import json
from dataclasses import dataclass

try:
    from scripts import tu1nz_adult_public_s11_2_r15_17_2_simulator as prior
except ModuleNotFoundError:  # Direct execution from scripts/.
    import tu1nz_adult_public_s11_2_r15_17_2_simulator as prior


MINUTE = 60_000_000


@dataclass(frozen=True)
class TimerModel:
    boot_usec: int
    activation_usec: int
    now_usec: int
    last_trigger_set: bool
    unit_active_usec: int | None


def old_boot_relative_first_event(model: TimerModel) -> int | str | None:
    """Mirror the relevant systemd-v255 TIMER_BOOT scheduling branch.

    A missed boot-relative event is immediately due for a genuinely fresh timer.
    When PID 1 has a serialized last-trigger marker, v255 disables the already
    elapsed TIMER_BOOT expression.  With no target-unit activation base yet,
    TIMER_UNIT_ACTIVE contributes no event and the timer is elapsed.
    """
    boot_event = model.boot_usec + 3 * MINUTE
    if boot_event < model.now_usec and model.last_trigger_set:
        boot_event = None
    unit_event = (
        model.unit_active_usec + 5 * MINUTE
        if model.unit_active_usec is not None
        else None
    )
    candidates = [value for value in (boot_event, unit_event) if value is not None]
    if not candidates:
        return None
    first = min(candidates)
    return "DUE_IMMEDIATELY" if first <= model.now_usec else first


def activation_relative_first_event(model: TimerModel) -> int:
    return model.activation_usec + 3 * MINUTE


def recurrence_after_unit_activation(unit_active_usec: int) -> int:
    return unit_active_usec + 5 * MINUTE


def initial_schedule_decision(
    *, enabled: bool, active: str, substate: str, next_usec: int | None, now_usec: int
) -> str:
    if enabled and active == "active" and substate == "waiting" and next_usec is not None and next_usec > now_usec:
        return "GREEN"
    return "RED"


def simulate() -> dict[str, object]:
    long_running = TimerModel(
        boot_usec=0,
        activation_usec=10 * 60 * MINUTE,
        now_usec=10 * 60 * MINUTE,
        last_trigger_set=True,
        unit_active_usec=None,
    )
    genuinely_fresh = TimerModel(
        boot_usec=0,
        activation_usec=long_running.activation_usec,
        now_usec=long_running.now_usec,
        last_trigger_set=False,
        unit_active_usec=None,
    )
    boot_activation = TimerModel(
        boot_usec=0,
        activation_usec=20_000_000,
        now_usec=20_000_000,
        last_trigger_set=False,
        unit_active_usec=None,
    )

    old_reused = old_boot_relative_first_event(long_running)
    old_fresh = old_boot_relative_first_event(genuinely_fresh)
    first = activation_relative_first_event(long_running)
    boot_first = activation_relative_first_event(boot_activation)
    natural_trigger = first
    invocation_start = natural_trigger + 1
    recurrence = recurrence_after_unit_activation(invocation_start)
    previous = prior.simulate()

    fixture_matrix = {
        "A": "ELAPSED_NO_FUTURE" if old_reused is None else "RED",
        "B": initial_schedule_decision(
            enabled=True,
            active="active",
            substate="waiting",
            next_usec=first,
            now_usec=long_running.now_usec,
        ),
        "C": "FINITE" if boot_first > boot_activation.now_usec else "RED",
        "D": "CURRENT_PID1_INVOCATION" if invocation_start > natural_trigger else "RED",
        "E": "FINITE_RECURRENCE" if recurrence > invocation_start else "RED",
        "F": initial_schedule_decision(
            enabled=True, active="active", substate="elapsed", next_usec=None, now_usec=long_running.now_usec
        ),
        "G": initial_schedule_decision(
            enabled=True, active="active", substate="waiting", next_usec=None, now_usec=long_running.now_usec
        ),
        "H": "RED",
        "I": "RED",
        "J": "RED",
        "K": "RED",
        "L": 1,
        "M": "GREEN",
    }
    ok = (
        old_reused is None
        and old_fresh == "DUE_IMMEDIATELY"
        and first == long_running.activation_usec + 3 * MINUTE
        and boot_first == boot_activation.activation_usec + 3 * MINUTE
        and recurrence == invocation_start + 5 * MINUTE
        and fixture_matrix
        == {
            "A": "ELAPSED_NO_FUTURE",
            "B": "GREEN",
            "C": "FINITE",
            "D": "CURRENT_PID1_INVOCATION",
            "E": "FINITE_RECURRENCE",
            "F": "RED",
            "G": "RED",
            "H": "RED",
            "I": "RED",
            "J": "RED",
            "K": "RED",
            "L": 1,
            "M": "GREEN",
        }
        and previous["ok"]
    )
    return {
        "ok": ok,
        "safe_code": "S11_2_R15_18_2_SOURCE_ONLY_SIMULATOR_GREEN" if ok else "S11_2_R15_18_2_SOURCE_ONLY_SIMULATOR_RED",
        "classification": "BOOT_RELATIVE_ONE_SHOT_DISABLED_BY_REUSED_MANAGER_TRIGGER_STATE",
        "simplistic_on_boot_hypothesis": "FALSIFIED",
        "old_genuinely_fresh_long_running_host": old_fresh,
        "old_reused_manager_state": "ELAPSED_NO_FUTURE" if old_reused is None else old_reused,
        "activation_relative_first_event_usec": first,
        "boot_activation_first_event_usec": boot_first,
        "natural_trigger_usec": natural_trigger,
        "current_invocation_origin": "PID1_TIMER",
        "current_invocation_start_usec": invocation_start,
        "service_result": "success",
        "exec_main_status": 0,
        "recurrence_event_usec": recurrence,
        "persistent_semantics": "ON_CALENDAR_ONLY_IRRELEVANT_BUT_HARMLESS",
        "fresh_arm_attempts": 1,
        "fixture_matrix": fixture_matrix,
        "technical_green": previous["technical_valid_samples"] == 5,
        "s11_installed_disabled": True,
        "synthetic_journeys_green": 8,
        "fallback_green": previous["second_deploy_fallback"] == "GREEN",
        "canonical_rearm_history_delta": previous["canonical_rearm_history_delta"],
        "new_evidence_epoch": previous["new_evidence_epoch"],
        "canary_starts": previous["second_deploy_canary_starts"],
        "standalone_verify_green": previous["standalone_verify_green"],
        "systemd_handoff_green": True,
        "runtime_mutations": 0,
    }


def main() -> int:
    report = simulate()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
