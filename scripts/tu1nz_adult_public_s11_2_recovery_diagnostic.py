#!/usr/bin/env python3
"""Source-only R8 recovery diagnostic: classify precisely and never retry."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Mapping

try:
    from scripts.tu1nz_adult_public_community_health_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
        TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE,
        TELEGRAM_HEALTH_RED,
        CommunityHealthFailure,
        failure,
        failure_from_payload,
        normalize_report,
    )
except ModuleNotFoundError:  # direct execution from /usr/local/bin
    from tu1nz_adult_public_community_health_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
        TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE,
        TELEGRAM_HEALTH_RED,
        CommunityHealthFailure,
        failure,
        failure_from_payload,
        normalize_report,
    )


MAXIMUM_INPUT_BYTES = 64 * 1024


def diagnose(report: object) -> dict[str, object]:
    if isinstance(report, Mapping) and report.get("ok") is True:
        return {
            "decision": "HEALTH_GREEN",
            "ok": True,
            "retry": False,
            "safe_code": "S11_2_R12_RECOVERY_DIAGNOSTIC_GREEN",
        }
    health_failure = normalize_report(report)
    return {
        **health_failure.as_dict(),
        "decision": "STOP_NO_RETRY",
        "ok": False,
        "retry": False,
        "safe_code": "S11_2_R12_RECOVERY_DIAGNOSTIC_RED",
    }


def parse_stream(material: str) -> object:
    if len(material.encode("utf-8")) > MAXIMUM_INPUT_BYTES:
        return {}
    candidate: object = {}
    for line in material.splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, Mapping) and (
            parsed.get("outer_code") is not None
            or parsed.get("safe_code") == "S10_2D_COMMUNITY_STATE_RED"
            or parsed.get("safe_code") == TELEGRAM_HEALTH_RED
        ):
            candidate = parsed
    return candidate


def _report(child_code: object = None, component: str = "COMMUNITY") -> dict[str, object]:
    return failure(child_code, component).as_dict()


def _community_payload(
    technical: str,
    full: str,
    *,
    canary_technical: str = "INSUFFICIENT_EVIDENCE",
    canary_real: str = "INSUFFICIENT_EVIDENCE",
    pending_moderation: int = 0,
) -> dict[str, object]:
    def profile(name: str, state: str) -> dict[str, object]:
        return {"profile": name, "state": state, "samples": 0 if state == "INSUFFICIENT_EVIDENCE" else 5}

    return {
        "ok": True,
        "state": "GREEN",
        "community": {
            "bot_event_path": {"ok": True, "safe_code": "BOT_EVENT_PATH_GREEN"},
            "latency_24h": {"samples": 0},
            "latency_degraded": full == "RED",
            "latency_slo_profiles": {
                "TECHNICAL_RUNTIME_LATENCY": profile("TECHNICAL_RUNTIME_LATENCY", technical),
                "REAL_USER_DIRECT_LATENCY": profile("REAL_USER_DIRECT_LATENCY", full),
                "S11_CANARY_TECHNICAL_LATENCY": profile("S11_CANARY_TECHNICAL_LATENCY", canary_technical),
                "S11_CANARY_REAL_USER_LATENCY": profile("S11_CANARY_REAL_USER_LATENCY", canary_real),
            },
            "pending_moderation": pending_moderation,
            "provider": {"ok": True, "safe_code": "S10_2D_COMMUNITY_GREEN"},
            "stuck_restrictions": 0,
        },
    }


def _runtime_decision(payload: dict[str, object], return_code: int = 0) -> dict[str, object]:
    runtime_failure = failure_from_payload(payload, return_code)
    if runtime_failure is None:
        return {"decision": "HEALTH_GREEN", "ok": True, "retry": False}
    return diagnose(runtime_failure.as_dict())


def _telegram_health_report(state: str) -> dict[str, object]:
    if state == "GREEN":
        return {"ok": True, "safe_code": "S9_TELEGRAM_CHANNEL_GREEN", "state": "GREEN"}
    if state == "RED":
        return {"ok": False, "safe_code": TELEGRAM_HEALTH_RED, "state": "RED"}
    raise ValueError("S11_2_R12_TELEGRAM_SIMULATION_STATE_INVALID")


def simulate_telegram_sequence(*states: str) -> dict[str, object]:
    """Model observations without granting or executing a runtime retry."""

    if not states:
        raise ValueError("S11_2_R12_TELEGRAM_SIMULATION_EMPTY")
    observations = [diagnose(_telegram_health_report(state)) for state in states]
    persistent = len(states) >= 3 and all(state == "RED" for state in states)
    recovered_after_red = "RED" in states[:-1] and states[-1] == "GREEN"
    if persistent:
        classification = "PERSISTENT_PROVIDER_BLOCKER"
    elif recovered_after_red:
        classification = TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE
    elif states[-1] == "RED":
        classification = TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE
    else:
        classification = "TELEGRAM_HEALTH_GREEN"
    return {
        "classification": classification,
        "observations": observations,
        "ok": all(
            observation.get("retry") is False
            and (
                observation.get("decision") == "HEALTH_GREEN"
                or observation.get("child_code") == TELEGRAM_HEALTH_RED
            )
            for observation in observations
        ),
        "runtime_retry_authorized": False,
    }


def simulate_recovery_paths() -> dict[str, object]:
    telegram_red = diagnose(_telegram_health_report("RED"))
    telegram_green = diagnose(_telegram_health_report("GREEN"))
    red_path = {
        "child_code": telegram_red.get("child_code"),
        "decision": telegram_red["decision"],
        "poller": "GREEN",
        "rollback": True,
        "s8_start_count": 1,
        "s9": "GREEN",
        "s10_telegram": "RED",
        "second_start": False,
    }
    green_path = {
        "decision": telegram_green["decision"],
        "poller": "GREEN",
        "recovery_complete": True,
        "rollback": False,
        "s8_start_count": 1,
        "s9": "GREEN",
        "s10_telegram": "GREEN",
        "second_start": False,
    }
    ok = (
        red_path["child_code"] == TELEGRAM_HEALTH_RED
        and red_path["decision"] == "STOP_NO_RETRY"
        and red_path["rollback"] is True
        and red_path["s8_start_count"] == 1
        and red_path["second_start"] is False
        and green_path["decision"] == "HEALTH_GREEN"
        and green_path["recovery_complete"] is True
        and green_path["s8_start_count"] == 1
        and green_path["second_start"] is False
    )
    return {"green_path": green_path, "ok": ok, "red_path": red_path}


def simulate_contract() -> dict[str, object]:
    cases = {
        "A": _runtime_decision(_community_payload("GREEN", "INSUFFICIENT_EVIDENCE")),
        "B": _runtime_decision(_community_payload("GREEN", "INSUFFICIENT_EVIDENCE", canary_real="INSUFFICIENT_EVIDENCE")),
        "C": _runtime_decision(_community_payload("GREEN", "GREEN", canary_technical="GREEN", canary_real="GREEN")),
        "D": _runtime_decision(_community_payload("GREEN", "RED", canary_technical="GREEN", canary_real="RED")),
        "E": _runtime_decision(_community_payload("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", canary_technical="GREEN")),
        "F": _runtime_decision(_community_payload("RED", "RED")),
        "G": _runtime_decision(_community_payload("GREEN", "INSUFFICIENT_EVIDENCE", pending_moderation=1)),
        "H": diagnose(_report("BOT_RUNTIME_CONTRACT_MISMATCH", "LOCAL_CONFIG_HEALTH")),
        "I": _runtime_decision(_community_payload("RED", "INSUFFICIENT_EVIDENCE")),
        "J": _runtime_decision(_community_payload("GREEN", "INSUFFICIENT_EVIDENCE")),
    }
    expectations = {
        "A": ("HEALTH_GREEN", None),
        "B": ("HEALTH_GREEN", None),
        "C": ("HEALTH_GREEN", None),
        "D": ("HEALTH_GREEN", None),
        "E": ("HEALTH_GREEN", None),
        "F": ("STOP_NO_RETRY", "COMMUNITY_RUNTIME_LATENCY_RED"),
        "G": ("STOP_NO_RETRY", "S10_2D_MODERATION_DELIVERY_STATE_RED"),
        "H": ("STOP_NO_RETRY", "BOT_RUNTIME_CONTRACT_MISMATCH"),
        "I": ("STOP_NO_RETRY", "COMMUNITY_RUNTIME_LATENCY_RED"),
        "J": ("HEALTH_GREEN", None),
    }
    ok = all(
        cases[name].get("decision") == expected[0]
        and cases[name].get("child_code") == expected[1]
        and cases[name].get("retry") is False
        for name, expected in expectations.items()
    )
    telegram = {
        "transient": simulate_telegram_sequence("RED", "GREEN"),
        "persistent": simulate_telegram_sequence("RED", "RED", "RED"),
        "configuration": diagnose(
            _report("S10_2D_COMMUNITY_ADMIN_RIGHT_MISSING", "PROVIDER")
        ),
        "release_binding": diagnose(
            _report("BOT_RUNTIME_CONTRACT_MISMATCH", "LOCAL_CONFIG_HEALTH")
        ),
    }
    recovery = simulate_recovery_paths()
    ok = (
        ok
        and telegram["transient"]["ok"] is True
        and telegram["transient"]["runtime_retry_authorized"] is False
        and telegram["persistent"]["classification"] == "PERSISTENT_PROVIDER_BLOCKER"
        and telegram["persistent"]["runtime_retry_authorized"] is False
        and telegram["configuration"]["decision"] == "STOP_NO_RETRY"
        and telegram["release_binding"]["decision"] == "STOP_NO_RETRY"
        and recovery["ok"] is True
    )
    return {
        "cases": {
            name: {
                "child_code": result.get("child_code"),
                "decision": result["decision"],
                "decision_class": result.get("decision_class"),
                "retry": result["retry"],
            }
            for name, result in cases.items()
        },
        "ok": ok,
        "recovery": recovery,
        "safe_code": "S11_2_R12_RECOVERY_SIMULATOR_GREEN" if ok else "S11_2_R12_RECOVERY_SIMULATOR_RED",
        "telegram": telegram,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate-contract", action="store_true")
    parser.add_argument("--parse-stream", action="store_true")
    arguments = parser.parse_args()
    if arguments.simulate_contract:
        report = simulate_contract()
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["ok"] is True else 2
    if not arguments.parse_stream:
        parser.error("one mode is required")
    report = diagnose(parse_stream(sys.stdin.read(MAXIMUM_INPUT_BYTES + 1)))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
