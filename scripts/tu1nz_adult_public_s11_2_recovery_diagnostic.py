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
        CommunityHealthFailure,
        failure,
        failure_from_payload,
        normalize_report,
    )
except ModuleNotFoundError:  # direct execution from /usr/local/bin
    from tu1nz_adult_public_community_health_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
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
            "safe_code": "S11_2_R8_RECOVERY_DIAGNOSTIC_GREEN",
        }
    health_failure = normalize_report(report)
    return {
        **health_failure.as_dict(),
        "decision": "STOP_NO_RETRY",
        "ok": False,
        "retry": False,
        "safe_code": "S11_2_R8_RECOVERY_DIAGNOSTIC_RED",
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
        "safe_code": "S11_2_R10_RECOVERY_SIMULATOR_GREEN" if ok else "S11_2_R10_RECOVERY_SIMULATOR_RED",
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
