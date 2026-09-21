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
        normalize_report,
    )
except ModuleNotFoundError:  # direct execution from /usr/local/bin
    from tu1nz_adult_public_community_health_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
        CommunityHealthFailure,
        failure,
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


def simulate_contract() -> dict[str, object]:
    cases = {
        "A": diagnose({"ok": True, "state": "GREEN"}),
        "B": diagnose(_report("S11_COMMUNITY_LATENCY_SLO_RED", "LATENCY_SLO")),
        "C": diagnose({"ok": False, "outer_code": "S10_2D_COMMUNITY_STATE_RED"}),
        "D": diagnose(_report("NOT_CANONICAL", "COMMUNITY")),
        "E": diagnose(_report("BOT_RUNTIME_CONTRACT_MISMATCH", "LOCAL_CONFIG_HEALTH")),
        "F": diagnose(_report("BOT_POLLER_NOT_RUNNING", "POLLING")),
        "G": diagnose(_report("BOT_EVENT_PATH_RED", "POLLING")),
        "H": diagnose(_report("RETAINED_MODERATION_STATE_RED", "RETAINED_STATE")),
        "I": diagnose(_report("S10_2D_COMMUNITY_PROFILE_MISMATCH", "PROVIDER")),
    }
    expectations = {
        "A": ("HEALTH_GREEN", None),
        "B": ("STOP_NO_RETRY", "S11_COMMUNITY_LATENCY_SLO_RED"),
        "C": ("STOP_NO_RETRY", CHILD_MISSING),
        "D": ("STOP_NO_RETRY", CHILD_UNKNOWN),
        "E": ("STOP_NO_RETRY", "BOT_RUNTIME_CONTRACT_MISMATCH"),
        "F": ("STOP_NO_RETRY", "BOT_POLLER_NOT_RUNNING"),
        "G": ("STOP_NO_RETRY", "BOT_EVENT_PATH_RED"),
        "H": ("STOP_NO_RETRY", "RETAINED_MODERATION_STATE_RED"),
        "I": ("STOP_NO_RETRY", "S10_2D_COMMUNITY_PROFILE_MISMATCH"),
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
        "safe_code": "S11_2_R8_RECOVERY_SIMULATOR_GREEN" if ok else "S11_2_R8_RECOVERY_SIMULATOR_RED",
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
