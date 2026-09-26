#!/usr/bin/env python3
"""Read-only R15.5 S10 health preflight with stable structured run boundaries."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

try:
    from scripts.tu1nz_adult_public_community_health_contract import (
        CommunityHealthFailure,
        failure as community_failure,
        normalize_report as normalize_community_report,
    )
    from scripts.tu1nz_adult_public_s10_health_child_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
        CONTRACT_VERSION,
        HARD,
        OUTER_CODE,
        S10HealthFailure,
        TRANSIENT,
        UNKNOWN_HARD,
        failure as s10_failure,
        normalize_report as normalize_s10_report,
    )
except ModuleNotFoundError:  # direct execution from an installed Control copy
    from tu1nz_adult_public_community_health_contract import (
        CommunityHealthFailure,
        failure as community_failure,
        normalize_report as normalize_community_report,
    )
    from tu1nz_adult_public_s10_health_child_contract import (
        CHILD_MISSING,
        CHILD_UNKNOWN,
        CONTRACT_VERSION,
        HARD,
        OUTER_CODE,
        S10HealthFailure,
        TRANSIENT,
        UNKNOWN_HARD,
        failure as s10_failure,
        normalize_report as normalize_s10_report,
    )


MAXIMUM_INPUT_BYTES = 128 * 1024
PERSISTENT_OBSERVATIONS = 2
GREEN_CODES = frozenset({
    "S10_1_WMS_LOCAL_SFW_GREEN",
    "S10_1_WMS_PRE_GROWTH_SFW_GREEN",
    "S10_1_WMS_PUBLIC_SFW_GREEN",
})
COMMUNITY_EXIT = {
    "S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED": 40,
    "S10_2D_COMMUNITY_POLLER_RED": 41,
    "S10_2D_COMMUNITY_OFFSET_RED": 42,
    "S10_2D_COMMUNITY_PROVIDER_RED": 43,
    "S10_2D_COMMUNITY_STATE_RED": 44,
}


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _failure_dict(failure: S10HealthFailure | CommunityHealthFailure) -> dict[str, object]:
    if isinstance(failure, S10HealthFailure):
        return failure.as_dict()
    return {
        **failure.as_dict(),
        "classification": failure.decision_class,
        "exit_code": COMMUNITY_EXIT.get(failure.outer_code, 44),
        "retry": False,
    }


def _normalize_failure(report: Mapping[str, object]) -> dict[str, object]:
    if report.get("outer_code") == OUTER_CODE or report.get("safe_code") == OUTER_CODE:
        return _failure_dict(normalize_s10_report(report))
    return _failure_dict(normalize_community_report(report))


def parse_stream(material: str) -> list[dict[str, object]]:
    """Extract only versioned S10 JSON reports; ignore all unstructured journal text."""

    if len(material.encode("utf-8")) > MAXIMUM_INPUT_BYTES:
        return [{
            **s10_failure(CHILD_UNKNOWN, "INTERNAL_HEALTH_CONTRACT").as_dict(),
            "observed_at": "1970-01-01T00:00:00Z",
        }]
    reports: list[dict[str, object]] = []
    for line in material.splitlines():
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(candidate, dict):
            continue
        if (
            candidate.get("contract_version") == CONTRACT_VERSION
            and _timestamp(candidate.get("observed_at")) is not None
            and candidate.get("state") in {"GREEN", "RED"}
        ):
            reports.append(candidate)
    return reports


def evaluate(reports: list[dict[str, object]]) -> dict[str, object]:
    """Evaluate current state separately from retained failure evidence."""

    ordered: list[tuple[datetime, dict[str, object]]] = []
    for report in reports:
        observed_at = _timestamp(report.get("observed_at"))
        if observed_at is None or report.get("contract_version") != CONTRACT_VERSION:
            failure = s10_failure(CHILD_UNKNOWN, "INTERNAL_HEALTH_CONTRACT")
            report = {**failure.as_dict(), "observed_at": "1970-01-01T00:00:00Z"}
            observed_at = datetime(1970, 1, 1, tzinfo=timezone.utc)
        ordered.append((observed_at, report))
    ordered.sort(key=lambda item: item[0])
    if not ordered or len({item[0] for item in ordered}) != len(ordered):
        failure = s10_failure(CHILD_MISSING if not ordered else CHILD_UNKNOWN, "INTERNAL_HEALTH_CONTRACT")
        normalized = _failure_dict(failure)
        return {
            "current_health_state": "RED",
            "decision": "STOP_NO_DEPLOYMENT",
            "deployment_started": False,
            "last_failure": normalized,
            "last_recovery_time": None,
            "ok": False,
            "safe_code": "S11_2_R15_6_HEALTH_PREFLIGHT_RED",
            "separate_deployment_authorization_required": True,
        }

    normalized_runs: list[dict[str, object]] = []
    for observed_at, report in ordered:
        if (
            report.get("ok") is True
            and report.get("state") == "GREEN"
            and report.get("safe_code") in GREEN_CODES
        ):
            normalized_runs.append({
                "health_state": "GREEN",
                "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            })
        else:
            normalized_runs.append({
                **_normalize_failure(report),
                "health_state": "RED",
                "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            })

    current = normalized_runs[-1]
    failures = [run for run in normalized_runs if run["health_state"] == "RED"]
    last_failure = failures[-1] if failures else None
    last_recovery_time = None
    if current["health_state"] == "GREEN" and last_failure is not None:
        if current["observed_at"] > last_failure["observed_at"]:
            last_recovery_time = current["observed_at"]

    if current["health_state"] == "GREEN":
        return {
            "current_health_state": "GREEN",
            "decision": "PHASE_A_GREEN_SEPARATE_AUTHORIZATION_REQUIRED",
            "deployment_started": False,
            "last_failure": last_failure,
            "last_recovery_time": last_recovery_time,
            "ok": True,
            "safe_code": "S11_2_R15_6_HEALTH_PREFLIGHT_GREEN",
            "separate_deployment_authorization_required": True,
        }

    consecutive = 0
    for run in reversed(normalized_runs):
        if run.get("health_state") != "RED" or run.get("child_code") != current.get("child_code"):
            break
        consecutive += 1
    result = dict(current)
    if current.get("classification") == TRANSIENT and consecutive >= PERSISTENT_OBSERVATIONS:
        result["classification"] = "PERSISTENT_BLOCKER"
        result["decision_class"] = "PERSISTENT_BLOCKER"
        result["next_action"] = "STOP_AND_DIAGNOSE_PERSISTENT_HEALTH_BEFORE_NEW_AUTHORIZATION"
    return {
        "current_health_state": "RED",
        "decision": "STOP_NO_DEPLOYMENT",
        "deployment_started": False,
        "last_failure": result,
        "last_recovery_time": None,
        "ok": False,
        "safe_code": "S11_2_R15_6_HEALTH_PREFLIGHT_RED",
        "separate_deployment_authorization_required": True,
    }


def _at(offset: int) -> str:
    return (datetime(2026, 9, 26, tzinfo=timezone.utc) + timedelta(minutes=offset)).isoformat().replace("+00:00", "Z")


def _green(offset: int) -> dict[str, object]:
    return {
        "contract_version": CONTRACT_VERSION,
        "observed_at": _at(offset),
        "ok": True,
        "safe_code": "S10_1_WMS_PUBLIC_SFW_GREEN",
        "state": "GREEN",
    }


def _red(child_code: str, component: str, offset: int) -> dict[str, object]:
    return {**s10_failure(child_code, component).as_dict(), "observed_at": _at(offset)}


def _community_red(child_code: str, component: str, offset: int) -> dict[str, object]:
    return {
        **community_failure(child_code, component).as_dict(),
        "contract_version": CONTRACT_VERSION,
        "exit_code": 44,
        "observed_at": _at(offset),
        "retry": False,
    }


def simulate_contract() -> dict[str, object]:
    cases = {
        "A": evaluate([_green(0)]),
        "B": evaluate([_red("S10_TELEGRAM_HEALTH_RED", "GROWTH", 1)]),
        "C": evaluate([
            _red("S10_TELEGRAM_HEALTH_RED", "GROWTH", 1),
            _red("S10_TELEGRAM_HEALTH_RED", "GROWTH", 2),
        ]),
        "D": evaluate([_community_red("BOT_POLLER_NOT_RUNNING", "POLLING", 3)]),
        "E": evaluate([_community_red("BOT_POLLER_LEASE_RED", "POLLING", 4)]),
        "F": evaluate([_community_red("BOT_EVENT_PATH_RED", "POLLING", 5)]),
        "G": evaluate([_red("S10_DATABASE_STATE_RED", "DATABASE_STATE", 6)]),
        "H": evaluate([_community_red("BOT_RUNTIME_CONTRACT_MISMATCH", "LOCAL_CONFIG_HEALTH", 7)]),
        "I": evaluate([{**s10_failure(None, "INTERNAL_HEALTH_CONTRACT").as_dict(), "observed_at": _at(8)}]),
        "J": evaluate([{**s10_failure("NOT_ALLOWLISTED", "INTERNAL_HEALTH_CONTRACT").as_dict(), "observed_at": _at(9)}]),
        "K": evaluate([
            _red("S10_TELEGRAM_HEALTH_RED", "GROWTH", 10),
            _green(11),
        ]),
        "L": evaluate([_red("S10_PUBLIC_ENDPOINT_RED", "WMS_PUBLIC_HEALTH", 12)]),
    }
    expected_children = {
        "B": "S10_TELEGRAM_HEALTH_RED",
        "C": "S10_TELEGRAM_HEALTH_RED",
        "D": "BOT_POLLER_NOT_RUNNING",
        "E": "BOT_POLLER_LEASE_RED",
        "F": "BOT_EVENT_PATH_RED",
        "G": "S10_DATABASE_STATE_RED",
        "H": "BOT_RUNTIME_CONTRACT_MISMATCH",
        "I": CHILD_MISSING,
        "J": CHILD_UNKNOWN,
        "L": "S10_PUBLIC_ENDPOINT_RED",
    }
    ok = (
        cases["A"]["ok"] is True
        and cases["A"]["deployment_started"] is False
        and all(cases[name]["last_failure"]["child_code"] == child for name, child in expected_children.items())
        and cases["B"]["last_failure"]["classification"] == TRANSIENT
        and cases["C"]["last_failure"]["classification"] == "PERSISTENT_BLOCKER"
        and all(cases[name]["last_failure"]["classification"] != TRANSIENT for name in "DEFGHIJL")
        and cases["K"]["current_health_state"] == "GREEN"
        and cases["K"]["last_failure"]["child_code"] == "S10_TELEGRAM_HEALTH_RED"
        and cases["K"]["last_recovery_time"] == _at(11)
        and all(case["deployment_started"] is False for case in cases.values())
        and all(case["separate_deployment_authorization_required"] is True for case in cases.values())
    )
    return {
        "cases": cases,
        "contract_version": CONTRACT_VERSION,
        "deployment_started": False,
        "next_r15_5_runtime_deployment_ready": ok,
        "ok": ok,
        "runtime_mutation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--structured-runs", type=Path)
    parser.add_argument("--simulate-contract", action="store_true")
    arguments = parser.parse_args()
    if arguments.simulate_contract:
        report = simulate_contract()
    elif arguments.structured_runs is not None:
        try:
            material = arguments.structured_runs.read_text(encoding="utf-8")
        except OSError:
            material = ""
        report = evaluate(parse_stream(material))
    else:
        parser.error("one read-only input mode is required")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("ok") is True else 2


if __name__ == "__main__":
    sys.exit(main())
