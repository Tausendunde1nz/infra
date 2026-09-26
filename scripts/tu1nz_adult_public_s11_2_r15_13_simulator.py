#!/usr/bin/env python3
"""Full source-only R15.13 Community envelope contract simulator."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import tu1nz_adult_public_community_health_contract as contract
from scripts import tu1nz_adult_public_s11_2_health_preflight as health_preflight
from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration


def envelope(child: object, component: object) -> dict[str, object]:
    return {
        "health_schema_version": contract.APPLICATION_HEALTH_SCHEMA_VERSION,
        "community_failure": {
            "schema": contract.COMMUNITY_FAILURE_ENVELOPE_SCHEMA,
            "version": contract.COMMUNITY_FAILURE_ENVELOPE_VERSION,
            "child_code": child,
            "component": component,
        },
        "ok": False,
        "safe_code": "S8_DIAGNOSTIC_RED",
        "state": "RED",
    }


def simulate() -> dict[str, object]:
    cases = {
        "provider": envelope("S10_2D_COMMUNITY_ADMIN_MISSING", "PROVIDER"),
        "event_path": envelope("BOT_EVENT_PATH_WAITING", "POLLING"),
        "moderation": envelope("S10_2D_MODERATION_DELIVERY_STATE_RED", "MODERATION"),
        "restriction": envelope("S10_2D_RESTRICTION_RELEASE_STATE_RED", "COMMUNITY"),
        "technical_latency": envelope("COMMUNITY_RUNTIME_LATENCY_RED", "LATENCY_SLO"),
        "unknown": envelope("NOT_ALLOWLISTED", "POLLING"),
    }
    reports: dict[str, object] = {}
    for name, payload in cases.items():
        failure = contract.failure_from_payload(payload, 2)
        reports[name] = failure.as_dict() if failure is not None else None
    event_failure = contract.failure_from_payload(cases["event_path"], 2)
    s10_report = {
        **event_failure.as_dict(),
        "contract_version": "S10_1_HEALTH_CHILD_V1",
        "exit_code": 44,
        "observed_at": "2026-09-26T00:00:00Z",
        "retry": False,
    }
    preflight = health_preflight.evaluate([s10_report])
    happy = orchestration.simulate("zero-missing-5-of-5")
    negative = {
        "application_child": event_failure.child_code,
        "canary_starts": 0,
        "component": event_failure.component,
        "outer_code": event_failure.outer_code,
        "pre_canary_decision": preflight["decision"],
        "pre_canary_child": preflight["last_failure"]["child_code"],
        "technical_probes": 0,
    }
    ok = (
        reports["provider"]["child_code"] == "S10_2D_COMMUNITY_ADMIN_MISSING"
        and reports["event_path"]["child_code"] == "BOT_EVENT_PATH_WAITING"
        and reports["moderation"]["child_code"] == "S10_2D_MODERATION_DELIVERY_STATE_RED"
        and reports["restriction"]["child_code"] == "S10_2D_RESTRICTION_RELEASE_STATE_RED"
        and reports["technical_latency"]["child_code"] == "COMMUNITY_RUNTIME_LATENCY_RED"
        and reports["unknown"]["child_code"] == contract.CHILD_UNKNOWN
        and happy["stopped"] is False
        and happy["technical_probes"] == 0
        and happy["canary_starts"] == 1
        and happy["technical_complete_before_canary"] is True
        and negative == {
            "application_child": "BOT_EVENT_PATH_WAITING",
            "canary_starts": 0,
            "component": "POLLING",
            "outer_code": "S10_2D_COMMUNITY_STATE_RED",
            "pre_canary_decision": "STOP_NO_DEPLOYMENT",
            "pre_canary_child": "BOT_EVENT_PATH_WAITING",
            "technical_probes": 0,
        }
    )
    return {
        "cases": reports,
        "control_reader_version": contract.CONTROL_COMMUNITY_READER_VERSION,
        "happy_path": happy,
        "negative_community_path": negative,
        "ok": ok,
        "runtime_mutation": False,
        "safe_code": "S11_2_R15_13_SIMULATOR_GREEN" if ok else "S11_2_R15_13_SIMULATOR_RED",
    }


if __name__ == "__main__":
    result = simulate()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if result["ok"] else 2)
