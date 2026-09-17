#!/usr/bin/env python3
"""Fail-closed S10.2D technical-readiness and human-acceptance contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


STRICT_PROFILE = "FULL_HUMAN_E2E"
DEFERRED_PROFILE = "TECHNICAL_RUNTIME_WITH_HUMAN_DEFERRED"
HUMAN_STATES = frozenset({"GREEN", "DEFERRED", "RED", "NOT_RUN"})
LATENCY_STATES = frozenset({"MEASURED", "NOT_MEASURED"})


class ReadinessContractError(ValueError):
    """A safe, user-independent contract failure."""


def require(condition: bool, safe_code: str) -> None:
    if not condition:
        raise ReadinessContractError(safe_code)


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReadinessContractError("READINESS_MANIFEST_RED") from error
    require(isinstance(value, dict), "READINESS_MANIFEST_RED")
    require(
        value.get("version") == "tu1nz-commercial-s10-2d-r8-3-technical-readiness-v1",
        "READINESS_MANIFEST_VERSION_RED",
    )
    return value


def _integer(value: object, safe_code: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), safe_code)
    return int(value)


def _human_contract(manifest: dict[str, Any], profile: str) -> tuple[dict[str, str], dict[str, str]]:
    human = manifest.get("human_acceptance")
    latency = manifest.get("human_latency")
    require(isinstance(human, dict), "HUMAN_ACCEPTANCE_CONTRACT_RED")
    require(isinstance(latency, dict), "HUMAN_LATENCY_CONTRACT_RED")
    require(
        set(human) == {"direct_bot", "community", "moderation"},
        "HUMAN_ACCEPTANCE_CONTRACT_RED",
    )
    require(
        set(latency) == {"bot_response", "join_welcome"},
        "HUMAN_LATENCY_CONTRACT_RED",
    )
    require(all(value in HUMAN_STATES for value in human.values()), "HUMAN_ACCEPTANCE_STATE_RED")
    require(all(value in LATENCY_STATES for value in latency.values()), "HUMAN_LATENCY_STATE_RED")
    require("RED" not in human.values(), "HUMAN_ACCEPTANCE_RED")
    required_human = "GREEN" if profile == STRICT_PROFILE else "DEFERRED"
    required_latency = "MEASURED" if profile == STRICT_PROFILE else "NOT_MEASURED"
    require(all(value == required_human for value in human.values()), "HUMAN_ACCEPTANCE_PROFILE_RED")
    require(all(value == required_latency for value in latency.values()), "HUMAN_LATENCY_PROFILE_RED")
    return dict(human), dict(latency)


def evaluate_readiness(
    manifest: dict[str, Any],
    evidence: dict[str, Any],
    profile: str,
    *,
    enforce_selected_profile: bool = True,
) -> dict[str, Any]:
    profiles = manifest.get("acceptance_profiles")
    require(isinstance(profiles, dict), "ACCEPTANCE_PROFILE_CONTRACT_RED")
    require(profile in profiles, "UNKNOWN_ACCEPTANCE_PROFILE")
    require(profile in {STRICT_PROFILE, DEFERRED_PROFILE}, "UNKNOWN_ACCEPTANCE_PROFILE")
    require(isinstance(profiles[profile], dict), "ACCEPTANCE_PROFILE_CONTRACT_RED")
    if enforce_selected_profile:
        require(
            profile == manifest.get("acceptance_profile"),
            "ACCEPTANCE_PROFILE_SELECTION_RED",
        )

    technical = evidence.get("technical_gates")
    required_gates = manifest.get("technical_readiness", {}).get("required_gates")
    require(isinstance(technical, dict), "TECHNICAL_EVIDENCE_RED")
    require(isinstance(required_gates, list) and required_gates, "TECHNICAL_GATE_CONTRACT_RED")
    require(set(technical) == set(required_gates), "TECHNICAL_GATE_SET_RED")
    require(all(technical.get(gate) is True for gate in required_gates), "TECHNICAL_GATE_RED")

    expected_release = manifest.get("technical_evidence_release_id")
    require(isinstance(expected_release, str) and expected_release, "TECHNICAL_RELEASE_CONTRACT_RED")
    require(evidence.get("technical_evidence_release_id") == expected_release, "TECHNICAL_EVIDENCE_STALE")
    require(evidence.get("technical_evidence_run_bound") is True, "TECHNICAL_EVIDENCE_RUN_RED")

    observation = _integer(evidence.get("observation_duration_seconds"), "OBSERVATION_EVIDENCE_RED")
    minimum_observation = _integer(
        manifest.get("minimum_observation_seconds"), "OBSERVATION_CONTRACT_RED"
    )
    require(observation >= minimum_observation, "OBSERVATION_WINDOW_INCOMPLETE")
    require(_integer(evidence.get("pending_moderation"), "MODERATION_EVIDENCE_RED") == 0, "MODERATION_OUTBOX_PENDING")
    require(_integer(evidence.get("stuck_restrictions"), "MODERATION_EVIDENCE_RED") == 0, "COMMUNITY_RESTRICTION_STUCK")
    require(_integer(evidence.get("unknown_retained_state"), "RETAINED_STATE_EVIDENCE_RED") == 0, "RETAINED_UNKNOWN_STATE_RED")
    require(evidence.get("real_acquisition_active") is False, "REAL_ACQUISITION_UNEXPECTEDLY_ACTIVE")
    require(evidence.get("real_acquisition_baseline_start") is None, "REAL_ACQUISITION_BASELINE_UNEXPECTED")

    boundaries = manifest.get("product_boundaries")
    require(isinstance(boundaries, dict) and boundaries, "PRODUCT_BOUNDARY_CONTRACT_RED")
    require(all(value == "CLOSED" for value in boundaries.values()), "PRODUCT_BOUNDARY_RED")

    human, latency = _human_contract(manifest, profile)
    samples = _integer(evidence.get("bot_response_samples"), "LATENCY_SAMPLE_EVIDENCE_RED")
    p50 = evidence.get("bot_response_p50_ms")
    p95 = evidence.get("bot_response_p95_ms")
    p99 = evidence.get("bot_response_p99_ms")
    if profile == STRICT_PROFILE:
        strict = profiles[STRICT_PROFILE]
        minimum_samples = _integer(strict.get("minimum_samples"), "LATENCY_SAMPLE_CONTRACT_RED")
        require(samples >= minimum_samples, "LATENCY_SAMPLE_FLOOR_MISSING")
        for value, name, limit_key, safe_code in (
            (p50, "p50", "p50_strictly_less_than_ms", "LATENCY_P50_RED"),
            (p95, "p95", "p95_strictly_less_than_ms", "LATENCY_P95_RED"),
            (p99, "p99", "p99_strictly_less_than_ms", "LATENCY_P99_RED"),
        ):
            measured = _integer(value, f"LATENCY_{name.upper()}_EVIDENCE_RED")
            limit = _integer(strict.get(limit_key), "LATENCY_LIMIT_CONTRACT_RED")
            require(0 <= measured < limit, safe_code)
    else:
        require(profiles[DEFERRED_PROFILE].get("human_samples_required") is False, "DEFERRED_PROFILE_CONTRACT_RED")
        p50 = p95 = p99 = None

    return {
        "ok": True,
        "safe_code": "S10_2D_R8_3_TECHNICAL_READINESS_GREEN",
        "acceptance_profile": profile,
        "technical_runtime_status": "GO",
        "WMS_REAL_ACQUISITION_TECHNICALLY_READY": True,
        "DIRECT_BOT_TECHNICAL_RUNTIME": "GO",
        "COMMUNITY_RUNTIME_TECHNICAL": "GO",
        "MODERATION_TECHNICAL": "GO",
        "DIRECT_BOT_HUMAN_ACCEPTANCE": human["direct_bot"],
        "COMMUNITY_HUMAN_ACCEPTANCE": human["community"],
        "MODERATION_HUMAN_LIVE_ACCEPTANCE": human["moderation"],
        "BOT_RESPONSE_LATENCY": latency["bot_response"],
        "JOIN_WELCOME_LATENCY": latency["join_welcome"],
        "observation_duration_seconds": observation,
        "technical_evidence_release_id": expected_release,
        "latency_samples": samples,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "REAL_ACQUISITION_ACTIVE": False,
        "REAL_ACQUISITION_BASELINE_START": None,
        "business_loop_state": "WAITING_OPERATOR_ACQUISITION_GO",
        "automatic_link_seeding": False,
        "adult_media": False,
        "avs": False,
        "payments": False,
        "publishing": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    arguments = parser.parse_args()
    try:
        evidence = json.load(sys.stdin)
        require(isinstance(evidence, dict), "TECHNICAL_EVIDENCE_RED")
        report = evaluate_readiness(
            load_manifest(arguments.manifest), evidence, arguments.profile
        )
    except (OSError, json.JSONDecodeError, ReadinessContractError) as error:
        candidate = str(error)
        safe_code = (
            candidate
            if candidate.isupper() and " " not in candidate
            else "READINESS_CONTRACT_UNEXPECTED_RED"
        )
        print(json.dumps({"ok": False, "safe_code": safe_code}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
