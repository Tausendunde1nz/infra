#!/usr/bin/env python3
"""Strict, privacy-safe outer/child contract for WMS Community health."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


OUTER_STATE_RED = "S10_2D_COMMUNITY_STATE_RED"
CHILD_MISSING = "COMMUNITY_CHILD_CODE_MISSING_RED"
CHILD_UNKNOWN = "COMMUNITY_CHILD_CODE_UNKNOWN_RED"
TELEGRAM_HEALTH_RED = "S10_TELEGRAM_HEALTH_RED"

RETRYABLE_RUNTIME_READINESS = "RETRYABLE_RUNTIME_READINESS"
STATE_INTEGRITY_BLOCKER = "STATE_INTEGRITY_BLOCKER"
RELEASE_BINDING_BLOCKER = "RELEASE_BINDING_BLOCKER"
PROVIDER_EXTERNAL_BLOCKER = "PROVIDER_EXTERNAL_BLOCKER"
TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE = "TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE"
UNKNOWN_HARD_RED = "UNKNOWN_HARD_RED"

TRANSIENT_PROVIDER_OR_TIMING = "TRANSIENT_PROVIDER_OR_TIMING"
PROVIDER_UNREACHABLE = "PROVIDER_UNREACHABLE"
CHANNEL_CONFIGURATION_RED = "CHANNEL_CONFIGURATION_RED"
RELEASE_OR_BOT_BINDING_RED = "RELEASE_OR_BOT_BINDING_RED"
AUTHORIZATION_OR_PERMISSION_RED = "AUTHORIZATION_OR_PERMISSION_RED"
INTERNAL_RUNTIME_RED = "INTERNAL_RUNTIME_RED"
NOT_TELEGRAM_SPECIFIC = "NOT_TELEGRAM_SPECIFIC"

CHILD_CLASSIFICATION = {
    "BOT_POLLER_NOT_RUNNING": RETRYABLE_RUNTIME_READINESS,
    "BOT_POLLER_LEASE_RED": RETRYABLE_RUNTIME_READINESS,
    "BOT_EVENT_PATH_WAITING": RETRYABLE_RUNTIME_READINESS,
    "BOT_EVENT_PATH_TIMEOUT": RETRYABLE_RUNTIME_READINESS,
    "S8_POLLING_HEARTBEAT_MISSING": RETRYABLE_RUNTIME_READINESS,
    "S8_POLLING_HEARTBEAT_STALE": RETRYABLE_RUNTIME_READINESS,
    "BOT_OFFSET_STALLED": STATE_INTEGRITY_BLOCKER,
    "BOT_EVENT_PATH_RED": STATE_INTEGRITY_BLOCKER,
    "BOT_HANDLER_NOT_STARTED": STATE_INTEGRITY_BLOCKER,
    "BOT_HANDLER_TIMEOUT": STATE_INTEGRITY_BLOCKER,
    "BOT_RESPONSE_NOT_SENT": STATE_INTEGRITY_BLOCKER,
    "BOT_METRIC_PATH_MISSING": STATE_INTEGRITY_BLOCKER,
    "S10_2D_MODERATION_ATTEMPT_STATE_RED": STATE_INTEGRITY_BLOCKER,
    "S10_2D_MODERATION_DELIVERY_STATE_RED": STATE_INTEGRITY_BLOCKER,
    "S10_2D_RESTRICTION_RELEASE_STATE_RED": STATE_INTEGRITY_BLOCKER,
    "RETAINED_MODERATION_STATE_RED": STATE_INTEGRITY_BLOCKER,
    "COMMUNITY_RUNTIME_LATENCY_RED": STATE_INTEGRITY_BLOCKER,
    "S11_COMMUNITY_LATENCY_SLO_RED": STATE_INTEGRITY_BLOCKER,
    "S8_PRODUCT_BOUNDARY_RED": STATE_INTEGRITY_BLOCKER,
    "S8_QUEUE_FAILED_DELIVERIES_PRESENT": STATE_INTEGRITY_BLOCKER,
    "BOT_RUNTIME_CONTRACT_MISMATCH": RELEASE_BINDING_BLOCKER,
    "S8_LOCAL_CONFIG_AND_BOT_ID_BOUND": RELEASE_BINDING_BLOCKER,
    "S8_TELEGRAM_IDENTITY_MISMATCH": RELEASE_BINDING_BLOCKER,
    "S8_DATABASE_CREDENTIAL_INVALID": RELEASE_BINDING_BLOCKER,
    "S8_TELEGRAM_CREDENTIAL_INVALID": RELEASE_BINDING_BLOCKER,
    "S10_2D_COMMUNITY_CONTROL_MISSING": RELEASE_BINDING_BLOCKER,
    "COMMUNITY_LATENCY_PROFILE_CONTRACT_RED": RELEASE_BINDING_BLOCKER,
    "S10_2D_COMMUNITY_PROFILE_MISMATCH": PROVIDER_EXTERNAL_BLOCKER,
    "S10_2D_COMMUNITY_ADMIN_MISSING": PROVIDER_EXTERNAL_BLOCKER,
    "S10_2D_COMMUNITY_ADMIN_RIGHT_MISSING": PROVIDER_EXTERNAL_BLOCKER,
    "S10_2D_COMMUNITY_ADMIN_RIGHT_EXCESS": PROVIDER_EXTERNAL_BLOCKER,
    "S10_2D_COMMUNITY_DEFAULT_PERMISSIONS_MISMATCH": PROVIDER_EXTERNAL_BLOCKER,
    "S10_2D_COMMUNITY_RULES_NOT_PINNED": PROVIDER_EXTERNAL_BLOCKER,
    "BOT_TELEGRAM_SEND_FAILED": PROVIDER_EXTERNAL_BLOCKER,
    "S8_TELEGRAM_IDENTITY_UNVERIFIED_REMOTE_UNAVAILABLE": PROVIDER_EXTERNAL_BLOCKER,
    "S8_TRANSPORT_CIRCUIT_OPEN": PROVIDER_EXTERNAL_BLOCKER,
    "S8_TRANSPORT_ERROR_BUDGET_EXHAUSTED": PROVIDER_EXTERNAL_BLOCKER,
    TELEGRAM_HEALTH_RED: TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE,
    CHILD_MISSING: UNKNOWN_HARD_RED,
    CHILD_UNKNOWN: UNKNOWN_HARD_RED,
}
ALLOWED_CHILD_CODES = frozenset(CHILD_CLASSIFICATION)

TELEGRAM_FAILURE_CLASSIFICATION = {
    TELEGRAM_HEALTH_RED: TRANSIENT_PROVIDER_OR_TIMING,
    "BOT_TELEGRAM_SEND_FAILED": PROVIDER_UNREACHABLE,
    "S8_TELEGRAM_IDENTITY_UNVERIFIED_REMOTE_UNAVAILABLE": PROVIDER_UNREACHABLE,
    "S8_TRANSPORT_CIRCUIT_OPEN": PROVIDER_UNREACHABLE,
    "S8_TRANSPORT_ERROR_BUDGET_EXHAUSTED": PROVIDER_UNREACHABLE,
    "S10_2D_COMMUNITY_PROFILE_MISMATCH": CHANNEL_CONFIGURATION_RED,
    "S10_2D_COMMUNITY_ADMIN_MISSING": AUTHORIZATION_OR_PERMISSION_RED,
    "S10_2D_COMMUNITY_ADMIN_RIGHT_MISSING": AUTHORIZATION_OR_PERMISSION_RED,
    "S10_2D_COMMUNITY_ADMIN_RIGHT_EXCESS": AUTHORIZATION_OR_PERMISSION_RED,
    "S10_2D_COMMUNITY_DEFAULT_PERMISSIONS_MISMATCH": CHANNEL_CONFIGURATION_RED,
    "S10_2D_COMMUNITY_RULES_NOT_PINNED": CHANNEL_CONFIGURATION_RED,
    "BOT_RUNTIME_CONTRACT_MISMATCH": RELEASE_OR_BOT_BINDING_RED,
    "S8_LOCAL_CONFIG_AND_BOT_ID_BOUND": RELEASE_OR_BOT_BINDING_RED,
    "S8_TELEGRAM_IDENTITY_MISMATCH": RELEASE_OR_BOT_BINDING_RED,
    "S8_TELEGRAM_CREDENTIAL_INVALID": AUTHORIZATION_OR_PERMISSION_RED,
    "S10_2D_COMMUNITY_CONTROL_MISSING": RELEASE_OR_BOT_BINDING_RED,
    "BOT_POLLER_NOT_RUNNING": INTERNAL_RUNTIME_RED,
    "BOT_POLLER_LEASE_RED": INTERNAL_RUNTIME_RED,
    "BOT_EVENT_PATH_WAITING": INTERNAL_RUNTIME_RED,
    "BOT_EVENT_PATH_TIMEOUT": INTERNAL_RUNTIME_RED,
    "BOT_OFFSET_STALLED": INTERNAL_RUNTIME_RED,
    "BOT_EVENT_PATH_RED": INTERNAL_RUNTIME_RED,
    "BOT_HANDLER_NOT_STARTED": INTERNAL_RUNTIME_RED,
    "BOT_HANDLER_TIMEOUT": INTERNAL_RUNTIME_RED,
    "BOT_RESPONSE_NOT_SENT": INTERNAL_RUNTIME_RED,
    "BOT_METRIC_PATH_MISSING": INTERNAL_RUNTIME_RED,
    CHILD_MISSING: UNKNOWN_HARD_RED,
    CHILD_UNKNOWN: UNKNOWN_HARD_RED,
}

ALLOWED_COMPONENTS = frozenset({
    "ANALYTICS",
    "BOT_PROCESS",
    "COMMUNITY",
    "DATABASE",
    "KILL_SWITCH",
    "LANDING_INTEGRATION",
    "LATENCY_SLO",
    "LOCAL_CONFIG_HEALTH",
    "MODERATION",
    "NOTIFIER",
    "POLLING",
    "PRODUCT_BOUNDARY",
    "PROVIDER",
    "QUEUE",
    "REMOTE_TELEGRAM_AVAILABILITY",
    "RETAINED_STATE",
    "TELEGRAM_AUTH",
    "TELEGRAM_CHANNEL_HEALTH",
    "WAITLIST",
})

NEXT_ACTION = {
    RETRYABLE_RUNTIME_READINESS: "SEPARATE_BACKUP_FIRST_S8_READINESS_RECOVERY",
    STATE_INTEGRITY_BLOCKER: "DIAGNOSE_AND_RECONCILE_STATE_BEFORE_RECOVERY",
    RELEASE_BINDING_BLOCKER: "REPAIR_RELEASE_BINDING_BEFORE_RECOVERY",
    PROVIDER_EXTERNAL_BLOCKER: "CORRECT_PROVIDER_STATE_BEFORE_RECOVERY",
    TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE: (
        "READ_ONLY_RECHECK_BEFORE_NEW_RECOVERY_AUTHORIZATION"
    ),
    UNKNOWN_HARD_RED: "STOP_AND_EXTEND_CANONICAL_CONTRACT",
}

_ENVELOPE_CODES = frozenset({"S8_DIAGNOSTIC_RED", "S8_RUNTIME_STARTUP_RED"})
_OUTER_BY_CHILD = {
    "BOT_RUNTIME_CONTRACT_MISMATCH": "S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED",
    "BOT_POLLER_NOT_RUNNING": "S10_2D_COMMUNITY_POLLER_RED",
    "BOT_OFFSET_STALLED": "S10_2D_COMMUNITY_OFFSET_RED",
    TELEGRAM_HEALTH_RED: OUTER_STATE_RED,
}
_PROVIDER_CHILD_CODES = frozenset(
    code for code, classification in CHILD_CLASSIFICATION.items()
    if classification == PROVIDER_EXTERNAL_BLOCKER
)
_COMPONENT_ORDER = (
    "LOCAL_CONFIG_HEALTH",
    "TELEGRAM_AUTH",
    "REMOTE_TELEGRAM_AVAILABILITY",
    "POLLING",
    "DATABASE",
    "WAITLIST",
    "NOTIFIER",
    "QUEUE",
    "ANALYTICS",
    "PRODUCT_BOUNDARY",
    "KILL_SWITCH",
    "LANDING_INTEGRATION",
    "BOT_PROCESS",
)
_LATENCY_PROFILE_NAMES = (
    "TECHNICAL_RUNTIME_LATENCY",
    "REAL_USER_DIRECT_LATENCY",
    "S11_CANARY_TECHNICAL_LATENCY",
    "S11_CANARY_REAL_USER_LATENCY",
)
_LATENCY_PROFILE_STATES = frozenset({"GREEN", "RED", "INSUFFICIENT_EVIDENCE"})


@dataclass(frozen=True)
class CommunityHealthFailure(ValueError):
    outer_code: str
    child_code: str
    component: str
    decision_class: str
    failure_class: str
    next_action: str

    def __str__(self) -> str:
        return self.outer_code

    def as_dict(self) -> dict[str, object]:
        return {
            "child_code": self.child_code,
            "component": self.component,
            "decision_class": self.decision_class,
            "failure_class": self.failure_class,
            "next_action": self.next_action,
            "ok": False,
            "outer_code": self.outer_code,
            "safe_code": self.outer_code,
            "state": "RED",
        }


def _bounded_component(candidate: object) -> str:
    return candidate if isinstance(candidate, str) and candidate in ALLOWED_COMPONENTS else "COMMUNITY"


def failure(child_candidate: object, component: object = "COMMUNITY") -> CommunityHealthFailure:
    if not isinstance(child_candidate, str) or not child_candidate:
        child_code = CHILD_MISSING
    elif child_candidate not in ALLOWED_CHILD_CODES:
        child_code = CHILD_UNKNOWN
    else:
        child_code = child_candidate
    decision_class = CHILD_CLASSIFICATION[child_code]
    outer_code = _OUTER_BY_CHILD.get(
        child_code,
        "S10_2D_COMMUNITY_PROVIDER_RED" if child_code in _PROVIDER_CHILD_CODES else OUTER_STATE_RED,
    )
    return CommunityHealthFailure(
        outer_code=outer_code,
        child_code=child_code,
        component=_bounded_component(component),
        decision_class=decision_class,
        failure_class=TELEGRAM_FAILURE_CLASSIFICATION.get(child_code, NOT_TELEGRAM_SPECIFIC),
        next_action=(
            "WAIT_FOR_LATENCY_SLO_OR_FIX_PROVENANCE_BEFORE_RECOVERY"
            if child_code == "S11_COMMUNITY_LATENCY_SLO_RED"
            else NEXT_ACTION[decision_class]
        ),
    )


def _red_component(payload: Mapping[str, object]) -> tuple[object, str] | None:
    components = payload.get("components")
    if not isinstance(components, Mapping):
        return None
    for component in _COMPONENT_ORDER:
        evidence = components.get(component)
        if isinstance(evidence, Mapping) and evidence.get("status") == "RED":
            return evidence.get("safe_reason"), component
    return None


def latency_profile_states(community: Mapping[str, object]) -> dict[str, str]:
    """Return canonical profile states or fail closed on reader-contract drift."""

    profiles = community.get("latency_slo_profiles")
    if not isinstance(profiles, Mapping):
        raise failure("COMMUNITY_LATENCY_PROFILE_CONTRACT_RED", "LATENCY_SLO")
    states: dict[str, str] = {}
    for name in _LATENCY_PROFILE_NAMES:
        profile = profiles.get(name)
        if (
            not isinstance(profile, Mapping)
            or profile.get("profile") != name
            or profile.get("state") not in _LATENCY_PROFILE_STATES
            or not isinstance(profile.get("samples"), int)
            or profile.get("samples", -1) < 0
        ):
            raise failure("COMMUNITY_LATENCY_PROFILE_CONTRACT_RED", "LATENCY_SLO")
        states[name] = profile["state"]
    return states


def failure_from_payload(payload: object, return_code: int) -> CommunityHealthFailure | None:
    """Return a strict failure for a child payload, otherwise ``None`` for GREEN."""

    if not isinstance(payload, Mapping):
        return failure(None)
    community = payload.get("community")
    if return_code != 0:
        safe_code = payload.get("safe_code")
        if safe_code in _ENVELOPE_CODES or safe_code is None:
            safe_code = payload.get("safe_reason")
        if safe_code not in ALLOWED_CHILD_CODES:
            component_failure = _red_component(payload)
            if component_failure is not None:
                return failure(*component_failure)
        return failure(safe_code)
    if not isinstance(community, Mapping):
        return failure(None)
    provider = community.get("provider")
    latency = community.get("latency_24h")
    if not isinstance(provider, Mapping) or not isinstance(latency, Mapping):
        return failure(None)
    if provider.get("ok") is not True:
        return failure(provider.get("safe_code"), "PROVIDER")
    event_path = community.get("bot_event_path")
    if isinstance(event_path, Mapping) and event_path.get("ok") is not True:
        return failure(event_path.get("safe_code"), "POLLING")
    if community.get("pending_moderation") != 0:
        return failure("S10_2D_MODERATION_DELIVERY_STATE_RED", "MODERATION")
    if community.get("stuck_restrictions") != 0:
        return failure("S10_2D_RESTRICTION_RELEASE_STATE_RED", "COMMUNITY")
    try:
        latency_states = latency_profile_states(community)
    except CommunityHealthFailure as latency_failure:
        return latency_failure
    if latency_states["TECHNICAL_RUNTIME_LATENCY"] == "RED":
        return failure("COMMUNITY_RUNTIME_LATENCY_RED", "LATENCY_SLO")
    if payload.get("ok") is not True or payload.get("state") not in {"GREEN", "YELLOW"}:
        component_failure = _red_component(payload)
        return failure(*(component_failure or (None, "COMMUNITY")))
    return None


def normalize_report(report: object) -> CommunityHealthFailure:
    """Validate a serialized wrapper report without accepting free-form values."""

    if not isinstance(report, Mapping):
        return failure(None)
    if (
        report.get("safe_code") == TELEGRAM_HEALTH_RED
        and report.get("outer_code") is None
        and report.get("child_code") is None
    ):
        return failure(TELEGRAM_HEALTH_RED, "TELEGRAM_CHANNEL_HEALTH")
    if (
        report.get("outer_code") is None
        and report.get("safe_code") is None
        and report.get("child_code") is None
    ):
        return failure(None)
    normalized = failure(report.get("child_code"), report.get("component"))
    outer_code = report.get("outer_code", report.get("safe_code"))
    if outer_code != normalized.outer_code:
        return failure(CHILD_UNKNOWN)
    if report.get("failure_class", normalized.failure_class) != normalized.failure_class:
        return failure(CHILD_UNKNOWN)
    return normalized
