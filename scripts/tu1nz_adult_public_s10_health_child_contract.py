#!/usr/bin/env python3
"""Strict, privacy-safe child-code contract for the S10.1 health envelope."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Mapping


OUTER_CODE = "S10_1_WMS_HEALTH_RED"
CHILD_MISSING = "S10_HEALTH_CHILD_CODE_MISSING_RED"
CHILD_UNKNOWN = "S10_HEALTH_CHILD_CODE_UNKNOWN_RED"
CHILD_TIMEOUT = "S10_HEALTH_CHILD_TIMEOUT_RED"
CHILD_IO = "S10_HEALTH_CHILD_IO_RED"
CHILD_SUBPROCESS = "S10_HEALTH_CHILD_SUBPROCESS_RED"

TRANSIENT = "TRANSIENT_PROVIDER_OR_TIMING_CANDIDATE"
HARD = "HARD_BLOCKER"
UNKNOWN_HARD = "UNKNOWN_HARD_RED"

READ_ONLY_RECHECK = "READ_ONLY_RECHECK_BEFORE_NEW_DEPLOYMENT_AUTHORIZATION"
STOP_HARD = "STOP_AND_DIAGNOSE_BEFORE_NEW_DEPLOYMENT_AUTHORIZATION"
STOP_UNKNOWN = "STOP_AND_EXTEND_CANONICAL_CONTRACT"

CONTRACT_VERSION = "S10_1_HEALTH_CHILD_V1"

ALLOWED_COMPONENTS = frozenset({
    "AGGREGATE_STATE",
    "COMMUNITY",
    "CONFIG_AUTH",
    "DATABASE_STATE",
    "GROWTH",
    "INTERNAL_HEALTH_CONTRACT",
    "PRODUCT_BOUNDARY",
    "RELEASE_BINDING",
    "SYSTEMD",
    "TELEGRAM_CHANNEL_HEALTH",
    "WMS_LOCAL_HEALTH",
    "WMS_PUBLIC_HEALTH",
})

# These values are emitted by the existing S10.1 entrypoint. Keeping the
# allowlist here makes a new, misspelled or free-text value fail closed.
_HARD_CODES = frozenset({
    "S10_2D_COMMUNITY_HEALTH_ARGUMENTS_INCOMPLETE",
    "S10_2D_COMMUNITY_HEALTH_ARGUMENTS_MISSING",
    "S10_2D_COMMUNITY_HEALTH_INVALID",
    "S10_2D_COMMUNITY_REQUIRED_FILE_MISSING",
    "S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED",
    "S10_2D_COMMUNITY_S8_COPY_MISSING",
    "S10_2D_COMMUNITY_STATE_RED",
    "S10_2F_CHANGESET_PATH_RED",
    "S10_2F_CHANGESET_STATE_RED",
    "S10_BASELINE_SERVICE_RED",
    "S10_DATABASE_STATE_RED",
    "S10_GROWTH_BOUNDARY_RED",
    "S10_GROWTH_HEALTH_INVALID",
    "S10_GROWTH_HEALTH_RED",
    "S10_PRODUCT_BOUNDARY_RED",
    "S10_PUBLIC_BRAND_RED",
    "S10_PUBLIC_ENDPOINT_RED",
    "S10_PUBLIC_HEALTH_INVALID",
    "S10_PUBLIC_HTTP_STATUS_RED",
    "S10_PUBLIC_LEGACY_BRAND_LEAK",
    "S10_PUBLIC_LEGAL_LINK_RED",
    "S10_PUBLIC_RESPONSE_INVALID",
    "S10_PUBLIC_ROBOTS_RED",
    "S10_PUBLIC_SITEMAP_RED",
    "S10_REQUIRED_FILE_MISSING",
    "S10_SYSTEMD_STATE_RED",
    "S10_TELEGRAM_HEALTH_INVALID",
    "S10_TIMER_LIVENESS_RED",
    "S10_TIMER_STATE_RED",
    "S10_TRAFFIC_QUALITY_PATH_RED",
    "S10_TRAFFIC_QUALITY_STATE_RED",
    CHILD_IO,
    CHILD_SUBPROCESS,
})
_TRANSIENT_CODES = frozenset({
    "S10_TELEGRAM_HEALTH_RED",
    CHILD_TIMEOUT,
})
ALLOWED_CHILD_CODES = frozenset({
    *_HARD_CODES,
    *_TRANSIENT_CODES,
    CHILD_MISSING,
    CHILD_UNKNOWN,
})


def exit_status(child_code: str) -> int:
    """Return the existing stable S10 process class for an exact child."""

    if child_code in {
        "S10_REQUIRED_FILE_MISSING",
        "S10_2D_COMMUNITY_S8_COPY_MISSING",
        "S10_2D_COMMUNITY_REQUIRED_FILE_MISSING",
    }:
        return 30
    if child_code in {
        "S10_SYSTEMD_STATE_RED",
        "S10_BASELINE_SERVICE_RED",
        "S10_TIMER_STATE_RED",
        "S10_TIMER_LIVENESS_RED",
    }:
        return 31
    if child_code.startswith("S10_PUBLIC_") or child_code == "S10_PRODUCT_BOUNDARY_RED":
        return 32
    if child_code.startswith("S10_GROWTH_"):
        return 33
    if child_code.startswith("S10_TELEGRAM_"):
        return 34
    return 2


def _canonical_component(child_code: str, candidate: str) -> str:
    if child_code == "S10_PRODUCT_BOUNDARY_RED":
        return "PRODUCT_BOUNDARY"
    if child_code.startswith("S10_TELEGRAM_"):
        return "TELEGRAM_CHANNEL_HEALTH"
    if child_code.startswith("S10_GROWTH_"):
        return "GROWTH"
    if child_code.startswith("S10_2F_"):
        return "RELEASE_BINDING"
    if child_code == "S10_DATABASE_STATE_RED":
        return "DATABASE_STATE"
    if child_code.startswith("S10_TRAFFIC_QUALITY_"):
        return "AGGREGATE_STATE"
    if child_code in {
        "S10_SYSTEMD_STATE_RED",
        "S10_BASELINE_SERVICE_RED",
        "S10_TIMER_STATE_RED",
        "S10_TIMER_LIVENESS_RED",
    }:
        return "SYSTEMD"
    if child_code.startswith("S10_2D_COMMUNITY_"):
        return "COMMUNITY"
    if child_code in {
        "S10_REQUIRED_FILE_MISSING",
        "S10_2D_COMMUNITY_S8_COPY_MISSING",
        "S10_2D_COMMUNITY_REQUIRED_FILE_MISSING",
    }:
        return "CONFIG_AUTH"
    return candidate if candidate in ALLOWED_COMPONENTS else "INTERNAL_HEALTH_CONTRACT"


@dataclass(frozen=True)
class S10HealthFailure(ValueError):
    outer_code: str
    child_code: str
    component: str
    classification: str
    next_action: str
    exit_code: int

    def __str__(self) -> str:
        return self.outer_code

    def as_dict(self) -> dict[str, object]:
        return {
            "child_code": self.child_code,
            "classification": self.classification,
            "component": self.component,
            "contract_version": CONTRACT_VERSION,
            "decision_class": self.classification,
            "exit_code": self.exit_code,
            "next_action": self.next_action,
            "ok": False,
            "outer_code": self.outer_code,
            "retry": False,
            "safe_code": self.outer_code,
            "state": "RED",
        }


def failure(child_candidate: object, component: str) -> S10HealthFailure:
    if not isinstance(child_candidate, str) or not child_candidate:
        child_code = CHILD_MISSING
    elif child_candidate not in ALLOWED_CHILD_CODES:
        child_code = CHILD_UNKNOWN
    else:
        child_code = child_candidate
    if child_code in _TRANSIENT_CODES:
        classification = TRANSIENT
        next_action = READ_ONLY_RECHECK
    elif child_code in {CHILD_MISSING, CHILD_UNKNOWN}:
        classification = UNKNOWN_HARD
        next_action = STOP_UNKNOWN
    else:
        classification = HARD
        next_action = STOP_HARD
    return S10HealthFailure(
        outer_code=OUTER_CODE,
        child_code=child_code,
        component=_canonical_component(child_code, component),
        classification=classification,
        next_action=next_action,
        exit_code=exit_status(child_code),
    )


def failure_from_exception(error: BaseException, component: str) -> S10HealthFailure:
    if isinstance(error, subprocess.TimeoutExpired):
        child_code: object = CHILD_TIMEOUT
    elif isinstance(error, subprocess.SubprocessError):
        child_code = CHILD_SUBPROCESS
    elif isinstance(error, OSError):
        child_code = CHILD_IO
    elif isinstance(error, ValueError):
        child_code = str(error)
    else:
        child_code = CHILD_UNKNOWN
    return failure(child_code, component)


def normalize_report(report: object) -> S10HealthFailure:
    """Validate a structured general S10 report; inconsistent data fails closed."""

    if not isinstance(report, Mapping):
        return failure(None, "INTERNAL_HEALTH_CONTRACT")
    child_candidate = report.get("child_code")
    if not isinstance(child_candidate, str) or not child_candidate:
        return failure(None, "INTERNAL_HEALTH_CONTRACT")
    if child_candidate not in ALLOWED_CHILD_CODES:
        return failure(child_candidate, "INTERNAL_HEALTH_CONTRACT")
    normalized = failure(child_candidate, str(report.get("component", "")))
    required = {
        "classification": normalized.classification,
        "component": normalized.component,
        "contract_version": CONTRACT_VERSION,
        "exit_code": normalized.exit_code,
        "next_action": normalized.next_action,
        "outer_code": OUTER_CODE,
        "retry": False,
        "safe_code": OUTER_CODE,
        "state": "RED",
    }
    if report.get("ok") is not False or any(report.get(key) != value for key, value in required.items()):
        return failure(CHILD_UNKNOWN, "INTERNAL_HEALTH_CONTRACT")
    return normalized
