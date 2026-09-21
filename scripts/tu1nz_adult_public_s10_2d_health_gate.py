#!/usr/bin/env python3
"""Privacy-safe S10.2D systemd health-gate runner shared with the simulator."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol

try:
    from scripts.tu1nz_adult_public_community_health_contract import normalize_report
except ModuleNotFoundError:  # direct execution from /usr/local/bin
    from tu1nz_adult_public_community_health_contract import normalize_report


HEALTH_UNITS = (
    "tu1nz-adult-public-s8-health.service",
    "tu1nz-adult-public-s9-health.service",
    "tu1nz-adult-public-s10-health.service",
)
EXPECTED_STATE = "SYSTEMD_RESULT_SUCCESS_EXIT_0"
MAXIMUM_REPORTED_ELAPSED_MS = 300_000

_UNIT_STAGE = {
    HEALTH_UNITS[0]: "S8_RUNTIME",
    HEALTH_UNITS[1]: "S9_PUBLIC_HEALTH",
    HEALTH_UNITS[2]: "S10_PUBLIC_HEALTH",
}
_EXIT_CHECKS = {
    30: ("CONFIGURATION", "CONFIGURATION_RED"),
    31: ("SYSTEM_STATE", "SYSTEM_STATE_RED"),
    32: ("PUBLIC_HTTP", "PUBLIC_HTTP_RED"),
    33: ("GROWTH_DATABASE", "GROWTH_DATABASE_RED"),
    34: ("TELEGRAM_CHANNEL", "TELEGRAM_CHANNEL_RED"),
    40: ("COMMUNITY_RUNTIME_CONTRACT", "COMMUNITY_RUNTIME_CONTRACT_RED"),
    41: ("COMMUNITY_POLLER", "COMMUNITY_POLLER_RED"),
    42: ("COMMUNITY_OFFSET", "COMMUNITY_OFFSET_RED"),
    43: ("COMMUNITY_PROVIDER", "COMMUNITY_PROVIDER_RED"),
    44: ("COMMUNITY_STATE", "COMMUNITY_STATE_RED"),
    45: ("COMMUNITY_ENVELOPE", "COMMUNITY_ENVELOPE_RED"),
    46: ("COMMUNITY_ARGUMENTS", "COMMUNITY_ARGUMENTS_RED"),
    47: ("RUNTIME_PROCESS", "PROCESS_NOT_RUNNING"),
    48: ("POLLER_READINESS", "POLLER_NOT_READY"),
    49: ("RUNTIME_RELEASE", "RELEASE_ID_RED"),
    200: ("WORKING_DIRECTORY", "WORKING_DIRECTORY_RED"),
    203: ("EXECUTABLE", "EXECUTABLE_RED"),
    216: ("SUPPLEMENTARY_GROUPS", "SUPPLEMENTARY_GROUPS_RED"),
    217: ("USER", "USER_RED"),
    226: ("NAMESPACE", "NAMESPACE_RED"),
}
_ALLOWED_RESULTS = {
    "success",
    "exit-code",
    "timeout",
    "signal",
    "core-dump",
    "watchdog",
    "start-limit-hit",
    "resources",
    "protocol",
}


class HealthGateClient(Protocol):
    def reset_failed(self, unit: str) -> None: ...

    def start(self, unit: str) -> int: ...

    def show(self, unit: str, property_name: str) -> str: ...

    def safe_report(self, unit: str) -> dict[str, object] | None: ...


@dataclass(frozen=True)
class HealthGateFailure(Exception):
    report: dict[str, object]


class SystemctlClient:
    """Bounded adapter for the three systemd operations used by the gate."""

    def __init__(
        self,
        executable: str = "/usr/bin/systemctl",
        journal_executable: str = "/usr/bin/journalctl",
    ) -> None:
        self.executable = executable
        self.journal_executable = journal_executable

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.executable, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=95,
            check=False,
        )

    def reset_failed(self, unit: str) -> None:
        self._run("reset-failed", unit)

    def start(self, unit: str) -> int:
        return self._run("start", unit).returncode

    def show(self, unit: str, property_name: str) -> str:
        completed = self._run("show", unit, "-p", property_name, "--value")
        return completed.stdout.strip() if completed.returncode == 0 else ""

    def safe_report(self, unit: str) -> dict[str, object] | None:
        invocation_id = self.show(unit, "InvocationID")
        if len(invocation_id) != 32 or any(value not in "0123456789abcdef" for value in invocation_id.lower()):
            return None
        completed = subprocess.run(
            [
                self.journal_executable,
                "--no-pager",
                "-o",
                "cat",
                "-n",
                "20",
                f"_SYSTEMD_INVOCATION_ID={invocation_id}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 64 * 1024:
            return None
        for line in reversed(completed.stdout.splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("ok") is False:
                return payload
        return None


def _bounded_result(value: str) -> str:
    return value if value in _ALLOWED_RESULTS else "unknown"


def _bounded_exit_status(value: str) -> int | None:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 0 <= status <= 255 else None


def _failure_report(
    unit: str,
    *,
    start_status: int,
    result: str,
    exit_status: int | None,
    elapsed_ms: int,
    child_report: dict[str, object] | None = None,
) -> dict[str, object]:
    unit_stage = _UNIT_STAGE[unit]
    check_suffix, reason_suffix = _EXIT_CHECKS.get(
        exit_status if exit_status is not None else -1,
        ("PROCESS", "PROCESS_RED"),
    )
    check_id = f"{unit_stage}_{check_suffix}"
    safe_code = f"HEALTH_GATE_{unit_stage}_{reason_suffix}"
    actual_state = (
        f"PROCESS_EXIT_{exit_status}"
        if exit_status is not None
        else f"SYSTEMCTL_START_EXIT_{max(0, min(start_status, 255))}"
    )
    bounded_result = _bounded_result(result)
    child_failure = (
        normalize_report(child_report)
        if unit == HEALTH_UNITS[1] and exit_status in {40, 41, 42, 43, 44}
        else None
    )
    fingerprint_input = {
        "actual_state": actual_state,
        "check_id": check_id,
        "exit_code": exit_status,
        "expected_state": EXPECTED_STATE,
        "result": bounded_result,
        "stage": "HEALTH_GATE_START",
        "child_code": None if child_failure is None else child_failure.child_code,
        "outer_code": None if child_failure is None else child_failure.outer_code,
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    report: dict[str, object] = {
        "actual_state": actual_state,
        "check_id": check_id,
        "elapsed_ms": max(0, min(elapsed_ms, MAXIMUM_REPORTED_ELAPSED_MS)),
        "exit_code": exit_status,
        "expected_state": EXPECTED_STATE,
        "fingerprint": fingerprint,
        "ok": False,
        "result": bounded_result,
        "safe_code": safe_code,
        "stage": "HEALTH_GATE_START",
    }
    if child_failure is not None:
        report.update({
            "child_code": child_failure.child_code,
            "component": child_failure.component,
            "decision_class": child_failure.decision_class,
            "next_action": child_failure.next_action,
            "outer_code": child_failure.outer_code,
            "retry": False,
        })
    return report


def run_health_gates(client: HealthGateClient | None = None) -> dict[str, object]:
    """Start and verify the exact production health-unit sequence."""

    active_client = client or SystemctlClient()
    completed_units: list[str] = []
    for unit in HEALTH_UNITS:
        active_client.reset_failed(unit)
        started = time.monotonic_ns()
        try:
            start_status = active_client.start(unit)
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
            raise HealthGateFailure(
                _failure_report(
                    unit,
                    start_status=124,
                    result="timeout",
                    exit_status=None,
                    elapsed_ms=elapsed_ms,
                )
            ) from None
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        result = active_client.show(unit, "Result")
        exit_status = _bounded_exit_status(active_client.show(unit, "ExecMainStatus"))
        if start_status != 0 or result != "success" or exit_status != 0:
            safe_report = getattr(active_client, "safe_report", None)
            child_report = safe_report(unit) if callable(safe_report) else None
            raise HealthGateFailure(
                _failure_report(
                    unit,
                    start_status=start_status,
                    result=result,
                    exit_status=exit_status,
                    elapsed_ms=elapsed_ms,
                    child_report=child_report,
                )
            )
        completed_units.append(unit)
    return {
        "ok": True,
        "safe_code": "S10_2D_HEALTH_GATES_GREEN",
        "stage": "HEALTH_GATE_START",
        "units": completed_units,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    arguments = parser.parse_args()
    try:
        report = run_health_gates(SystemctlClient(arguments.systemctl))
    except (HealthGateFailure, OSError, subprocess.SubprocessError) as error:
        if isinstance(error, HealthGateFailure):
            report = error.report
        else:
            report = _failure_report(
                HEALTH_UNITS[0],
                start_status=2,
                result="unknown",
                exit_status=None,
                elapsed_ms=0,
            )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
