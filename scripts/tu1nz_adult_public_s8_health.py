#!/usr/bin/env python3
"""Privacy-safe, component-level Commercial S8 diagnostic health runner."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


COMPONENTS = (
    "BOT_PROCESS",
    "TELEGRAM_AUTH",
    "POLLING",
    "DATABASE",
    "WAITLIST",
    "NOTIFIER",
    "QUEUE",
    "ANALYTICS",
    "PRODUCT_BOUNDARY",
    "KILL_SWITCH",
)
FIELDS = (
    "status",
    "started_at",
    "completed_at",
    "elapsed_ms",
    "safe_reason",
    "safe_exception_type",
    "errno",
    "sqlstate",
    "retryable",
)
S8_SERVICE = "tu1nz-adult-public-s8-telegram.service"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--copy", type=Path, required=True)
    parser.add_argument("--telegram-token", type=Path, required=True)
    parser.add_argument("--database-dsn", type=Path, required=True)
    parser.add_argument("--mode", choices=("prestart", "runtime"), required=True)
    return parser


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _component(status: str, safe_reason: str, exception_type: str | None = None) -> dict[str, object]:
    moment = _timestamp()
    return {
        "status": status,
        "started_at": moment,
        "completed_at": moment,
        "elapsed_ms": 0,
        "safe_reason": safe_reason,
        "safe_exception_type": exception_type,
        "errno": None,
        "sqlstate": None,
        "retryable": False,
    }


def _fallback(mode: str, safe_reason: str) -> dict[str, object]:
    return {
        "ok": False,
        "safe_code": "S8_DIAGNOSTIC_RED",
        "state": "RED",
        "mode": mode.upper(),
        "components": {
            name: _component("RED", safe_reason, "DiagnosticEnvelopeError") for name in COMPONENTS
        },
    }


def _validate(payload: object, mode: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("S8_DIAGNOSTIC_ENVELOPE_INVALID")
    if payload.get("mode") != mode.upper() or payload.get("state") not in {"GREEN", "YELLOW", "RED"}:
        raise ValueError("S8_DIAGNOSTIC_ENVELOPE_INVALID")
    components = payload.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise ValueError("S8_DIAGNOSTIC_COMPONENT_SET_INVALID")
    for value in components.values():
        if not isinstance(value, dict) or set(value) != set(FIELDS):
            raise ValueError("S8_DIAGNOSTIC_COMPONENT_SHAPE_INVALID")
        if value["status"] not in {"GREEN", "YELLOW", "RED"}:
            raise ValueError("S8_DIAGNOSTIC_COMPONENT_STATUS_INVALID")
        if not isinstance(value["safe_reason"], str) or not value["safe_reason"].startswith("S8_"):
            raise ValueError("S8_DIAGNOSTIC_SAFE_REASON_INVALID")
        if not isinstance(value["elapsed_ms"], int) or value["elapsed_ms"] < 0:
            raise ValueError("S8_DIAGNOSTIC_TIMING_INVALID")
        if not isinstance(value["retryable"], bool):
            raise ValueError("S8_DIAGNOSTIC_RETRY_INVALID")
    return payload


def _service_active() -> bool:
    return subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", S8_SERVICE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    ).returncode == 0


def _recompute(payload: dict[str, object]) -> None:
    components = payload["components"]
    statuses = {value["status"] for value in components.values()}
    state = "RED" if "RED" in statuses else "YELLOW" if "YELLOW" in statuses else "GREEN"
    payload["state"] = state
    payload["ok"] = state == "GREEN"
    payload["safe_code"] = "S8_DIAGNOSTIC_{0}".format(state)


def main() -> int:
    arguments = _parser().parse_args()
    command = [
        "/opt/tu1nz_repos/adult-publishing-core/.venv/bin/tu1nz-public-s8-telegram",
        "--contract", str(arguments.contract),
        "--copy", str(arguments.copy),
        "--telegram-token", str(arguments.telegram_token),
        "--database-dsn", str(arguments.database_dsn),
        "--diagnostic-mode", arguments.mode,
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        payload = _validate(json.loads(completed.stdout), arguments.mode)
    except Exception:
        payload = _fallback(arguments.mode, "S8_DIAGNOSTIC_COMMAND_ENVELOPE_RED")
    if arguments.mode == "runtime":
        components = payload["components"]
        if _service_active():
            components["BOT_PROCESS"] = _component("GREEN", "S8_RUNTIME_SYSTEMD_PROCESS_ACTIVE")
        else:
            components["BOT_PROCESS"] = _component("RED", "S8_RUNTIME_SYSTEMD_PROCESS_INACTIVE")
        _recompute(payload)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if payload["ok"] is True else 2


if __name__ == "__main__":
    sys.exit(main())
