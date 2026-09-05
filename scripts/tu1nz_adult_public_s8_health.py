#!/usr/bin/env python3
"""Privacy-safe, component-level Commercial S8 diagnostic health runner."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


COMPONENTS = (
    "BOT_PROCESS",
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
    "telegram_safe_status",
)
S8_SERVICE = "tu1nz-adult-public-s8-telegram.service"
LANDING_URL = "http://127.0.0.1:18096/adult/"
LANDING_HEALTH_URL = "http://127.0.0.1:18096/adult/health"
LANDING_TRACKED_ROUTE = "/adult/go/telegram?campaign=s8_launch&source=landing"
LANDING_TRACKED_MARKER = "/adult/go/telegram?campaign=s8_launch&amp;source=landing"
MAXIMUM_LANDING_BYTES = 512 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--copy", type=Path, required=True)
    parser.add_argument("--telegram-token", type=Path, required=True)
    parser.add_argument("--database-dsn", type=Path, required=True)
    parser.add_argument("--community-contract", type=Path)
    parser.add_argument("--community-copy", type=Path)
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
        "telegram_safe_status": None,
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


def _read(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "TU1NZ-S8-Health/1"}, method="GET")
    try:
        with urlopen(request, timeout=6) as response:
            body = response.read(MAXIMUM_LANDING_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError):
        raise ValueError("S8_LANDING_CANDIDATE_UNAVAILABLE") from None
    if not body or len(body) > MAXIMUM_LANDING_BYTES:
        raise ValueError("S8_LANDING_RESPONSE_INVALID")
    return body


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _redirect_location(url: str) -> str:
    request = Request(url, headers={"User-Agent": "TU1NZ-S8-Health/1"}, method="GET")
    try:
        with build_opener(_RejectRedirect()).open(request, timeout=6):
            raise ValueError("S8_LANDING_REDIRECT_MISSING")
    except HTTPError as error:
        if error.code not in {301, 302, 303, 307, 308}:
            raise ValueError("S8_LANDING_REDIRECT_INVALID") from None
        location = error.headers.get("Location")
    except (URLError, OSError, TimeoutError):
        raise ValueError("S8_LANDING_CANDIDATE_UNAVAILABLE") from None
    if not isinstance(location, str) or not location:
        raise ValueError("S8_LANDING_REDIRECT_INVALID")
    return location


def _landing_component(contract_path: Path) -> dict[str, object]:
    started = datetime.now(timezone.utc)
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        bot_username = contract.get("bot_username") if isinstance(contract, dict) else None
        if not isinstance(bot_username, str) or not bot_username.casefold().endswith("bot"):
            raise ValueError("S8_LANDING_BOT_IDENTITY_INVALID")
        landing = _read(LANDING_URL).decode("utf-8", errors="strict")
        health = json.loads(_read(LANDING_HEALTH_URL).decode("utf-8", errors="strict"))
        expected_deep_link = "https://t.me/{0}?start=landing_s8_launch".format(bot_username)
        if LANDING_TRACKED_MARKER in landing:
            local_route = "http://127.0.0.1:18096" + LANDING_TRACKED_ROUTE
            if _redirect_location(local_route) != expected_deep_link:
                raise ValueError("S8_LANDING_DEEP_LINK_MISMATCH")
        elif expected_deep_link not in landing:
            raise ValueError("S8_LANDING_ENTRY_MISSING")
        if not isinstance(health, dict) or health.get("ok") is not True:
            raise ValueError("S8_LANDING_HEALTH_RED")
        if any(health.get("forbidden_capabilities", {}).values()):
            raise ValueError("S8_LANDING_PRODUCT_BOUNDARY_RED")
        result = _component("GREEN", "S8_LANDING_CANDIDATE_INTEGRATION_GREEN")
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        reason = str(error) if str(error).startswith("S8_") else "S8_LANDING_RESPONSE_INVALID"
        result = _component("RED", reason, type(error).__name__)
    completed = datetime.now(timezone.utc)
    result["started_at"] = started.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    result["completed_at"] = completed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    result["elapsed_ms"] = max(0, round((completed - started).total_seconds() * 1000))
    return result


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
    if (arguments.community_contract is None) != (arguments.community_copy is None):
        payload = _fallback(arguments.mode, "S8_COMMUNITY_ARGUMENTS_INCOMPLETE")
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 2
    if arguments.community_contract is not None and arguments.community_copy is not None:
        command.extend([
            "--community-contract", str(arguments.community_contract),
            "--community-copy", str(arguments.community_copy),
        ])
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
    payload["components"]["LANDING_INTEGRATION"] = _landing_component(arguments.contract)
    _recompute(payload)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    accepted = payload["state"] in ({"GREEN", "YELLOW"} if arguments.mode == "runtime" else {"GREEN"})
    return 0 if accepted else 2


if __name__ == "__main__":
    sys.exit(main())
