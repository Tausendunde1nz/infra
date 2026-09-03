#!/usr/bin/env python3
"""Privacy-safe Commercial S9 health envelope for the public SFW runtime."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


APPLICATION = Path("/opt/tu1nz_repos/adult-publishing-core")
RUNTIME = APPLICATION / ".venv/bin/tu1nz-commercial-s9-growth"
LOCAL_ORIGIN = "http://127.0.0.1:18096"
PUBLIC_ORIGIN = "https://tu1nz.com"
EXPECTED_REDIRECT = "https://t.me/tu1nz_adult_early_access_bot?start=organic_search_s9_organic_launch"
SERVICES = (
    "tu1nz-adult-public-s7.service",
    "tu1nz-adult-public-s8-telegram.service",
    "tu1nz-adult-public-s8-landing.service",
    "nginx.service",
)
TIMERS = (
    "tu1nz-adult-public-s9-audience.timer",
    "tu1nz-adult-public-s9-nurture.timer",
    "tu1nz-adult-public-s9-report.timer",
    "tu1nz-adult-public-s9-health.timer",
)
MAXIMUM_BYTES = 768 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _systemctl(*arguments: str) -> str:
    completed = _run(["/usr/bin/systemctl", *arguments], timeout=8)
    if completed.returncode != 0:
        raise ValueError("S9_SYSTEMD_STATE_RED")
    return completed.stdout.strip()


def _timer_has_future(unit: str) -> bool:
    values = (
        _systemctl("show", unit, "-p", "NextElapseUSecRealtime", "--value"),
        _systemctl("show", unit, "-p", "NextElapseUSecMonotonic", "--value"),
    )
    return any(value not in {"", "0", "infinity"} for value in values)


def _read(url: str) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers={"User-Agent": "TU1NZ-S9-Health/1"}, method="GET")
    try:
        with urlopen(request, timeout=8) as response:
            body = response.read(MAXIMUM_BYTES + 1)
            status = response.status
            headers = dict(response.headers.items())
    except (HTTPError, URLError, OSError, TimeoutError):
        raise ValueError("S9_PUBLIC_ENDPOINT_RED") from None
    if not body or len(body) > MAXIMUM_BYTES:
        raise ValueError("S9_PUBLIC_RESPONSE_INVALID")
    return status, headers, body


def _redirect(url: str) -> str:
    request = Request(url, headers={"User-Agent": "TU1NZ-S9-Health/1"}, method="GET")
    try:
        build_opener(_NoRedirect()).open(request, timeout=8)
    except HTTPError as error:
        if error.code != 302:
            raise ValueError("S9_TELEGRAM_REDIRECT_RED") from None
        location = error.headers.get("Location", "")
    except (URLError, OSError, TimeoutError):
        raise ValueError("S9_TELEGRAM_REDIRECT_RED") from None
    if location != EXPECTED_REDIRECT:
        raise ValueError("S9_TELEGRAM_REDIRECT_DRIFT")
    return location


def _application_health(contract: Path, database_dsn: Path) -> dict[str, object]:
    completed = _run([
        str(RUNTIME),
        "--contract", str(contract),
        "--database-dsn", str(database_dsn),
        "--health-only",
    ])
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise ValueError("S9_APPLICATION_HEALTH_ENVELOPE_INVALID") from None
    if completed.returncode != 0 or not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("S9_APPLICATION_HEALTH_RED")
    if payload.get("state") != "GREEN" or any(payload.get("forbidden_capabilities", {}).values()):
        raise ValueError("S9_PRODUCT_BOUNDARY_RED")
    components = payload.get("components", {})
    if components.get("X") != "DISABLED_EXPECTED" or components.get("REDDIT") != "DISABLED_EXPECTED":
        raise ValueError("S9_DISABLED_CHANNEL_STATE_DIVERGED")
    if components.get("TELEGRAM_CHANNEL") != "GREEN":
        raise ValueError("S9_TELEGRAM_CHANNEL_GATE_DIVERGED")
    return payload


def _channel_health(
    contract: Path,
    database_dsn: Path,
    s8_contract: Path,
    telegram_token: Path,
    telegram_channel: str,
) -> dict[str, object]:
    completed = _run([
        str(RUNTIME),
        "--contract", str(contract),
        "--database-dsn", str(database_dsn),
        "--channel-health",
        "--s8-contract", str(s8_contract),
        "--telegram-token", str(telegram_token),
        "--telegram-channel", telegram_channel,
    ])
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise ValueError("S9_TELEGRAM_CHANNEL_HEALTH_ENVELOPE_INVALID") from None
    if (
        completed.returncode != 0
        or payload != {
            "bot_can_post": True,
            "channel_bound": True,
            "ok": True,
            "safe_code": "S9_TELEGRAM_CHANNEL_GREEN",
        }
    ):
        raise ValueError("S9_TELEGRAM_CHANNEL_PROVIDER_RED")
    return {"identity": "GREEN", "bot_can_post": True}


def _system_health() -> dict[str, object]:
    services: dict[str, dict[str, object]] = {}
    for unit in SERVICES:
        active = _systemctl("show", unit, "-p", "ActiveState", "--value")
        restarts = _systemctl("show", unit, "-p", "NRestarts", "--value")
        if active != "active" or restarts != "0":
            raise ValueError("S9_BASELINE_SERVICE_RED")
        services[unit] = {"active": True, "restarts": 0}
    timers: dict[str, dict[str, object]] = {}
    for unit in TIMERS:
        active = _systemctl("show", unit, "-p", "ActiveState", "--value")
        enabled = _systemctl("is-enabled", unit)
        if active != "active" or enabled != "enabled":
            raise ValueError("S9_TIMER_STATE_RED")
        if not _timer_has_future(unit):
            raise ValueError("S9_TIMER_LIVENESS_RED")
        timers[unit] = {"active": True, "enabled": True, "future_elapse": True}
    return {"services": services, "timers": timers}


def _web_health() -> dict[str, object]:
    local_status, _, local_body = _read(LOCAL_ORIGIN + "/adult/?source=organic_search&campaign=s9_organic_launch")
    public_status, _, public_body = _read(PUBLIC_ORIGIN + "/adult/?source=organic_search&campaign=s9_organic_launch")
    guide_status, _, guide_body = _read(PUBLIC_ORIGIN + "/adult/guides/how-tu1nz-works")
    robots_status, _, robots_body = _read(PUBLIC_ORIGIN + "/adult/robots.txt")
    sitemap_status, _, sitemap_body = _read(PUBLIC_ORIGIN + "/adult/sitemap.xml")
    health_status, _, health_body = _read(PUBLIC_ORIGIN + "/adult/health")
    if any(value != 200 for value in (local_status, public_status, guide_status, robots_status, sitemap_status, health_status)):
        raise ValueError("S9_PUBLIC_HTTP_STATUS_RED")
    marker = b"/adult/go/telegram?campaign=s9_organic_launch&amp;source=organic_search"
    if marker not in local_body or marker not in public_body:
        raise ValueError("S9_INTERNAL_TELEGRAM_ROUTE_MISSING")
    if b"SFW CREATOR GUIDE" not in guide_body and b"SFW-CREATOR-GUIDE" not in guide_body:
        raise ValueError("S9_GUIDE_PAGE_RED")
    if b"Sitemap: https://tu1nz.com/adult/sitemap.xml" not in robots_body or sitemap_body.count(b"<url>") != 9:
        raise ValueError("S9_DISCOVERY_METADATA_RED")
    try:
        health = json.loads(health_body)
    except json.JSONDecodeError:
        raise ValueError("S9_PUBLIC_HEALTH_INVALID") from None
    if health.get("ok") is not True or any(health.get("forbidden_capabilities", {}).values()):
        raise ValueError("S9_PUBLIC_PRODUCT_BOUNDARY_RED")
    _redirect(PUBLIC_ORIGIN + "/adult/go/telegram?source=organic_search&campaign=s9_organic_launch")
    return {
        "landing": "GREEN",
        "guides": 6,
        "robots": "GREEN",
        "sitemap_urls": 9,
        "telegram_redirect": "GREEN",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--database-dsn", type=Path, required=True)
    parser.add_argument("--s8-contract", type=Path, required=True)
    parser.add_argument("--telegram-token", type=Path, required=True)
    parser.add_argument("--telegram-channel", required=True)
    arguments = parser.parse_args()
    try:
        application = _application_health(arguments.contract, arguments.database_dsn)
        channel = _channel_health(
            arguments.contract,
            arguments.database_dsn,
            arguments.s8_contract,
            arguments.telegram_token,
            arguments.telegram_channel,
        )
        system = _system_health()
        web = _web_health()
        payload = {
            "ok": True,
            "safe_code": "S9_PUBLIC_SFW_GROWTH_GREEN",
            "state": "GREEN",
            "components": application["components"],
            "runtime": application["runtime"],
            "telegram_channel": channel,
            "system": system,
            "web": web,
            "adult_content": False,
            "real_avs": False,
            "payments": False,
            "external_adult_publishing": False,
            "creator_invite": False,
            "controlled_beta": False,
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        safe_code = str(error) if str(error).startswith("S9_") else "S9_PUBLIC_HEALTH_RED"
        print(json.dumps({"ok": False, "safe_code": safe_code, "state": "RED"}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
