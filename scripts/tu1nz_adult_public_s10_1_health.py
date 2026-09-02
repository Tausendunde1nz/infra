#!/usr/bin/env python3
"""Privacy-safe health envelope for Want Me Seen Commercial S10.1."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


APPLICATION = Path("/opt/tu1nz_repos/adult-publishing-core")
S9_RUNTIME = APPLICATION / ".venv/bin/python"
LOCAL_ORIGIN = "http://127.0.0.1:18110"
PUBLIC_ORIGIN = "https://wantmeseen.com"
MAXIMUM_BYTES = 768 * 1024
SERVICES = (
    "tu1nz-adult-public-s7.service",
    "tu1nz-adult-public-s8-telegram.service",
    "tu1nz-adult-public-s8-landing.service",
    "tu1nz-adult-public-s10-wms.service",
    "nginx.service",
)
TIMERS = (
    "tu1nz-adult-public-s9-audience.timer",
    "tu1nz-adult-public-s9-nurture.timer",
    "tu1nz-adult-public-s9-report.timer",
    "tu1nz-adult-public-s9-health.timer",
    "tu1nz-adult-public-s10-health.timer",
)
S9_FORBIDDEN_CAPABILITIES = {
    "adult_content",
    "media_intake",
    "real_avs",
    "payments",
    "external_adult_publishing",
    "controlled_beta",
    "invite_automation",
}
S9_COMPONENTS = {
    "CONTENT_ENGINE": "GREEN",
    "SCHEDULER": "GREEN",
    "TELEGRAM_CHANNEL": "GREEN",
    "X": "DISABLED_EXPECTED",
    "REDDIT": "DISABLED_EXPECTED",
    "FUNNEL": "GREEN",
    "ATTRIBUTION": "GREEN",
    "NUDGE_QUEUE": "GREEN",
    "INVITE_ENGINE": "DISABLED_EXPECTED",
}
S9_RUNTIME_FLAGS = {
    "public_sfw_growth_enabled": True,
    "audience_seeding_enabled": True,
    "telegram_channel_enabled": True,
    "x_enabled": False,
    "reddit_enabled": False,
    "organic_discovery_enabled": True,
    "nurture_enabled": True,
    "invite_automation_enabled": False,
}
S9_CHANNELS = {
    "telegram_channel": "AUTOMATED_SUPPORTED",
    "x": "DISABLED_FOR_NOW",
    "reddit": "DISABLED_FOR_NOW",
}


def _run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(APPLICATION / "src")
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=environment,
        timeout=timeout,
        check=False,
    )


def _systemctl(*arguments: str) -> str:
    result = _run(["/usr/bin/systemctl", *arguments], timeout=8)
    if result.returncode != 0:
        raise ValueError("S10_SYSTEMD_STATE_RED")
    return result.stdout.strip()


def _read(url: str) -> tuple[int, bytes]:
    request = Request(url, headers={"User-Agent": "WMS-S10-Health/1"}, method="GET")
    try:
        with urlopen(request, timeout=8) as response:
            body = response.read(MAXIMUM_BYTES + 1)
            status = response.status
    except (HTTPError, URLError, OSError, TimeoutError):
        raise ValueError("S10_PUBLIC_ENDPOINT_RED") from None
    if not body or len(body) > MAXIMUM_BYTES:
        raise ValueError("S10_PUBLIC_RESPONSE_INVALID")
    return status, body


def _web(origin: str) -> dict[str, object]:
    bodies: dict[str, bytes] = {}
    for path in ("/", "/privacy?lang=en", "/terms?lang=en", "/imprint?lang=en", "/robots.txt", "/sitemap.xml", "/health"):
        status, body = _read(origin + path)
        if status != 200:
            raise ValueError("S10_PUBLIC_HTTP_STATUS_RED")
        bodies[path] = body
    page = bodies["/"]
    normalized_page = page.lower()
    if b"want me seen" not in normalized_page or b"exposed on purpose" not in normalized_page:
        raise ValueError("S10_PUBLIC_BRAND_RED")
    if b"tu1nz" in normalized_page or b"seen by choice" in normalized_page or b"seen-by-choice" in normalized_page:
        raise ValueError("S10_PUBLIC_LEGACY_BRAND_LEAK")
    legal_expectations = {
        "/privacy?lang=en": (b"<title>Privacy ", b'href="https://wantmeseen.com/privacy"'),
        "/terms?lang=en": (b"<title>Early Access terms ", b'href="https://wantmeseen.com/terms"'),
        "/imprint?lang=en": (b"<title>Imprint ", b'href="https://wantmeseen.com/imprint"'),
    }
    if any(
        title not in bodies[path]
        or canonical not in bodies[path]
        or b"contact@wantmeseen.com" not in bodies[path]
        for path, (title, canonical) in legal_expectations.items()
    ):
        raise ValueError("S10_PUBLIC_LEGAL_LINK_RED")
    if bodies["/robots.txt"] != b"User-agent: *\nAllow: /\nSitemap: https://wantmeseen.com/sitemap.xml\n":
        raise ValueError("S10_PUBLIC_ROBOTS_RED")
    try:
        sitemap = ET.fromstring(bodies["/sitemap.xml"])
    except ET.ParseError:
        raise ValueError("S10_PUBLIC_SITEMAP_RED") from None
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    expected_locations = {
        "https://wantmeseen.com/",
        "https://wantmeseen.com/privacy",
        "https://wantmeseen.com/terms",
        "https://wantmeseen.com/imprint",
    }
    locations = {value.text for value in sitemap.findall(f"{namespace}url/{namespace}loc")}
    if sitemap.tag != f"{namespace}urlset" or locations != expected_locations:
        raise ValueError("S10_PUBLIC_SITEMAP_RED")
    try:
        health = json.loads(bodies["/health"])
    except json.JSONDecodeError:
        raise ValueError("S10_PUBLIC_HEALTH_INVALID") from None
    if health.get("ok") is not True or any(
        health.get(key) is not False
        for key in ("adult_content", "real_avs", "payments", "external_publishing")
    ):
        raise ValueError("S10_PRODUCT_BOUNDARY_RED")
    return {"landing": "GREEN", "legal": "GREEN", "seo": "GREEN"}


def _system(local_only: bool, require_timers: bool) -> dict[str, object]:
    services: dict[str, object] = {}
    for unit in SERVICES:
        if local_only and unit == "nginx.service":
            continue
        active = _systemctl("show", unit, "-p", "ActiveState", "--value")
        restarts = _systemctl("show", unit, "-p", "NRestarts", "--value")
        if active != "active" or restarts != "0":
            raise ValueError("S10_BASELINE_SERVICE_RED")
        services[unit] = {"active": True, "restarts": 0}
    if require_timers:
        for unit in TIMERS:
            if _systemctl("show", unit, "-p", "ActiveState", "--value") != "active":
                raise ValueError("S10_TIMER_STATE_RED")
            if _systemctl("is-enabled", unit) != "enabled":
                raise ValueError("S10_TIMER_STATE_RED")
    return services


def _growth(arguments: argparse.Namespace) -> dict[str, object]:
    base = [
        str(S9_RUNTIME), "-m", "tu1nz_growth_s9.runtime",
        "--contract", str(arguments.s9_contract),
        "--database-dsn", str(arguments.database_dsn),
        "--s10-contract", str(arguments.contract),
        "--public-origin", PUBLIC_ORIGIN,
    ]
    health = _run(base + ["--health-only"])
    try:
        payload = json.loads(health.stdout)
    except json.JSONDecodeError:
        raise ValueError("S10_GROWTH_HEALTH_INVALID") from None
    if health.returncode != 0 or payload.get("ok") is not True or payload.get("state") != "GREEN":
        raise ValueError("S10_GROWTH_HEALTH_RED")
    forbidden = payload.get("forbidden_capabilities")
    components = payload.get("components")
    runtime = payload.get("runtime")
    if (
        not isinstance(forbidden, dict)
        or set(forbidden) != S9_FORBIDDEN_CAPABILITIES
        or any(forbidden[key] is not False for key in S9_FORBIDDEN_CAPABILITIES)
        or components != S9_COMPONENTS
        or not isinstance(runtime, dict)
        or any(runtime.get(key) is not expected for key, expected in S9_RUNTIME_FLAGS.items())
        or runtime.get("channels") != S9_CHANNELS
    ):
        raise ValueError("S10_GROWTH_BOUNDARY_RED")
    if arguments.local_only:
        return {"application": "GREEN", "telegram": "NOT_PROBED_LOCAL_ONLY"}
    channel = _run(base + [
        "--channel-health", "--s8-contract", str(arguments.s8_contract),
        "--telegram-token", str(arguments.telegram_token),
        "--telegram-channel", arguments.telegram_channel,
    ])
    try:
        channel_payload = json.loads(channel.stdout)
    except json.JSONDecodeError:
        raise ValueError("S10_TELEGRAM_HEALTH_INVALID") from None
    if channel.returncode != 0 or channel_payload != {
        "bot_can_post": True,
        "channel_bound": True,
        "ok": True,
        "safe_code": "S9_TELEGRAM_CHANNEL_GREEN",
    }:
        raise ValueError("S10_TELEGRAM_HEALTH_RED")
    return {"application": "GREEN", "telegram": "GREEN"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--copy", type=Path, required=True)
    parser.add_argument("--s8-contract", type=Path, required=True)
    parser.add_argument("--s9-contract", type=Path, required=True)
    parser.add_argument("--database-dsn", type=Path, required=True)
    parser.add_argument("--telegram-token", type=Path, required=True)
    parser.add_argument("--telegram-channel", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local-only", action="store_true")
    mode.add_argument("--pre-growth", action="store_true")
    arguments = parser.parse_args()
    try:
        if not all(path.is_file() for path in (arguments.contract, arguments.copy, arguments.s8_contract, arguments.s9_contract, arguments.database_dsn, arguments.telegram_token)):
            raise ValueError("S10_REQUIRED_FILE_MISSING")
        safe_code = (
            "S10_1_WMS_LOCAL_SFW_GREEN"
            if arguments.local_only
            else "S10_1_WMS_PRE_GROWTH_SFW_GREEN"
            if arguments.pre_growth
            else "S10_1_WMS_PUBLIC_SFW_GREEN"
        )
        payload = {
            "ok": True,
            "safe_code": safe_code,
            "state": "GREEN",
            "web_local": _web(LOCAL_ORIGIN),
            "web_public": None if arguments.local_only else _web(PUBLIC_ORIGIN),
            "growth": _growth(arguments),
            "system": _system(arguments.local_only, not arguments.local_only and not arguments.pre_growth),
            "adult_content": False,
            "real_avs": False,
            "payments": False,
            "external_adult_publishing": False,
            "creator_invite": False,
            "controlled_beta": False,
            "production": False,
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        safe_code = str(error) if str(error).startswith("S10_") else "S10_1_WMS_HEALTH_RED"
        print(json.dumps({"ok": False, "safe_code": safe_code, "state": "RED"}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
