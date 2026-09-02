#!/usr/bin/env python3
"""Two-hour privacy-safe observer for the Want Me Seen SFW cutover."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


APPLICATION = Path("/opt/tu1nz_repos/adult-publishing-core")
CONTROL = Path("/opt/tu1nz_repos/control")
HEALTH_SERVICE = "tu1nz-adult-public-s10-health.service"
OBSERVATION_PARENT = Path("/opt/tu1nz_repos/backups")
OBSERVATION_PREFIX = "/opt/tu1nz_repos/backups/commercial-s10-1-wms-observation-"
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


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _run(command: list[str], timeout: int = 30) -> str:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("S10_1_OBSERVATION_COMMAND_RED")
    return completed.stdout.strip()


def _read_json(url: str) -> dict[str, object]:
    request = Request(url, headers={"User-Agent": "WMS-S10-Observer/1"}, method="GET")
    try:
        with urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise ValueError("S10_1_OBSERVATION_HTTP_RED")
            body = response.read(256 * 1024 + 1)
    except (HTTPError, URLError, OSError, TimeoutError):
        raise ValueError("S10_1_OBSERVATION_HTTP_RED") from None
    if not body or len(body) > 256 * 1024:
        raise ValueError("S10_1_OBSERVATION_RESPONSE_RED")
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        raise ValueError("S10_1_OBSERVATION_JSON_RED") from None
    if not isinstance(value, dict):
        raise ValueError("S10_1_OBSERVATION_JSON_RED")
    return value


def _git(repository: Path, expected_sha: str, expected_tree: str) -> None:
    command = ["/usr/sbin/runuser", "-u", "chatops", "--", "/usr/bin/git", "-C", str(repository)]
    if _run(command + ["rev-parse", "HEAD"]) != expected_sha:
        raise ValueError("S10_1_OBSERVATION_GIT_SHA_RED")
    if _run(command + ["rev-parse", "HEAD^{tree}"]) != expected_tree:
        raise ValueError("S10_1_OBSERVATION_GIT_TREE_RED")
    if _run(command + ["status", "--porcelain=v1"]):
        raise ValueError("S10_1_OBSERVATION_GIT_DIRTY")


def _system() -> None:
    for unit in SERVICES:
        active = _run(["/usr/bin/systemctl", "show", unit, "-p", "ActiveState", "--value"], timeout=8)
        restarts = _run(["/usr/bin/systemctl", "show", unit, "-p", "NRestarts", "--value"], timeout=8)
        if active != "active" or restarts != "0":
            raise ValueError("S10_1_OBSERVATION_SERVICE_RED")
    for unit in TIMERS:
        active = _run(["/usr/bin/systemctl", "show", unit, "-p", "ActiveState", "--value"], timeout=8)
        enabled = _run(["/usr/bin/systemctl", "is-enabled", unit], timeout=8)
        if active != "active" or enabled != "enabled":
            raise ValueError("S10_1_OBSERVATION_TIMER_RED")


def _health() -> None:
    _run(["/usr/bin/systemctl", "start", HEALTH_SERVICE], timeout=90)
    result = _run(["/usr/bin/systemctl", "show", HEALTH_SERVICE, "-p", "Result", "--value"], timeout=8)
    status = _run(["/usr/bin/systemctl", "show", HEALTH_SERVICE, "-p", "ExecMainStatus", "--value"], timeout=8)
    if result != "success" or status != "0":
        raise ValueError("S10_1_OBSERVATION_HEALTH_RED")
    public = _read_json("https://wantmeseen.com/health")
    legacy = _read_json("https://tu1nz.com/adult/health")
    if public.get("ok") is not True or legacy.get("ok") is not True:
        raise ValueError("S10_1_OBSERVATION_PUBLIC_RED")
    if any(
        public.get(key) is not False
        for key in ("adult_content", "real_avs", "payments", "external_publishing")
    ):
        raise ValueError("S10_1_OBSERVATION_BOUNDARY_RED")
    legacy_boundaries = legacy.get("forbidden_capabilities")
    if not isinstance(legacy_boundaries, dict) or set(legacy_boundaries) != {
        "adult_content", "payments", "real_avs", "real_creator_publishing",
    } or any(value is not False for value in legacy_boundaries.values()):
        raise ValueError("S10_1_OBSERVATION_LEGACY_BOUNDARY_RED")


def _write(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _sample(arguments: argparse.Namespace) -> None:
    _git(APPLICATION, arguments.application_sha, arguments.application_tree)
    _git(CONTROL, arguments.control_sha, arguments.control_tree)
    _system()
    _health()
    redirect = _run([
        "/usr/bin/curl", "--silent", "--show-error", "--max-time", "10",
        "--output", "/dev/null", "--write-out", "%{http_code}|%{redirect_url}",
        "https://wantmeseen.de/",
    ])
    if redirect != "302|https://tu1nz.com/adult/":
        raise ValueError("S10_1_OBSERVATION_DE_FALLBACK_RED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--application-sha", required=True)
    parser.add_argument("--application-tree", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--control-tree", required=True)
    parser.add_argument("--activation-id", required=True)
    parser.add_argument("--activated-at-epoch", type=int, required=True)
    parser.add_argument("--duration", type=int, default=7200)
    parser.add_argument("--interval", type=int, default=300)
    arguments = parser.parse_args()
    if arguments.duration < 7200 or not 60 <= arguments.interval <= 600:
        print('{"ok":false,"safe_code":"S10_1_OBSERVATION_WINDOW_RED"}')
        return 2
    if not arguments.output.is_dir() or arguments.output.is_symlink():
        print('{"ok":false,"safe_code":"S10_1_OBSERVATION_PATH_RED"}')
        return 2
    try:
        resolved_output = arguments.output.resolve(strict=True)
        resolved_parent = OBSERVATION_PARENT.resolve(strict=True)
    except OSError:
        print('{"ok":false,"safe_code":"S10_1_OBSERVATION_PATH_RED"}')
        return 2
    if (
        resolved_output != arguments.output
        or resolved_output.parent != resolved_parent
        or not resolved_output.name.startswith("commercial-s10-1-wms-observation-")
        or not resolved_output.name.removeprefix("commercial-s10-1-wms-observation-")[:1].isdigit()
    ):
        print('{"ok":false,"safe_code":"S10_1_OBSERVATION_PATH_RED"}')
        return 2
    started = time.monotonic()
    started_at_epoch = int(time.time())
    if started_at_epoch < arguments.activated_at_epoch:
        print('{"ok":false,"safe_code":"S10_1_OBSERVATION_ACTIVATION_TIME_RED"}')
        return 2
    started_at = _now()
    samples = 0
    next_sample_at = started
    observations = arguments.output / "observations.jsonl"
    try:
        while True:
            _sample(arguments)
            samples += 1
            with observations.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({
                    "at": _now(), "ok": True,
                    "safe_code": "S10_1_WMS_OBSERVATION_SAMPLE_GREEN",
                }, sort_keys=True, separators=(",", ":")) + "\n")
            os.chmod(observations, 0o600)
            elapsed = int(time.monotonic() - started)
            if elapsed >= arguments.duration:
                _write(arguments.output / "result.json", {
                    "ok": True,
                    "safe_code": "S10_1_WMS_OBSERVATION_GREEN",
                    "state": "GREEN",
                    "started_at": started_at,
                    "started_at_epoch": started_at_epoch,
                    "completed_at": _now(),
                    "duration_seconds": elapsed,
                    "sample_count": samples,
                    "application_sha": arguments.application_sha,
                    "application_tree": arguments.application_tree,
                    "control_sha": arguments.control_sha,
                    "control_tree": arguments.control_tree,
                    "activation_id": arguments.activation_id,
                    "adult_media": False,
                    "real_avs": False,
                    "payments": False,
                    "external_adult_publishing": False,
                })
                return 0
            next_sample_at += arguments.interval
            time.sleep(max(0.0, min(next_sample_at - time.monotonic(), arguments.duration - elapsed)))
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        safe_code = str(error) if str(error).startswith("S10_1_") else "S10_1_OBSERVATION_RED"
        _write(arguments.output / "failure.json", {
            "ok": False, "safe_code": safe_code, "state": "RED",
            "failed_at": _now(), "sample_count": samples,
        })
        return 2


if __name__ == "__main__":
    sys.exit(main())
