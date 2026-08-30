#!/usr/bin/env python3
"""Privacy-safe, bounded observer for Commercial S8 public Early Access."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


S7_SERVICE = "tu1nz-adult-public-s7.service"
S8_SERVICE = "tu1nz-adult-public-s8-telegram.service"
LANDING_SERVICE = "tu1nz-adult-public-s8-landing.service"
HEALTH_SERVICE = "tu1nz-adult-public-s8-health.service"
HEALTH_TIMER = "tu1nz-adult-public-s8-health.timer"
NGINX_SERVICE = "nginx.service"
APPLICATION_ROOT = Path("/opt/tu1nz_repos/adult-publishing-core")
CONTROL_ROOT = Path("/opt/tu1nz_repos/control")
EVIDENCE_PARENT = Path("/opt/tu1nz_repos/backups")
ACTIVE_PROXY = Path("/etc/nginx/sites-enabled/tu1nz.conf")
ACTIVE_PROXY_SHA = "65c0bc9d12981a4532d5453c668f8b2f9a4ad32cf5a7a18b8ef4ed3b56a0f062"
S8_DEEP_LINK = "https://t.me/tu1nz_adult_early_access_bot?start=landing_s8_launch"
LOCAL_S7_HEALTH = "http://127.0.0.1:8095/adult/health"
LOCAL_S8_LANDING = "http://127.0.0.1:18096/adult/"
LOCAL_S8_HEALTH = "http://127.0.0.1:18096/adult/health"
EXTERNAL_LANDING = "https://tu1nz.com/adult/"
EXTERNAL_HEALTH = "https://tu1nz.com/adult/health"
EXTERNAL_PRIVACY = "https://tu1nz.com/adult/privacy"
EXTERNAL_TERMS = "https://tu1nz.com/adult/terms"
FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "bot_id",
        "chat_id",
        "credential",
        "dsn",
        "media",
        "message",
        "subject_id",
        "token",
        "user_id",
    }
)
MAXIMUM_TRANSPORT_FAILURES = 8
MAXIMUM_HEALTH_YELLOW_SAMPLES = 2
MAXIMUM_CONSECUTIVE_HEALTH_YELLOW_SAMPLES = 2
RETRYABLE_PROVIDER_SAFE_CODES = frozenset(
    {"S8_TELEGRAM_API_UNAVAILABLE", "S8_TELEGRAM_RATE_LIMITED"}
)


class ObservationFailure(RuntimeError):
    pass


def fail(code: str) -> NoReturn:
    raise ObservationFailure(code)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def command(*arguments: str, timeout: int = 30) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        completed = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=True,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        fail("COMMAND_FAILED")
    return completed.stdout


def service_properties(unit: str) -> dict[str, str]:
    output = command(
        "systemctl",
        "show",
        unit,
        "--property=ActiveState,SubState,NRestarts,MainPID,CPUUsageNSec,MemoryCurrent,TasksCurrent",
    )
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def require_running(unit: str) -> dict[str, str]:
    value = service_properties(unit)
    if not (
        value.get("ActiveState") == "active"
        and value.get("SubState") in {"running", "waiting"}
        and int(value.get("MainPID", "0") or 0) > 0
        and int(value.get("NRestarts", "0") or 0) == 0
    ):
        fail("SERVICE_STATE_RED")
    return value


def require_timer() -> None:
    value = service_properties(HEALTH_TIMER)
    # A timer can move through a short trigger substate while its oneshot service runs.
    # ActiveState plus the persisted enablement state are the stable safety contract.
    if value.get("ActiveState") != "active":
        fail("HEALTH_TIMER_RED")
    if command("systemctl", "is-enabled", HEALTH_TIMER).strip() != "enabled":
        fail("HEALTH_TIMER_DISABLED")


def process_metrics(pid: int) -> dict[str, int]:
    status = Path(f"/proc/{pid}/status")
    descriptors = Path(f"/proc/{pid}/fd")
    if not status.is_file() or not descriptors.is_dir():
        fail("PROCESS_EVIDENCE_MISSING")
    rss_kib = 0
    for line in status.read_text(encoding="ascii").splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = int(line.split()[1])
            break
    return {"file_descriptors": len(tuple(descriptors.iterdir())), "rss_kib": rss_kib}


def network_classes(pid: int) -> dict[str, int]:
    result = {"EXTERNAL_HTTPS": 0, "LOOPBACK_POSTGRES": 0, "OTHER": 0}
    marker = f"pid={pid},"
    for line in command("ss", "-Htanp").splitlines():
        if marker not in line:
            continue
        fields = line.split()
        if len(fields) < 5:
            result["OTHER"] += 1
            continue
        host, separator, port = fields[4].rpartition(":")
        normalized = host.strip("[]")
        if not separator:
            result["OTHER"] += 1
        elif port == "443":
            result["EXTERNAL_HTTPS"] += 1
        elif port == "5432" and normalized in {"127.0.0.1", "::1"}:
            result["LOOPBACK_POSTGRES"] += 1
        else:
            result["OTHER"] += 1
    return result


def read_url(url: str, maximum: int = 512 * 1024) -> bytes:
    request = Request(url, headers={"User-Agent": "TU1NZ-S8-Observer/1"}, method="GET")
    try:
        with urlopen(request, timeout=10) as response:
            if response.status != 200:
                fail("HTTP_STATUS_RED")
            body = response.read(maximum + 1)
    except (HTTPError, URLError, OSError, TimeoutError):
        fail("HTTP_REQUEST_RED")
    if not body or len(body) > maximum:
        fail("HTTP_BODY_RED")
    return body


def health_document(url: str) -> dict[str, Any]:
    try:
        value = json.loads(read_url(url).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        fail("HEALTH_DOCUMENT_RED")
    if not isinstance(value, dict) or value.get("ok") is not True:
        fail("HEALTH_DOCUMENT_RED")
    forbidden = value.get("forbidden_capabilities")
    if not isinstance(forbidden, dict) or any(forbidden.values()):
        fail("PRODUCT_BOUNDARY_RED")
    return value


def latest_runtime_health(now: datetime) -> dict[str, Any]:
    output = command("journalctl", "-u", HEALTH_SERVICE, "-n", "120", "--no-pager", "-o", "cat")
    payload: dict[str, Any] | None = None
    for line in reversed(output.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and candidate.get("mode") == "RUNTIME":
            payload = candidate
            break
    if payload is None or payload.get("safe_code") not in {
        "S8_DIAGNOSTIC_GREEN",
        "S8_DIAGNOSTIC_YELLOW",
    }:
        fail("RUNTIME_HEALTH_MISSING_OR_RED")
    components = payload.get("components")
    if not isinstance(components, dict):
        fail("RUNTIME_HEALTH_COMPONENTS_RED")
    statuses = {name: value.get("status") for name, value in components.items() if isinstance(value, dict)}
    if set(statuses.values()) - {"GREEN", "YELLOW"}:
        fail("RUNTIME_HEALTH_COMPONENT_RED")
    completed = max(
        datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))
        for value in components.values()
        if isinstance(value, dict) and isinstance(value.get("completed_at"), str)
    )
    age = max(0.0, (now - completed).total_seconds())
    if age > 720:
        fail("RUNTIME_HEALTH_STALE")
    return {
        "age_seconds": round(age, 3),
        "component_statuses": dict(sorted(statuses.items())),
        "state": payload.get("state"),
    }


def repository_state(root: Path, expected_sha: str, expected_tree: str) -> None:
    if command("git", "-C", str(root), "rev-parse", "HEAD").strip() != expected_sha:
        fail("REPOSITORY_SHA_DRIFT")
    if command("git", "-C", str(root), "rev-parse", "HEAD^{tree}").strip() != expected_tree:
        fail("REPOSITORY_TREE_DRIFT")
    if command("git", "-C", str(root), "status", "--porcelain=v1").strip():
        fail("REPOSITORY_DIRTY")


def host_capacity() -> dict[str, int]:
    memory_kib = 0
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            memory_kib = int(line.split()[1])
            break
    disk = os.statvfs("/")
    return {
        "memory_available_kib": memory_kib,
        "root_available_bytes": disk.f_bavail * disk.f_frsize,
    }


def journal_transport_evidence(since: str) -> dict[str, Any]:
    output = command(
        "journalctl", "-u", S8_SERVICE, "--since", since, "--no-pager", "-o", "cat"
    )
    runtime_red = 0
    transport_red = 0
    yellow = 0
    recovered = 0
    maximum_failures = 0
    last_state = "GREEN"
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        event = value.get("event")
        if event == "S8_RUNTIME_CYCLE_RED":
            runtime_red += 1
        elif event == "S8_TRANSPORT_RED":
            transport_red += 1
            last_state = "RED"
        elif event == "S8_TRANSPORT_YELLOW":
            provider_code = value.get("provider_safe_reason")
            failures = value.get("failures_in_window")
            if provider_code not in RETRYABLE_PROVIDER_SAFE_CODES:
                fail("TRANSPORT_YELLOW_CLASSIFICATION_RED")
            if isinstance(failures, bool) or not isinstance(failures, int) or failures < 1:
                fail("TRANSPORT_YELLOW_EVIDENCE_RED")
            maximum_failures = max(maximum_failures, failures)
            yellow += 1
            last_state = "YELLOW"
        elif event == "S8_TRANSPORT_RECOVERED":
            recovered += 1
            last_state = "GREEN"
    return {
        "last_state": last_state,
        "maximum_failures_in_window": maximum_failures,
        "recovered_count": recovered,
        "runtime_red_count": runtime_red,
        "transport_red_count": transport_red,
        "yellow_transition_count": yellow,
    }


def safe_sample(arguments: argparse.Namespace, started_for_journal: str) -> dict[str, Any]:
    now = utc_now()
    repository_state(CONTROL_ROOT, arguments.control_sha, arguments.control_tree)
    repository_state(APPLICATION_ROOT, arguments.application_sha, arguments.application_tree)
    s7 = require_running(S7_SERVICE)
    s8 = require_running(S8_SERVICE)
    landing = require_running(LANDING_SERVICE)
    nginx = require_running(NGINX_SERVICE)
    require_timer()
    for unit in ("tu1nz-adult-commercial-s0.service", "tu1nz-adult-commercial-s3.service"):
        if service_properties(unit).get("ActiveState") != "inactive":
            fail("ADULT_RUNTIME_ACTIVE")
    if hashlib.sha256(ACTIVE_PROXY.read_bytes()).hexdigest() != ACTIVE_PROXY_SHA:
        fail("PUBLIC_PROXY_DRIFT")
    health_document(LOCAL_S7_HEALTH)
    local_landing = read_url(LOCAL_S8_LANDING).decode("utf-8")
    if S8_DEEP_LINK not in local_landing:
        fail("LOCAL_DEEP_LINK_RED")
    health_document(LOCAL_S8_HEALTH)
    external_landing = read_url(EXTERNAL_LANDING).decode("utf-8")
    if S8_DEEP_LINK not in external_landing:
        fail("EXTERNAL_DEEP_LINK_RED")
    health_document(EXTERNAL_HEALTH)
    read_url(EXTERNAL_PRIVACY)
    read_url(EXTERNAL_TERMS)
    runtime = latest_runtime_health(now)
    result: dict[str, Any] = {
        "checked_at": iso(now),
        "host": host_capacity(),
        "journal_transport": journal_transport_evidence(started_for_journal),
        "nginx": {
            "cpu_usage_nsec": int(nginx.get("CPUUsageNSec", "0") or 0),
            "main_pid": int(nginx["MainPID"]),
            "restarts": int(nginx.get("NRestarts", "0") or 0),
        },
        "runtime_health": runtime,
        "s7": {
            **process_metrics(int(s7["MainPID"])),
            "cpu_usage_nsec": int(s7.get("CPUUsageNSec", "0") or 0),
            "main_pid": int(s7["MainPID"]),
            "restarts": int(s7.get("NRestarts", "0") or 0),
        },
        "s8": {
            **process_metrics(int(s8["MainPID"])),
            "cpu_usage_nsec": int(s8.get("CPUUsageNSec", "0") or 0),
            "main_pid": int(s8["MainPID"]),
            "network_classes": network_classes(int(s8["MainPID"])),
            "restarts": int(s8.get("NRestarts", "0") or 0),
        },
        "s8_landing": {
            **process_metrics(int(landing["MainPID"])),
            "cpu_usage_nsec": int(landing.get("CPUUsageNSec", "0") or 0),
            "main_pid": int(landing["MainPID"]),
            "restarts": int(landing.get("NRestarts", "0") or 0),
        },
    }
    def validate_evidence_keys(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key).lower() in FORBIDDEN_EVIDENCE_KEYS:
                    fail("FORBIDDEN_EVIDENCE_FIELD")
                validate_evidence_keys(nested)
        elif isinstance(value, list):
            for nested in value:
                validate_evidence_keys(nested)

    validate_evidence_keys(result)
    return result


def write_exclusive(path: Path, value: object) -> None:
    material = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())


def append_sample(path: Path, value: object) -> None:
    material = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="ascii") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())


def summarize(samples: list[dict[str, Any]], started: datetime, completed: datetime) -> dict[str, Any]:
    s8_rss = [item["s8"]["rss_kib"] for item in samples]
    s8_fds = [item["s8"]["file_descriptors"] for item in samples]
    health_states = [item["runtime_health"]["state"] for item in samples]
    component_statuses = [
        status
        for item in samples
        for status in item["runtime_health"]["component_statuses"].values()
    ]
    longest_yellow_run = 0
    current_yellow_run = 0
    for state in health_states:
        if state == "YELLOW":
            current_yellow_run += 1
            longest_yellow_run = max(longest_yellow_run, current_yellow_run)
        else:
            current_yellow_run = 0
    transport = samples[-1]["journal_transport"]
    return {
        "completed_at": iso(completed),
        "duration_seconds": round((completed - started).total_seconds()),
        "health_red_samples": health_states.count("RED"),
        "health_yellow_samples": health_states.count("YELLOW"),
        "health_yellow_samples_maximum": MAXIMUM_HEALTH_YELLOW_SAMPLES,
        "health_yellow_consecutive_max": longest_yellow_run,
        "health_yellow_consecutive_maximum": MAXIMUM_CONSECUTIVE_HEALTH_YELLOW_SAMPLES,
        "final_health_state": health_states[-1],
        "health_component_red_count": component_statuses.count("RED"),
        "health_component_yellow_count": component_statuses.count("YELLOW"),
        "journal_runtime_red_count_max": transport["runtime_red_count"],
        "journal_transport_red_count": transport["transport_red_count"],
        "journal_transport_yellow_transitions": transport["yellow_transition_count"],
        "journal_transport_recovered_count": transport["recovered_count"],
        "journal_transport_last_state": transport["last_state"],
        "transport_failures_in_window_max": transport["maximum_failures_in_window"],
        "transport_failures_in_window_maximum": MAXIMUM_TRANSPORT_FAILURES,
        "nginx_main_pid_changes": sum(
            left["nginx"]["main_pid"] != right["nginx"]["main_pid"]
            for left, right in zip(samples, samples[1:])
        ),
        "s7_main_pid_changes": sum(
            left["s7"]["main_pid"] != right["s7"]["main_pid"]
            for left, right in zip(samples, samples[1:])
        ),
        "s7_restarts_max": max(item["s7"]["restarts"] for item in samples),
        "s8_file_descriptors_max": max(s8_fds),
        "s8_file_descriptors_min": min(s8_fds),
        "s8_landing_main_pid_changes": sum(
            left["s8_landing"]["main_pid"] != right["s8_landing"]["main_pid"]
            for left, right in zip(samples, samples[1:])
        ),
        "s8_landing_restarts_max": max(item["s8_landing"]["restarts"] for item in samples),
        "s8_main_pid_changes": sum(
            left["s8"]["main_pid"] != right["s8"]["main_pid"]
            for left, right in zip(samples, samples[1:])
        ),
        "s8_network_other_max": max(item["s8"]["network_classes"]["OTHER"] for item in samples),
        "s8_restarts_max": max(item["s8"]["restarts"] for item in samples),
        "s8_rss_kib_average": round(statistics.fmean(s8_rss), 2),
        "s8_rss_kib_peak": max(s8_rss),
        "sample_count": len(samples),
        "started_at": iso(started),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--application-sha", required=True)
    parser.add_argument("--application-tree", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--control-tree", required=True)
    arguments = parser.parse_args()
    for field in ("application_sha", "application_tree", "control_sha", "control_tree"):
        value = getattr(arguments, field)
        if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
            fail("PROVENANCE_ARGUMENT_INVALID")
    if not 120 <= arguments.duration_seconds <= 21600:
        fail("DURATION_OUT_OF_RANGE")
    if not 60 <= arguments.interval_seconds <= 900:
        fail("INTERVAL_OUT_OF_RANGE")
    if arguments.evidence_directory.parent != EVIDENCE_PARENT:
        fail("EVIDENCE_PATH_INVALID")
    if not arguments.evidence_directory.name.startswith("commercial-s8-public-observation-"):
        fail("EVIDENCE_PATH_INVALID")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    os.mkdir(arguments.evidence_directory, 0o700)
    if arguments.evidence_directory.is_symlink() or arguments.evidence_directory.stat().st_mode & 0o077:
        fail("EVIDENCE_DIRECTORY_UNSAFE")
    write_exclusive(arguments.evidence_directory / "observer.pid.json", {"pid": os.getpid()})
    started = utc_now()
    started_for_journal = started.strftime("%Y-%m-%d %H:%M:%S UTC")
    samples: list[dict[str, Any]] = []
    deadline = time.monotonic() + arguments.duration_seconds
    try:
        while True:
            sample = safe_sample(arguments, started_for_journal)
            samples.append(sample)
            append_sample(arguments.evidence_directory / "observations.ndjson", sample)
            print(
                json.dumps(
                    {
                        "health": sample["runtime_health"]["state"],
                        "ok": sample["runtime_health"]["state"] in {"GREEN", "YELLOW"},
                        "safe_code": "S8_PUBLIC_OBSERVATION_SAMPLE_{0}".format(
                            sample["runtime_health"]["state"]
                        ),
                        "sample": len(samples),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                flush=True,
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(arguments.interval_seconds, remaining))
        completed = utc_now()
        summary = summarize(samples, started, completed)
        write_exclusive(arguments.evidence_directory / "summary.json", summary)
        if (
            summary["duration_seconds"] < arguments.duration_seconds
            or summary["health_red_samples"]
            or summary["health_yellow_samples"] > MAXIMUM_HEALTH_YELLOW_SAMPLES
            or summary["health_yellow_consecutive_max"] > MAXIMUM_CONSECUTIVE_HEALTH_YELLOW_SAMPLES
            or summary["final_health_state"] != "GREEN"
            or summary["health_component_red_count"]
            or summary["health_component_yellow_count"] > MAXIMUM_HEALTH_YELLOW_SAMPLES
            or summary["journal_runtime_red_count_max"]
            or summary["journal_transport_red_count"]
            or summary["journal_transport_last_state"] != "GREEN"
            or summary["transport_failures_in_window_max"] > MAXIMUM_TRANSPORT_FAILURES
            or summary["nginx_main_pid_changes"]
            or summary["s7_main_pid_changes"]
            or summary["s7_restarts_max"]
            or summary["s8_main_pid_changes"]
            or summary["s8_restarts_max"]
            or summary["s8_landing_main_pid_changes"]
            or summary["s8_landing_restarts_max"]
            or summary["s8_network_other_max"]
        ):
            fail("OBSERVATION_SUMMARY_RED")
        write_exclusive(
            arguments.evidence_directory / "result.json",
            {"ok": True, "safe_code": "S8_PUBLIC_TWO_HOUR_OBSERVATION_GREEN"},
        )
        return 0
    except ObservationFailure as error:
        write_exclusive(
            arguments.evidence_directory / "failure.json",
            {"ok": False, "safe_code": str(error)},
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
