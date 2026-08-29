#!/usr/bin/env python3
"""Privacy-safe bounded observer for Commercial S4 server staging."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from typing import Any


SERVICE = "tu1nz-adult-commercial-s3.service"
STATE_ROOT = Path("/var/lib/tausendunde1nz/adult-commercial-s3")
DSN_PATH = Path("/etc/tu1nz/adult-commercial-s3.postgres-dsn")
EVIDENCE_PREFIX = Path("/opt/tu1nz_repos/backups/commercial-s4-extended-staging")
FORBIDDEN_KEYS = frozenset(
    {"bot_id", "chat_id", "credential", "dsn", "media", "token", "user_id"}
)


def fail(code: str) -> "NoReturn":
    raise SystemExit(f"S4_OBSERVER_RED {code}")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def command(*arguments: str) -> str:
    completed = subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
    )
    return completed.stdout


def service_properties() -> dict[str, str]:
    output = command(
        "systemctl",
        "show",
        SERVICE,
        "--property=ActiveState,SubState,NRestarts,MainPID,CPUUsageNSec,Restart",
    )
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def process_metrics(pid: int) -> tuple[int, int]:
    status = Path(f"/proc/{pid}/status")
    descriptors = Path(f"/proc/{pid}/fd")
    if not status.is_file() or not descriptors.is_dir():
        fail("PROCESS_EVIDENCE_MISSING")
    rss_kib = 0
    for line in status.read_text(encoding="ascii").splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = int(line.split()[1])
            break
    return rss_kib, len(tuple(descriptors.iterdir()))


def tree_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return total
    for candidate in path.rglob("*"):
        if candidate.is_file() and not candidate.is_symlink():
            total += candidate.stat().st_size
    return total


def journal_bytes(since: str) -> int:
    material = command(
        "journalctl",
        "--unit",
        SERVICE,
        "--since",
        since,
        "--output=cat",
        "--no-pager",
    )
    return len(material.encode("utf-8"))


def health_snapshot() -> tuple[str, dict[str, str]]:
    path = STATE_ROOT / "status.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8192:
        fail("HEALTH_EVIDENCE_INVALID")
    value = json.loads(path.read_text(encoding="ascii"))
    state = value.get("state")
    components = value.get("components")
    if state not in {"GREEN", "YELLOW", "RED"} or not isinstance(components, dict):
        fail("HEALTH_EVIDENCE_INVALID")
    if any(item not in {"GREEN", "YELLOW", "RED", "DISABLED_EXPECTED"} for item in components.values()):
        fail("HEALTH_EVIDENCE_INVALID")
    return state, dict(sorted(components.items()))


def database_snapshot() -> dict[str, int | float | None]:
    if not DSN_PATH.is_file() or DSN_PATH.is_symlink() or DSN_PATH.stat().st_size > 4096:
        fail("DATABASE_CREDENTIAL_FILE_INVALID")
    try:
        import psycopg  # type: ignore[import-not-found]

        with psycopg.connect(DSN_PATH.read_text(encoding="ascii").strip()) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database()"
                )
                connections = int(cursor.fetchone()[0])
                cursor.execute(
                    "SELECT count(*), COALESCE(max(revision), 0), "
                    "EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - max(last_successful_poll_at))) "
                    "FROM telegram_s2_1_polling_states"
                )
                row = cursor.fetchone()
        return {
            "connections": connections,
            "cursor_rows": int(row[0]),
            "cursor_revision_max": int(row[1]),
            "last_poll_age_seconds": None if row[2] is None else max(0.0, float(row[2])),
        }
    except Exception as exc:
        fail("DATABASE_OBSERVATION_FAILED_" + exc.__class__.__name__.upper())


def network_classes(pid: int) -> dict[str, int]:
    counts = {"EXTERNAL_HTTPS": 0, "LOOPBACK_POSTGRES": 0, "OTHER": 0}
    output = command("ss", "-Htanp")
    marker = f"pid={pid},"
    for line in output.splitlines():
        if marker not in line:
            continue
        fields = line.split()
        if len(fields) < 5:
            counts["OTHER"] += 1
            continue
        remote = fields[4]
        host, separator, port = remote.rpartition(":")
        if not separator:
            counts["OTHER"] += 1
        elif port == "443":
            counts["EXTERNAL_HTTPS"] += 1
        elif port == "5432" and host.strip("[]") in {"127.0.0.1", "::1"}:
            counts["LOOPBACK_POSTGRES"] += 1
        else:
            counts["OTHER"] += 1
    return counts


def safe_sample(started_at: str) -> dict[str, Any]:
    properties = service_properties()
    if not (
        properties.get("ActiveState") == "active"
        and properties.get("SubState") == "running"
        and properties.get("Restart") == "no"
    ):
        fail("SERVICE_NOT_ACTIVE_RUNNING")
    pid = int(properties.get("MainPID", "0"))
    if pid <= 0:
        fail("SERVICE_PID_INVALID")
    rss_kib, descriptors = process_metrics(pid)
    health, components = health_snapshot()
    result: dict[str, Any] = {
        "checked_at": utc_now().isoformat().replace("+00:00", "Z"),
        "cpu_usage_nsec": int(properties.get("CPUUsageNSec", "0") or 0),
        "database": database_snapshot(),
        "file_descriptors": descriptors,
        "health_components": components,
        "health_state": health,
        "journal_bytes": journal_bytes(started_at),
        "main_pid": pid,
        "network_classes": network_classes(pid),
        "restarts": int(properties.get("NRestarts", "0") or 0),
        "rss_kib": rss_kib,
        "state_bytes": tree_bytes(STATE_ROOT),
    }
    if FORBIDDEN_KEYS.intersection(result):
        fail("FORBIDDEN_EVIDENCE_FIELD")
    return result


def write_json(path: Path, value: object) -> None:
    material = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())


def summary(samples: list[dict[str, Any]], started_at: str, completed_at: str) -> dict[str, Any]:
    rss = [item["rss_kib"] for item in samples]
    descriptors = [item["file_descriptors"] for item in samples]
    connections = [item["database"]["connections"] for item in samples]
    states = [item["health_state"] for item in samples]
    return {
        "completed_at": completed_at,
        "cpu_delta_nsec": samples[-1]["cpu_usage_nsec"] - samples[0]["cpu_usage_nsec"],
        "database_connections_max": max(connections),
        "file_descriptors_max": max(descriptors),
        "file_descriptors_min": min(descriptors),
        "health_red_samples": states.count("RED"),
        "health_yellow_samples": states.count("YELLOW"),
        "journal_growth_bytes": samples[-1]["journal_bytes"] - samples[0]["journal_bytes"],
        "main_pid_changes": sum(
            left["main_pid"] != right["main_pid"] for left, right in zip(samples, samples[1:])
        ),
        "network_other_max": max(item["network_classes"]["OTHER"] for item in samples),
        "restarts_max": max(item["restarts"] for item in samples),
        "rss_kib_average": round(statistics.fmean(rss), 2),
        "rss_kib_peak": max(rss),
        "sample_count": len(samples),
        "started_at": started_at,
        "state_growth_bytes": samples[-1]["state_bytes"] - samples[0]["state_bytes"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=int, default=300)
    arguments = parser.parse_args()
    try:
        resolved = arguments.evidence_directory.resolve(strict=True)
        resolved.relative_to(EVIDENCE_PREFIX)
    except (OSError, ValueError):
        fail("EVIDENCE_PATH_INVALID")
    if resolved.is_symlink() or resolved.stat().st_uid != 0 or resolved.stat().st_mode & 0o077:
        fail("EVIDENCE_PATH_UNSAFE")
    if not 120 <= arguments.duration_seconds <= 21600:
        fail("DURATION_OUT_OF_RANGE")
    if not 60 <= arguments.interval_seconds <= 900:
        fail("INTERVAL_OUT_OF_RANGE")
    samples_path = resolved / "commercial-s4-observations.ndjson"
    summary_path = resolved / "commercial-s4-observation-summary.json"
    if samples_path.exists() or summary_path.exists():
        fail("EVIDENCE_ALREADY_EXISTS")
    started = utc_now()
    started_for_journal = started.strftime("%Y-%m-%d %H:%M:%S UTC")
    started_iso = started.isoformat().replace("+00:00", "Z")
    samples: list[dict[str, Any]] = []
    deadline = time.monotonic() + arguments.duration_seconds
    while True:
        item = safe_sample(started_for_journal)
        samples.append(item)
        with samples_path.open("a", encoding="ascii") as handle:
            os.chmod(samples_path, 0o600)
            handle.write(json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        print(
            json.dumps(
                {
                    "ok": True,
                    "safe_code": "S4_OBSERVER_SAMPLE_GREEN",
                    "sample": len(samples),
                    "health": item["health_state"],
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
    completed_iso = utc_now().isoformat().replace("+00:00", "Z")
    value = summary(samples, started_iso, completed_iso)
    write_json(summary_path, value)
    if value["health_red_samples"] or value["network_other_max"] or value["restarts_max"]:
        fail("ACCEPTANCE_SUMMARY_RED")
    print('{"ok":true,"safe_code":"S4_EXTENDED_OBSERVATION_GREEN"}', flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
