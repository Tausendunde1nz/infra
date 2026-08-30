#!/usr/bin/env python3
"""Privacy-safe, state-aware Commercial S8 Telegram health check."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--copy", type=Path, required=True)
    parser.add_argument("--telegram-token", type=Path, required=True)
    parser.add_argument("--database-dsn", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    command = [
        "/opt/tu1nz_repos/adult-publishing-core/.venv/bin/tu1nz-public-s8-telegram",
        "--contract",
        str(arguments.contract),
        "--copy",
        str(arguments.copy),
        "--telegram-token",
        str(arguments.telegram_token),
        "--database-dsn",
        str(arguments.database_dsn),
        "--health-only",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=80,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError("HEALTH_COMMAND_RED")
        payload = json.loads(completed.stdout)
        components = payload.get("components", {})
        forbidden = payload.get("forbidden_capabilities", {})
        required = {
            "BOT_PROCESS": "READY",
            "TELEGRAM_AUTH": "READY",
            "POLLING": "READY",
            "DATABASE": "READY",
            "WAITLIST": "READY",
            "NOTIFIER": "READY",
            "QUEUE": "READY",
            "ANALYTICS": "READY",
            "PRODUCT_BOUNDARY": "READY",
            "AVS": "DISABLED_EXPECTED",
            "PAYMENT": "DISABLED_EXPECTED",
        }
        if payload.get("ok") is not True or any(components.get(key) != value for key, value in required.items()):
            raise ValueError("COMPONENT_RED")
        if any(forbidden.values()):
            raise ValueError("PRODUCT_BOUNDARY_RED")
        metrics = payload.get("metrics", {})
        safe_metrics = {
            "waitlisted": int(metrics.get("waitlisted", 0)),
            "subscribed": int(metrics.get("subscribed", 0)),
            "queue_pending": int(metrics.get("queue_pending", 0)),
            "queue_failed": int(metrics.get("queue_failed", 0)),
        }
    except Exception:
        print('{"ok":false,"safe_code":"S8_PUBLIC_TELEGRAM_HEALTH_RED","state":"RED"}')
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "safe_code": "S8_PUBLIC_TELEGRAM_HEALTH_GREEN",
                "state": "GREEN",
                "metrics": safe_metrics,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
