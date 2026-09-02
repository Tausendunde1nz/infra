#!/usr/bin/env python3
"""Run the complete S9 health envelope while publication timers stay disarmed."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path


S9_HEALTH = Path("/usr/local/bin/tu1nz_adult_public_s9_health.py")
S9_HEALTH_SHA256 = "56e04474cdabdd5b80b5f19ffadb76c57f5c0036e3214795dd66d164f081c0fc"


def main() -> int:
    if not S9_HEALTH.is_file() or S9_HEALTH.is_symlink():
        return 2
    if hashlib.sha256(S9_HEALTH.read_bytes()).hexdigest() != S9_HEALTH_SHA256:
        return 2
    specification = importlib.util.spec_from_file_location("tu1nz_s9_health_prearm", S9_HEALTH)
    if specification is None or specification.loader is None:
        return 2
    health = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(health)

    def system_health_prearm() -> dict[str, object]:
        services: dict[str, dict[str, object]] = {}
        for unit in health.SERVICES:
            active = health._systemctl("show", unit, "-p", "ActiveState", "--value")
            restarts = health._systemctl("show", unit, "-p", "NRestarts", "--value")
            if active != "active" or restarts != "0":
                raise ValueError("S9_PREARM_BASELINE_SERVICE_RED")
            services[unit] = {"active": True, "restarts": 0}
        timers: dict[str, dict[str, object]] = {}
        for unit in health.TIMERS:
            active = health._systemctl("show", unit, "-p", "ActiveState", "--value")
            enabled = health._run(["/usr/bin/systemctl", "is-enabled", unit], timeout=8)
            if active != "inactive" or enabled.stdout.strip() != "disabled" or enabled.returncode not in (0, 1):
                raise ValueError("S9_PREARM_TIMER_NOT_DISARMED")
            timers[unit] = {"active": False, "enabled": False}
        return {"services": services, "timers": timers, "prearm": True}

    health._system_health = system_health_prearm
    return health.main()


if __name__ == "__main__":
    sys.exit(main())
