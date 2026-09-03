#!/usr/bin/env python3
"""Hash-bound S10.1 launcher for the target S9 public health envelope."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path


TARGET_HEALTH = Path("/opt/tu1nz_repos/control/scripts/tu1nz_adult_public_s9_health.py")
TARGET_HEALTH_SHA256 = "06d39a7253d66c7e67c76675746fbe591b8971ab51c86685076a1531c1ddd172"


def main() -> int:
    if not TARGET_HEALTH.is_file() or TARGET_HEALTH.is_symlink():
        return 2
    if hashlib.sha256(TARGET_HEALTH.read_bytes()).hexdigest() != TARGET_HEALTH_SHA256:
        return 2
    specification = importlib.util.spec_from_file_location("tu1nz_s10_1_s9_health", TARGET_HEALTH)
    if specification is None or specification.loader is None:
        return 2
    health = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(health)
    return health.main()


if __name__ == "__main__":
    sys.exit(main())
