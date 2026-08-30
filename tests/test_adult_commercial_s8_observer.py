from __future__ import annotations

import py_compile
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "scripts/tu1nz_adult_public_s8_observe.py"


class CommercialS8PublicObserverTests(unittest.TestCase):
    def test_observer_compiles_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(
                str(OBSERVER), cfile=str(Path(temporary) / "observer.pyc"), doraise=True
            )
        source = OBSERVER.read_text(encoding="utf-8")
        self.assertIn("21600", source)
        self.assertIn("S8_PUBLIC_TWO_HOUR_OBSERVATION_GREEN", source)
        self.assertIn("S8_PUBLIC_OBSERVATION_SAMPLE_GREEN", source)
        self.assertIn("duration_seconds", source)
        self.assertIn("interval_seconds", source)

    def test_observer_covers_runtime_fallback_resources_and_boundaries(self) -> None:
        source = OBSERVER.read_text(encoding="utf-8")
        for expected in (
            "tu1nz-adult-public-s7.service",
            "tu1nz-adult-public-s8-telegram.service",
            "tu1nz-adult-public-s8-landing.service",
            "tu1nz-adult-public-s8-health.timer",
            "nginx.service",
            "NRestarts",
            "MemoryCurrent",
            "CPUUsageNSec",
            "file_descriptors",
            "network_classes",
            "journal_runtime_red_count",
            "health_component_yellow_count",
            "forbidden_capabilities",
            "PRODUCT_BOUNDARY_RED",
            "validate_evidence_keys",
            "commercial-s8-public-observation-",
        ):
            self.assertIn(expected, source)

    def test_observer_is_read_only_and_privacy_safe(self) -> None:
        source = OBSERVER.read_text(encoding="utf-8")
        for forbidden in (
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "systemctl enable",
            "systemctl disable",
            "git fetch",
            "git pull",
            "getUpdates",
            "sendMessage",
            "getFile",
            "psql",
            "pg_dump",
            "rm -rf",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))


if __name__ == "__main__":
    unittest.main()
