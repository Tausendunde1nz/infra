from __future__ import annotations

import py_compile
import re
import tempfile
import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "scripts/tu1nz_adult_public_s8_observe.py"


def load_observer():
    spec = importlib.util.spec_from_file_location("tu1nz_s8_observer_test", OBSERVER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CommercialS8PublicObserverTests(unittest.TestCase):
    def test_observer_compiles_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(
                str(OBSERVER), cfile=str(Path(temporary) / "observer.pyc"), doraise=True
            )
        source = OBSERVER.read_text(encoding="utf-8")
        self.assertIn("21600", source)
        self.assertIn("S8_PUBLIC_TWO_HOUR_OBSERVATION_GREEN", source)
        self.assertIn("S8_PUBLIC_OBSERVATION_SAMPLE_{0}", source)
        self.assertIn("MAXIMUM_TRANSPORT_FAILURES = 8", source)
        self.assertIn("MAXIMUM_HEALTH_YELLOW_SAMPLES = 2", source)
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

    def test_timer_check_uses_stable_active_and_enabled_contract(self) -> None:
        source = OBSERVER.read_text(encoding="utf-8")
        timer_check = source.split("def require_timer()", 1)[1].split(
            "def process_metrics", 1
        )[0]
        self.assertIn('value.get("ActiveState") != "active"', timer_check)
        self.assertIn('systemctl", "is-enabled", HEALTH_TIMER', timer_check)
        self.assertNotIn('value.get("SubState") != "waiting"', timer_check)

    def test_retryable_transport_yellow_and_recovery_are_classified(self) -> None:
        observer = load_observer()
        observer.command = lambda *_args, **_kwargs: "\n".join(
            (
                '{"event":"S8_TRANSPORT_YELLOW","provider_safe_reason":"S8_TELEGRAM_API_UNAVAILABLE","failures_in_window":1}',
                '{"event":"S8_TRANSPORT_RECOVERED"}',
                '{"event":"S8_TRANSPORT_YELLOW","provider_safe_reason":"S8_TELEGRAM_RATE_LIMITED","failures_in_window":2}',
                '{"event":"S8_TRANSPORT_RECOVERED"}',
            )
        )
        evidence = observer.journal_transport_evidence("now")
        self.assertEqual(evidence["last_state"], "GREEN")
        self.assertEqual(evidence["maximum_failures_in_window"], 2)
        self.assertEqual(evidence["yellow_transition_count"], 2)
        self.assertEqual(evidence["recovered_count"], 2)
        self.assertEqual(evidence["transport_red_count"], 0)

    def test_unapproved_yellow_classification_fails_closed(self) -> None:
        observer = load_observer()
        observer.command = lambda *_args, **_kwargs: (
            '{"event":"S8_TRANSPORT_YELLOW","provider_safe_reason":"S8_TELEGRAM_CREDENTIAL_REJECTED","failures_in_window":1}'
        )
        with self.assertRaisesRegex(observer.ObservationFailure, "TRANSPORT_YELLOW_CLASSIFICATION_RED"):
            observer.journal_transport_evidence("now")


if __name__ == "__main__":
    unittest.main()
