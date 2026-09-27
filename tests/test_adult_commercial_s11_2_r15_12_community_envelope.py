from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_community_health_contract as contract
from scripts import tu1nz_adult_public_s11_2_r15_13_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/s11_2_r15_12_application_event_path_red.json"


def envelope(child: object, component: object, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "health_schema_version": contract.APPLICATION_HEALTH_SCHEMA_VERSION,
        "community_failure": {
            "schema": contract.COMMUNITY_FAILURE_ENVELOPE_SCHEMA,
            "version": contract.COMMUNITY_FAILURE_ENVELOPE_VERSION,
            "child_code": child,
            "component": component,
        },
        "ok": False,
        "safe_code": "S8_DIAGNOSTIC_RED",
        "state": "RED",
    }
    payload.update(changes)
    return payload


def green_payload() -> dict[str, object]:
    def profile(name: str) -> dict[str, object]:
        return {"profile": name, "state": "GREEN", "samples": 5}

    return {
        "health_schema_version": contract.APPLICATION_HEALTH_SCHEMA_VERSION,
        "ok": True,
        "safe_code": "S8_DIAGNOSTIC_GREEN",
        "state": "GREEN",
        "community": {
            "provider": {"ok": True, "safe_code": "S10_2D_COMMUNITY_GREEN"},
            "bot_event_path": {"ok": True, "safe_code": "BOT_EVENT_PATH_GREEN"},
            "pending_moderation": 0,
            "stuck_restrictions": 0,
            "latency_24h": {"samples": 5},
            "latency_slo_profiles": {
                name: profile(name)
                for name in (
                    "TECHNICAL_RUNTIME_LATENCY",
                    "REAL_USER_DIRECT_LATENCY",
                    "S11_CANARY_TECHNICAL_LATENCY",
                    "S11_CANARY_REAL_USER_LATENCY",
                )
            },
        },
    }


class R1512CommunityEnvelopeTests(unittest.TestCase):
    def test_exact_r15_11_fixture_preserves_event_path_child(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        failure = contract.failure_from_payload(payload, 2)
        self.assertEqual(failure.child_code, "BOT_EVENT_PATH_WAITING")
        self.assertEqual(failure.component, "POLLING")
        self.assertEqual(failure.outer_code, "S10_2D_COMMUNITY_STATE_RED")

    def test_explicit_provider_event_moderation_restriction_and_latency(self):
        cases = (
            ("S10_2D_COMMUNITY_ADMIN_MISSING", "PROVIDER"),
            ("BOT_EVENT_PATH_WAITING", "POLLING"),
            ("S10_2D_MODERATION_DELIVERY_STATE_RED", "MODERATION"),
            ("S10_2D_RESTRICTION_RELEASE_STATE_RED", "COMMUNITY"),
            ("COMMUNITY_RUNTIME_LATENCY_RED", "LATENCY_SLO"),
        )
        for child, component in cases:
            with self.subTest(child=child):
                failure = contract.failure_from_payload(envelope(child, component), 2)
                self.assertEqual(failure.child_code, child)
                self.assertEqual(failure.component, component)

    def test_explicit_envelope_is_return_code_symmetric(self):
        payload = envelope("BOT_EVENT_PATH_WAITING", "POLLING")
        for return_code in (0, 2):
            with self.subTest(return_code=return_code):
                failure = contract.failure_from_payload(payload, return_code)
                self.assertEqual(failure.child_code, "BOT_EVENT_PATH_WAITING")

    def test_green_payload_has_no_failure(self):
        self.assertIsNone(contract.failure_from_payload(green_payload(), 0))

    def test_legacy_structured_compatibility_is_bounded_and_prioritized(self):
        payload = green_payload()
        payload["ok"] = False
        payload["state"] = "RED"
        payload["community"].update({
            "provider": {"ok": True, "safe_code": "S10_2D_COMMUNITY_GREEN"},
            "bot_event_path": {"ok": False, "safe_code": "BOT_EVENT_PATH_WAITING"},
            "pending_moderation": 2,
            "stuck_restrictions": 3,
        })
        for return_code in (0, 2):
            failure = contract.failure_from_payload(payload, return_code)
            self.assertEqual(failure.child_code, "BOT_EVENT_PATH_WAITING")
            self.assertEqual(failure.component, "POLLING")

    def test_multiple_explicit_failures_follow_application_selected_priority(self):
        payload = envelope("S10_2D_COMMUNITY_ADMIN_MISSING", "PROVIDER")
        payload["community"] = {
            "provider": {"ok": False, "safe_code": "S10_2D_COMMUNITY_ADMIN_MISSING"},
            "bot_event_path": {"ok": False, "safe_code": "BOT_EVENT_PATH_WAITING"},
            "pending_moderation": 2,
        }
        failure = contract.failure_from_payload(payload, 2)
        self.assertEqual(failure.child_code, "S10_2D_COMMUNITY_ADMIN_MISSING")

    def test_malformed_explicit_envelope_never_downgrades_to_legacy(self):
        cases = (
            {"schema": "WRONG", "version": contract.COMMUNITY_FAILURE_ENVELOPE_VERSION,
             "child_code": "BOT_EVENT_PATH_WAITING", "component": "POLLING"},
            {"schema": contract.COMMUNITY_FAILURE_ENVELOPE_SCHEMA, "version": "WRONG",
             "child_code": "BOT_EVENT_PATH_WAITING", "component": "POLLING"},
            {"schema": contract.COMMUNITY_FAILURE_ENVELOPE_SCHEMA,
             "version": contract.COMMUNITY_FAILURE_ENVELOPE_VERSION,
             "child_code": "BOT_EVENT_PATH_WAITING", "component": "FREE_TEXT"},
        )
        for malformed in cases:
            payload = green_payload()
            payload.update({
                "ok": False,
                "state": "RED",
                "community_failure": malformed,
            })
            payload["community"]["bot_event_path"] = {
                "ok": False,
                "safe_code": "BOT_EVENT_PATH_WAITING",
            }
            with self.subTest(malformed=malformed):
                failure = contract.failure_from_payload(payload, 2)
                self.assertEqual(failure.child_code, contract.CHILD_UNKNOWN)

    def test_missing_and_unknown_explicit_children_fail_closed(self):
        missing = envelope(None, "POLLING")
        unknown = envelope("FREE_TEXT", "POLLING")
        self.assertEqual(
            contract.failure_from_payload(missing, 2).child_code,
            contract.CHILD_MISSING,
        )
        self.assertEqual(
            contract.failure_from_payload(unknown, 2).child_code,
            contract.CHILD_UNKNOWN,
        )

    def test_no_envelope_and_no_structured_reason_remains_missing(self):
        failure = contract.failure_from_payload(
            {"ok": False, "safe_code": "S8_DIAGNOSTIC_RED", "state": "RED"},
            2,
        )
        self.assertEqual(failure.child_code, contract.CHILD_MISSING)

    def test_privacy_surface_is_exact_and_bounded(self):
        payload = envelope("BOT_EVENT_PATH_WAITING", "POLLING")
        serialized = json.dumps(payload["community_failure"], sort_keys=True).lower()
        self.assertEqual(
            set(payload["community_failure"]),
            {"schema", "version", "child_code", "component"},
        )
        for forbidden in ("user_id", "chat_id", "message", "username", "token", "email", "ip_address"):
            self.assertNotIn(forbidden, serialized)

    def test_r15_13_full_source_simulator_is_green_and_non_mutating(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertFalse(report["runtime_mutation"])
        self.assertEqual(report["control_reader_version"], "CONTROL_COMMUNITY_READER_V2")
        self.assertEqual(report["cases"]["unknown"]["child_code"], contract.CHILD_UNKNOWN)
        self.assertEqual(report["happy_path"]["canary_starts"], 1)
        self.assertEqual(report["negative_community_path"]["technical_probes"], 0)
        self.assertEqual(report["negative_community_path"]["canary_starts"], 0)
        self.assertEqual(
            report["negative_community_path"]["pre_canary_child"],
            "BOT_EVENT_PATH_WAITING",
        )


if __name__ == "__main__":
    unittest.main()
