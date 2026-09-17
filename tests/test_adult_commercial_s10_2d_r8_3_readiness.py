from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tu1nz_adult_public_s10_2d_readiness.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-r8-3-technical-readiness.json"


def load_module():
    specification = importlib.util.spec_from_file_location("tu1nz_r8_3_readiness_tests", SCRIPT)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


READINESS = load_module()


class CommercialS102DR83ReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def evidence(self) -> dict[str, object]:
        return {
            "technical_gates": {
                gate: True for gate in self.manifest["technical_readiness"]["required_gates"]
            },
            "technical_evidence_release_id": "s10-2d-r3-5",
            "technical_evidence_run_bound": True,
            "observation_duration_seconds": 1818,
            "bot_response_samples": 0,
            "bot_response_p50_ms": -1,
            "bot_response_p95_ms": -1,
            "bot_response_p99_ms": -1,
            "pending_moderation": 0,
            "stuck_restrictions": 0,
            "unknown_retained_state": 0,
            "real_acquisition_active": False,
            "real_acquisition_baseline_start": None,
        }

    def strict_manifest(self) -> dict[str, object]:
        manifest = copy.deepcopy(self.manifest)
        manifest["human_acceptance"] = {
            "direct_bot": "GREEN",
            "community": "GREEN",
            "moderation": "GREEN",
        }
        manifest["human_latency"] = {
            "bot_response": "MEASURED",
            "join_welcome": "MEASURED",
        }
        return manifest

    def assert_red(self, safe_code: str, manifest: dict[str, object], evidence: dict[str, object], profile: str) -> None:
        with self.assertRaisesRegex(READINESS.ReadinessContractError, f"^{safe_code}$"):
            READINESS.evaluate_readiness(
                manifest,
                evidence,
                profile,
                enforce_selected_profile=False,
            )

    def test_r8_2_exact_fixture_is_technical_green_and_human_deferred(self) -> None:
        report = READINESS.evaluate_readiness(
            self.manifest,
            self.evidence(),
            READINESS.DEFERRED_PROFILE,
        )
        self.assertTrue(report["WMS_REAL_ACQUISITION_TECHNICALLY_READY"])
        self.assertEqual(report["DIRECT_BOT_HUMAN_ACCEPTANCE"], "DEFERRED")
        self.assertEqual(report["COMMUNITY_HUMAN_ACCEPTANCE"], "DEFERRED")
        self.assertEqual(report["MODERATION_HUMAN_LIVE_ACCEPTANCE"], "DEFERRED")
        self.assertEqual(report["BOT_RESPONSE_LATENCY"], "NOT_MEASURED")
        self.assertEqual(report["JOIN_WELCOME_LATENCY"], "NOT_MEASURED")
        self.assertFalse(report["REAL_ACQUISITION_ACTIVE"])
        self.assertIsNone(report["REAL_ACQUISITION_BASELINE_START"])
        self.assertEqual(report["latency_samples"], 0)
        self.assertIsNone(report["p50_ms"])

    def test_full_human_profile_remains_strict(self) -> None:
        evidence = self.evidence()
        evidence.update({
            "bot_response_samples": 5,
            "bot_response_p50_ms": 500,
            "bot_response_p95_ms": 900,
            "bot_response_p99_ms": 950,
        })
        report = READINESS.evaluate_readiness(
            self.strict_manifest(),
            evidence,
            READINESS.STRICT_PROFILE,
            enforce_selected_profile=False,
        )
        self.assertEqual(report["DIRECT_BOT_HUMAN_ACCEPTANCE"], "GREEN")
        self.assertEqual(report["BOT_RESPONSE_LATENCY"], "MEASURED")

        zero_samples = self.evidence()
        self.assert_red(
            "LATENCY_SAMPLE_FLOOR_MISSING",
            self.strict_manifest(),
            zero_samples,
            READINESS.STRICT_PROFILE,
        )

    def test_unknown_profile_and_implicit_profile_fail_closed(self) -> None:
        self.assert_red("UNKNOWN_ACCEPTANCE_PROFILE", self.manifest, self.evidence(), "UNKNOWN")
        with self.assertRaisesRegex(
            READINESS.ReadinessContractError, "^ACCEPTANCE_PROFILE_SELECTION_RED$"
        ):
            READINESS.evaluate_readiness(
                self.strict_manifest(), self.evidence(), READINESS.STRICT_PROFILE
            )

        incomplete_human = copy.deepcopy(self.manifest)
        del incomplete_human["human_acceptance"]["moderation"]
        self.assert_red(
            "HUMAN_ACCEPTANCE_CONTRACT_RED",
            incomplete_human,
            self.evidence(),
            READINESS.DEFERRED_PROFILE,
        )

        incomplete_latency = copy.deepcopy(self.manifest)
        del incomplete_latency["human_latency"]["join_welcome"]
        self.assert_red(
            "HUMAN_LATENCY_CONTRACT_RED",
            incomplete_latency,
            self.evidence(),
            READINESS.DEFERRED_PROFILE,
        )

    def test_technical_red_human_red_and_stale_evidence_fail_closed(self) -> None:
        technical = self.evidence()
        technical["technical_gates"]["wms_health"] = False
        self.assert_red("TECHNICAL_GATE_RED", self.manifest, technical, READINESS.DEFERRED_PROFILE)

        human = copy.deepcopy(self.manifest)
        human["human_acceptance"]["direct_bot"] = "RED"
        self.assert_red("HUMAN_ACCEPTANCE_RED", human, self.evidence(), READINESS.DEFERRED_PROFILE)

        stale = self.evidence()
        stale["technical_evidence_release_id"] = "s10-2d-r3-4"
        self.assert_red("TECHNICAL_EVIDENCE_STALE", self.manifest, stale, READINESS.DEFERRED_PROFILE)

    def test_acquisition_adult_observation_and_unknown_state_guards(self) -> None:
        active = self.evidence()
        active["real_acquisition_active"] = True
        self.assert_red(
            "REAL_ACQUISITION_UNEXPECTEDLY_ACTIVE",
            self.manifest,
            active,
            READINESS.DEFERRED_PROFILE,
        )

        adult = copy.deepcopy(self.manifest)
        adult["product_boundaries"]["ADULT_MEDIA"] = "OPEN"
        self.assert_red("PRODUCT_BOUNDARY_RED", adult, self.evidence(), READINESS.DEFERRED_PROFILE)

        observation = self.evidence()
        observation["observation_duration_seconds"] = 1799
        self.assert_red(
            "OBSERVATION_WINDOW_INCOMPLETE",
            self.manifest,
            observation,
            READINESS.DEFERRED_PROFILE,
        )

        unknown = self.evidence()
        unknown["unknown_retained_state"] = 1
        self.assert_red(
            "RETAINED_UNKNOWN_STATE_RED",
            self.manifest,
            unknown,
            READINESS.DEFERRED_PROFILE,
        )

    def test_manifest_and_controller_keep_profiles_explicit_and_acquisition_separate(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(
            self.manifest["acceptance_profile"],
            "TECHNICAL_RUNTIME_WITH_HUMAN_DEFERRED",
        )
        self.assertEqual(
            set(self.manifest["acceptance_profiles"]),
            {"FULL_HUMAN_E2E", "TECHNICAL_RUNTIME_WITH_HUMAN_DEFERRED"},
        )
        self.assertIn('mark-ready) [ "$#" -eq 4 ]', controller)
        self.assertIn('--profile "$profile"', controller)
        self.assertIn("SET pre_acquisition_readiness='GREEN'", controller)
        mark_ready = controller.split("mark_ready() {", 1)[1].split('case "${1:-}"', 1)[0]
        self.assertNotIn("wms_real_acquisition_ready=true", mark_ready)
        self.assertNotIn("real_acquisition_baseline_start=CURRENT_TIMESTAMP", mark_ready)
        self.assertFalse(self.manifest["real_acquisition_active"])
        self.assertIsNone(self.manifest["real_acquisition_baseline_start"])
        self.assertEqual(self.manifest["technical_runtime_status"], "GO")
        self.assertEqual(self.manifest["direct_bot_human_acceptance"], "DEFERRED")
        self.assertEqual(self.manifest["community_human_acceptance"], "DEFERRED")
        self.assertEqual(self.manifest["moderation_human_acceptance"], "DEFERRED")
        self.assertEqual(self.manifest["bot_response_latency_status"], "NOT_MEASURED")
        self.assertEqual(self.manifest["join_welcome_latency_status"], "NOT_MEASURED")
        self.assertEqual(self.manifest["observation_duration"], 1818)
        self.assertEqual(self.manifest["adult_gate_state"], "CLOSED")


if __name__ == "__main__":
    unittest.main()
