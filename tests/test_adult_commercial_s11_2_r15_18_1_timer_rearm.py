from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_r15_18_1_timer_rearm_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
FREEZE = ROOT / "scripts/tu1nz_adult_public_s11_2_freeze.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
DOC = ROOT / "docs/COMMERCIAL_S11_2_R15_18_1_TIMER_REARM_CONTRACT.md"


class R15181TimerRearmTests(unittest.TestCase):
    def test_exact_r15_18_regression_old_times_out_new_is_green(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["old_enable_now_outcome"], "TIMEOUT")
        self.assertEqual(report["old_timer_state"]["substate"], "elapsed")
        self.assertIsNone(report["old_timer_state"]["next_monotonic"])
        self.assertIsNone(report["old_timer_state"]["invocation_id"])
        self.assertEqual(report["new_explicit_arm_outcome"], "GREEN")
        self.assertTrue(report["new_pid1_invocation"])
        self.assertEqual(report["service_result"], "success")
        self.assertEqual(report["exec_main_status"], 0)
        self.assertEqual(report["timer_final_substate"], "waiting")
        self.assertTrue(report["finite_future"])

    def test_fixture_matrix_a_through_l(self):
        self.assertEqual(
            simulator.simulate()["fixture_matrix"],
            {
                "A": "GREEN",
                "B": "GREEN",
                "C": "waiting",
                "D": "RED",
                "E": "TIMEOUT",
                "F": "RED",
                "G": "RED",
                "H": "GREEN",
                "I": "RED",
                "J": "RED",
                "K": "GREEN",
                "L": 1,
            },
        )

    def test_full_next_runtime_simulation_preserves_prior_contracts(self):
        report = simulator.simulate()
        self.assertTrue(report["technical_green"])
        self.assertTrue(report["s11_installed_disabled"])
        self.assertEqual(report["synthetic_journeys_green"], 8)
        self.assertTrue(report["fallback_green"])
        self.assertEqual(report["canonical_rearm_history_delta"], 1)
        self.assertEqual(report["new_evidence_epoch"], "PRE_CANARY_ARMED")
        self.assertEqual(report["canary_starts"], 1)
        self.assertTrue(report["standalone_verify_green"])
        self.assertTrue(report["systemd_handoff_green"])
        self.assertEqual(report["runtime_mutations"], 0)

    def test_controller_separates_enablement_arm_and_acceptance(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("arm_controller_timer_for_handoff() {"):
            source.index("first_invocation_after_trigger() {")
        ]
        phases = source[
            source.index("run_remaining_phases() {"):
            source.index("finalize_deployment_evidence() {")
        ]
        self.assertNotIn("enable --now", helper)
        self.assertEqual(helper.count('systemctl start "$timer"'), 1)
        self.assertNotIn('systemctl start "$service"', helper)
        self.assertLess(helper.index('systemctl enable "$timer"'), helper.index('systemctl stop "$timer"'))
        self.assertLess(helper.index('systemctl stop "$timer"'), helper.index('systemctl reset-failed'))
        self.assertLess(helper.index('S11_HANDOFF_MONOTONIC="'), helper.index('systemctl start "$timer"'))
        self.assertLess(phases.index("release_inherited_lock"), phases.index("arm_controller_timer_for_handoff"))
        self.assertLess(phases.index("arm_controller_timer_for_handoff"), phases.index("wait_controller_natural_run"))
        self.assertIn("timer_activation", source)
        self.assertIn("fresh_arm_attempts", source)

    def test_manual_service_start_remains_forbidden(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertNotIn("systemctl start tu1nz-adult-public-s11-canary-controller.service", source)
        unit = (ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.service").read_text(encoding="utf-8")
        self.assertIn("RefuseManualStart=yes", unit)

    def test_freeze_and_manifest_bind_exact_new_contract(self):
        freeze = FREEZE.read_text(encoding="utf-8")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertIn('FREEZE_TAG = "s11-2-r15-18-1-timer-rearm-contract-freeze-r1"', freeze)
        self.assertIn('"phase_contract": "S11_2_R15_18_1_EXPLICIT_TIMER_REARM_V1"', freeze)
        self.assertIn('"r15_15_simulator": "EXPLICIT_SINGLE_FRESH_TIMER_ARM_V1"', freeze)
        self.assertEqual(
            manifest["r15_18_2_activation_relative_timer_contract"]["previous_freeze_immutable"],
            "s11-2-r15-18-1-timer-rearm-contract-freeze-r1",
        )
        contract = manifest["r15_18_1_timer_rearm_contract"]
        self.assertEqual(contract["fresh_arm_attempts_per_deployment"], 1)
        self.assertTrue(DOC.is_file())
        expected_historical_bindings = {
            "controller_sha256": "f77808c050b8626e68a18cf682d623cad365680f78bd26d00757c8eef8bbeb55",
            "freeze_helper_sha256": "5138f09702dd331668118deb54ca349984dd5f4914771de954e4cab6e64d3fe4",
            "simulator_sha256": "be419a154a2d77e31c86675b61801a6cb1cb4a7460643da4f7a6c392232be241",
            "focused_suite_sha256": "4a3029b13d9b25786dde0dfa0f3ad8d2d3f96e9352f9ce9e0e9f7dcaebdec639",
            "ssot_sha256": "588bcf07579989002af333abd17961cfa2197eb2991601c0a97a1c0bdd903296",
            "controller_unit_sha256": "b613ab16ae16bdae2175569428ca005b398e5844dc6d98167882230f5ef08b9f",
            "controller_timer_sha256": "cb21506ba674c33c7ec654010cb4d51ca91b84a8db0dff7256d92533fe971ebd",
        }
        for key, expected in expected_historical_bindings.items():
            with self.subTest(key=key):
                self.assertEqual(contract["artifact_bindings"][key], expected)
