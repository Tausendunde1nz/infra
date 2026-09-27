from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_r15_18_2_timer_semantics as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
FREEZE = ROOT / "scripts/tu1nz_adult_public_s11_2_freeze.py"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_r15_18_2_timer_semantics.py"
TIMER = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.timer"
SERVICE = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.service"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
DOC = ROOT / "docs/COMMERCIAL_S11_2_R15_18_2_ACTIVATION_RELATIVE_TIMER_CONTRACT.md"


class R15182ActivationRelativeTimerTests(unittest.TestCase):
    def test_source_semantics_falsify_simple_hypothesis_and_prove_refined_cause(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["simplistic_on_boot_hypothesis"], "FALSIFIED")
        self.assertEqual(report["old_genuinely_fresh_long_running_host"], "DUE_IMMEDIATELY")
        self.assertEqual(report["old_reused_manager_state"], "ELAPSED_NO_FUTURE")
        self.assertEqual(
            report["classification"],
            "BOOT_RELATIVE_ONE_SHOT_DISABLED_BY_REUSED_MANAGER_TRIGGER_STATE",
        )
        self.assertEqual(report["persistent_semantics"], "ON_CALENDAR_ONLY_IRRELEVANT_BUT_HARMLESS")

    def test_fixture_matrix_a_through_m(self):
        self.assertEqual(
            simulator.simulate()["fixture_matrix"],
            {
                "A": "ELAPSED_NO_FUTURE",
                "B": "GREEN",
                "C": "FINITE",
                "D": "CURRENT_PID1_INVOCATION",
                "E": "FINITE_RECURRENCE",
                "F": "RED",
                "G": "RED",
                "H": "RED",
                "I": "RED",
                "J": "RED",
                "K": "RED",
                "L": 1,
                "M": "GREEN",
            },
        )

    def test_timer_is_activation_relative_and_recurring(self):
        source = TIMER.read_text(encoding="ascii").splitlines()
        self.assertEqual(source.count("OnActiveSec=3min"), 1)
        self.assertEqual(source.count("OnUnitActiveSec=5min"), 1)
        self.assertFalse(any(line.startswith("OnBootSec=") for line in source))
        self.assertIn("RandomizedDelaySec=30s", source)
        self.assertIn("AccuracySec=15s", source)
        self.assertIn("Persistent=true", source)
        self.assertIn("RefuseManualStart=yes", SERVICE.read_text(encoding="ascii"))

    def test_arm_is_single_and_fails_fast_on_invalid_initial_schedule(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("arm_controller_timer_for_handoff() {"):
            source.index("first_invocation_after_trigger() {")
        ]
        self.assertEqual(helper.count('systemctl start "$timer"'), 1)
        self.assertNotIn('systemctl start "$service"', helper)
        self.assertIn('post_timer_substate" = waiting', helper)
        self.assertIn("timer_has_finite_future_values", helper)
        self.assertIn("S11_2_CONTROLLER_TIMER_INITIAL_SCHEDULE_RED", helper)
        self.assertIn('"initial_schedule_green": initial_schedule_green', helper)

    def test_full_simulator_preserves_runtime_contracts(self):
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

    def test_freeze_manifest_and_artifact_bindings(self):
        freeze = FREEZE.read_text(encoding="utf-8")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertIn('FREEZE_TAG = "s11-2-r15-18-2-activation-relative-timer-freeze-r1"', freeze)
        self.assertIn('"phase_contract": "S11_2_R15_18_2_ACTIVATION_RELATIVE_TIMER_V1"', freeze)
        self.assertIn('"r15_15_simulator": "ACTIVATION_RELATIVE_TIMER_AND_INITIAL_SCHEDULE_V1"', freeze)
        self.assertEqual(
            manifest["control_release"]["freeze_tag"],
            "s11-2-r15-18-2-activation-relative-timer-freeze-r1",
        )
        contract = manifest["r15_18_2_activation_relative_timer_contract"]
        self.assertEqual(contract["fresh_arm_attempts_per_deployment"], 1)
        self.assertEqual(contract["fixture_matrix"], "A-M")
        self.assertTrue(DOC.is_file())
        for key, path in {
            "controller_sha256": CONTROLLER,
            "freeze_helper_sha256": FREEZE,
            "simulator_sha256": SIMULATOR,
            "focused_suite_sha256": Path(__file__),
            "ssot_sha256": DOC,
            "controller_unit_sha256": SERVICE,
            "controller_timer_sha256": TIMER,
        }.items():
            with self.subTest(key=key):
                self.assertEqual(
                    contract["artifact_bindings"][key],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )


if __name__ == "__main__":
    unittest.main()
