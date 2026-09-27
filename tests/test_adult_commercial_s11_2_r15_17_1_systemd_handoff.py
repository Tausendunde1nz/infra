from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_r15_17_1_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
TIMER = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.timer"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_r15_17_1_simulator.py"
SSOT = ROOT / "docs/COMMERCIAL_S11_2_R15_17_1_SYSTEMD_HANDOFF_CONTRACT.md"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"


def controller_prelude() -> str:
    source = CONTROLLER.read_text(encoding="utf-8")
    return source[: source.index('\ncase "${1:-}" in')]


def run_bash(script: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        prelude = Path(directory) / "controller-prelude.sh"
        prelude.write_text(controller_prelude(), encoding="utf-8")
        return subprocess.run(
            ["bash", "-s", "--", str(prelude)],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )


class R15171SystemdHandoffTests(unittest.TestCase):
    def test_fixture_matrix_a_through_j_is_fail_closed(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(
            report["fixture_matrix"],
            {
                "A": "RED",
                "B": "RED",
                "C": "RED",
                "D": "RED",
                "E": "RED",
                "F": "RED",
                "G": "GREEN",
                "H": "RED",
                "I": "RED",
                "J": "GREEN",
            },
        )
        self.assertEqual(report["canary_starts"], 1)
        self.assertEqual(report["automatic_retries"], 0)
        self.assertEqual(report["runtime_mutations"], 0)
        self.assertTrue(report["next_runtime_deployment_ready"])
        self.assertTrue(report["manual_pretrigger_invocation_rejected"])
        self.assertTrue(report["failed_timer_cannot_be_masked_by_manual_success"])

    def test_historical_success_never_substitutes_for_current_invocation(self):
        report = simulator.simulate()
        self.assertTrue(report["historical_state_cannot_pass"])
        self.assertTrue(report["current_invocation_required"])
        self.assertTrue(report["failed_current_invocation_is_red"])
        source = CONTROLLER.read_text(encoding="utf-8")
        for evidence in (
            "LastTriggerUSecMonotonic",
            "InvocationID",
            "ExecMainStartTimestampMonotonic",
            "Result",
            "ExecMainStatus",
            "_SYSTEMD_INVOCATION_ID",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, source)

    def test_service_invocation_must_not_predate_timer_trigger(self):
        decision = simulator._decision(
            trigger="1100",
            invocation="new-invocation",
            start="1050",
        )
        self.assertNotEqual(decision, "GREEN")
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("start_usec < trigger_usec", source)

    def test_failed_timer_invocation_cannot_be_masked_by_manual_success(self):
        decision = simulator._decision(
            trigger="1100",
            invocation="later-manual-success",
            start="1200",
            first_invocation="failed-timer-invocation",
        )
        self.assertEqual(decision, "RED")
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("first_invocation_after_trigger", source)
        self.assertIn("_SYSTEMD_INVOCATION_ID", source)
        self.assertIn("__MONOTONIC_TIMESTAMP", source)
        self.assertIn(
            '| S11_TRIGGER_USEC="$trigger_usec" /usr/bin/python3',
            source,
        )

    def test_finite_future_helper_is_canonical_and_rejects_no_event_values(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("timer_has_finite_future_values() {") :
            source.index("handoff_snapshot_decision() {")
        ]
        for value in ('""', "n/a", "0", "infinity", "infinite", "never", "-"):
            with self.subTest(value=value):
                self.assertIn(value, source)
        services = source[
            source.index("require_services_and_timers() {") :
            source.index("require_public_health() {")
        ]
        verify = source[source.index("verify_target() {") : source.index("restore_optional() {")]
        handoff = source[
            source.index("handoff_snapshot_decision() {") :
            source.index("wait_controller_natural_run() {")
        ]
        self.assertIn("timer_has_finite_future", services)
        self.assertIn("timer_has_finite_future", verify)
        self.assertIn("timer_has_finite_future_values", handoff)
        self.assertNotIn("NextElapseUSec", services)
        self.assertIn("date --date", helper)
        self.assertIn("systemd-analyze timespan", source)

    def test_comparison_markers_use_systemd_monotonic_clock(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("monotonic_now_usec() {") :
            source.index("systemd_timespan_usec() {")
        ]
        self.assertIn("time.CLOCK_MONOTONIC", helper)
        self.assertIn("time.clock_gettime_ns", helper)
        self.assertNotIn("/proc/uptime", helper)

    def test_recurring_timer_requires_waiting_and_preserves_unit_semantics(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn('SubState --value)" = waiting', source)
        unit = TIMER.read_text(encoding="ascii")
        for directive in (
            "OnBootSec=3min",
            "OnUnitActiveSec=5min",
            "RandomizedDelaySec=30s",
            "AccuracySec=15s",
            "Persistent=true",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, unit)

    def test_standalone_verify_initializes_clean_environment(self):
        result = run_bash(
            r'''
set -Eeuo pipefail
source "$1"
unset S11_2_TARGET_CONTROL S11_2_BACKUP_PATH || true
require_root() { return 0; }
acquire_lock() { return 0; }
verify_target() {
  [ "$S11_2_TARGET_CONTROL" = "$1" ]
  [ "$S11_2_BACKUP_PATH" = /opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260927T130000Z-predeploy ]
}
standalone_verify \
  0123456789012345678901234567890123456789 \
  /opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260927T130000Z-predeploy
'''
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("unbound variable", result.stderr)

    def test_standalone_verify_preserves_negative_failure(self):
        result = run_bash(
            r'''
set -Eeuo pipefail
source "$1"
require_root() { return 0; }
acquire_lock() { return 0; }
verify_target() { return 27; }
standalone_verify \
  0123456789012345678901234567890123456789 \
  /opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260927T130000Z-predeploy
'''
        )
        self.assertEqual(result.returncode, 27)

    def test_verify_keeps_all_fail_closed_runtime_gates(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        verify = source[source.index("verify_target() {") : source.index("restore_optional() {")]
        for gate in (
            "require_clean_commit",
            "require_local_freeze",
            "INSTALLED_CONTROLLER_DRIFT",
            "verify_health_contract",
            "require_hard_gates",
            "TECHNICAL_LATENCY_RED",
            "CONTROLLER_TIMER_SUBSTATE_RED",
            "CONTROLLER_FUTURE_RUN_MISSING",
        ):
            with self.subTest(gate=gate):
                self.assertIn(gate, verify)

    def test_full_source_simulator_entrypoint_is_green(self):
        completed = subprocess.run(
            [sys.executable, str(SIMULATOR)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(
            report["safe_code"],
            "S11_2_R15_17_1_SOURCE_ONLY_SIMULATOR_GREEN",
        )
        self.assertEqual(report["synthetic_journeys_green"], 8)

    def test_manifest_and_ssot_bind_r15_17_1_contract(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        contract = manifest["r15_17_1_systemd_handoff_contract"]
        self.assertEqual(contract["fixture_matrix"], "A-J")
        self.assertEqual(contract["natural_run_proof"], "CURRENT_INVOCATION_AFTER_HANDOFF")
        self.assertEqual(contract["future_timer_contract"], "FINITE_AND_WAITING")
        self.assertTrue(contract["standalone_verify_clean_environment"])
        self.assertFalse(contract["runtime_mutation_performed"])
        self.assertTrue(SSOT.is_file())


if __name__ == "__main__":
    unittest.main()
