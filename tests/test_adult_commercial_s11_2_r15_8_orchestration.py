from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
GATE = ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"


def valid_samples(count: int) -> list[dict[str, str]]:
    return [
        {
            "source": "DIRECT",
            "evidence_class": "INTERNAL_TEST",
            "sample_type": "DIRECT_BOT_RESPONSE",
            "interaction_path": "INTERNAL_ACCEPTANCE",
        }
        for _ in range(count)
    ]


class R158OrchestrationTests(unittest.TestCase):
    def test_phase_contract_is_complete_and_strictly_ordered(self):
        self.assertEqual(len(orchestration.PHASES), 11)
        self.assertEqual(orchestration.PHASES[0], "PRECHECK")
        self.assertEqual(orchestration.PHASES[2], "HEALTH_CONTRACT_INSTALLED")
        self.assertLess(
            orchestration.PHASES.index("TECHNICAL_EVIDENCE_COMPLETE"),
            orchestration.PHASES.index("CANARY_ACTIVE"),
        )
        self.assertEqual(orchestration.PHASES[-1], "SYSTEMD_HANDOFF")

    def test_phase_is_committed_only_after_predecessor_and_never_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "phase-state.json"
            orchestration.initialize(state, "release", "run")
            with self.assertRaisesRegex(orchestration.ContractError, "PHASE_ORDER"):
                orchestration.complete(state, "BACKUP_COMPLETE", "release", "run")
            orchestration.complete(state, "PRECHECK", "release", "run")
            with self.assertRaisesRegex(orchestration.ContractError, "PHASE_DUPLICATE"):
                orchestration.complete(state, "PRECHECK", "release", "run")
            report = orchestration.inspect(state, "release", "run")
            self.assertEqual(report["next_phase"], "BACKUP_COMPLETE")

    def test_state_binds_release_run_and_contract_without_pii(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "phase-state.json"
            orchestration.initialize(state, "release", "run")
            payload = json.loads(state.read_text(encoding="ascii"))
            self.assertEqual(payload["contract_version"], orchestration.CONTRACT_VERSION)
            self.assertEqual(payload["release_id"], "release")
            self.assertEqual(payload["run_id"], "run")
            self.assertNotIn("user", payload)
            with self.assertRaisesRegex(orchestration.ContractError, "BINDING"):
                orchestration.inspect(state, "release", "other-run")

    def test_state_rejects_relative_path_and_malformed_completed_record(self):
        with self.assertRaisesRegex(orchestration.ContractError, "STATE_UNSAFE"):
            orchestration.initialize(Path("relative-state.json"), "release", "run")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "phase-state.json"
            orchestration.initialize(state, "release", "run")
            payload = json.loads(state.read_text(encoding="ascii"))
            payload["completed"] = ["PRECHECK"]
            state.write_text(json.dumps(payload), encoding="ascii")
            with self.assertRaisesRegex(orchestration.ContractError, "PHASE_RECORD"):
                orchestration.inspect(state, "release", "run")

    def test_dynamic_technical_plan_exactly_matches_missing_floor(self):
        for current, expected in ((4, 1), (5, 0), (3, 2)):
            with self.subTest(current=current):
                state = "GREEN" if current >= 5 else "INSUFFICIENT_EVIDENCE"
                report = orchestration.technical_plan(
                    {
                        "required_floor": 5,
                        "current_valid_samples": current,
                        "state": state,
                        "samples": valid_samples(current),
                        "health": "GREEN",
                    }
                )
                self.assertEqual(report["missing_samples"], expected)
                self.assertEqual(report["hard_cap"], expected)

    def test_bad_provenance_slo_red_and_health_red_stop(self):
        invalid = valid_samples(4) + [
            {
                "source": "DIRECT",
                "evidence_class": "REAL",
                "sample_type": "DIRECT_BOT_RESPONSE",
                "interaction_path": "INTERNAL_ACCEPTANCE",
            }
        ]
        fixtures = (
            ({"required_floor": 5, "current_valid_samples": 5, "state": "GREEN", "samples": invalid, "health": "GREEN"}, "PROVENANCE"),
            ({"required_floor": 5, "current_valid_samples": 5, "state": "RED", "samples": valid_samples(5), "health": "GREEN"}, "SLO_RED"),
            ({"required_floor": 5, "current_valid_samples": 4, "state": "INSUFFICIENT_EVIDENCE", "samples": valid_samples(4), "health": "RED"}, "HEALTH_RED"),
        )
        for profile, code in fixtures:
            with self.subTest(code=code), self.assertRaisesRegex(orchestration.ContractError, code):
                orchestration.technical_plan(profile)

    def test_happy_zero_missing_and_two_missing_simulators(self):
        expected = {
            "happy-4-of-5": 1,
            "zero-missing-5-of-5": 0,
            "two-missing-3-of-5": 2,
        }
        for case, probes in expected.items():
            with self.subTest(case=case):
                report = orchestration.simulate(case)
                self.assertFalse(report["stopped"])
                self.assertEqual(report["technical_probes"], probes)
                self.assertEqual(report["canary_starts"], 1)
                self.assertTrue(report["technical_complete_before_canary"])

    def test_bad_probe_slo_and_health_simulators_never_start_canary(self):
        for case in ("bad-provenance", "slo-red", "health-red"):
            with self.subTest(case=case):
                report = orchestration.simulate(case)
                self.assertTrue(report["stopped"])
                self.assertEqual(report["technical_probes"], 0)
                self.assertEqual(report["canary_starts"], 0)

    def test_resume_boundaries_are_explicit_and_duplicate_free(self):
        for phase in (
            "BACKUP_COMPLETE",
            "HEALTH_CONTRACT_INSTALLED",
            "TECHNICAL_EVIDENCE_COMPLETE",
            "S11_INSTALLED_DISABLED",
            "SYNTHETIC_VALIDATION_GREEN",
            "EVIDENCE_EPOCH_SET",
        ):
            with self.subTest(phase=phase):
                report = orchestration.simulate("resume", phase)
                self.assertEqual(report["duplicate_side_effects"], 0)
                self.assertFalse(report["automatic_retry"])
                self.assertNotEqual(report["next_phase"], phase)

    def test_rollback_simulator_preserves_source_permissions(self):
        before = orchestration.simulate("rollback-before-canary")
        after = orchestration.simulate("rollback-after-canary")
        for report in (before, after):
            self.assertTrue(report["restore_bytes"])
            self.assertTrue(report["restore_modes"])
            self.assertTrue(report["restore_units"])
            self.assertFalse(report["source_permission_changes"])
        self.assertFalse(before["canonical_fallback"])
        self.assertTrue(after["canonical_fallback"])

    def test_controller_has_no_fixed_five_probe_fixture(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertNotIn("technical_latency_fixture", source)
        self.assertNotIn("insert_technical_evidence", source)
        self.assertNotIn("for iteration in 1 2 3 4 5", source)
        self.assertIn("iteration<=missing", source)

    def test_controller_hard_orders_health_technical_install_and_canary(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        phases = source[source.index("run_remaining_phases() {"):source.index("finalize_deployment_evidence() {")]
        order = [
            "HEALTH_CONTRACT_INSTALLED)",
            "TECHNICAL_EVIDENCE_COMPLETE)",
            "S11_INSTALLED_DISABLED)",
            "SYNTHETIC_VALIDATION_GREEN)",
            "FALLBACK_GREEN)",
            "CANARY_REARMED)",
            "EVIDENCE_EPOCH_SET)",
            "CANARY_ACTIVE)",
            "SYSTEMD_HANDOFF)",
        ]
        positions = [phases.index(value) for value in order]
        self.assertEqual(positions, sorted(positions))
        canary = phases[phases.index("CANARY_ACTIVE)"):phases.index("SYSTEMD_HANDOFF)")]
        self.assertNotIn("systemctl start \"$TECHNICAL_PROBE_SERVICE\"", canary)
        self.assertEqual(canary.count("database_transition START_CANARY"), 1)

    def test_r15_6_install_is_hash_owner_group_mode_and_version_bound(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        installer = source[source.index("install_health_contract() {"):source.index("verify_health_contract() {")]
        verifier = source[source.index("verify_health_contract() {"):source.index("apply_migration() {")]
        for artifact in (
            "tu1nz_adult_public_s10_health_child_contract.py",
            "tu1nz_adult_public_s10_1_health.py",
            "tu1nz_adult_public_s10_2d_health_gate.py",
            "tu1nz_adult_public_s11_2_health_preflight.py",
            "tu1nz_adult_public_s11_2_recovery_diagnostic.py",
        ):
            self.assertIn(artifact, installer)
        self.assertIn("S10_1_HEALTH_CHILD_V1", installer)
        self.assertIn("sha256", verifier)
        self.assertIn("0o755", verifier)

    def test_pre_canary_health_is_bound_to_the_new_service_invocation(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        preflight = source[source.index("pre_canary_health() {"):source.index("gate_json() {")]
        self.assertIn("--show-cursor", preflight)
        self.assertIn("--after-cursor", preflight)
        self.assertIn("S11_2_PRE_CANARY_HEALTH_RUN_MISSING", preflight)
        self.assertNotIn("-n 20", preflight)
        self.assertNotIn("|| true", preflight)

    def test_gate_uses_run_bound_pre_canary_technical_evidence(self):
        source = GATE.read_text(encoding="utf-8")
        runtime = source[source.index("def _runtime_payload"):source.index("def simulate_contract")]
        self.assertIn("technical_evidence_run_id", runtime)
        self.assertIn('value[1] == "DIRECT_BOT_RESPONSE"', runtime)
        self.assertIn('value[0] == "INTERNAL_TEST"', runtime)
        self.assertIn("now - timedelta(hours=24)", runtime)
        self.assertNotIn('value[1] == "S11_CANARY_RESPONSE"\n        and value[2] == "INTERNAL_ACCEPTANCE"', runtime)

    def test_fresh_deploy_and_resume_are_distinct_no_auto_retry_entrypoints(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("deploy() {", source)
        self.assertIn("resume() {", source)
        self.assertIn("resume TARGET_CONTROL BACKUP_PATH", source)
        deploy = source[source.index("deploy() {"):source.index("resume() {")]
        self.assertNotIn("resume ", deploy)
        self.assertNotIn("retry", deploy.lower())
        resume = source[source.index("resume() {"):source.index("deployment_error() {")]
        self.assertIn("S11_2_RESUME_AFTER_ROLLBACK_RED", resume)

    def test_epoch_and_canary_resume_do_not_repeat_state_transitions(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        phases = source[source.index("run_remaining_phases() {"):source.index("finalize_deployment_evidence() {")]
        epoch = phases[phases.index("EVIDENCE_EPOCH_SET)"):phases.index("CANARY_ACTIVE)")]
        canary = phases[phases.index("CANARY_ACTIVE)"):phases.index("SYSTEMD_HANDOFF)")]
        self.assertIn("UNSET)", epoch)
        self.assertIn("SET)", epoch)
        self.assertEqual(epoch.count("database_transition SET_EVIDENCE_EPOCH"), 1)
        self.assertIn("S11_CANARY\\|CANARY_COLLECTING_EVIDENCE", canary)
        self.assertEqual(canary.count("database_transition START_CANARY"), 1)

    def test_rollback_marks_run_as_non_resumable(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        error = source[source.index("deployment_error() {"):source.index("observe() {")]
        rollback = source[source.index("rollback() {"):source.index("usage() {")]
        operation = source[
            source.index("perform_rollback_once() {"):
            source.index("run_guarded_deployment() {")
        ]
        self.assertIn("ROLLBACK_STARTED", operation)
        self.assertIn("ROLLBACK_COMPLETED", operation)
        for body in (error, rollback):
            self.assertIn("run_rollback_strict", body)

    def test_pre_canary_rollback_cancels_armed_epoch_before_source_switch(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        restore = source[source.index("restore_source() {"):source.index("phase_next() {")]
        cancel = restore.index(
            "database_transition CANCEL_EVIDENCE_EPOCH "
            "S11_2_R15_8_PRE_CANARY_EPOCH_ROLLBACK"
        )
        application_switch = restore.index(
            'git_chatops "$APPLICATION_ROOT" switch --detach "$SOURCE_APPLICATION_COMMIT"'
        )
        control_switch = restore.index(
            'git_chatops "$CONTROL_ROOT" switch --detach "$SOURCE_CONTROL_COMMIT"'
        )
        self.assertLess(cancel, application_switch)
        self.assertLess(cancel, control_switch)
        self.assertIn("canary_release_id IS NULL", restore[cancel:application_switch])
        self.assertIn("canary_evidence_start IS NULL", restore[cancel:application_switch])
        self.assertIn("canary_live_start IS NULL", restore[cancel:application_switch])
        self.assertIn("canary_horizon_at IS NULL", restore[cancel:application_switch])

    def test_epoch_migration_detection_binds_the_actual_transition_contract(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        migration = source[source.index("apply_migration() {"):source.index("rearm_canary() {")]
        self.assertIn("tu1nz_s11_2_transition_runtime_control", migration)
        self.assertIn("CANCEL_EVIDENCE_EPOCH", migration)
        self.assertNotIn("tu1nz_s11_2_set_evidence_epoch", migration)

    def test_manifest_hash_binds_r15_8_contract_artifacts(self):
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["r15_8_artifact_bindings"]
        expected = {
            "controller_sha256": "c0ebc1b5f884a41e97a8dbd69aa094c2df7429619ddb5a823aa4084861ba6ab3",
            "gate_sha256": "d82868367387111fd73aa972335465432c922ef8f018872b9df8a2d1fa797f40",
            "orchestration_sha256": "2de1c7156363273bc6774fdcbd4a795674d67f525992cb53911d88bd40be36bc",
            "focused_suite_sha256": "55e32cafc949cb6c51facec97d35dfd71f7c43dd8017142fcbc27d77bae9975e",
            "ssot_sha256": "056e721dc34e38bf9c1a683f0b46c4e36e84af6edb1130cbb13d15220f5e25a4",
        }
        for key, expected_hash in expected.items():
            with self.subTest(binding=key):
                self.assertEqual(bindings[key], expected_hash)
        self.assertEqual(bindings["application_commit"], "dc901d01fd20bedd92a9c2565bd1d3370f7f3e14")
        self.assertEqual(bindings["application_tree"], "52b9960eff5348310c06f8480971260c00fa20ef")


if __name__ == "__main__":
    unittest.main()
