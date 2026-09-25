from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
ACCESS_SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_access_simulator.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
SSOT = ROOT / "docs/COMMERCIAL_S11_2_CANARY_BOOTSTRAP.md"
SERVICE = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.service"
TIMER = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.timer"
OLD_SERVICE = ROOT / "tests/fixtures/s11-2-r15-3/controller-without-chatops.service"
P0_RECOVERY = ROOT / "scripts/tu1nz_adult_public_s11_2_p0_recovery.sh"
S8_POLLER_RECOVERY = ROOT / "scripts/tu1nz_adult_public_s11_2_s8_poller_recovery.sh"


def load_gate():
    stub = types.SimpleNamespace(Connection=object, Error=Exception, connect=None)
    original = sys.modules.get("psycopg")
    sys.modules["psycopg"] = stub
    try:
        spec = importlib.util.spec_from_file_location("s11_2_canary_gate", GATE)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        if original is None:
            del sys.modules["psycopg"]
        else:
            sys.modules["psycopg"] = original


MODULE = load_gate()


def fixture(real=None, **overrides):
    real = [] if real is None else real
    payload = {
        "release_state": "S11_CANARY",
        "promotion_state": "CANARY_COLLECTING_EVIDENCE",
        "now": "2026-01-01T12:00:00Z",
        "evidence_start": "2026-01-01T00:00:00Z",
        "horizon_at": "2026-01-02T00:00:00Z",
        "session_cap": 10,
        "admitted_count": len(real),
        "technical_values_ms": [100, 110, 120, 130, 140],
        "real_values_ms": real,
        "new_unknown_count": 0,
        "historical_unknown_count": 3,
        "experience_sessions": len(real),
        "product_event_count": len(real),
        "hard_gates_green": True,
    }
    payload.update(overrides)
    return payload


class CommercialS112CanaryBootstrapTests(unittest.TestCase):
    def test_contract_simulator_covers_required_matrix(self):
        result = MODULE.simulate_contract()
        self.assertTrue(result["ok"])
        self.assertEqual(result["safe_code"], "S11_2_CANARY_SIMULATOR_GREEN")
        self.assertEqual(result["cases"]["C"], "CANARY_READY_FOR_PROMOTION")
        self.assertEqual(result["cases"]["D"], "CANARY_RED")
        self.assertEqual(result["cases"]["I"], "CANARY_INSUFFICIENT_REAL_VOLUME")
        self.assertEqual(result["cases"]["CAP"], "CANARY_INSUFFICIENT_REAL_VOLUME")

    def test_real_and_technical_profiles_are_separate_and_strict(self):
        collecting = MODULE.evaluate(fixture([200, 250, 300, 350]))
        self.assertEqual(collecting["decision"], "CANARY_COLLECTING_EVIDENCE")
        ready = MODULE.evaluate(fixture([200, 250, 300, 350, 400]))
        self.assertEqual(ready["transition"], "PROMOTE_FULL")
        technical_red = MODULE.evaluate(
            fixture([], technical_values_ms=[100, 110, 120, 130, 6000])
        )
        self.assertEqual(technical_red["decision"], "CANARY_RED")

    def test_epoch_provenance_and_hard_gates_fail_closed(self):
        historical = MODULE.evaluate(
            fixture([200, 250, 300, 350, 400], historical_unknown_count=99)
        )
        self.assertEqual(historical["transition"], "PROMOTE_FULL")
        self.assertEqual(
            MODULE.evaluate(fixture([], new_unknown_count=1))["decision"],
            "CANARY_RED",
        )
        self.assertEqual(
            MODULE.evaluate(fixture([], hard_gates_green=False))["reason"],
            "HARD_GATE_RED",
        )

    def test_runtime_reader_binds_epoch_samples_to_frozen_release(self):
        source = GATE.read_text(encoding="utf-8")
        runtime = source[source.index("def _runtime_payload"):source.index("def simulate_contract")]
        self.assertIn("canary_release_id", runtime)
        self.assertGreaterEqual(runtime.count("release_id=%s"), 2)
        self.assertIn("recorded_at >= %s AND recorded_at <= %s", runtime)
        self.assertNotIn("DELETE FROM commercial_s10_2d_latency_samples", source)
        self.assertNotIn("UPDATE commercial_s10_2d_latency_samples", source)

    def test_deploy_is_backup_first_and_canary_starts_after_gates(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        self.assertLess(deploy.index("backup_runtime"), deploy.index("fetch_and_require_target"))
        self.assertLess(deploy.index("require_backup"), deploy.index("switch --detach"))
        self.assertLess(deploy.index("apply_migration"), deploy.index("database_transition START_CANARY"))
        self.assertLess(deploy.index("run_synthetic_journeys"), deploy.index("database_transition START_CANARY"))
        self.assertLess(deploy.index("technical_latency_fixture"), deploy.index("database_transition START_CANARY"))
        self.assertLess(deploy.index("require_hard_gates"), deploy.index("database_transition START_CANARY"))
        self.assertIn("S11_DISABLED|NOT_STARTED", deploy)

    def test_terminal_epoch_rearm_is_bound_archival_after_backup(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        migration = source[source.index("apply_migration() {"):source.index("run_synthetic_journeys() {")]
        target = source[source.index("fetch_and_require_target() {"):source.index("install_from_git() {")]
        self.assertLess(deploy.index("require_backup"), deploy.index("apply_migration"))
        self.assertIn("0034_commercial_s11_2_canary_rearm.sql", target)
        self.assertIn("0034_commercial_s11_2_canary_rearm.down.sql", target)
        self.assertIn("MIGRATION_REARM_UP_SHA", target)
        self.assertIn("MIGRATION_REARM_DOWN_SHA", target)
        self.assertIn("S11_DISABLED\\|CANARY_RED", migration)
        self.assertIn("S11_DISABLED\\|CANARY_INSUFFICIENT_REAL_VOLUME", migration)
        self.assertIn("database_rearm S11_2_R15_TERMINAL_EPOCH_REARMED", migration)
        self.assertIn("history_before + 1", migration)
        self.assertIn("S11_2_TERMINAL_EPOCH_ARCHIVE_RED", migration)
        self.assertNotIn("DELETE FROM commercial_s10_2d_latency_samples", source)
        self.assertNotIn("UPDATE commercial_s10_2d_latency_samples", source)

    def test_predeploy_evidence_accepts_the_pre_canary_schema(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        evidence = source[source.index("database_evidence() {"):source.index("backup_optional() {")]
        self.assertIn('if "release_state" in s11_control_columns:', evidence)
        self.assertIn('if "admission_state" in s11_session_columns:', evidence)
        self.assertIn("PRE_CANARY_SCHEMA", evidence)
        backup = source[source.index("backup_runtime() {"):source.index("require_backup() {")]
        self.assertLess(backup.index("database_evidence"), backup.index("SHA256SUMS"))

    def test_controller_preserves_evidence_and_acquisition_baseline(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertNotIn("DELETE FROM commercial_s10_2d_latency_samples", source)
        self.assertNotIn("UPDATE commercial_s10_2d_latency_samples", source)
        self.assertNotIn("real_acquisition_baseline_start=", source)
        self.assertIn('ACQUISITION_BASELINE="2026-09-18T00:41:06.710027Z"', source)
        self.assertIn("INTERNAL_TEST", source)
        self.assertIn("INTERNAL_ACCEPTANCE", source)
        self.assertNotIn("evidence_class,'REAL'", source)

    def test_rollback_is_evidence_preserving_and_rejects_full(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        restore = source[source.index("restore_source() {"):source.index("deploy() {")]
        self.assertIn("S11_FULL\\|*) return 1", restore)
        self.assertNotIn("0033_commercial_s11_2_canary_bootstrap.down.sql", restore)
        self.assertIn("database_transition CANARY_RED", restore)
        self.assertLess(
            restore.index("require_wms_runtime_binding"),
            restore.index("systemctl restart \"$S8_SERVICE\""),
        )

    def test_preflight_proves_source_copy_runtime_binding(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        binding = source[
            source.index("require_wms_runtime_binding() {"):
            source.index("require_source_state() {")
        ]
        self.assertIn("WMSLandingApplication", binding)
        self.assertIn("ExposureCopy.load", binding)
        self.assertIn("AggregateCounter", binding)
        self.assertIn("TrafficQualityCounter", binding)
        preflight = source[
            source.index("require_source_state() {"):
            source.index("preflight() {")
        ]
        self.assertIn("S11_2_SOURCE_WMS_RUNTIME_BINDING_RED", preflight)

    def test_target_copy_binding_is_proved_before_source_switch(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        binding = source[
            source.index("require_target_wms_compatibility() {"):
            source.index("require_source_state() {")
        ]
        self.assertIn("S11_2_TARGET_WMS_PARSER_DRIFT", binding)
        self.assertIn("TARGET_APPLICATION_COMMIT", binding)
        self.assertIn("commercial-s10-1-wms-copy.v1.json", binding)
        self.assertIn("WMSLandingApplication", binding)
        fetch = source[
            source.index("fetch_and_require_target() {"):
            source.index("install_from_git() {")
        ]
        self.assertIn("require_target_wms_compatibility", fetch)
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        self.assertLess(
            deploy.index("fetch_and_require_target"),
            deploy.index("switch --detach"),
        )

    def test_backup_captures_complete_wms_runtime_tuple(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        backup = source[source.index("backup_runtime() {"):source.index("require_backup() {")]
        for artifact in (
            "wms-contract.json",
            "wms-landing-copy.json",
            "wms-bot-contract.json",
            "community-contract.json",
            "landing-aggregates.exact",
            "wms-traffic-quality.exact",
        ):
            self.assertIn(artifact, backup)

    def test_terminal_transition_leaves_single_controller_read_only(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        observe = source[source.index("observe() {"):source.index("rollback() {")]
        self.assertNotIn("systemctl disable", observe)
        self.assertIn("S11_2_TERMINAL_HARD_GATE_RED", observe)
        self.assertIn("require_hard_gates", observe)
        self.assertIn("promote_under_barrier_json", observe)
        self.assertIn("S11_FULL|FULL_RELEASE", observe)

    def test_observer_failures_cannot_be_overwritten_or_skip_canary_shutdown(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        hard = source[source.index("require_services_and_timers() {"):source.index("require_source_state() {")]
        self.assertGreaterEqual(hard.count("return 2; }"), 9)
        self.assertIn("require_services_and_timers || return $?", hard)
        self.assertIn("require_poller_and_rotation || return $?", hard)
        self.assertIn("require_public_health || return $?", hard)
        observe = source[source.index("observe() {"):source.index("rollback() {")]
        self.assertLess(
            observe.index('current_state="$(release_state)"'),
            observe.index("verify_runtime_access_contract"),
        )
        self.assertIn("database_transition CANARY_RED S11_2_RUNTIME_INTEGRITY_RED", observe)
        self.assertIn(
            '"$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE"',
            observe,
        )
        self.assertNotIn("require_local_freeze", observe)
        self.assertNotIn("CONTROL_ROOT", observe)

    def test_retired_s8_health_timer_is_preserved_not_reactivated(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        timers = source[source.index('readonly TIMERS=('):source.index("fail() {")]
        self.assertNotIn("tu1nz-adult-public-s8-health.timer", timers)
        self.assertIn(
            'RETIRED_S8_HEALTH_TIMER="tu1nz-adult-public-s8-health.timer"',
            source,
        )
        gates = source[
            source.index("require_services_and_timers() {"):
            source.index("require_public_health() {")
        ]
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_MISSING", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_ENABLED", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_ACTIVE", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_SUBSTATE_RED", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_PATH_DRIFT", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_DROPIN_PRESENT", gates)
        self.assertIn("S11_2_RETIRED_S8_HEALTH_TIMER_UNIT_DRIFT", gates)
        self.assertIn("RETIRED_S8_HEALTH_TIMER_SHA", gates)
        self.assertNotIn('cmp -s "$CONTROL_ROOT/systemd/$RETIRED_S8_HEALTH_TIMER"', gates)
        runtime_health = source[
            source.index("run_runtime_health() {"):
            source.index("gate_json() {")
        ]
        self.assertIn("tu1nz-adult-public-s8-health.service", runtime_health)
        self.assertNotIn("tu1nz-adult-public-s8-health.timer", runtime_health)

    def test_promotion_rechecks_hard_gates_and_is_atomic_under_writer_barrier(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        observe = controller[controller.index("observe() {"):controller.index("rollback() {")]
        promotion = observe[observe.index("PROMOTE_FULL)"):]
        self.assertLess(promotion.index("require_hard_gates"), promotion.index("promote_under_barrier_json"))
        self.assertIn("database_transition CANARY_RED S11_2_PROMOTION_HARD_GATE_RED", promotion)
        self.assertNotIn("database_transition CANARY_READY_FOR_PROMOTION", promotion)
        self.assertNotIn("database_transition FULL_RELEASE", promotion)
        helper = controller[
            controller.index("promote_under_barrier_json() {"):
            controller.index("gate_field() {")
        ]
        self.assertIn('"$APPLICATION_RUNTIME_PYTHON" "$INSTALLED_GATE"', helper)
        gate = GATE.read_text(encoding="utf-8")
        barrier = gate[gate.index("def promote_under_barrier("):gate.index("def simulate_contract")]
        self.assertLess(barrier.index("FOR UPDATE"), barrier.index("pg_advisory_xact_lock"))
        self.assertLess(barrier.index("pg_advisory_xact_lock"), barrier.index("clock_timestamp"))
        self.assertLess(barrier.index("clock_timestamp"), barrier.index("_runtime_payload"))
        self.assertLess(barrier.index("_runtime_payload"), barrier.index("CANARY_READY_FOR_PROMOTION"))
        self.assertIn("FULL_RELEASE", barrier)
        self.assertNotIn("commit()", barrier)

    def test_atomic_promotion_rechecks_evidence_after_acquiring_writer_barrier(self):
        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class Connection:
            def __init__(self):
                self.calls = []

            def execute(self, statement, parameters=None):
                self.calls.append((statement, parameters))
                if "target_release_id" in statement:
                    return Result(("s10-2d-r3-5",))
                if statement == "SELECT clock_timestamp()":
                    return Result((MODULE._timestamp("2026-01-01T12:00:00Z"),))
                return Result()

        connection = Connection()
        with mock.patch.object(
            MODULE,
            "_runtime_payload",
            return_value=fixture([200, 250, 300, 350, 400]),
        ):
            result = MODULE.promote_under_barrier(
                connection,
                "s10-2d-r3-5",
                lambda: True,
            )
        statements = [call[0] for call in connection.calls]
        self.assertIn("FOR UPDATE", statements[0])
        self.assertIn("pg_advisory_xact_lock", statements[1])
        self.assertEqual(statements[2], "SELECT clock_timestamp()")
        self.assertEqual(result["decision"], "FULL_RELEASE")
        self.assertTrue(result["promotion_applied"])
        transitions = [call[1][1] for call in connection.calls[3:]]
        self.assertEqual(
            transitions,
            ["CANARY_READY_FOR_PROMOTION", "FULL_RELEASE"],
        )

    def test_in_barrier_hard_gate_failure_prevents_every_transition(self):
        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class Connection:
            def __init__(self):
                self.calls = []

            def execute(self, statement, parameters=None):
                self.calls.append((statement, parameters))
                if "target_release_id" in statement:
                    return Result(("s10-2d-r3-5",))
                return Result()

        connection = Connection()
        with self.assertRaisesRegex(ValueError, "S11_2_IN_BARRIER_HARD_GATE_RED"):
            MODULE.promote_under_barrier(
                connection,
                "s10-2d-r3-5",
                lambda: False,
            )
        self.assertEqual(len(connection.calls), 2)
        self.assertFalse(
            any("tu1nz_s11_2_transition_runtime_control" in call[0] for call in connection.calls)
        )

    def test_rollback_requires_an_explicit_readable_known_state(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        restore = source[source.index("restore_source() {"):source.index("deploy() {")]
        self.assertNotIn("release_state 2>/dev/null || true", restore)
        self.assertIn('if ! current_state="$(release_state 2>/dev/null)"; then', restore)
        self.assertIn("S11_FULL\\|*) return 1", restore)
        self.assertIn("*) return 1", restore)

    def test_frozen_release_and_manifest_contract(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn('SOURCE_APPLICATION_COMMIT="77f9079956a42ee411e17f5697da96f6810ba966"', source)
        self.assertIn('SOURCE_APPLICATION_TREE="370001f8ce0491ddf7709c2cee16d452d6098721"', source)
        self.assertIn('SOURCE_CONTROL_COMMIT="7c634d3b82572e8459d51c69f04dce82c624d766"', source)
        self.assertIn('SOURCE_CONTROL_TREE="1bfbd80d5478dd24f8f3e47d3654a8b7dea649e4"', source)
        self.assertIn('TARGET_APPLICATION_COMMIT="84619ea0204aeb4b133fe6491f3315beccd635ae"', source)
        self.assertIn('TARGET_APPLICATION_TREE="8f90cfc39b038e6438a6ee6bf2b96c029c4ebbab"', source)
        self.assertIn('FINAL_CONTROL_TAG="s11-2-r15-4-runtime-access-freeze-r1"', source)
        self.assertIn(
            'CONTROLLER_UNIT_SHA="afa0ea4801404b34483adde8c63289b0b05f9b3392b2821fda0c1c52c1a22031"',
            source,
        )
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], "tu1nz-commercial-s11-2-canary-bootstrap-v17")
        self.assertEqual(
            manifest["status"],
            "S11_2_R15_4_SOURCE_RUNTIME_ACCESS_CONTRACT_SOURCE_GREEN_PENDING_REVIEW",
        )
        self.assertEqual(
            manifest["control_release"]["freeze_tag"],
            "s11-2-r15-4-runtime-access-freeze-r1",
        )
        self.assertEqual(
            manifest["application_release"]["commit"],
            "84619ea0204aeb4b133fe6491f3315beccd635ae",
        )
        self.assertEqual(
            manifest["application_release"]["tree"],
            "8f90cfc39b038e6438a6ee6bf2b96c029c4ebbab",
        )
        self.assertEqual(manifest["application_release"]["pull_request"], 119)
        self.assertEqual(manifest["application_release"]["post_merge_ci"], 35903748692)
        self.assertEqual(
            manifest["r15_activation"]["source_application_commit"],
            "77f9079956a42ee411e17f5697da96f6810ba966",
        )
        self.assertEqual(
            manifest["r15_activation"]["source_control_commit"],
            "7c634d3b82572e8459d51c69f04dce82c624d766",
        )
        self.assertEqual(manifest["r15_activation"]["maximum_real_sessions"], 10)
        self.assertTrue(manifest["r15_activation"]["p0_recovery_closed"])
        self.assertTrue(manifest["r15_activation"]["r14_1_runtime_ready"])
        self.assertEqual(manifest["r15_activation"]["authoritative_controller_count"], 1)
        self.assertTrue(manifest["r15_activation"]["terminal_epoch_rearm_required"])
        self.assertTrue(manifest["r15_activation"]["terminal_epoch_archival_required"])
        self.assertTrue(manifest["r15_activation"]["latency_evidence_preserved"])
        self.assertEqual(
            manifest["r15_rearm_artifact_bindings"]["migration_0034_up_sha256"],
            "8d2d293c1f382bb5f726624c5dbe24e85b8f5c47a037b0d1bb52726d3fc23621",
        )
        self.assertEqual(
            manifest["r15_rearm_artifact_bindings"]["migration_0034_down_sha256"],
            "ca1a286f042f685d7a48d6db1231d7a816973c5496da2702d9562958965f3d73",
        )
        self.assertTrue(manifest["r15_rearm_artifact_bindings"]["archive_is_append_only"])
        self.assertFalse(manifest["r15_rearm_artifact_bindings"]["latency_evidence_mutated"])
        self.assertFalse(manifest["r15_rearm_artifact_bindings"]["product_evidence_mutated"])
        self.assertEqual(
            manifest["r15_1_admin_readback"]["classification"],
            "CONTROL_ADMIN_READ_INGRESS_MISMATCH",
        )
        self.assertEqual(
            manifest["r15_1_admin_readback"]["history_read_ingress"],
            "LOCAL_POSTGRES_ADMIN",
        )
        self.assertFalse(manifest["r15_1_admin_readback"]["runtime_grants_expanded"])
        self.assertTrue(manifest["r15_1_admin_readback"]["query_is_constant"])
        self.assertTrue(manifest["r15_1_admin_readback"]["fresh_backup_required"])
        self.assertEqual(
            manifest["r15_2_optional_evidence"]["classification"],
            "OPTIONAL_EVIDENCE_GLOB_FALSE_REQUIRED",
        )
        self.assertTrue(manifest["r15_2_optional_evidence"]["primary_json_required"])
        self.assertTrue(manifest["r15_2_optional_evidence"]["companions_optional"])
        self.assertTrue(manifest["r15_2_optional_evidence"]["existing_move_errors_fatal"])
        self.assertEqual(
            manifest["r15_2_optional_evidence"]["fixture_counts"],
            [0, 1, 3],
        )
        self.assertEqual(
            manifest["r15_2_freeze_provenance"]["classification"],
            "FREEZE_PROVENANCE_LITERAL_MISMATCH",
        )
        self.assertEqual(
            manifest["r15_2_freeze_provenance"]["rejected_freeze_immutable"],
            "s11-2-r15-bounded-canary-freeze-r4",
        )
        self.assertEqual(
            manifest["r15_2_freeze_provenance"]["corrected_freeze"],
            "s11-2-r15-bounded-canary-freeze-r5",
        )
        self.assertFalse(
            manifest["r15_2_freeze_provenance"]["server_mutation_before_detection"]
        )
        self.assertEqual(
            manifest["r15_2_freeze_provenance"]["required_canary_binding"],
            "canary_contract=FIRST_10_24H_EPOCH_BOUND",
        )
        self.assertEqual(
            manifest["r15_2_freeze_provenance"]["required_promotion_binding"],
            "promotion_contract=FIVE_REAL_AND_TECHNICAL_SLO_GREEN",
        )
        access = manifest["r15_3_systemd_repository_access"]
        self.assertEqual(access["effective_user"], "root")
        self.assertEqual(access["effective_group"], "root")
        self.assertEqual(access["old_supplementary_groups"], [])
        self.assertEqual(access["new_supplementary_groups"], ["chatops"])
        self.assertFalse(access["repository_permissions_changed"])
        self.assertFalse(access["sudoers_changed"])
        self.assertTrue(access["access_preflight_is_product_read_only"])
        self.assertTrue(access["first_natural_controller_run_required"])
        self.assertTrue(access["exactly_one_canary_retry"])
        runtime_access = manifest["r15_4_source_runtime_access"]
        self.assertEqual(
            runtime_access["classification"],
            "SOURCE_RUNTIME_ACCESS_IDENTITY_CONFLATION",
        )
        self.assertEqual(runtime_access["source_identity"], "chatops")
        self.assertTrue(runtime_access["source_mode_0700_allowed"])
        self.assertFalse(runtime_access["source_permissions_changed"])
        self.assertEqual(runtime_access["runtime_identity"], "root:root+chatops")
        self.assertEqual(
            runtime_access["runtime_controller_path"],
            "/usr/local/bin/tu1nz_adult_public_s11_2_control.sh",
        )
        self.assertEqual(
            runtime_access["runtime_access_manifest"],
            "/etc/tu1nz/adult-commercial-s11-2-runtime-access.json",
        )
        self.assertEqual(
            runtime_access["runtime_interpreter_class"],
            "CANONICAL_APPLICATION_RUNTIME_VENV",
        )
        self.assertFalse(runtime_access["controller_source_checkout_required_at_runtime"])
        self.assertTrue(runtime_access["application_checkout_integrity_required_at_runtime"])
        self.assertTrue(runtime_access["installed_copy_hash_required"])
        self.assertEqual(runtime_access["installed_copy_owner_group"], "root:root")
        self.assertEqual(runtime_access["installed_controller_mode"], "0755")
        self.assertTrue(runtime_access["unit_exec_start_is_installed_copy"])
        self.assertFalse(runtime_access["unit_working_directory_uses_repository"])
        self.assertEqual(runtime_access["supplementary_groups"], ["chatops"])
        self.assertEqual(
            runtime_access["supplementary_group_reason"],
            "TRAVERSE_CANONICAL_APPLICATION_RUNTIME_VENV",
        )
        self.assertTrue(runtime_access["umask_077_regression"])
        self.assertEqual(runtime_access["deployment_simulator"], "SOURCE_ONLY")
        self.assertEqual(runtime_access["rollback_simulator"], "SOURCE_ONLY")
        self.assertFalse(runtime_access["runtime_retry_performed"])
        self.assertFalse(runtime_access["canary_retry_performed"])
        self.assertTrue(runtime_access["next_s11_canary_deployment_ready"])
        self.assertEqual(manifest["canary_contract"]["session_cap"], 10)
        self.assertEqual(manifest["canary_contract"]["evidence_epoch_hours"], 24)
        self.assertTrue(manifest["canary_contract"]["terminal_epoch_archived_before_rearm"])
        self.assertTrue(manifest["canary_contract"]["rearm_serialized_with_promotion_lock"])
        self.assertEqual(manifest["promotion_contract"]["minimum_real_samples"], 5)
        self.assertEqual(manifest["human_acceptance"], "DEFERRED")
        self.assertTrue(manifest["preserved_runtime"]["real_acquisition_active"])

        self.assertEqual(
            manifest["preserved_runtime"]["s8_health_timer"],
            "RETIRED_DISABLED_INACTIVE",
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["source_copy_binding_preflight"]
        )
        self.assertEqual(
            manifest["rollback_compatibility"]["p0_recovery_target"],
            "PUBLIC_WMS_ONLY",
        )
        self.assertEqual(
            manifest["rollback_compatibility"]["backup_directory_exact_mode"],
            "root:root:0700",
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["inherited_setgid_removed_before_backup"]
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["local_health_ready_before_public_gate"]
        )
        self.assertEqual(
            manifest["rollback_compatibility"]["local_health_timeout_seconds"],
            30,
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["canary_controller_uses_local_health_gate"]
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["target_copy_binding_preflight"]
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["feature_off_fallback_gate"]
        )
        self.assertTrue(
            manifest["rollback_compatibility"]["r7_gate_field_exit_code_fixed"]
        )
        self.assertEqual(
            manifest["rollback_compatibility"]["r7_s8_poller_recovery_target"],
            "S8_POLLER_START_LIMIT_ONLY",
        )

    def test_epoch_history_counts_use_bounded_admin_ingress(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("database_admin_history_count() {"):
            source.index("database_transition() {")
        ]
        self.assertIn("runuser -u postgres -- psql", helper)
        self.assertIn(
            'SELECT count(*) FROM commercial_s11_canary_epoch_history;',
            helper,
        )
        self.assertNotIn("$1", helper)
        self.assertNotIn("DATABASE_DSN", helper)
        self.assertNotIn("database_scalar", helper)
        self.assertEqual(source.count("database_admin_history_count"), 3)
        self.assertNotIn(
            'database_scalar "SELECT count(*) FROM commercial_s11_canary_epoch_history;"',
            source,
        )

    def test_optional_synthetic_companions_support_zero_one_and_many(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[
            source.index("move_optional_synthetic_companions() {"):
            source.index("technical_latency_fixture() {")
        ]
        self.assertIn('[ -e "$companion" ] || break', helper)
        self.assertIn('[ -f "$companion" ] || fail', helper)
        self.assertIn('mv -- "$companion" "$postdeploy/"', helper)
        self.assertNotIn("nullglob", helper)

        shell = (
            "set -Eeuo pipefail\n"
            "fail() { return 2; }\n"
            f"{helper}\n"
            'move_optional_synthetic_companions "$1" "$2"'
        )
        for count in (0, 1, 3):
            with self.subTest(companion_count=count), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_dir = root / "source"
                target_dir = root / "target"
                source_dir.mkdir()
                target_dir.mkdir()
                for index in range(count):
                    (source_dir / f"synthetic-journeys.json.{index}.json").write_text(
                        "{}\n",
                        encoding="utf-8",
                    )
                result = subprocess.run(
                    ["bash", "-c", shell, "test", str(source_dir), str(target_dir)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    sorted(path.name for path in target_dir.iterdir()),
                    [f"synthetic-journeys.json.{index}.json" for index in range(count)],
                )
                self.assertEqual(list(source_dir.iterdir()), [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "source"
            target_dir = root / "target"
            source_dir.mkdir()
            target_dir.mkdir()
            (source_dir / "synthetic-journeys.json.invalid").mkdir()
            result = subprocess.run(
                ["bash", "-c", shell, "test", str(source_dir), str(target_dir)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((source_dir / "synthetic-journeys.json.invalid").is_dir())

    def test_gate_field_returns_zero_for_present_values_and_two_for_missing(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        match = re.search(
            r"gate_field\(\) \{\n\s+/usr/bin/python3 -c '([^']+)' \"\$1\"\n\}",
            source,
        )
        self.assertIsNotNone(match)
        code = match.group(1)
        present = subprocess.run(
            ["/usr/bin/python3", "-c", code, "decision"],
            input='{"decision":"CANARY_COLLECTING_EVIDENCE"}',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(present.returncode, 0)
        self.assertEqual(present.stdout.strip(), "CANARY_COLLECTING_EVIDENCE")
        missing = subprocess.run(
            ["/usr/bin/python3", "-c", code, "missing"],
            input='{"decision":"CANARY_COLLECTING_EVIDENCE"}',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(missing.stdout, "")

    def test_r10_s8_poller_recovery_binds_reader_backup_first_and_never_retries_canary(self):
        source = S8_POLLER_RECOVERY.read_text(encoding="utf-8")
        self.assertIn(
            'FAILED_DEPLOY_BACKUP="/opt/tu1nz_repos/backups/commercial-s11-2-canary-bootstrap/20260921T161900Z-predeploy"',
            source,
        )
        self.assertIn(
            'FAILED_DEPLOY_CONTROL_COMMIT="42fcbbefda36718540e8a7208f7b5cfaa6902ea0"',
            source,
        )
        self.assertIn('FINAL_CONTROL_TAG="s11-2-canary-bootstrap-freeze-r12"', source)
        self.assertIn(
            'TARGET_APPLICATION_COMMIT="23230af0b4dab4c1462a326cc137c2ded39cee4c"',
            source,
        )
        self.assertIn("exec 9> /run/tu1nz-adult-public-s11-2-control.lock", source)
        self.assertIn("S11_DISABLED|CANARY_RED|false", source)
        self.assertIn("BOT_POLLER_NOT_RUNNING", source)
        self.assertIn("start-limit-hit", source)
        self.assertIn('"inactive|dead|success"', source)
        self.assertIn("S11_2_R10_1_S8_RECOVERY_STATE_DRIFT", source)
        self.assertIn("S11_2_R7_S8_S9_HEALTH_SIGNATURE_DRIFT", source)
        self.assertIn("root:root:700", source)
        self.assertNotIn("database_transition", source)
        self.assertNotIn("START_CANARY", source)
        self.assertNotIn("FULL_RELEASE", source)
        self.assertNotIn("systemctl restart", source)
        preflight = source[source.index("preflight() {"):source.index("backup_runtime() {")]
        self.assertIn("require_failed_deploy_backup", preflight)
        self.assertIn("require_failure_state", preflight)
        self.assertIn("require_s11_closed", preflight)
        recover = source[source.index("recover() {"):source.index("usage() {")]
        self.assertLess(recover.index("preflight"), recover.index("backup_runtime"))
        self.assertLess(recover.index("require_backup"), recover.index('systemctl reset-failed "$S8_SERVICE"'))
        self.assertLess(
            recover.index('switch --detach "$TARGET_APPLICATION_COMMIT"'),
            recover.index('systemctl start "$S8_SERVICE"'),
        )
        self.assertLess(recover.index('systemctl reset-failed "$S8_SERVICE"'), recover.index('systemctl start "$S8_SERVICE"'))
        self.assertEqual(recover.count('systemctl start "$S8_SERVICE"'), 1)
        self.assertLess(recover.index("wait_poller_green"), recover.index("run_health_services"))
        self.assertIn("S11_2_R7_S8_S11_STATE_MUTATED", recover)
        handler = source[source.index("recovery_error() {"):source.index("recover() {")]
        self.assertIn('systemctl stop "$S8_SERVICE"', handler)
        self.assertIn("restore_source_contracts", handler)

    def test_canary_deploy_and_restore_use_r5_readiness_before_public_gate(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        readiness = source[source.index("wait_wms_ready() {"):source.index("run_runtime_health() {")]
        self.assertIn('LOCAL_WMS_HEALTH="http://127.0.0.1:18110/health"', source)
        self.assertIn("deadline=$((SECONDS + 30))", readiness)
        self.assertIn("while (( SECONDS < deadline ))", readiness)
        self.assertIn("sleep 0.25", readiness)
        self.assertIn('p.get("ok") is True', readiness)
        self.assertIn("forbidden_capabilities", readiness)
        self.assertIn("S11_2_WMS_LOCAL_HEALTH_TIMEOUT", readiness)
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        self.assertLess(deploy.index('systemctl restart "$WMS_SERVICE"'), deploy.index("wait_wms_ready"))
        self.assertLess(deploy.index("wait_wms_ready"), deploy.index("require_public_health"))
        self.assertLess(deploy.index("require_public_health"), deploy.index("run_runtime_health"))
        self.assertLess(deploy.index("S11_2_FEATURE_OFF_FALLBACK_GREEN"), deploy.index("database_transition START_CANARY"))
        restore = source[source.index("restore_source() {"):source.index("deploy() {")]
        self.assertLess(restore.index('systemctl restart "$WMS_SERVICE"'), restore.index("wait_wms_ready"))
        self.assertLess(restore.index("wait_wms_ready"), restore.index("require_public_health"))

    def test_p0_recovery_is_exact_backup_first_and_does_not_retry_canary(self):
        source = P0_RECOVERY.read_text(encoding="utf-8")
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn(
            "exec 9> /run/tu1nz-adult-public-s11-2-control.lock",
            source,
        )
        self.assertIn(
            "exec 9> /run/tu1nz-adult-public-s11-2-control.lock",
            controller,
        )
        self.assertNotIn("s11-2-p0-recovery.lock", source)
        backup = source[source.index("backup_runtime() {"):source.index("require_backup() {")]
        self.assertLess(backup.index('chmod g-s "$backup_path"'), backup.index("application.bundle"))
        self.assertGreaterEqual(backup.count('chmod g-s "$backup_path"'), 2)
        self.assertIn("S11_2_P0_BACKUP_MODE_NORMALIZATION_RED", backup)
        self.assertIn("root:root:700", backup)
        self.assertNotIn("root:root:2700", backup)
        recover = source[source.index("recover() {"):source.index("usage() {")]
        readiness = source[source.index("wait_wms_ready() {"):source.index("require_runtime_health() {")]
        self.assertIn('LOCAL_WMS_HEALTH="http://127.0.0.1:18110/health"', source)
        self.assertIn("deadline=$((SECONDS + 30))", readiness)
        self.assertIn("while (( SECONDS < deadline ))", readiness)
        self.assertIn("sleep 0.25", readiness)
        self.assertIn('p.get("ok") is True', readiness)
        self.assertIn("forbidden_capabilities", readiness)
        self.assertIn("S11_2_P0_WMS_LOCAL_HEALTH_TIMEOUT", readiness)
        self.assertNotIn("return 0\n    fi\n    sleep 1", readiness)
        self.assertLess(recover.index("preflight"), recover.index("backup_runtime"))
        self.assertLess(recover.index("require_backup"), recover.index("install -o root"))
        self.assertLess(recover.index("require_candidate_binding"), recover.index("systemctl restart"))
        self.assertLess(recover.index("wait_wms_ready"), recover.index("require_public_health"))
        self.assertLess(recover.index("require_public_health"), recover.index("run_health_services"))
        self.assertIn("S11_2_P0_PUBLIC_COMMITTED=true", recover)
        self.assertIn("S11_2_P0_S11_STATE_MUTATED", recover)
        self.assertNotIn("database_transition", source)
        self.assertNotIn("START_CANARY", source)
        self.assertNotIn("FULL_RELEASE", source)
        self.assertIn('FAILED_WMS_COPY_SHA="cdc9a48', source)
        self.assertIn('RECOVERY_WMS_COPY_SHA="86b074', source)
        handler = source[
            source.index("recovery_error() {"):
            source.index("recover() {")
        ]
        self.assertLess(handler.index('systemctl stop "$WMS_SERVICE"'), handler.index("failed-wms-copy.json"))
        self.assertLess(handler.index("failed-wms-copy.json"), handler.index('systemctl start "$WMS_SERVICE"'))

    def test_systemd_controller_is_serial_periodic_and_bounded(self):
        service = SERVICE.read_text(encoding="utf-8")
        timer = TIMER.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", service)
        self.assertIn("TimeoutStartSec=300", service)
        self.assertIn(
            "ExecStart=/usr/local/bin/tu1nz_adult_public_s11_2_control.sh observe",
            service,
        )
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("CapabilityBoundingSet=CAP_SETUID CAP_SETGID", service)
        self.assertIn("User=root", service)
        self.assertIn("Group=root", service)
        self.assertEqual(service.count("SupplementaryGroups=chatops"), 1)
        self.assertNotIn("NoNewPrivileges=", service)
        self.assertIn("ReadWritePaths=/run", service)
        self.assertNotIn("ReadWritePaths=/opt/tu1nz_repos", service)
        self.assertNotIn("Requires=tu1nz-adult-public-s8-telegram.service", service)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)

    def test_r15_3_unit_security_diff_is_exactly_one_group_line(self):
        old = OLD_SERVICE.read_text(encoding="utf-8")
        new = SERVICE.read_text(encoding="utf-8")
        self.assertEqual(new.replace("SupplementaryGroups=chatops\n", ""), old)
        self.assertEqual(
            [line for line in new.splitlines() if line.startswith("SupplementaryGroups=")],
            ["SupplementaryGroups=chatops"],
        )

    def test_r15_3_exit_126_permission_fixture_and_fixed_contract(self):
        def execute_allowed(groups):
            owner_uid = 1001
            group_gid = 1001
            effective_uid = 0
            mode = 0o2770
            if effective_uid == owner_uid:
                return bool(mode & 0o100)
            if group_gid in groups:
                return bool(mode & 0o010)
            return bool(mode & 0o001)

        old_exit = 0 if execute_allowed({0}) else 126
        new_exit = 0 if execute_allowed({0, 1001}) else 126
        self.assertEqual(old_exit, 126)
        self.assertEqual(new_exit, 0)

    def test_r15_3_live_access_preflight_precedes_canary_and_natural_run(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        self.assertIn("run_controller_access_check", deploy)
        self.assertLess(
            deploy.index("run_controller_access_check"),
            deploy.index("database_transition START_CANARY"),
        )
        self.assertLess(deploy.index("release_lock"), deploy.index("systemctl enable --now"))
        self.assertLess(
            deploy.index("systemctl enable --now"),
            deploy.index("wait_controller_natural_run"),
        )
        self.assertIn('safe_code":"S11_2_CONTROLLER_ACCESS_GREEN', source)
        self.assertIn('safe_code":"S11_2_FIRST_NATURAL_CONTROLLER_RUN_GREEN', source)
        self.assertIn("LastTriggerUSec", source)
        self.assertNotIn("InvocationID", source)

    def test_r15_4_source_access_is_chatops_owned_and_accepts_0700(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        contract = source[
            source.index("source_access_check() {"):
            source.index("artifact_sha_from_git() {")
        ]
        self.assertIn('runuser -u chatops -- test -r "$source_controller"', contract)
        self.assertIn('runuser -u chatops -- test -x "$source_controller"', contract)
        self.assertIn('git_chatops "$CONTROL_ROOT"', contract)
        self.assertNotIn("chmod", contract)
        self.assertNotIn("chown", contract)
        preflight = source[
            source.index("require_source_state() {"):
            source.index("preflight() {")
        ]
        self.assertIn("source_access_check", preflight)
        ssot = SSOT.read_text(encoding="utf-8")
        self.assertIn("R15.4 source/runtime access identity contract", ssot)
        self.assertIn("a `0700` source script is valid", ssot)
        self.assertIn("R15.4 performs no server", ssot)
        self.assertIn("installation, controller start or Canary retry", ssot)

    def test_r15_4_runtime_access_is_installed_hash_bound_and_repo_independent(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        access = source[
            source.index("controller_access_check() {"):
            source.index("verify_controller_unit_contract() {")
        ]
        self.assertIn("verify_runtime_access_contract", access)
        self.assertIn('"$APPLICATION_RUNTIME_PYTHON" -c \'import psycopg\'', access)
        self.assertNotIn("CONTROL_ROOT", access)
        self.assertNotIn("git -C", access)
        runtime = source[
            source.index("verify_runtime_access_contract() {"):
            source.index("controller_access_check() {")
        ]
        for path in (
            "/usr/local/bin/tu1nz_adult_public_s11_2_control.sh",
            "/usr/local/bin/tu1nz_adult_public_s11_2_gate.py",
            "/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service",
            "/etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer",
        ):
            self.assertIn(path, source)
        self.assertIn("hashlib.sha256(path.read_bytes()).hexdigest()", runtime)
        self.assertIn("current.st_uid", runtime)
        self.assertIn("stat.S_IMODE", runtime)
        self.assertIn("os.access(runtime_python, os.X_OK)", runtime)
        self.assertIn('payload.get("application_commit")', runtime)
        self.assertIn('payload.get("application_tree")', runtime)

    def test_r15_4_natural_observer_never_uses_control_checkout(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        observe = source[source.index("observe() {"):source.index("rollback() {")]
        self.assertIn("verify_runtime_access_contract", observe)
        self.assertIn(
            '"$APPLICATION_ROOT" "$TARGET_APPLICATION_COMMIT" "$TARGET_APPLICATION_TREE"',
            observe,
        )
        for forbidden in (
            "CONTROL_ROOT",
            "target_control_commit",
            "target_control_tree",
            "require_local_freeze",
            "switch --detach",
            "chmod",
            "chown",
        ):
            self.assertNotIn(forbidden, observe)

    def test_r15_4_manifest_is_installed_before_live_access_and_restored(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        deploy = source[source.index("deploy() {"):source.index("deployment_error() {")]
        self.assertLess(
            deploy.index("install_runtime_access_manifest"),
            deploy.index("run_controller_access_check"),
        )
        backup = source[source.index("backup_runtime() {"):source.index("require_backup() {")]
        restore = source[source.index("restore_source() {"):source.index("deploy() {")]
        self.assertIn("s11-2-runtime-access.json", backup)
        self.assertIn("S11_2_RUNTIME_ACCESS_ABSENT", backup)
        self.assertIn("s11-2-runtime-access.json", restore)
        self.assertIn("S11_2_RUNTIME_ACCESS_ABSENT", restore)
        self.assertIn('install -o root -g root -m 0644 "$temporary" "$RUNTIME_ACCESS_MANIFEST"', source)

    def test_r15_4_source_only_simulator_covers_access_and_rollback_matrix(self):
        simulator_source = ACCESS_SIMULATOR.read_text(encoding="utf-8")
        self.assertIn("MODELED_RUNTIME_UID = 0", simulator_source)
        self.assertIn("MODELED_SOURCE_UID = 1001", simulator_source)
        self.assertNotIn("source_owner = source.stat().st_uid", simulator_source)
        completed = subprocess.run(
            [sys.executable, str(ACCESS_SIMULATOR)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["safe_code"], "S11_2_R15_4_SOURCE_ONLY_SIMULATOR_GREEN")
        self.assertEqual(payload["source_mode"], "0700")
        self.assertEqual(payload["runtime_mode"], "0755")
        self.assertEqual(payload["cases"]["A_OLD_DIRECT_REPO_RUNTIME"], "RED_EXIT_126")
        self.assertEqual(payload["cases"]["B_SOURCE_AS_OWNER"], "GREEN")
        self.assertEqual(payload["cases"]["C_INSTALLED_RUNTIME_COPY"], "GREEN")
        self.assertEqual(payload["cases"]["D_INSTALLED_COPY_MISSING"], "RED")
        self.assertEqual(payload["cases"]["E_INSTALLED_COPY_HASH_MISMATCH"], "RED")
        self.assertEqual(payload["cases"]["F_INSTALLED_COPY_NON_EXECUTABLE"], "RED")
        self.assertEqual(payload["cases"]["G_RUNTIME_POINTS_TO_REPOSITORY"], "RED")
        self.assertEqual(payload["cases"]["NATURAL_ONESHOT_EXECUTION"], "GREEN_NO_EXIT_126")
        self.assertEqual(payload["cases"]["ROLLBACK_EXACT_BYTES_AND_MODES"], "GREEN")


if __name__ == "__main__":
    unittest.main()
