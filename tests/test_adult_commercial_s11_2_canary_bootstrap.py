from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
SERVICE = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.service"
TIMER = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.timer"
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
        self.assertLess(observe.index('current_state="$(release_state)"'), observe.index("require_clean_commit"))
        self.assertIn("require_local_freeze", observe)
        self.assertIn("database_transition CANARY_RED S11_2_REPOSITORY_INTEGRITY_RED", observe)

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
        self.assertIn('cmp -s "$CONTROL_ROOT/systemd/$RETIRED_S8_HEALTH_TIMER"', gates)
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
        self.assertIn('"$APPLICATION_ROOT/.venv/bin/python" "$INSTALLED_GATE"', helper)
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
        self.assertIn('TARGET_APPLICATION_COMMIT="d1c9aeba7d6f3cd692cd8127b565aea7234e13e8"', source)
        self.assertIn('TARGET_APPLICATION_TREE="9b931764246189938225406b7b592d0baf6a50d9"', source)
        self.assertIn('FINAL_CONTROL_TAG="s11-2-canary-bootstrap-freeze-r8"', source)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["canary_contract"]["session_cap"], 10)
        self.assertEqual(manifest["canary_contract"]["evidence_epoch_hours"], 24)
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
        self.assertIn('FINAL_CONTROL_TAG="s11-2-canary-bootstrap-freeze-r10"', source)
        self.assertIn(
            'TARGET_APPLICATION_COMMIT="23230af0b4dab4c1462a326cc137c2ded39cee4c"',
            source,
        )
        self.assertIn("exec 9> /run/tu1nz-adult-public-s11-2-control.lock", source)
        self.assertIn("S11_DISABLED|CANARY_RED|false", source)
        self.assertIn("BOT_POLLER_NOT_RUNNING", source)
        self.assertIn("start-limit-hit", source)
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
        self.assertNotIn("Requires=tu1nz-adult-public-s8-telegram.service", service)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)


if __name__ == "__main__":
    unittest.main()
