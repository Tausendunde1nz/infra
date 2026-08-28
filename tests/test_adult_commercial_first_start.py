from __future__ import annotations

import importlib.util
import ast
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_first_start_gate.py"
CONTROLLER = ROOT / "scripts" / "tu1nz_adult_commercial_s0_first_start.py"
CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json"


def load_controller() -> types.ModuleType:
    specification = importlib.util.spec_from_file_location("m4_24_controller", CONTROLLER)
    if specification is None or specification.loader is None:
        raise RuntimeError("controller module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class CommercialFirstStartContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.contract = json.loads(CONTRACT.read_text(encoding="ascii"))
        self.path = Path(self.temporary.name) / "contract.json"
        self.write_contract()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_contract(self) -> None:
        self.path.write_text(
            json.dumps(self.contract, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )

    def gate(self, *, approved: bool = False) -> subprocess.CompletedProcess[str]:
        arguments = [sys.executable, str(GATE), "--contract", str(self.path)]
        if approved:
            arguments.append("--require-approved")
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def approve(self) -> None:
        self.contract["active"] = True
        self.contract["decision"] = "GO_FOR_ONE_CONTROLLED_NETWORK_FREE_FIRST_START"
        self.contract["blockers"] = []
        self.contract["approval"]["first_start_approved"] = True
        self.contract["approval"]["no_swap_risk_accepted"] = True
        self.contract["approval"]["approved_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.contract["preflight_observation"]["unit_single_start_guard_installed"] = True
        self.contract["preflight_observation"]["unit_restart_policy"] = "no"
        self.contract["preflight_observation"]["runtime_maximum_seconds"] = 180
        self.write_contract()

    def assert_rejected(self, *, approved: bool = False) -> None:
        self.write_contract()
        self.assertNotEqual(self.gate(approved=approved).returncode, 0)

    def test_current_contract_is_valid_no_go(self) -> None:
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_24_FIRST_START_CONTRACT_OK_NO_GO", result.stdout)

    def test_current_contract_cannot_authorize_execution(self) -> None:
        result = self.gate(approved=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FIRST_START_NOT_APPROVED", result.stderr)

    def test_complete_post_preflight_approval_is_accepted(self) -> None:
        self.approve()
        result = self.gate(approved=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M4_24_FIRST_START_AUTHORIZED", result.stdout)

    def test_rejects_approval_before_observation(self) -> None:
        self.approve()
        self.contract["approval"]["approved_at"] = "2026-08-28T17:14:49Z"
        self.assert_rejected(approved=True)

    def test_rejects_stale_approval(self) -> None:
        self.approve()
        self.contract["approval"]["approved_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assert_rejected(approved=True)

    def test_rejects_future_approval(self) -> None:
        self.approve()
        self.contract["approval"]["approved_at"] = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assert_rejected(approved=True)

    def test_rejects_non_boolean_active(self) -> None:
        self.contract["active"] = 0
        self.assert_rejected()

    def test_rejects_approved_contract_without_single_start_guard(self) -> None:
        self.approve()
        self.contract["preflight_observation"]["unit_single_start_guard_installed"] = False
        self.assert_rejected(approved=True)

    def test_rejects_approval_without_no_swap_acceptance(self) -> None:
        self.approve()
        self.contract["approval"]["no_swap_risk_accepted"] = False
        self.assert_rejected(approved=True)

    def test_rejects_release_manifest_drift(self) -> None:
        self.contract["release"]["release_manifest_sha256"] = "0" * 64
        self.assert_rejected()

    def test_rejects_archive_drift(self) -> None:
        self.contract["archive"]["exact_archive_sha256"] = "0" * 64
        self.assert_rejected()

    def test_rejects_prior_start_claim(self) -> None:
        self.contract["preflight_observation"]["unit_previously_started"] = True
        self.assert_rejected()

    def test_rejects_business_rows(self) -> None:
        self.contract["starting_database"]["business_rows_zero"] = False
        self.assert_rejected()

    def test_rejects_network_enablement(self) -> None:
        self.contract["product_boundary"]["network_enabled"] = True
        self.assert_rejected()

    def test_rejects_weakened_abort_contract(self) -> None:
        self.contract["recovery"]["abort_must_stop_unit"] = False
        self.assert_rejected()

    def test_rejects_extra_top_level_key(self) -> None:
        self.contract["unexpected"] = False
        self.assert_rejected()


class CommercialFirstStartControllerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_controller()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract = self.root / "contract.json"
        self.contract.write_bytes(CONTRACT.read_bytes())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def before(self) -> dict[str, object]:
        tables = {
            **{table: 0 for table in self.module.BUSINESS_TABLES},
            **self.module.SEED_COUNTS,
        }
        return {
            "application_sha": self.module.APPLICATION_SHA,
            "archive_sha256": self.module.ARCHIVE_SHA256,
            "canonical_control_sha": "c" * 40,
            "contract_sha256": hashlib.sha256(self.contract.read_bytes()).hexdigest(),
            "database": {
                "table_count": 39,
                "function_count": 21,
                "other_sessions": 0,
                "tables": tables,
                "content_sha256": "b" * 64,
                "schema_sha256": "c" * 64,
            },
            "state_sha256": "a" * 64,
            "unit_sha256": self.module.UNIT_SHA256,
        }

    def test_database_snapshot_contract_is_exact_and_empty(self) -> None:
        self.module.verify_initial_database(self.before()["database"])
        drift = json.loads(json.dumps(self.before()["database"]))
        drift["tables"]["submissions"] = 1
        with self.assertRaises(self.module.FirstStartFailure):
            self.module.verify_initial_database(drift)

    def test_database_snapshot_uses_one_transaction_and_hashes_all_rows(self) -> None:
        counts = {
            "table_count": 39,
            "function_count": 21,
            "other_sessions": 0,
            "tables": self.before()["database"]["tables"],
        }
        output = "\n".join(
            (
                "__COUNTS__" + json.dumps(counts, separators=(",", ":")),
                "__CONTENT__" + b"creators\t{synthetic-row}".hex(),
                "__SCHEMA__" + b"table-definition".hex(),
            )
        )
        with mock.patch.object(self.module, "database_query", return_value=output) as query:
            snapshot = self.module.database_snapshot()
        query.assert_called_once_with(self.module.DATABASE_SNAPSHOT_SQL)
        self.assertIn("REPEATABLE READ READ ONLY", self.module.DATABASE_SNAPSHOT_SQL)
        self.assertEqual(snapshot["tables"], counts["tables"])
        self.assertNotEqual(snapshot["content_sha256"], "0" * 64)
        self.assertNotEqual(snapshot["schema_sha256"], "0" * 64)

    def test_execute_orders_authorization_before_start_and_ends_stopped(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        calls: list[list[str]] = []

        def fake_command(arguments: list[str], **_: object) -> types.SimpleNamespace:
            calls.append(arguments)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=self.before())
            )
            authorization = stack.enter_context(mock.patch.object(self.module, "validate_contract"))
            stack.enter_context(mock.patch.object(self.module, "git_value", return_value="c" * 40))
            stack.enter_context(
                mock.patch.object(self.module, "create_evidence_directory", return_value=evidence)
            )
            stack.enter_context(mock.patch.object(self.module, "write_json"))
            stack.enter_context(mock.patch.object(self.module, "write_private"))
            stack.enter_context(mock.patch.object(self.module, "command", side_effect=fake_command))
            stack.enter_context(
                mock.patch.object(
                self.module,
                "wait_for_runtime_state",
                side_effect=[{"state": "READY"}, {"state": "STOPPED"}],
                )
            )
            stack.enter_context(mock.patch.object(self.module, "active_state", return_value="active"))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "ensure_stopped",
                    side_effect=lambda *_: (
                        calls.append([self.module.SYSTEMCTL, "stop", self.module.UNIT])
                        or ({"ActiveState": "active"}, {"ActiveState": "inactive"})
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(self.module, "postcheck", return_value={"stopped": True})
            )
            stack.enter_context(mock.patch.object(self.module, "capture_journal"))
            result = self.module.execute_window(self.contract)

        self.assertEqual(result, evidence)
        self.assertEqual(authorization.call_count, 2)
        authorization.assert_has_calls(
            [mock.call(self.contract, require_approved=True)] * 2
        )
        start = [self.module.SYSTEMCTL, "start", self.module.UNIT]
        stop = [self.module.SYSTEMCTL, "stop", self.module.UNIT]
        self.assertIn(start, calls)
        self.assertIn(stop, calls)
        self.assertLess(calls.index(start), calls.index(stop))

    def test_authorization_failure_prevents_start(self) -> None:
        calls: list[list[str]] = []

        def reject(*_: object, **__: object) -> None:
            raise self.module.FirstStartFailure("FIRST_START_NOT_APPROVED", "blocked")

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=self.before())
            )
            stack.enter_context(mock.patch.object(self.module, "validate_contract", side_effect=reject))
            stack.enter_context(
                mock.patch.object(
                self.module,
                "command",
                side_effect=lambda arguments, **_: calls.append(arguments),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure):
                self.module.execute_window(self.contract)
        self.assertNotIn([self.module.SYSTEMCTL, "start", self.module.UNIT], calls)

    def test_authorization_change_after_preflight_prevents_start(self) -> None:
        before = self.before()
        before["contract_sha256"] = "0" * 64
        calls: list[list[str]] = []
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=before)
            )
            stack.enter_context(mock.patch.object(self.module, "validate_contract"))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "command",
                    side_effect=lambda arguments, **_: calls.append(arguments),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.execute_window(self.contract)
        self.assertEqual(failure.exception.code, "AUTHORIZATION_CHANGED_AFTER_PREFLIGHT")
        self.assertNotIn([self.module.SYSTEMCTL, "start", self.module.UNIT], calls)

    def test_canonical_control_change_after_preflight_prevents_start(self) -> None:
        calls: list[list[str]] = []
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=self.before())
            )
            stack.enter_context(mock.patch.object(self.module, "validate_contract"))
            stack.enter_context(mock.patch.object(self.module, "git_value", return_value="d" * 40))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "command",
                    side_effect=lambda arguments, **_: calls.append(arguments),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.execute_window(self.contract)
        self.assertEqual(failure.exception.code, "CONTROL_CHANGED_AFTER_PREFLIGHT")
        self.assertNotIn([self.module.SYSTEMCTL, "start", self.module.UNIT], calls)

    def test_health_failure_invokes_abort_and_final_stop(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        calls: list[list[str]] = []

        def fake_command(arguments: list[str], **_: object) -> types.SimpleNamespace:
            calls.append(arguments)
            if str(self.module.HEALTH) in arguments:
                raise self.module.FirstStartFailure("COMMAND_REJECTED", "health failed")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=self.before())
            )
            stack.enter_context(mock.patch.object(self.module, "validate_contract"))
            stack.enter_context(mock.patch.object(self.module, "git_value", return_value="c" * 40))
            stack.enter_context(
                mock.patch.object(self.module, "create_evidence_directory", return_value=evidence)
            )
            stack.enter_context(mock.patch.object(self.module, "write_json"))
            stack.enter_context(mock.patch.object(self.module, "write_private"))
            stack.enter_context(mock.patch.object(self.module, "command", side_effect=fake_command))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "wait_for_runtime_state",
                    return_value={"state": "READY"},
                )
            )
            stack.enter_context(mock.patch.object(self.module, "active_state", return_value="active"))
            final_stop = stack.enter_context(mock.patch.object(self.module, "ensure_stopped"))
            abort = stack.enter_context(mock.patch.object(self.module, "abort_window"))
            with self.assertRaises(self.module.FirstStartFailure):
                self.module.execute_window(self.contract)
        abort.assert_called_once()
        final_stop.assert_not_called()

    def test_unexpected_evidence_failure_after_start_invokes_abort(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        writes = 0

        def failing_write(*_: object) -> None:
            nonlocal writes
            writes += 1
            if writes == 3:
                raise OSError("evidence device failed")

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "technical_preflight", return_value=self.before())
            )
            stack.enter_context(mock.patch.object(self.module, "validate_contract"))
            stack.enter_context(mock.patch.object(self.module, "git_value", return_value="c" * 40))
            stack.enter_context(
                mock.patch.object(self.module, "create_evidence_directory", return_value=evidence)
            )
            stack.enter_context(mock.patch.object(self.module, "write_json", side_effect=failing_write))
            stack.enter_context(mock.patch.object(self.module, "write_private"))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "command",
                    return_value=types.SimpleNamespace(returncode=0, stdout="", stderr=""),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "wait_for_runtime_state",
                    return_value={"state": "READY"},
                )
            )
            stack.enter_context(mock.patch.object(self.module, "active_state", return_value="active"))
            abort = stack.enter_context(mock.patch.object(self.module, "abort_window"))
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.execute_window(self.contract)
        self.assertEqual(failure.exception.code, "UNEXPECTED_EXECUTION_FAILURE")
        abort.assert_called_once()

    def test_stop_timeout_is_a_fatal_failure(self) -> None:
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "systemctl_state",
                    return_value={"ActiveState": "active", "SubState": "running"},
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "command",
                    return_value=types.SimpleNamespace(returncode=1, stdout="", stderr="failed"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "wait_inactive",
                    side_effect=self.module.FirstStartFailure("UNIT_STOP_TIMEOUT", "active"),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.ensure_stopped("FINAL_STOP_FAILED")
        self.assertEqual(failure.exception.code, "FINAL_STOP_FAILED")

    def test_postcheck_accepts_stopped_unchanged_boundary(self) -> None:
        lock = self.root / "runtime.lock"
        lock.write_text("", encoding="ascii")
        lock.chmod(0o600)
        status = {
            "state": "STOPPED",
            "synthetic_data_only": True,
            "outbound_providers_enabled": False,
            "projected_submissions": 0,
        }
        stopped = {
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "static",
            "NRestarts": "0",
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.module, "LOCK_FILE", lock))
            stack.enter_context(mock.patch.object(self.module, "systemctl_state", return_value=stopped))
            stack.enter_context(mock.patch.object(self.module, "enabled_state", return_value="static"))
            stack.enter_context(mock.patch.object(self.module, "read_runtime_status", return_value=status))
            stack.enter_context(
                mock.patch.object(self.module, "verify_empty_state", return_value="a" * 64)
            )
            stack.enter_context(
                mock.patch.object(self.module, "database_snapshot", return_value=self.before()["database"])
            )
            stack.enter_context(mock.patch.object(self.module, "verify_clean_release"))
            stack.enter_context(mock.patch.object(self.module, "verify_manifest"))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "sha256_file",
                    side_effect=lambda path: {
                        self.module.ARCHIVE: self.module.ARCHIVE_SHA256,
                        self.module.INSTALLED_UNIT: self.module.UNIT_SHA256,
                        self.module.CONTRACT: self.before()["contract_sha256"],
                    }[path],
                )
            )
            stack.enter_context(mock.patch.object(self.module, "git_value", return_value="c" * 40))
            stack.enter_context(mock.patch.object(self.module, "run_release_gate"))
            stack.enter_context(
                mock.patch.object(self.module, "verify_provider_environment_boundary")
            )
            stack.enter_context(mock.patch.object(self.module, "verify_services"))
            stack.enter_context(mock.patch.object(self.module, "process_references", return_value=[]))
            stack.enter_context(mock.patch.object(self.module, "runtime_user_processes", return_value=[]))
            stack.enter_context(
                mock.patch.object(
                    self.module.pwd,
                    "getpwnam",
                    return_value=types.SimpleNamespace(pw_uid=os.getuid()),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module.grp,
                    "getgrnam",
                    return_value=types.SimpleNamespace(gr_gid=os.getgid()),
                )
            )
            result = self.module.postcheck(self.before())
        self.assertEqual(result["runtime_status"], status)
        self.assertEqual(result["unit"], stopped)

    def test_postcheck_rejects_database_drift(self) -> None:
        lock = self.root / "runtime.lock"
        lock.write_text("", encoding="ascii")
        lock.chmod(0o600)
        drift = json.loads(json.dumps(self.before()["database"]))
        drift["content_sha256"] = "d" * 64
        stopped = {
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "static",
            "NRestarts": "0",
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.module, "LOCK_FILE", lock))
            stack.enter_context(mock.patch.object(self.module, "systemctl_state", return_value=stopped))
            stack.enter_context(mock.patch.object(self.module, "enabled_state", return_value="static"))
            stack.enter_context(mock.patch.object(self.module, "read_runtime_status", return_value={}))
            stack.enter_context(
                mock.patch.object(self.module, "verify_empty_state", return_value="a" * 64)
            )
            stack.enter_context(mock.patch.object(self.module, "database_snapshot", return_value=drift))
            stack.enter_context(
                mock.patch.object(
                    self.module.pwd,
                    "getpwnam",
                    return_value=types.SimpleNamespace(pw_uid=os.getuid()),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module.grp,
                    "getgrnam",
                    return_value=types.SimpleNamespace(gr_gid=os.getgid()),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.postcheck(self.before())
        self.assertEqual(failure.exception.code, "POSTCHECK_DATABASE_DRIFT")

    def test_abort_stops_active_unit_and_records_evidence(self) -> None:
        calls: list[list[str]] = []

        def fake_command(arguments: list[str], **_: object) -> types.SimpleNamespace:
            calls.append(arguments)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "safe_evidence_directory", return_value=self.root)
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "ensure_stopped",
                    side_effect=lambda *_: (
                        calls.append([self.module.SYSTEMCTL, "stop", self.module.UNIT])
                        or (
                            {"ActiveState": "active"},
                            {"ActiveState": "inactive", "SubState": "dead"},
                        )
                    ),
                )
            )
            stack.enter_context(mock.patch.object(self.module, "verify_empty_state", return_value="a" * 64))
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "database_snapshot",
                    return_value=self.before()["database"],
                )
            )
            stack.enter_context(mock.patch.object(self.module, "capture_runtime_status"))
            stack.enter_context(mock.patch.object(self.module, "capture_journal"))
            result_writer = stack.enter_context(mock.patch.object(self.module, "write_json"))
            self.module.abort_window(self.root, "test failure", self.before())
        self.assertIn([self.module.SYSTEMCTL, "stop", self.module.UNIT], calls)
        result_writer.assert_called_once()
        self.assertTrue(result_writer.call_args.args[0].name.startswith("abort-result."))

    def test_source_has_no_enable_restart_delete_or_provider_credentials(self) -> None:
        source = CONTROLLER.read_text(encoding="ascii")
        for required in (
            'choices=("preflight", "execute", "postcheck", "abort")',
            'validate_contract(contract, require_approved=True)',
            '[SYSTEMCTL, "start", UNIT]',
            '[SYSTEMCTL, "stop", UNIT]',
            "abort_window(evidence",
            "M4_24_TECHNICAL_PREFLIGHT_OK_FIRST_START_NOT_EXECUTED",
            "M4_24_FIRST_START_ACCEPTED_STOPPED",
            "M4_24_ABORT_COMPLETED_STOPPED",
        ):
            self.assertIn(required, source)
        for forbidden in (
            'SYSTEMCTL, "enable"',
            'SYSTEMCTL, "restart"',
            "rm -rf",
            "shutil.rmtree",
            "TELEGRAM_TOKEN",
            "X_TOKEN",
            "REDDIT_TOKEN",
            "PAYMENT_TOKEN",
            "AVS_TOKEN",
            "https://api.",
        ):
            self.assertNotIn(forbidden, source)

    def test_database_query_covers_every_nonseed_table(self) -> None:
        self.assertEqual(len(self.module.ALL_TABLES), 39)
        for table in self.module.ALL_TABLES:
            self.assertIn("public." + table, self.module.DATABASE_COUNTS_SQL)
            self.assertIn("public." + table, self.module.DATABASE_CONTENT_SQL)

    def test_single_start_guard_rejects_restart_and_unbounded_runtime(self) -> None:
        for state in (
            {"Restart": "on-failure", "RuntimeMaxUSec": "180000000"},
            {"Restart": "no", "RuntimeMaxUSec": "infinity"},
        ):
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.verify_single_start_guard(state)
            self.assertEqual(failure.exception.code, "UNIT_SINGLE_START_GUARD_MISSING")
        self.module.verify_single_start_guard(
            {"Restart": "no", "RuntimeMaxUSec": "180000000"}
        )
        self.module.verify_single_start_guard(
            {"Restart": "no", "RuntimeMaxUSec": "3min"}
        )

    def test_prestart_revalidation_rejects_database_content_drift(self) -> None:
        before = self.before()
        prestart = json.loads(json.dumps(before))
        prestart["database"]["content_sha256"] = "d" * 64
        with self.assertRaises(self.module.FirstStartFailure) as failure:
            self.module.verify_prestart_revalidation(before, prestart)
        self.assertEqual(failure.exception.code, "PRESTART_BOUNDARY_DRIFT")

    def test_per_table_counts_detect_sum_cancellation(self) -> None:
        before = self.before()
        prestart = json.loads(json.dumps(before))
        prestart["database"]["tables"]["creators"] = 0
        prestart["database"]["tables"]["submissions"] = 1
        with self.assertRaises(self.module.FirstStartFailure):
            self.module.verify_prestart_revalidation(before, prestart)

    def test_runtime_status_before_window_is_rejected(self) -> None:
        status_path = self.root / "runtime-status.json"
        now = datetime.now(timezone.utc)
        payload = {
            "checked_at": now.isoformat(),
            "commercial_contract_version": "m4.15",
            "environment": "STAGING-S0-COMMERCIAL-CANDIDATE",
            "last_synchronized_at": now.isoformat(),
            "outbound_providers_enabled": False,
            "postgres_major": 17,
            "projected_submissions": 0,
            "service": "tu1nz-commercial-runtime-candidate",
            "started_at": (now - timedelta(seconds=30)).isoformat(),
            "state": "READY",
            "synthetic_data_only": True,
            "version": 1,
        }
        status_path.write_text(json.dumps(payload), encoding="ascii")
        status_path.chmod(0o600)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.module, "STATUS_FILE", status_path))
            stack.enter_context(
                mock.patch.object(
                    self.module.pwd,
                    "getpwnam",
                    return_value=types.SimpleNamespace(pw_uid=os.getuid()),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module.grp,
                    "getgrnam",
                    return_value=types.SimpleNamespace(gr_gid=os.getgid()),
                )
            )
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.read_runtime_status("READY", now)
        self.assertEqual(failure.exception.code, "RUNTIME_STATUS_STALE")

    def test_abort_stop_failure_is_never_reported_as_success(self) -> None:
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(self.module, "safe_evidence_directory", return_value=self.root)
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "ensure_stopped",
                    side_effect=self.module.FirstStartFailure("ABORT_STOP_FAILED", "active"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "systemctl_state",
                    return_value={"ActiveState": "active", "SubState": "running"},
                )
            )
            stack.enter_context(mock.patch.object(self.module, "capture_runtime_status"))
            stack.enter_context(mock.patch.object(self.module, "capture_journal"))
            writer = stack.enter_context(mock.patch.object(self.module, "write_json"))
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                self.module.abort_window(self.root, "test", self.before())
        self.assertEqual(failure.exception.code, "ABORT_STOP_FAILED")
        self.assertFalse(writer.call_args.args[1]["stop_verified"])

    def test_controller_lock_rejects_parallel_execution(self) -> None:
        with self.module.contract_execution_lock(self.contract):
            with self.assertRaises(self.module.FirstStartFailure) as failure:
                with self.module.contract_execution_lock(self.contract):
                    pass
        self.assertEqual(failure.exception.code, "FIRST_START_ALREADY_CONTROLLED")

    def test_command_does_not_inherit_sensitive_environment(self) -> None:
        completed = subprocess.CompletedProcess(["/bin/true"], 0, "", "")
        with mock.patch.dict(os.environ, {"EXAMPLE_SECRET": "must-not-leak"}, clear=False):
            with mock.patch.object(self.module.subprocess, "run", return_value=completed) as run:
                self.module.command(["/bin/true"])
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("EXAMPLE_SECRET", environment)
        self.assertEqual(environment["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")

    def test_signal_guard_turns_termination_into_controlled_failure(self) -> None:
        with self.assertRaises(self.module.FirstStartFailure) as failure:
            with self.module.execution_signal_guard():
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(failure.exception.code, "EXECUTION_INTERRUPTED")

    def test_systemctl_command_grammar_is_literal_and_allowlisted(self) -> None:
        tree = ast.parse(CONTROLLER.read_text(encoding="ascii"))
        verbs: list[str] = []
        direct_subprocess_calls = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
            ):
                direct_subprocess_calls += 1
            if not (
                isinstance(node.func, ast.Name)
                and node.func.id == "command"
                and node.args
                and isinstance(node.args[0], ast.List)
            ):
                continue
            elements = node.args[0].elts
            if elements and isinstance(elements[0], ast.Name) and elements[0].id == "SYSTEMCTL":
                self.assertGreaterEqual(len(elements), 2)
                self.assertIsInstance(elements[1], ast.Constant)
                self.assertIsInstance(elements[1].value, str)
                verbs.append(elements[1].value)
        self.assertEqual(direct_subprocess_calls, 1)
        self.assertEqual(verbs.count("start"), 1)
        self.assertNotIn("enable", verbs)
        self.assertNotIn("restart", verbs)
        self.assertLessEqual(
            set(verbs),
            {"--failed", "is-active", "is-enabled", "list-timers", "show", "show-environment", "start", "stop"},
        )


if __name__ == "__main__":
    unittest.main()
