from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
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
        self.contract["approval"]["approved_at"] = "2026-08-28T17:15:00Z"
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
        return {
            "application_sha": self.module.APPLICATION_SHA,
            "canonical_control_sha": "c" * 40,
            "contract_sha256": hashlib.sha256(self.contract.read_bytes()).hexdigest(),
            "database": {
                "table_count": 39,
                "function_count": 21,
                "creators": 1,
                "policy_versions": 1,
                "country_policy_rules": 1,
                "platform_policy_rules": 3,
                "integration_accounts": 3,
                "publication_destinations": 3,
                "business_rows": 0,
            },
            "state_sha256": "a" * 64,
        }

    def test_database_snapshot_contract_is_exact_and_empty(self) -> None:
        self.module.verify_initial_database(self.before()["database"])
        drift = dict(self.before()["database"])
        drift["business_rows"] = 1
        with self.assertRaises(self.module.FirstStartFailure):
            self.module.verify_initial_database(drift)

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
            stack.enter_context(mock.patch.object(self.module, "wait_inactive"))
            stack.enter_context(
                mock.patch.object(self.module, "postcheck", return_value={"stopped": True})
            )
            stack.enter_context(mock.patch.object(self.module, "capture_journal"))
            result = self.module.execute_window(self.contract)

        self.assertEqual(result, evidence)
        authorization.assert_called_once_with(self.contract, require_approved=True)
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
            stack.enter_context(
                mock.patch.object(self.module, "active_state", side_effect=["active", "active"])
            )
            abort = stack.enter_context(mock.patch.object(self.module, "abort_window"))
            with self.assertRaises(self.module.FirstStartFailure):
                self.module.execute_window(self.contract)
        abort.assert_called_once()
        self.assertIn([self.module.SYSTEMCTL, "stop", self.module.UNIT], calls)

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
            stack.enter_context(mock.patch.object(self.module, "verify_services"))
            stack.enter_context(mock.patch.object(self.module, "process_references", return_value=[]))
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
        drift = dict(self.before()["database"])
        drift["business_rows"] = 1
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
                    "systemctl_state",
                    side_effect=[
                        {"ActiveState": "active"},
                        {"ActiveState": "inactive", "SubState": "dead"},
                    ],
                )
            )
            stack.enter_context(mock.patch.object(self.module, "command", side_effect=fake_command))
            stack.enter_context(mock.patch.object(self.module, "wait_inactive"))
            stack.enter_context(mock.patch.object(self.module, "capture_runtime_status"))
            stack.enter_context(mock.patch.object(self.module, "capture_journal"))
            result_writer = stack.enter_context(mock.patch.object(self.module, "write_json"))
            self.module.abort_window(self.root, "test failure")
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
        query = self.module.DATABASE_SNAPSHOT_SQL
        required = {
            "adult_verification_events",
            "adult_verifications",
            "audit_events",
            "command_receipts",
            "commercial_dispatch_entitlements",
            "consent_events",
            "consent_invites",
            "credit_transactions",
            "depicted_persons",
            "external_identities",
            "external_identity_aliases",
            "integration_event_receipts",
            "media_assets",
            "moderation_decisions",
            "payment_attempts",
            "payment_intent_events",
            "payment_intents",
            "payment_provider_event_receipts",
            "payments",
            "platform_dispatch_events",
            "platform_dispatches",
            "platform_provider_receipts",
            "policy_decisions",
            "policy_evaluations",
            "publication_entitlement_events",
            "publication_entitlements",
            "publications",
            "safety_complaint_events",
            "safety_complaints",
            "submission_intake_sessions",
            "submission_state_events",
            "submissions",
            "takedowns",
        }
        for table in required:
            self.assertIn("FROM " + table + ")", query)


if __name__ == "__main__":
    unittest.main()
