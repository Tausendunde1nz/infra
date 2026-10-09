"""Pure I/O-adapter negatives; no live database, journal or service access."""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_observer as observer
import tu1nz_s8_provision as provision
import tu1nz_s8_execution as execution


class ObserverTests(unittest.TestCase):
    def installed_state(self):
        return dict(ActiveState="failed", SubState="failed", Result="exit-code",
            ExecMainStatus="2", MainPID="0", ControlPID="0", NRestarts="0",
            InvocationID=c.FAILED_INVOCATION, NeedDaemonReload="no",
            FragmentPath=str(observer.BASE_UNIT), Restart="no", RefuseManualStart="yes",
            DropInPaths=str(observer.BASE_UNIT)+".d/00-atomic-admission.conf")

    def installed_io(self, stack, state):
        # Only in-memory adapter tests. No PID 1, files, ancestor operations,
        # SQL or provider calls; not a substitute for the blocked proof.
        stack.enter_context(patch.object(observer.os, "geteuid", return_value=0))
        stack.enter_context(patch.object(observer, "file_bytes", return_value=b"synthetic"))
        stack.enter_context(patch.object(observer, "service", return_value=state))
        stack.enter_context(patch.object(observer, "recognized_pollers", return_value=[]))
        stack.enter_context(patch.object(observer, "history", return_value={}))
        stack.enter_context(patch.object(observer, "public_health", return_value={"public": {}}))
        return stack.enter_context(patch.object(observer, "database", return_value=self.snapshot()))

    def snapshot(self):
        return dict(read_only="on", observed_at="2026-10-05T00:00:00+00:00",
            leases=[dict(release=c.LEASE_RELEASE, owner=None, expires=None, revision=c.LEASE_REVISION,
                last_poll=c.LAST_POLL, updated=c.LAST_UPDATE, code="BOT_POLLER_NOT_RUNNING")],
            s11=dict(enabled=False, release_state="S11_DISABLED", promotion_state="CANARY_RED", hard_gates_closed=True),
            acquisition=dict(active=True, baseline="2026-09-18T00:41:06.710027+00:00"))

    def test_readonly_explicit_sql_and_red_preserved(self):
        with patch.object(observer, "command", return_value=json.dumps(self.snapshot())) as call:
            result = observer.database()
        args, options = call.call_args
        self.assertEqual(args[0][:5], ["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql"])
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", options["input"])
        self.assertTrue(options["input"].strip().endswith("ROLLBACK;"))
        # The canonical migration defines the owner as UUID, not text. The
        # native PostgreSQL chain executes this exact query for null/non-null
        # owners; no later successful poll substitutes for first admission.
        self.assertIn("convert_to(lease_owner_id::text,'UTF8')", options["input"])
        self.assertNotRegex(options["input"], r"\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|GRANT)\b")
        self.assertEqual(result["s11"]["promotion_state"], "CANARY_RED")
        c.lease_admission(result["leases"][0])

    def test_nonreadonly_extra_lease_or_product_change_rejected(self):
        for change in (lambda s: s.update(read_only="off"), lambda s: s["leases"].append(s["leases"][0]),
                       lambda s: s["s11"].update(enabled=True), lambda s: s["s11"].update(hard_gates_closed=False),
                       lambda s: s["acquisition"].update(baseline="2026-10-05T00:00:00+00:00")):
            value = self.snapshot(); change(value)
            with patch.object(observer, "command", return_value=json.dumps(value)), self.assertRaises(c.ContractError):
                observer.database()

    def test_read_failure_is_not_historical_drift_or_green(self):
        with patch.object(observer, "command", side_effect=c.ContractError("S8_EXECUTION_OBSERVATION_READ_RED")):
            with self.assertRaisesRegex(c.ContractError, "OBSERVATION_READ_RED"): observer.database()

    def test_installed_guard_requires_exact_loaded_properties(self):
        observer.installed_start_guard(self.installed_state())
        for key, value in (("DropInPaths", ""), ("DropInPaths", "/foreign.conf"),
                ("DropInPaths", self.installed_state()["DropInPaths"]+" /foreign.conf"),
                ("Restart", "on-failure"), ("RefuseManualStart", "no"),
                ("FragmentPath", "/run/systemd/system/foreign.service"),
                ("NeedDaemonReload", "yes")):
            state = self.installed_state(); state[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    c.ContractError, "INSTALLED_ADMISSION_CONTRACT_RED"):
                observer.installed_start_guard(state)
        for key in ("DropInPaths", "Restart", "RefuseManualStart", "FragmentPath", "NeedDaemonReload"):
            state = self.installed_state(); del state[key]
            with self.subTest(missing=key), self.assertRaises(c.ContractError):
                observer.installed_start_guard(state)

    def test_installed_precondition_rejects_lost_guard_before_lease_read(self):
        for values in ({"DropInPaths": ""}, {"Restart": "on-failure"}, {"RefuseManualStart": "no"}):
            state = self.installed_state(); state.update(values)
            with self.subTest(values=values), ExitStack() as stack:
                database = self.installed_io(stack, state)
                with self.assertRaisesRegex(c.ContractError, "INSTALLED_ADMISSION_CONTRACT_RED"):
                    observer.failed_precondition(installed=True)
                database.assert_not_called()

    def test_installed_precondition_accepts_unchanged_incident_only(self):
        with ExitStack() as stack:
            self.installed_io(stack, self.installed_state())
            value = observer.failed_precondition(installed=True)
        self.assertEqual(value["s8"], self.installed_state())
        self.assertEqual(value["database"]["leases"][0]["revision"], c.LEASE_REVISION)

    def test_coordinator_observed_loss_never_dispatches_or_consumes_activation(self):
        state = self.installed_state(); state["DropInPaths"] = ""
        journal, channel = Mock(), Mock()
        config = dict(coordinator="synthetic", dispatcher={}, grant={}, binding={},
                      baseline=dict(history={}, health=dict(public={})))
        with ExitStack() as stack:
            self.installed_io(stack, state)
            stack.enter_context(patch.object(execution, "stock", return_value=Path("/synthetic-not-accessed")))
            stack.enter_context(patch.object(execution, "receive_once"))
            stack.enter_context(patch.object(execution, "ProtectedJournal", return_value=journal))
            stack.enter_context(patch.object(execution, "AdmissionChannel", return_value=channel))
            dispatch = stack.enter_context(patch.object(execution.subprocess, "Popen"))
            condition = stack.enter_context(patch.object(c, "consume_condition"))
            with self.assertRaisesRegex(c.ContractError, "INSTALLED_ADMISSION_CONTRACT_RED"):
                execution.coordinate(config)
            dispatch.assert_not_called(); condition.assert_not_called()
            channel.accept_once.assert_not_called()
            channel.close.assert_called_once(); journal.close.assert_called_once()
        records = journal.once.call_args_list
        self.assertEqual([row.args[0] for row in records], ["operation.json", "failed.json"])
        self.assertEqual(records[1].args[1]["primary"]["code"], "S8_EXECUTION_INSTALLED_ADMISSION_CONTRACT_RED")
        self.assertFalse(records[1].args[1]["retry_allowed"])

    def test_current_acceptance_rejects_guard_loss_before_history_or_database(self):
        state = self.installed_state(); state["DropInPaths"] = ""
        with patch.object(observer, "service", return_value=state), \
                patch.object(observer, "history") as history, patch.object(observer, "database") as database:
            with self.assertRaisesRegex(c.ContractError, "INSTALLED_ADMISSION_CONTRACT_RED"):
                execution.environment_unchanged({})
            history.assert_not_called(); database.assert_not_called()

    def test_abort_without_handoff_has_no_process_or_pid1_action(self):
        with patch.object(observer, "command") as command, patch.object(provision, "properties") as properties:
            self.assertEqual(provision.abort_owned(None), "NO_HANDOFF_NO_ADMISSION_AUTHORITY")
            command.assert_not_called(); properties.assert_not_called()

    def test_cleanup_keeps_all_errors_and_redacts_untrusted_exception(self):
        class Broken:
            def close(self): raise RuntimeError("unrelated-secret-or-message")
        self.assertEqual(provision.cleanup(Broken(), Broken()), [dict(type="RuntimeError", code="UNKNOWN")]*2)
        value = provision.ProvisionAborted(dict(type="OSError", code="UNKNOWN"), dict(result="UNKNOWN"), [])
        self.assertEqual(value.evidence["historical_cause"], "UNKNOWN")
        self.assertFalse(value.evidence["retry_allowed"])


if __name__ == "__main__": unittest.main()
