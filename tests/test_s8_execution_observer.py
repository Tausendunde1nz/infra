"""Pure I/O-adapter negatives; no live database, journal or service access."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_observer as observer
import tu1nz_s8_provision as provision


class ObserverTests(unittest.TestCase):
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
