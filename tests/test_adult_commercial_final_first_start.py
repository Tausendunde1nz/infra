from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import tu1nz_adult_commercial_final_first_start_contract as builder  # noqa: E402
import tu1nz_adult_commercial_final_first_start_gate as gate  # noqa: E402


def evidence(observed_at: str = "2026-08-29T03:49:09Z") -> dict[str, object]:
    tables = {**{name: 0 for name in gate.BUSINESS_TABLES}, **gate.SEED_COUNTS}
    return {
        "business_rows_zero": True,
        "candidate": {
            "ActiveEnterTimestamp": "",
            "ActiveEnterTimestampMonotonic": "0",
            "ActiveState": "inactive",
            "ControlPID": "0",
            "ExecMainStartTimestamp": "",
            "ExecMainStartTimestampMonotonic": "0",
            "LoadState": "loaded",
            "MainPID": "0",
            "NRestarts": "0",
            "Restart": "no",
            "RuntimeMaxUSec": "3min",
            "SubState": "dead",
            "TriggeredBy": "",
            "Triggers": "",
            "UnitFileState": "static",
            "journal_lines": 0,
            "never_started": True,
            "runtime_lock_present": False,
            "runtime_status_present": False,
            "timers": [],
        },
        "canonical_control": {
            "branch": "control-main",
            "origin_sha": "a" * 40,
            "sha": "a" * 40,
            "tracked_clean": True,
            "tree_sha": "b" * 40,
        },
        "capacity": {
            "memory_available_kib": 5 * 1024 * 1024,
            "root_available_bytes": 20 * 1024 * 1024 * 1024,
            "swap_total_kib": 0,
        },
        "control_automation_installed_hashes": dict(gate.CONTROL_AUTOMATION_HASHES),
        "control_open_files": [],
        "control_process_references": [
            "1234 chatops  bash /usr/local/bin/tu1nz_sync_all.sh --loop"
        ],
        "database": {
            "content_sha256": gate.CONTENT_SHA256,
            "function_count": 21,
            "other_sessions": 0,
            "schema_sha256": gate.SCHEMA_SHA256,
            "table_count": 39,
            "tables": tables,
        },
        "evidence_version": "tu1nz-final-first-start-readiness-fresh-prestart-v1",
        "failed_units": ["tu1nz-doc.service"],
        "first_start_executed": False,
        "host": {"hostname": "ubuntu-8gb-nbg1-2", "tailscale_ipv4": "100.121.130.51"},
        "load_average": [0.1, 0.2, 0.3],
        "observed_at": observed_at,
        "product_boundary": dict(gate.PRODUCT_BOUNDARY),
        "release": {
            "application_sha": gate.APPLICATION_SHA,
            "application_tree_sha": gate.APPLICATION_TREE,
            "archive": gate.ARCHIVE_SHA256,
            "archive_bytes": 64488092,
            "installed_control_sha": gate.INSTALLED_CONTROL_SHA,
            "installed_control_tree_sha": gate.INSTALLED_CONTROL_TREE,
            "links": {
                "application": "application/" + gate.APPLICATION_SHA,
                "control": "control/" + gate.INSTALLED_CONTROL_SHA,
                "venv": "venv/" + gate.APPLICATION_SHA,
            },
            "manifest": gate.MANIFEST_SHA256,
            "restore_evidence_path": (
                "/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-restore/"
                "20260828T18-35-00Z/restore-evidence.txt"
            ),
            "restore_evidence_sha256": gate.RESTORE_EVIDENCE_SHA256,
            "state": gate.STATE_SHA256,
            "unit": gate.UNIT_SHA256,
        },
        "services": copy.deepcopy(gate.SERVICES),
        "state_empty": True,
        "swap_free_kib": 0,
        "technical_checks_passed": True,
    }


class FinalFirstStartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "fresh-prestart.json"
        self.evidence.write_text(json.dumps(evidence()), encoding="ascii")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def contract(self, **arguments: object) -> dict[str, object]:
        return builder.build_contract(self.evidence, **arguments)

    def test_closed_contract_is_valid_and_cannot_authorize(self) -> None:
        contract = self.contract()
        self.assertFalse(gate.validate_contract(contract, require_approved=False))
        with self.assertRaisesRegex(gate.GateFailure, "FIRST_START_NOT_APPROVED"):
            gate.validate_contract(contract, require_approved=True)

    def test_complete_fresh_atomic_approval_is_valid(self) -> None:
        observed = datetime.now(timezone.utc).replace(microsecond=0)
        self.evidence.write_text(
            json.dumps(evidence(observed.strftime("%Y-%m-%dT%H:%M:%SZ"))),
            encoding="ascii",
        )
        approved_at = observed + timedelta(seconds=10)
        contract = self.contract(
            approve_first_start=True,
            accept_no_swap_risk=True,
            approved_at=approved_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.assertTrue(
            gate.validate_contract(
                contract,
                require_approved=True,
                now=approved_at,
            )
        )

    def test_partial_approval_is_rejected(self) -> None:
        with self.assertRaises(gate.GateFailure):
            self.contract(approve_first_start=True)

    def test_candidate_history_is_rejected(self) -> None:
        payload = evidence()
        payload["candidate"]["NRestarts"] = "1"
        self.evidence.write_text(json.dumps(payload), encoding="ascii")
        with self.assertRaises(gate.GateFailure):
            self.contract()

    def test_less_than_four_gib_available_is_rejected(self) -> None:
        payload = evidence()
        payload["capacity"]["memory_available_kib"] = gate.MIN_MEMORY_KIB - 1
        self.evidence.write_text(json.dumps(payload), encoding="ascii")
        with self.assertRaises(gate.GateFailure):
            self.contract()

    def test_release_and_database_drift_are_rejected(self) -> None:
        for field, value in (("archive", "0" * 64), ("unit", "0" * 64)):
            payload = evidence()
            payload["release"][field] = value
            self.evidence.write_text(json.dumps(payload), encoding="ascii")
            with self.assertRaises(gate.GateFailure):
                self.contract()
        payload = evidence()
        payload["database"]["tables"]["submissions"] = 1
        self.evidence.write_text(json.dumps(payload), encoding="ascii")
        with self.assertRaises(gate.GateFailure):
            self.contract()

    def test_product_boundary_drift_is_rejected(self) -> None:
        payload = evidence()
        payload["product_boundary"]["network_enabled"] = True
        self.evidence.write_text(json.dumps(payload), encoding="ascii")
        with self.assertRaises(gate.GateFailure):
            self.contract()

    def test_extra_evidence_and_contract_keys_are_rejected(self) -> None:
        payload = evidence()
        payload["unexpected"] = False
        self.evidence.write_text(json.dumps(payload), encoding="ascii")
        with self.assertRaises(gate.GateFailure):
            self.contract()
        self.evidence.write_text(json.dumps(evidence()), encoding="ascii")
        contract = self.contract()
        contract["unexpected"] = False
        with self.assertRaises(gate.GateFailure):
            gate.validate_contract(contract, require_approved=False)

    def test_approved_contract_expires_and_prestart_gap_is_bounded(self) -> None:
        observed = datetime.now(timezone.utc).replace(microsecond=0)
        self.evidence.write_text(
            json.dumps(evidence(observed.strftime("%Y-%m-%dT%H:%M:%SZ"))),
            encoding="ascii",
        )
        late = observed + timedelta(seconds=gate.PREFLIGHT_APPROVAL_MAXIMUM_GAP_SECONDS + 1)
        contract = self.contract(
            approve_first_start=True,
            accept_no_swap_risk=True,
            approved_at=late.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        with self.assertRaises(gate.GateFailure):
            gate.validate_contract(contract, require_approved=True, now=late)

    def test_final_controller_binds_current_release_and_has_no_direct_start_literal(self) -> None:
        source = (SCRIPTS / "tu1nz_adult_commercial_s0_first_start_final.py").read_text()
        self.assertIn(gate.INSTALLED_CONTROL_SHA, source)
        self.assertIn(gate.ARCHIVE_SHA256, source)
        self.assertNotIn('[base.SYSTEMCTL, "start"', source)
        specification = importlib.util.spec_from_file_location("final_controller", SCRIPTS / "tu1nz_adult_commercial_s0_first_start_final.py")
        self.assertIsNotNone(specification)

    def test_prestart_collector_is_read_only_and_has_no_activation_literal(self) -> None:
        source = (SCRIPTS / "tu1nz_adult_commercial_final_prestart.py").read_text()
        self.assertNotIn('"start"', source)
        self.assertNotIn('"restart"', source)
        self.assertNotIn('"enable"', source)
        self.assertNotIn("TELEGRAM_TOKEN", source)
        self.assertIn("gate.validate_evidence(payload)", source)


if __name__ == "__main__":
    unittest.main()
