from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-post-merge-sync-authorization.m4-29.json"
SCHEMA = ROOT / "manifests" / "adult-publishing-commercial-post-merge-sync-authorization.m4-29.schema.json"
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_m4_29_gate.py"
HISTORICAL = {
    "m4_24_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json",
    "m4_25_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-unit-refresh.m4-25.json",
    "m4_26_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-26.json",
    "m4_27_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start-authorization-preparation.m4-27.json",
    "m4_28_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-canonical-sync-authorization.m4-28.json",
}

SPEC = importlib.util.spec_from_file_location("m4_29_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CommercialM429Test(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 28, 20, 30, 0, tzinfo=timezone.utc)
        self.contract = json.loads(CONTRACT.read_text(encoding="ascii"))
        self.contact = copy.deepcopy(self.contract)
        self.contact["active"] = True
        self.contact["decision"] = "GO_READ_ONLY_SERVER_EVIDENCE_ONLY"
        self.contact["blockers"] = list(gate.CONTACT_BLOCKERS)
        self.contact["approval"]["server_contact_approved"] = True
        self.contact["approval"]["server_contact_approved_at"] = "2026-08-28T20:26:00Z"

        self.server_evidence = {
            "bindings": copy.deepcopy(gate.EXPECTED_BINDINGS),
            "candidate": {
                "active_state": "inactive",
                "active_enter_timestamp": "",
                "active_enter_timestamp_monotonic": 0,
                "exec_main_start_timestamp": "",
                "exec_main_start_timestamp_monotonic": 0,
                "journal_lines": 0,
                "n_restarts": 0,
                "never_started": True,
                "restart": "no",
                "runtime_lock_present": False,
                "runtime_maximum_seconds": 180,
                "runtime_status_present": False,
                "sub_state": "dead",
                "unit_file_state": "static",
            },
            "captured_at": "2026-08-28T20:27:00Z",
            "checkout_mutation": {
                "open_writers": [],
                "processes": [],
                "services": [],
                "timers": [],
            },
            "contract_path": gate.CONTRACT_RELATIVE,
            "evidence_version": "tu1nz-m4.29-read-only-server-evidence-v1",
            "ignored": {
                "changed_entries": [],
                "entries": list(gate.IGNORED_ENTRIES),
                "entries_sha256": gate.IGNORED_ENTRIES_SHA256,
                "incoming_tracked_collisions": [],
                "missing_entries": [],
                "recursive_inventory_matches_baseline": True,
                "recursive_inventory_sha256": "a" * 64,
            },
            "server_identity": {
                "hostname": gate.EXPECTED_HOSTNAME,
                "identity_matched": True,
                "tailscale_ipv4": gate.EXPECTED_TAILSCALE_IPV4,
            },
            "source": {
                "branch": gate.TARGET_BRANCH,
                "checkout_path": "/opt/tu1nz_repos/control",
                "fast_forward_possible": True,
                "git_integrity_passed": True,
                "head_sha": gate.SOURCE_SHA,
                "origin_control_main_sha": gate.SOURCE_SHA,
                "source_is_ancestor_of_target": True,
                "tracked_clean": True,
                "tree_sha": gate.SOURCE_TREE,
            },
            "target": {
                "branch": gate.TARGET_BRANCH,
                "repository": gate.TARGET_REPOSITORY,
                "sha": gate.TARGET_SHA,
                "tree_sha": gate.TARGET_TREE,
            },
        }

        self.authorized = copy.deepcopy(self.contract)
        self.authorized["active"] = True
        self.authorized["decision"] = "GO_SERVER_CONTROL_SYNC_ONLY"
        self.authorized["blockers"] = list(gate.SYNC_BLOCKERS)
        self.authorized["fresh_observed_server_source"] = gate.expected_fresh_source(
            self.server_evidence
        )
        self.authorized["read_only_server_evidence"]["capture_status"] = "CAPTURED"
        self.authorized["read_only_server_evidence"]["server_contact_approved"] = True
        self.authorized["approval"].update(
            {
                "approved_at": "2026-08-28T20:28:00Z",
                "fresh_server_evidence_present": True,
                "operator_sync_approved": True,
                "server_contact_approved": True,
                "server_contact_approved_at": "2026-08-28T20:26:00Z",
                "source_observed_at": self.server_evidence["captured_at"],
                "source_sha": gate.SOURCE_SHA,
                "source_tree_sha": gate.SOURCE_TREE,
                "sync_approved": True,
            }
        )

        root = "/opt/tu1nz_repos/backups/m4-29-control-sync/20260828T20-29-00Z"
        self.mutation_evidence = {
            "authorization_drift_free": True,
            "bundle": {
                "contains_source": True,
                "contains_target": True,
                "exists": True,
                "path": root + "/control-sync.bundle",
                "rollback_ref": "refs/tu1nz/rollback/m4-29-control-sync/20260828T20-29-00Z",
                "rollback_ref_sha": gate.SOURCE_SHA,
                "valid": True,
            },
            "candidate_never_started": True,
            "contract_path": gate.CONTRACT_RELATIVE,
            "evidence_root": root,
            "ignored_inventory_sha256": "a" * 64,
            "mutation_evidence_version": "tu1nz-m4.29-pre-mutation-evidence-v1",
            "prepared_at": "2026-08-28T20:29:00Z",
            "root_private": True,
            "source_drift_free": True,
            "source_sha": gate.SOURCE_SHA,
            "source_tree_sha": gate.SOURCE_TREE,
            "target_drift_free": True,
            "target_sha": gate.TARGET_SHA,
            "target_tree_sha": gate.TARGET_TREE,
        }
        self.mutation_ready = copy.deepcopy(self.authorized)
        self.mutation_ready["blockers"] = list(gate.MUTATION_BLOCKERS)
        self.mutation_ready["approval"]["mutation_approved"] = True
        self.mutation_ready["approval"]["mutation_approved_at"] = "2026-08-28T20:29:30Z"

    def test_committed_contract_is_closed_no_go(self) -> None:
        gate.validate_contract(self.contract)
        approval = self.contract["approval"]
        self.assertFalse(self.contract["active"])
        self.assertFalse(approval["server_contact_approved"])
        self.assertFalse(approval["fresh_server_evidence_present"])
        self.assertFalse(approval["sync_approved"])
        self.assertFalse(approval["mutation_approved"])
        self.assertEqual(self.contract["decision"], "NO_GO")

    def test_synthetic_contact_evidence_authorization_and_mutation_transitions(self) -> None:
        gate.validate_server_contact_ready(self.contact, now=self.now)
        gate.validate_evidence_capture(self.contact, self.server_evidence, now=self.now)
        gate.validate_sync_authorization(self.authorized, self.server_evidence, now=self.now)
        self.assertTrue(
            gate.validate_mutation_ready(
                self.mutation_ready,
                self.server_evidence,
                self.mutation_evidence,
                now=self.now,
            )
        )

    def test_new_post_merge_target_is_exact(self) -> None:
        target = self.contract["post_merge_target"]
        self.assertEqual(target["sha"], gate.TARGET_SHA)
        self.assertEqual(target["tree_sha"], gate.TARGET_TREE)
        self.assertEqual(target["pull_request"], 37)
        self.assertEqual(target["post_merge_ci_run_id"], 33207033378)

    def test_historical_contract_hashes_include_unchanged_m4_28(self) -> None:
        binding = self.contract["historical_binding"]
        for field, path in HISTORICAL.items():
            with self.subTest(field=field):
                self.assertEqual(binding[field], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_rejects_old_m4_28_target(self) -> None:
        changed = copy.deepcopy(self.server_evidence)
        changed["target"]["sha"] = gate.OLD_M4_28_TARGET_SHA
        with self.assertRaisesRegex(gate.GateFailure, "new post-M4.28 target"):
            gate.validate_server_evidence(changed, now=self.now)

    def test_rejects_wrong_new_target_sha_or_tree(self) -> None:
        for field in ("sha", "tree_sha"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.server_evidence)
                changed["target"][field] = "0" * 40
                with self.assertRaisesRegex(gate.GateFailure, "target SHA or tree"):
                    gate.validate_server_evidence(changed, now=self.now)

    def test_rejects_manipulated_merge_parents_or_ci_binding(self) -> None:
        cases = (
            ("merge_parents", ["0" * 40, "1" * 40]),
            ("post_merge_ci_run_id", 1),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.contract)
                changed["post_merge_target"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "profile drift"):
                    gate.validate_contract(changed)

    def test_rejects_missing_fresh_source(self) -> None:
        changed = copy.deepcopy(self.authorized)
        changed["fresh_observed_server_source"] = copy.deepcopy(gate.CLOSED_FRESH_SOURCE)
        with self.assertRaisesRegex(gate.GateFailure, "missing or drifted"):
            gate.validate_sync_authorization(changed, self.server_evidence, now=self.now)

    def test_rejects_stale_server_evidence(self) -> None:
        changed = copy.deepcopy(self.server_evidence)
        changed["captured_at"] = "2026-08-28T20:20:00Z"
        with self.assertRaisesRegex(gate.GateFailure, "stale"):
            gate.validate_server_evidence(changed, now=self.now)

    def test_rejects_server_contact_without_separate_approval(self) -> None:
        with self.assertRaisesRegex(gate.GateFailure, "not separately approved"):
            gate.validate_server_contact_ready(self.contract, now=self.now)

    def test_rejects_evidence_before_contact_approval(self) -> None:
        changed = copy.deepcopy(self.contact)
        changed["approval"]["server_contact_approved_at"] = "2026-08-28T20:27:30Z"
        with self.assertRaisesRegex(gate.GateFailure, "predates contact"):
            gate.validate_evidence_capture(changed, self.server_evidence, now=self.now)

    def test_rejects_sync_authorization_before_evidence(self) -> None:
        changed = copy.deepcopy(self.authorized)
        changed["approval"]["approved_at"] = "2026-08-28T20:26:59Z"
        with self.assertRaisesRegex(gate.GateFailure, "order"):
            gate.validate_sync_authorization(changed, self.server_evidence, now=self.now)

    def test_rejects_mutation_ready_without_bundle_or_rollback_ref(self) -> None:
        cases = (
            ("exists", False),
            ("valid", False),
            ("rollback_ref", ""),
            ("rollback_ref_sha", "0" * 40),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.mutation_evidence)
                changed["bundle"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "bundle and rollback"):
                    gate.validate_mutation_ready(
                        self.mutation_ready,
                        self.server_evidence,
                        changed,
                        now=self.now,
                    )

    def test_rejects_source_or_target_drift_after_approval(self) -> None:
        cases = (("source_sha", "0" * 40), ("target_sha", "0" * 40))
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.mutation_evidence)
                changed[field] = value
                with self.assertRaisesRegex(gate.GateFailure, "boundary drift"):
                    gate.validate_mutation_ready(
                        self.mutation_ready,
                        self.server_evidence,
                        changed,
                        now=self.now,
                    )

    def test_rejects_ignored_inventory_drift_after_approval(self) -> None:
        changed = copy.deepcopy(self.mutation_evidence)
        changed["ignored_inventory_sha256"] = "d" * 64
        with self.assertRaisesRegex(gate.GateFailure, "inventory drift"):
            gate.validate_mutation_ready(
                self.mutation_ready,
                self.server_evidence,
                changed,
                now=self.now,
            )

    def test_rejects_candidate_start_evidence(self) -> None:
        changed = copy.deepcopy(self.server_evidence)
        changed["candidate"]["exec_main_start_timestamp"] = "2026-08-28 20:00:00 UTC"
        with self.assertRaisesRegex(gate.GateFailure, "never-started"):
            gate.validate_server_evidence(changed, now=self.now)

    def test_rejects_first_start_or_no_swap_acceptance(self) -> None:
        for field in ("first_start_approved", "no_swap_risk_accepted"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.authorized)
                changed["approval"][field] = True
                with self.assertRaisesRegex(gate.GateFailure, "missing or drifted"):
                    gate.validate_sync_authorization(changed, self.server_evidence, now=self.now)

    def test_rejects_fresh_source_that_differs_from_historical_expectation(self) -> None:
        changed = copy.deepcopy(self.server_evidence)
        changed["source"]["head_sha"] = "0" * 40
        with self.assertRaisesRegex(gate.GateFailure, "historical boundary"):
            gate.validate_server_evidence(changed, now=self.now)

    def test_rejects_noncanonical_contract_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "contract.json"
            copied.write_text(CONTRACT.read_text(encoding="ascii"), encoding="ascii")
            with self.assertRaisesRegex(gate.GateFailure, "canonical"):
                gate.read_json(copied, canonical_contract=True)

    def test_gate_has_no_host_network_write_or_provider_surface(self) -> None:
        source = GATE.read_text(encoding="ascii")
        patterns = (
            r"subprocess",
            r"systemctl",
            r"daemon-reload",
            r"paramiko",
            r"\bssh\b",
            r"requests",
            r"urllib",
            r"socket",
            r"os\.system",
            r"shutil",
            r"write_text",
            r"write_bytes",
            r"unlink\(",
            r"rmtree",
            r"TELEGRAM_TOKEN",
            r"X_TOKEN",
            r"REDDIT_TOKEN",
            r"PAYMENT_TOKEN",
            r"AVS_TOKEN",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, source, re.IGNORECASE))

    def test_schema_is_valid_json(self) -> None:
        self.assertIsInstance(json.loads(SCHEMA.read_text(encoding="ascii")), dict)


if __name__ == "__main__":
    unittest.main()
