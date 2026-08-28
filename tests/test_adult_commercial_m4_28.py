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
CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-canonical-sync-authorization.m4-28.json"
SCHEMA = ROOT / "manifests" / "adult-publishing-commercial-canonical-sync-authorization.m4-28.schema.json"
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_m4_28_gate.py"
HISTORICAL = {
    "m4_24_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json",
    "m4_25_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-unit-refresh.m4-25.json",
    "m4_26_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-26.json",
    "m4_27_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start-authorization-preparation.m4-27.json",
}

SPEC = importlib.util.spec_from_file_location("m4_28_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CommercialM428Test(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 28, 20, 0, 0, tzinfo=timezone.utc)
        self.contract = json.loads(CONTRACT.read_text(encoding="ascii"))
        self.pre_sync = {
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
            "captured_at": "2026-08-28T19:58:00Z",
            "checkout_mutation": {
                "open_writers": [],
                "processes": [],
                "services": [],
                "timers": [],
            },
            "contract_path": gate.CONTRACT_RELATIVE,
            "evidence_version": "tu1nz-m4.28-pre-sync-evidence-v1",
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
        self.authorized["blockers"] = list(gate.AUTHORIZED_BLOCKERS)
        self.authorized["approval"].update(
            {
                "approved_at": "2026-08-28T19:59:00Z",
                "source_observed_at": self.pre_sync["captured_at"],
                "source_sha": gate.SOURCE_SHA,
                "source_tree_sha": gate.SOURCE_TREE,
                "sync_approved": True,
            }
        )
        root = "/opt/tu1nz_repos/backups/m4-28-control-sync/20260828T19-59-30Z"
        self.mutation = {
            "authorization_revalidated": True,
            "candidate_never_started": True,
            "contract_path": gate.CONTRACT_RELATIVE,
            "evidence_root": root,
            "git_integrity_evidence_sha256": "b" * 64,
            "git_status_evidence_sha256": "c" * 64,
            "ignored_inventory_sha256": "a" * 64,
            "incoming_tracked_collisions": [],
            "mutation_evidence_version": "tu1nz-m4.28-pre-mutation-evidence-v1",
            "prepared_at": "2026-08-28T19:59:30Z",
            "rollback": {
                "bundle_contains_source": True,
                "bundle_contains_target": True,
                "bundle_exists": True,
                "bundle_path": root + "/control-sync.bundle",
                "bundle_valid": True,
                "ref": "refs/tu1nz/rollback/m4-28-control-sync/20260828T19-59-30Z",
                "ref_sha": gate.SOURCE_SHA,
            },
            "root_private": True,
            "source_sha": gate.SOURCE_SHA,
            "source_tree_sha": gate.SOURCE_TREE,
            "target_sha": gate.TARGET_SHA,
            "target_tree_sha": gate.TARGET_TREE,
        }

    def test_committed_contract_is_exact_closed_no_go(self) -> None:
        gate.validate_contract(self.contract)
        self.assertFalse(self.contract["active"])
        self.assertFalse(self.contract["approval"]["sync_approved"])
        self.assertIsNone(self.contract["approval"]["approved_at"])
        self.assertEqual(self.contract["decision"], "NO_GO")

    def test_future_synthetic_authorization_and_mutation_evidence_can_validate(self) -> None:
        approved = gate.validate_authorization(
            self.authorized,
            self.pre_sync,
            now=self.now,
        )
        self.assertEqual(approved.isoformat(), "2026-08-28T19:59:00+00:00")
        self.assertTrue(
            gate.validate_mutation_ready(
                self.authorized,
                self.pre_sync,
                self.mutation,
                now=self.now,
            )
        )
        self.assertFalse(self.authorized["approval"]["first_start_approved"])
        self.assertFalse(self.authorized["approval"]["no_swap_risk_accepted"])

    def test_post_merge_target_is_exact(self) -> None:
        target = self.contract["post_merge_target"]
        self.assertEqual(target["repository"], gate.TARGET_REPOSITORY)
        self.assertEqual(target["branch"], gate.TARGET_BRANCH)
        self.assertEqual(target["sha"], gate.TARGET_SHA)
        self.assertEqual(target["tree_sha"], gate.TARGET_TREE)

    def test_historical_contract_hashes_are_exact(self) -> None:
        binding = self.contract["historical_binding"]
        for field, path in HISTORICAL.items():
            with self.subTest(field=field):
                self.assertEqual(
                    binding[field],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

    def test_rejects_wrong_target_sha_or_tree(self) -> None:
        for field in ("sha", "tree_sha"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.pre_sync)
                changed["target"][field] = "0" * 40
                with self.assertRaisesRegex(gate.GateFailure, "target SHA or tree"):
                    gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_dirty_branch_non_fast_forward_or_nonancestor_source(self) -> None:
        cases = (
            ("tracked_clean", False),
            ("branch", "main"),
            ("fast_forward_possible", False),
            ("source_is_ancestor_of_target", False),
            ("git_integrity_passed", False),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.pre_sync)
                changed["source"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "source"):
                    gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_missing_changed_or_colliding_ignored_material(self) -> None:
        cases = (
            ("missing_entries", ["checksums.txt"]),
            ("changed_entries", ["checksums.txt"]),
            ("incoming_tracked_collisions", ["checksums.txt"]),
            ("recursive_inventory_matches_baseline", False),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.pre_sync)
                changed["ignored"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "ignored material"):
                    gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_missing_or_invalid_bundle_and_wrong_rollback_ref(self) -> None:
        cases = (
            ("bundle_exists", False),
            ("bundle_valid", False),
            ("bundle_contains_source", False),
            ("bundle_contains_target", False),
            ("ref_sha", "0" * 40),
            ("ref", "refs/heads/control-main"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.mutation)
                changed["rollback"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "rollback ref and bundle"):
                    gate.validate_mutation_evidence(changed, now=self.now)

    def test_rejects_candidate_previously_started_or_active(self) -> None:
        cases = (
            ("never_started", False),
            ("active_state", "active"),
            ("sub_state", "running"),
            ("unit_file_state", "enabled"),
            ("restart", "on-failure"),
            ("runtime_maximum_seconds", 181),
            ("n_restarts", 1),
            ("runtime_status_present", True),
            ("runtime_lock_present", True),
            ("exec_main_start_timestamp", "2026-08-28 19:00:00 UTC"),
            ("journal_lines", 1),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.pre_sync)
                changed["candidate"][field] = value
                with self.assertRaisesRegex(gate.GateFailure, "never-started"):
                    gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_wrong_server_identity(self) -> None:
        changed = copy.deepcopy(self.pre_sync)
        changed["server_identity"]["tailscale_ipv4"] = "100.64.0.1"
        with self.assertRaisesRegex(gate.GateFailure, "identity"):
            gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_checkout_mutator(self) -> None:
        changed = copy.deepcopy(self.pre_sync)
        changed["checkout_mutation"]["processes"] = ["unknown-writer"]
        with self.assertRaisesRegex(gate.GateFailure, "mutate canonical Control"):
            gate.validate_pre_sync_evidence(changed, now=self.now)

    def test_rejects_missing_or_stale_authorization(self) -> None:
        with self.assertRaisesRegex(gate.GateFailure, "authorization is missing"):
            gate.validate_authorization(self.contract, self.pre_sync, now=self.now)
        changed = copy.deepcopy(self.authorized)
        changed["approval"]["approved_at"] = "2026-08-28T19:50:00Z"
        with self.assertRaisesRegex(gate.GateFailure, "stale"):
            gate.validate_authorization(changed, self.pre_sync, now=self.now)

    def test_rejects_authorization_before_source_observation(self) -> None:
        changed = copy.deepcopy(self.authorized)
        changed["approval"]["approved_at"] = "2026-08-28T19:57:59Z"
        with self.assertRaisesRegex(gate.GateFailure, "predates"):
            gate.validate_authorization(changed, self.pre_sync, now=self.now)

    def test_rejects_noncanonical_contract_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "contract.json"
            copied.write_text(CONTRACT.read_text(encoding="ascii"), encoding="ascii")
            with self.assertRaisesRegex(gate.GateFailure, "canonical"):
                gate.read_json(copied, canonical_contract=True)

    def test_rejects_manipulated_contract(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["post_merge_target"]["sha"] = "0" * 40
        with self.assertRaisesRegex(gate.GateFailure, "profile drift"):
            gate.validate_contract(changed)

    def test_rejects_changed_inventory_before_mutation(self) -> None:
        changed = copy.deepcopy(self.mutation)
        changed["ignored_inventory_sha256"] = "d" * 64
        with self.assertRaisesRegex(gate.GateFailure, "inventory changed"):
            gate.validate_mutation_ready(
                self.authorized,
                self.pre_sync,
                changed,
                now=self.now,
            )

    def test_rejects_mutation_evidence_before_authorization(self) -> None:
        changed = copy.deepcopy(self.mutation)
        changed["prepared_at"] = "2026-08-28T19:58:30Z"
        with self.assertRaisesRegex(gate.GateFailure, "predates authorization"):
            gate.validate_mutation_ready(
                self.authorized,
                self.pre_sync,
                changed,
                now=self.now,
            )

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
