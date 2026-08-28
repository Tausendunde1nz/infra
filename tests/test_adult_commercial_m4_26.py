from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-26.json"
SCHEMA = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-26.schema.json"
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_m4_26_gate.py"
M4_24 = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json"
M4_25 = ROOT / "manifests" / "adult-publishing-commercial-unit-refresh.m4-25.json"

SPEC = importlib.util.spec_from_file_location("m4_26_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CommercialM426Test(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="ascii"))

    def test_schema_and_contract_are_json(self) -> None:
        self.assertIsInstance(json.loads(SCHEMA.read_text(encoding="ascii")), dict)
        self.assertIsInstance(self.contract, dict)

    def test_contract_is_valid_but_never_approved(self) -> None:
        self.assertFalse(gate.validate_contract(self.contract))
        with self.assertRaisesRegex(gate.GateFailure, "never authorizes first start"):
            gate.validate_contract(self.contract, require_approved=True)

    def test_exact_merged_and_installed_release_binding(self) -> None:
        binding = self.contract["release_binding"]
        release = self.contract["preflight"]["release"]
        self.assertEqual(binding["base_control_main_sha"], gate.BASE_CONTROL_SHA)
        self.assertEqual(binding["base_control_main_tree_sha"], gate.BASE_CONTROL_TREE)
        self.assertEqual(release["installed_control_sha"], gate.ACTIVE_CONTROL_SHA)
        self.assertEqual(release["unit_sha256"], gate.UNIT_SHA256)
        self.assertEqual(release["release_manifest_sha256"], gate.MANIFEST_SHA256)
        self.assertEqual(
            binding["m4_24_contract_sha256"],
            hashlib.sha256(M4_24.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            binding["m4_25_contract_sha256"],
            hashlib.sha256(M4_25.read_bytes()).hexdigest(),
        )

    def test_candidate_remains_never_started(self) -> None:
        evidence = self.contract["preflight"]["start_evidence"]
        self.assertEqual(evidence["n_restarts"], 0)
        self.assertEqual(evidence["journal_lines"], 0)
        self.assertEqual(evidence["main_pid"], 0)
        self.assertFalse(evidence["runtime_status_present"])
        self.assertFalse(evidence["runtime_lock_present"])

    def test_rejects_activation_or_product_expansion(self) -> None:
        cases = (
            (("active",), True),
            (("approval", "first_start_approved"), True),
            (("product_boundary", "network_enabled"), True),
            (("product_boundary", "external_providers_enabled"), True),
            (("product_boundary", "real_media_enabled"), True),
            (("product_boundary", "real_payment_enabled"), True),
        )
        for path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.contract)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(gate.GateFailure):
                    gate.validate_contract(changed)

    def test_rejects_hash_start_or_database_drift(self) -> None:
        cases = (
            (("release_binding", "base_control_main_sha"), "0" * 40),
            (("preflight", "release", "unit_sha256"), "0" * 64),
            (("preflight", "archive", "archive_sha256"), "0" * 64),
            (("preflight", "start_evidence", "journal_lines"), 1),
            (("preflight", "systemd", "restart"), "on-failure"),
            (("preflight", "database", "business_rows_zero"), False),
            (("preflight", "isolation", "commercial_process_reference_detected"), True),
        )
        for path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.contract)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(gate.GateFailure):
                    gate.validate_contract(changed)

    def test_rejects_unbound_ignored_control_material(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["preflight"]["canonical_control"]["ignored_entries"].append(
            "unexpected-generated-file"
        )
        changed["preflight"]["canonical_control"]["ignored_entries_count"] += 1
        with self.assertRaisesRegex(gate.GateFailure, "ignored Control baseline"):
            gate.validate_contract(changed)

    def test_gate_has_no_system_or_network_mutation_surface(self) -> None:
        source = GATE.read_text(encoding="ascii")
        for forbidden in (
            "subprocess",
            "systemctl",
            "docker",
            "requests",
            "urllib",
            "socket",
            "TELEGRAM_TOKEN",
            "X_TOKEN",
            "REDDIT_TOKEN",
            "PAYMENT_TOKEN",
            "AVS_TOKEN",
            "write_text",
            "write_bytes",
            "unlink(",
            "rmtree",
        ):
            self.assertNotIn(forbidden, source)

    def test_historical_contracts_remain_closed(self) -> None:
        historical = json.loads(M4_24.read_text(encoding="ascii"))
        refreshed = json.loads(M4_25.read_text(encoding="ascii"))
        self.assertFalse(historical["active"])
        self.assertEqual(historical["decision"], "NO_GO")
        self.assertFalse(refreshed["active"])
        self.assertFalse(refreshed["first_start_approved"])


if __name__ == "__main__":
    unittest.main()
