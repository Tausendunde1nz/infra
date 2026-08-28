from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-first-start-authorization-preparation.m4-27.json"
SCHEMA = ROOT / "manifests" / "adult-publishing-commercial-first-start-authorization-preparation.m4-27.schema.json"
GATE = ROOT / "scripts" / "tu1nz_adult_commercial_m4_27_gate.py"
HISTORICAL = {
    "m4_24_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json",
    "m4_25_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-unit-refresh.m4-25.json",
    "m4_26_contract_sha256": ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-26.json",
}

SPEC = importlib.util.spec_from_file_location("m4_27_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CommercialM427Test(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="ascii"))

    def test_contract_is_valid_fail_closed_preparation(self) -> None:
        self.assertFalse(gate.validate_contract(self.contract))
        self.assertFalse(self.contract["active"])
        self.assertEqual(self.contract["decision"], "NO_GO")

    def test_every_readiness_escalation_is_rejected(self) -> None:
        cases = (
            ("require_sync_ready", "sync is not approved"),
            ("require_prestart_ready", "prestart is not executed"),
            ("require_authorization_ready", "never authorizes first start"),
        )
        for argument, message in cases:
            with self.subTest(argument=argument):
                with self.assertRaisesRegex(gate.GateFailure, message):
                    gate.validate_contract(self.contract, **{argument: True})

    def test_historical_contract_hashes_are_exact(self) -> None:
        binding = self.contract["release_binding"]
        for field, path in HISTORICAL.items():
            with self.subTest(field=field):
                self.assertEqual(
                    binding[field],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )

    def test_sync_is_planned_only_and_requires_target_refresh(self) -> None:
        sync = self.contract["canonical_control_sync"]
        self.assertFalse(sync["transaction"]["approved"])
        self.assertEqual(sync["transaction"]["status"], "NOT_EXECUTED")
        self.assertTrue(sync["transaction"]["fast_forward_only"])
        self.assertTrue(sync["planned_target"]["post_m4_27_merge_refresh_required"])
        self.assertEqual(sync["rollback"]["status"], "PLANNED_NOT_AUTHORIZED")
        self.assertTrue(sync["rollback"]["bundle_required"])

    def test_fresh_prestart_is_complete_checklist_but_not_evidence(self) -> None:
        prestart = self.contract["fresh_prestart"]
        self.assertEqual(prestart["checks"], gate.PREFLIGHT_CHECKS)
        self.assertFalse(prestart["executed"])
        self.assertIsNone(prestart["observed_at"])
        self.assertEqual(prestart["result"], "NOT_EXECUTED")
        self.assertEqual(len(prestart["checks"]), 39)

    def test_no_swap_recommendation_is_not_operator_acceptance(self) -> None:
        assessment = self.contract["no_swap_assessment"]
        self.assertEqual(
            assessment["recommendation"],
            "ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START",
        )
        self.assertFalse(assessment["operator_accepted"])
        self.assertFalse(self.contract["approval"]["no_swap_risk_accepted"])
        self.assertIn(
            "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
            self.contract["blockers"],
        )
        self.assertGreaterEqual(
            assessment["observed_memory_available_kib"],
            assessment["required_fresh_memory_available_kib"],
        )
        self.assertIsNone(assessment["empirical_peak_rss_kib"])
        self.assertFalse(assessment["memory_max_configured"])

    def test_first_start_and_abort_windows_are_exact(self) -> None:
        window = self.contract["first_start_window"]
        self.assertTrue(window["exactly_one_start"])
        self.assertFalse(window["restart_allowed"])
        self.assertFalse(window["enablement_allowed"])
        self.assertFalse(window["timer_allowed"])
        self.assertFalse(window["auto_recovery_enabled"])
        self.assertEqual(window["maximum_runtime_seconds"], 180)
        self.assertTrue(window["must_end_stopped"])
        recovery = self.contract["recovery"]
        self.assertFalse(recovery["second_start_allowed"])
        self.assertTrue(recovery["stop_failure_is_critical"])
        self.assertFalse(recovery["automatic_evidence_deletion"])

    def test_rejects_approval_sync_prestart_or_product_expansion(self) -> None:
        cases = (
            (("active",), True),
            (("approval", "server_control_sync_approved"), True),
            (("approval", "first_start_approved"), True),
            (("approval", "no_swap_risk_accepted"), True),
            (("fresh_prestart", "executed"), True),
            (("fresh_prestart", "result"), "PASS"),
            (("product_boundary", "network_enabled"), True),
            (("product_boundary", "external_providers_enabled"), True),
            (("product_boundary", "real_media_enabled"), True),
            (("product_boundary", "real_payment_enabled"), True),
            (("product_boundary", "publishing_enabled"), True),
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

    def test_rejects_release_ignored_or_safety_drift(self) -> None:
        cases = (
            (("release_binding", "canonical_control_sha"), "0" * 40),
            (("release_binding", "unit_sha256"), "0" * 64),
            (("canonical_control_sync", "transaction", "fast_forward_only"), False),
            (("canonical_control_sync", "planned_target", "post_m4_27_merge_refresh_required"), False),
            (("first_start_window", "maximum_runtime_seconds"), 181),
            (("recovery", "second_start_allowed"), True),
            (("recovery", "abort_steps"), list(reversed(gate.ABORT_STEPS))),
            (("no_swap_assessment", "operator_accepted"), True),
            (("no_swap_assessment", "mitigations"), list(reversed(gate.NO_SWAP_MITIGATIONS))),
            (("canonical_control_sync", "transaction", "steps"), list(reversed(gate.SYNC_STEPS))),
            (("canonical_control_sync", "rollback", "steps"), list(reversed(gate.ROLLBACK_STEPS))),
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
        changed = copy.deepcopy(self.contract)
        changed["canonical_control_sync"]["ignored_material"]["entries"].append(
            "unexpected"
        )
        with self.assertRaises(gate.GateFailure):
            gate.validate_contract(changed)

    def test_gate_has_no_system_network_or_write_surface(self) -> None:
        source = GATE.read_text(encoding="ascii")
        for forbidden in (
            r"subprocess",
            r"systemctl",
            r"daemon-reload",
            r"docker[.(]|(?:import|from)\s+docker",
            r"requests",
            r"urllib",
            r"socket",
            r"TELEGRAM_TOKEN",
            r"X_TOKEN",
            r"REDDIT_TOKEN",
            r"PAYMENT_TOKEN",
            r"AVS_TOKEN",
            r"write_text",
            r"write_bytes",
            r"unlink\(",
            r"rmtree",
        ):
            self.assertIsNone(re.search(forbidden, source, re.IGNORECASE))

    def test_schema_is_valid_json(self) -> None:
        self.assertIsInstance(json.loads(SCHEMA.read_text(encoding="ascii")), dict)


if __name__ == "__main__":
    unittest.main()
