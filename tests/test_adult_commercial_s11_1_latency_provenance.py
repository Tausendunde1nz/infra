from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / "scripts/tu1nz_adult_public_s11_latency_slo.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_1_control.sh"
S11_CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_control.sh"
RECONCILIATION = ROOT / "evidence/commercial-s11-1-latency-provenance-reconciliation.json"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-1-latency-provenance.json"


def load_reader():
    stub = types.SimpleNamespace(Connection=object, Error=Exception, connect=None)
    original = sys.modules.get("psycopg")
    sys.modules["psycopg"] = stub
    try:
        spec = importlib.util.spec_from_file_location("s11_latency_reader", READER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        if original is None:
            del sys.modules["psycopg"]
        else:
            sys.modules["psycopg"] = original


MODULE = load_reader()


def sample(value, evidence="REAL", *, poll=10, handler=20, path="TELEGRAM_DIRECT"):
    return {
        "source": "DIRECT",
        "bot_response_latency_ms": value,
        "poll_lag_ms": poll,
        "handler_duration_ms": handler,
        "send_ack_ms": 15,
        "evidence_class": evidence,
        "sample_type": "DIRECT_BOT_RESPONSE",
        "interaction_path": path,
    }


class CommercialS111LatencyProvenanceTests(unittest.TestCase):
    def test_old_contract_bug_is_reproduced(self):
        values = [464, 797, 19079, 687, 423, 359]
        old = lambda rows: len(rows) < 5 or MODULE._percentile(sorted(rows), 0.95) < 2000
        self.assertFalse(old(values))
        self.assertFalse(old(values[:5]))
        self.assertTrue(old(values[:4]))

    def test_tri_state_and_class_filtering(self):
        self.assertEqual(
            MODULE.evaluate([sample(value) for value in (200, 250, 300, 350)], "REAL_USER_DIRECT_LATENCY")["state"],
            "INSUFFICIENT_EVIDENCE",
        )
        self.assertEqual(
            MODULE.evaluate([sample(value) for value in (200, 250, 300, 350, 400)], "REAL_USER_DIRECT_LATENCY")["state"],
            "GREEN",
        )
        internal = [sample(100, "INTERNAL_TEST", path="INTERNAL_ACCEPTANCE") for _ in range(5)]
        self.assertEqual(MODULE.evaluate(internal, "REAL_USER_DIRECT_LATENCY")["state"], "INSUFFICIENT_EVIDENCE")

    def test_unknown_fails_closed_and_poll_lag_is_not_deleted(self):
        unknown = [sample(19079, "UNKNOWN", poll=18720, handler=172, path="UNKNOWN")]
        result = MODULE.evaluate(unknown, "REAL_USER_DIRECT_LATENCY")
        self.assertEqual(result["state"], "RED")
        self.assertEqual(result["reason"], "UNKNOWN_PROVENANCE_FAIL_CLOSED")
        internal = [sample(19079, "INTERNAL_TEST", poll=18720, handler=172, path="INTERNAL_ACCEPTANCE") for _ in range(5)]
        self.assertEqual(MODULE.evaluate(internal, "TECHNICAL_RUNTIME_LATENCY")["state"], "GREEN")

    def test_contract_simulator_covers_required_a_through_h_matrix(self):
        result = MODULE.simulate_contract()
        self.assertTrue(result["ok"])
        self.assertEqual(result["safe_code"], "S11_1_LATENCY_CONTRACT_SIMULATOR_GREEN")
        self.assertEqual(
            result["cases"],
            {
                "A": "RED",
                "B": "INSUFFICIENT_EVIDENCE",
                "C": "GREEN",
                "D": "INSUFFICIENT_EVIDENCE",
                "E": "INSUFFICIENT_EVIDENCE",
                "F": "INSUFFICIENT_EVIDENCE",
                "G_REAL": "RED",
                "G_TECHNICAL": "GREEN",
                "H": "RED",
            },
        )

    def test_reconciliation_preserves_rows_and_contains_no_identifiers(self):
        payload = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
        self.assertFalse(payload["original_rows_mutated"])
        self.assertEqual(len(payload["assertions"]), 6)
        self.assertEqual(
            [item["evidence_class"] for item in payload["assertions"]],
            ["UNKNOWN", "UNKNOWN", "UNKNOWN", "REAL", "REAL", "REAL"],
        )
        source = RECONCILIATION.read_text(encoding="utf-8").casefold()
        for forbidden in ("telegram_user_id", "chat_id", "message_body", "email", "token", "dsn"):
            self.assertNotIn(forbidden, source)

    def test_contract_deploy_is_backup_first_and_keeps_s11_off(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        body = source[source.index("deploy_contract() {"):source.index("deployment_error() {")]
        self.assertLess(body.index("backup_runtime"), body.index("switch --detach"))
        self.assertLess(body.index("backup_runtime"), body.index("apply_provenance_migration"))
        self.assertIn("require_acquisition_and_s11_off", body)
        self.assertNotIn("set_feature true", source)
        self.assertNotIn("commercial_s11_interactive_experience.sql", source)

    def test_authoritative_product_gate_requires_exact_real_profile(self):
        source = S11_CONTROLLER.read_text(encoding="utf-8")
        gate = source[source.index("community_latency_slo_state() {"):source.index("require_services_and_timers() {")]
        self.assertIn("REAL_USER_DIRECT_LATENCY", gate)
        self.assertIn("INSUFFICIENT_EVIDENCE", gate)
        self.assertIn("S11_COMMUNITY_LATENCY_SLO_INSUFFICIENT_EVIDENCE", gate)
        self.assertNotIn("samples<5", gate)

    def test_manifest_declares_profiles_and_no_gate_weakening(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["application_release"],
            {
                "commit": "ecc73e2557b3f5bf643fa89d06bda57a9c4d26cc",
                "tree": "1acc0300ca099bd57f2455753c0a2700867a68d5",
                "pull_request": 115,
                "post_merge_ci": 35509998343,
                "tests": "1039_GREEN",
            },
        )
        self.assertEqual(manifest["slo_contract"]["states"], ["GREEN", "RED", "INSUFFICIENT_EVIDENCE"])
        self.assertEqual(manifest["slo_contract"]["minimum_samples"], 5)
        self.assertEqual(manifest["deployment_gate"]["profile"], "REAL_USER_DIRECT_LATENCY")
        self.assertEqual(manifest["deployment_gate"]["allow_state"], "GREEN")
        self.assertEqual(manifest["simulator"]["required_cases"], [
            "A", "B", "C", "D", "E", "F", "G_REAL", "G_TECHNICAL", "H",
        ])
        self.assertFalse(manifest["historical_evidence"]["rows_mutated"])

    def test_contract_and_product_controllers_bind_the_new_freeze(self):
        contract = CONTROLLER.read_text(encoding="utf-8")
        product = S11_CONTROLLER.read_text(encoding="utf-8")
        for source in (contract, product):
            self.assertIn('TARGET_APPLICATION_COMMIT="ecc73e2557b3f5bf643fa89d06bda57a9c4d26cc"', source)
            self.assertIn('TARGET_APPLICATION_TREE="1acc0300ca099bd57f2455753c0a2700867a68d5"', source)
            self.assertIn('FINAL_CONTROL_TAG="s11-1-latency-provenance-slo-freeze-r1"', source)
        self.assertNotIn("__TARGET_APPLICATION_", contract)

    def test_product_deploy_starts_from_the_installed_frozen_contract(self):
        source = S11_CONTROLLER.read_text(encoding="utf-8")
        state = source[source.index("require_source_state() {"):source.index("require_s11_schema_absent_or_disabled() {")]
        self.assertIn('[ "$source_application" = "$TARGET_APPLICATION_COMMIT" ]', state)
        self.assertIn('[ "$source_control" = "$target_control" ]', state)
        self.assertIn('rev-parse "${source_control}^{tree}"', state)
        self.assertNotIn('readonly SOURCE_CONTROL_COMMIT=', source)
        self.assertNotIn('readonly SOURCE_CONTROL_TREE=', source)


if __name__ == "__main__":
    unittest.main()
