from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import tu1nz_adult_public_community_health_contract as community
from scripts import tu1nz_adult_public_s10_1_health as health
from scripts import tu1nz_adult_public_s10_2d_health_gate as health_gate
from scripts import tu1nz_adult_public_s10_health_child_contract as contract
from scripts import tu1nz_adult_public_s11_2_health_preflight as preflight
from scripts import tu1nz_adult_public_s11_2_recovery_diagnostic as recovery_diagnostic


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"


def _arguments(temporary: str) -> list[str]:
    paths = [Path(temporary) / str(index) for index in range(6)]
    for path in paths:
        path.write_text("safe", encoding="ascii")
    return [
        "health",
        "--contract", str(paths[0]),
        "--copy", str(paths[1]),
        "--s8-contract", str(paths[2]),
        "--s9-contract", str(paths[3]),
        "--database-dsn", str(paths[4]),
        "--telegram-token", str(paths[5]),
        "--telegram-channel", "SAFE_CHANNEL",
    ]


def _run_main(side_effect: BaseException) -> tuple[int, dict[str, object]]:
    with tempfile.TemporaryDirectory() as temporary:
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", _arguments(temporary)),
            mock.patch.object(health, "_web", return_value={"landing": "GREEN"}),
            mock.patch.object(health, "_traffic_quality", return_value=None),
            mock.patch.object(health, "_changeset", return_value=None),
            mock.patch.object(health, "_growth", side_effect=side_effect),
            mock.patch.object(health, "_community", return_value={"provider": "GREEN"}),
            mock.patch.object(health, "_system", return_value={"services": "GREEN"}),
            contextlib.redirect_stdout(output),
        ):
            status = health.main()
    return status, json.loads(output.getvalue())


class GeneralS10GateClient:
    def reset_failed(self, unit: str) -> None:
        return None

    def start(self, unit: str) -> int:
        return 1 if unit == health_gate.HEALTH_UNITS[2] else 0

    def show(self, unit: str, property_name: str) -> str:
        if unit != health_gate.HEALTH_UNITS[2]:
            return "success" if property_name == "Result" else "0"
        return "exit-code" if property_name == "Result" else "2"

    def safe_report(self, unit: str) -> dict[str, object] | None:
        if unit != health_gate.HEALTH_UNITS[2]:
            return None
        return contract.failure(contract.CHILD_TIMEOUT, "GROWTH").as_dict()


class S112R156HealthChildTests(unittest.TestCase):
    def test_original_loss_location_reproduces_generic_exit_two(self):
        error = subprocess.TimeoutExpired(["health-child"], 30)
        # The pre-R15.6 catch-all used only str(error), which does not begin S10_.
        safe_code = str(error) if str(error).startswith("S10_") else contract.OUTER_CODE
        self.assertEqual(safe_code, contract.OUTER_CODE)
        self.assertEqual(health.health_exit_status(safe_code), 2)

    def test_timeout_preserves_outer_child_component_classification_action_and_exit(self):
        status, report = _run_main(subprocess.TimeoutExpired(["growth"], 30))
        self.assertEqual(status, 2)
        self.assertEqual(report["outer_code"], contract.OUTER_CODE)
        self.assertEqual(report["safe_code"], contract.OUTER_CODE)
        self.assertEqual(report["child_code"], contract.CHILD_TIMEOUT)
        self.assertEqual(report["component"], "GROWTH")
        self.assertEqual(report["classification"], contract.TRANSIENT)
        self.assertEqual(report["next_action"], contract.READ_ONLY_RECHECK)
        self.assertEqual(report["exit_code"], status)
        self.assertFalse(report["retry"])
        self.assertEqual(report["contract_version"], contract.CONTRACT_VERSION)

    def test_telegram_transient_uses_existing_child_and_existing_exit_class(self):
        status, report = _run_main(ValueError("S10_TELEGRAM_HEALTH_RED"))
        self.assertEqual(status, 34)
        self.assertEqual(report["child_code"], "S10_TELEGRAM_HEALTH_RED")
        self.assertEqual(report["component"], "TELEGRAM_CHANNEL_HEALTH")
        self.assertEqual(report["classification"], contract.TRANSIENT)
        self.assertEqual(report["exit_code"], 34)

    def test_unknown_and_missing_children_fail_closed(self):
        missing = contract.failure(None, "INTERNAL_HEALTH_CONTRACT")
        unknown = contract.failure("FREE_TEXT", "GROWTH")
        self.assertEqual(missing.child_code, contract.CHILD_MISSING)
        self.assertEqual(unknown.child_code, contract.CHILD_UNKNOWN)
        self.assertEqual(missing.classification, contract.UNKNOWN_HARD)
        self.assertEqual(unknown.next_action, contract.STOP_UNKNOWN)
        inconsistent = unknown.as_dict()
        inconsistent["classification"] = contract.TRANSIENT
        self.assertEqual(contract.normalize_report(inconsistent).child_code, contract.CHILD_UNKNOWN)
        outer_only = {"ok": False, "outer_code": contract.OUTER_CODE, "state": "RED"}
        self.assertEqual(contract.normalize_report(outer_only).child_code, contract.CHILD_MISSING)

    def test_health_gate_preserves_general_s10_report_for_nonlegacy_exit(self):
        with self.assertRaises(health_gate.HealthGateFailure) as caught:
            health_gate.run_health_gates(GeneralS10GateClient())
        report = caught.exception.report
        self.assertEqual(report["outer_code"], contract.OUTER_CODE)
        self.assertEqual(report["child_code"], contract.CHILD_TIMEOUT)
        self.assertEqual(report["component"], "GROWTH")
        self.assertEqual(report["classification"], contract.TRANSIENT)
        self.assertFalse(report["retry"])

    def test_existing_recovery_diagnostic_accepts_new_general_envelope(self):
        raw = contract.failure(contract.CHILD_TIMEOUT, "GROWTH").as_dict()
        report = recovery_diagnostic.diagnose(raw)
        self.assertEqual(report["child_code"], contract.CHILD_TIMEOUT)
        self.assertEqual(report["component"], "GROWTH")
        self.assertEqual(report["classification"], contract.TRANSIENT)
        self.assertEqual(report["decision"], "STOP_NO_RETRY")
        self.assertFalse(report["retry"])

    def test_fixture_matrix_a_to_l_and_no_automatic_deployment(self):
        report = preflight.simulate_contract()
        self.assertTrue(report["ok"])
        self.assertEqual(set(report["cases"]), set("ABCDEFGHIJKL"))
        self.assertTrue(report["next_r15_5_runtime_deployment_ready"])
        self.assertFalse(report["deployment_started"])
        self.assertFalse(report["runtime_mutation"])
        self.assertEqual(
            report["cases"]["C"]["last_failure"]["classification"],
            "PERSISTENT_BLOCKER",
        )
        self.assertEqual(report["cases"]["E"]["last_failure"]["child_code"], "BOT_POLLER_LEASE_RED")
        self.assertEqual(report["cases"]["F"]["last_failure"]["child_code"], "BOT_EVENT_PATH_RED")
        self.assertEqual(report["cases"]["L"]["last_failure"]["classification"], contract.HARD)
        self.assertTrue(all(not case["deployment_started"] for case in report["cases"].values()))

    def test_red_then_natural_green_separates_current_and_historical_state(self):
        case = preflight.simulate_contract()["cases"]["K"]
        self.assertEqual(case["current_health_state"], "GREEN")
        self.assertEqual(case["last_failure"]["child_code"], "S10_TELEGRAM_HEALTH_RED")
        self.assertEqual(case["last_failure"]["classification"], contract.TRANSIENT)
        self.assertIsNotNone(case["last_recovery_time"])
        self.assertEqual(case["decision"], "PHASE_A_GREEN_SEPARATE_AUTHORIZATION_REQUIRED")
        self.assertFalse(case["deployment_started"])

    def test_structured_reader_uses_versioned_output_and_ignores_free_text(self):
        red = {
            **contract.failure("S10_TELEGRAM_HEALTH_RED", "GROWTH").as_dict(),
            "observed_at": "2026-09-26T06:25:58Z",
        }
        green = {
            "contract_version": contract.CONTRACT_VERSION,
            "observed_at": "2026-09-26T06:31:01Z",
            "ok": True,
            "safe_code": "S10_1_WMS_PUBLIC_SFW_GREEN",
            "state": "GREEN",
        }
        material = "unstructured sensitive-looking text\n" + json.dumps(red) + "\n" + json.dumps(green)
        parsed = preflight.parse_stream(material)
        report = preflight.evaluate(parsed)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(report["current_health_state"], "GREEN")
        self.assertNotIn("sensitive", json.dumps(report))

    def test_hard_classes_never_degrade_to_transient(self):
        for child, component in (
            ("S10_DATABASE_STATE_RED", "DATABASE_STATE"),
            ("S10_TRAFFIC_QUALITY_STATE_RED", "AGGREGATE_STATE"),
            ("S10_2F_CHANGESET_STATE_RED", "RELEASE_BINDING"),
            ("S10_TELEGRAM_HEALTH_INVALID", "CONFIG_AUTH"),
            ("S10_PRODUCT_BOUNDARY_RED", "PRODUCT_BOUNDARY"),
        ):
            with self.subTest(child=child):
                failure = contract.failure(child, component)
                self.assertEqual(failure.classification, contract.HARD)
                self.assertNotEqual(failure.next_action, contract.READ_ONLY_RECHECK)

    def test_r15_4_source_runtime_access_contract_remains_unchanged(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        access = manifest["r15_4_source_runtime_access"]
        self.assertEqual(access["source_identity"], "chatops")
        self.assertTrue(access["source_mode_0700_allowed"])
        self.assertFalse(access["source_permissions_changed"])
        self.assertEqual(access["installed_controller_mode"], "0755")
        self.assertTrue(access["unit_exec_start_is_installed_copy"])
        self.assertFalse(access["controller_source_checkout_required_at_runtime"])

    def test_r15_6_manifest_hash_binds_all_new_contract_artifacts(self):
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["r15_6_artifact_bindings"]
        expected = {
            "s10_health_child_contract_sha256": ROOT / "scripts/tu1nz_adult_public_s10_health_child_contract.py",
            "s10_health_entrypoint_sha256": ROOT / "scripts/tu1nz_adult_public_s10_1_health.py",
            "s10_health_gate_sha256": ROOT / "scripts/tu1nz_adult_public_s10_2d_health_gate.py",
            "r15_5_preflight_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_health_preflight.py",
            "recovery_diagnostic_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_recovery_diagnostic.py",
            "fixture_suite_sha256": ROOT / "tests/test_adult_commercial_s11_2_r15_6_health_child.py",
        }
        self.assertEqual(set(bindings), set(expected))
        for field, path in expected.items():
            with self.subTest(field=field):
                self.assertEqual(bindings[field], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_preflight_source_has_no_mutating_or_retry_operations(self):
        source = (ROOT / "scripts/tu1nz_adult_public_s11_2_health_preflight.py").read_text(encoding="utf-8")
        for forbidden in (
            "systemctl start",
            "systemctl restart",
            "sudo ",
            "INSERT INTO",
            "UPDATE commercial_",
            "START_CANARY",
            "AUTO_RETRY",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
