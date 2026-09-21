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

from scripts import tu1nz_adult_public_community_health_contract as contract
from scripts import tu1nz_adult_public_s10_1_health as health
from scripts import tu1nz_adult_public_s10_2d_health_gate as health_gate
from scripts import tu1nz_adult_public_s11_2_recovery_diagnostic as diagnostic


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
RECOVERY = ROOT / "scripts/tu1nz_adult_public_s11_2_s8_poller_recovery.sh"


def green_payload() -> dict[str, object]:
    return {
        "ok": True,
        "safe_code": "S8_DIAGNOSTIC_GREEN",
        "state": "GREEN",
        "community": {
            "bot_event_path": {"ok": True, "safe_code": "BOT_EVENT_PATH_GREEN"},
            "latency_24h": {
                "samples": 5,
                "bot_response_p50_ms": 100,
                "bot_response_p95_ms": 200,
                "bot_response_p99_ms": 300,
            },
            "latency_degraded": False,
            "pending_moderation": 0,
            "provider": {
                "ok": True,
                "safe_code": "S10_2D_COMMUNITY_GREEN",
                "rules_pinned": True,
            },
            "stuck_restrictions": 0,
        },
    }


def arguments() -> argparse.Namespace:
    return argparse.Namespace(
        community_contract=Path("/safe/community.json"),
        community_copy=Path("/safe/community-copy.json"),
        database_dsn=Path("/safe/database.dsn"),
        local_only=False,
        pre_growth=False,
        runtime_release_id="s10-2d-r3-5",
        s8_contract=Path("/safe/s8.json"),
        s8_copy=Path("/safe/s8-copy.json"),
        telegram_token=Path("/safe/token"),
    )


class FakeGateClient:
    def __init__(self, report: dict[str, object]) -> None:
        self.report = report

    def reset_failed(self, unit: str) -> None:
        return None

    def start(self, unit: str) -> int:
        return 1

    def show(self, unit: str, property_name: str) -> str:
        return {"Result": "exit-code", "ExecMainStatus": "44"}.get(property_name, "")

    def safe_report(self, unit: str) -> dict[str, object] | None:
        return self.report if unit == health_gate.HEALTH_UNITS[1] else None


class S112R8ChildCodeContractTests(unittest.TestCase):
    def _community(self, payload: dict[str, object], returncode: int = 0):
        completed = subprocess.CompletedProcess([], returncode, json.dumps(payload), "")
        with mock.patch.object(health, "_run", return_value=completed):
            return health._community(arguments())

    def test_case_a_green_preserves_existing_success_contract(self):
        report = self._community(green_payload())
        self.assertEqual(report["provider"], "GREEN")

    def test_r8_manifest_hash_binds_every_contract_and_simulator_artifact(self):
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["r8_artifact_bindings"]
        expected = {
            "community_health_contract_sha256": ROOT / "scripts/tu1nz_adult_public_community_health_contract.py",
            "s9_health_wrapper_sha256": ROOT / "scripts/tu1nz_adult_public_s10_1_health.py",
            "health_gate_sha256": ROOT / "scripts/tu1nz_adult_public_s10_2d_health_gate.py",
            "recovery_diagnostic_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_recovery_diagnostic.py",
            "recovery_entrypoint_sha256": RECOVERY,
            "fixture_suite_sha256": ROOT / "tests/test_adult_commercial_s11_2_r8_child_code_contract.py",
            "source_only_release_simulator_sha256": ROOT / "scripts/tu1nz_adult_public_s10_2d_release_simulator.py",
        }
        self.assertEqual(set(bindings), set(expected))
        for field, path in expected.items():
            with self.subTest(field=field):
                self.assertEqual(bindings[field], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_case_b_latency_child_is_preserved_under_outer_exit_44(self):
        payload = green_payload()
        payload["community"]["latency_degraded"] = True
        with self.assertRaises(contract.CommunityHealthFailure) as caught:
            self._community(payload)
        failure = caught.exception
        self.assertEqual(failure.outer_code, "S10_2D_COMMUNITY_STATE_RED")
        self.assertEqual(failure.child_code, "S11_COMMUNITY_LATENCY_SLO_RED")
        self.assertEqual(failure.component, "LATENCY_SLO")
        self.assertEqual(health.health_exit_status(failure.outer_code), 44)

    def test_cases_c_and_d_missing_and_unknown_fail_closed(self):
        missing = contract.failure_from_payload(
            {"ok": False, "safe_code": "S8_DIAGNOSTIC_RED", "components": {}}, 2
        )
        unknown = contract.failure_from_payload(
            {"event": "S8_RUNTIME_STARTUP_RED", "safe_reason": "FREE_TEXT"}, 2
        )
        self.assertEqual(missing.child_code, contract.CHILD_MISSING)
        self.assertEqual(unknown.child_code, contract.CHILD_UNKNOWN)
        self.assertEqual(missing.decision_class, contract.UNKNOWN_HARD_RED)
        self.assertEqual(unknown.next_action, "STOP_AND_EXTEND_CANONICAL_CONTRACT")
        inconsistent = diagnostic.diagnose({
            "ok": False,
            "outer_code": "S10_2D_COMMUNITY_STATE_RED",
            "child_code": "BOT_RUNTIME_CONTRACT_MISMATCH",
            "component": "LOCAL_CONFIG_HEALTH",
        })
        self.assertEqual(inconsistent["child_code"], contract.CHILD_UNKNOWN)

    def test_cases_e_to_i_preserve_canonical_children(self):
        cases = (
            ("BOT_RUNTIME_CONTRACT_MISMATCH", "LOCAL_CONFIG_HEALTH", contract.RELEASE_BINDING_BLOCKER),
            ("BOT_POLLER_NOT_RUNNING", "POLLING", contract.RETRYABLE_RUNTIME_READINESS),
            ("BOT_EVENT_PATH_RED", "POLLING", contract.STATE_INTEGRITY_BLOCKER),
            ("RETAINED_MODERATION_STATE_RED", "RETAINED_STATE", contract.STATE_INTEGRITY_BLOCKER),
            ("S10_2D_COMMUNITY_PROFILE_MISMATCH", "PROVIDER", contract.PROVIDER_EXTERNAL_BLOCKER),
        )
        for child_code, component, decision_class in cases:
            with self.subTest(child_code=child_code):
                failure = contract.failure(child_code, component)
                report = diagnostic.diagnose(failure.as_dict())
                self.assertEqual(report["child_code"], child_code)
                self.assertEqual(report["component"], component)
                self.assertEqual(report["decision_class"], decision_class)
                self.assertEqual(report["decision"], "STOP_NO_RETRY")
                self.assertFalse(report["retry"])

    def test_component_probe_preserves_exact_safe_reason(self):
        payload = {
            "ok": False,
            "safe_code": "S8_DIAGNOSTIC_RED",
            "state": "RED",
            "components": {
                "POLLING": {"status": "RED", "safe_reason": "BOT_POLLER_NOT_RUNNING"}
            },
        }
        failure = contract.failure_from_payload(payload, 2)
        self.assertEqual(failure.child_code, "BOT_POLLER_NOT_RUNNING")
        self.assertEqual(failure.component, "POLLING")

    def test_main_outputs_machine_readable_child_and_real_exit_status(self):
        failure = contract.failure("S11_COMMUNITY_LATENCY_SLO_RED", "LATENCY_SLO")
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / str(index) for index in range(6)]
            for path in paths:
                path.write_text("safe", encoding="ascii")
            argv = [
                "health",
                "--contract", str(paths[0]),
                "--copy", str(paths[1]),
                "--s8-contract", str(paths[2]),
                "--s9-contract", str(paths[3]),
                "--database-dsn", str(paths[4]),
                "--telegram-token", str(paths[5]),
                "--telegram-channel", "SAFE_CHANNEL",
            ]
            green_output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(health, "_web", return_value={"landing": "GREEN"}),
                mock.patch.object(health, "_traffic_quality", return_value=None),
                mock.patch.object(health, "_changeset", return_value=None),
                mock.patch.object(health, "_growth", return_value={"application": "GREEN"}),
                mock.patch.object(health, "_community", return_value={"provider": "GREEN"}),
                mock.patch.object(health, "_system", return_value={"services": "GREEN"}),
                contextlib.redirect_stdout(green_output),
            ):
                green_status = health.main()
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(health, "_web", return_value={"landing": "GREEN"}),
                mock.patch.object(health, "_traffic_quality", return_value=None),
                mock.patch.object(health, "_changeset", return_value=None),
                mock.patch.object(health, "_growth", return_value={"application": "GREEN"}),
                mock.patch.object(health, "_community", side_effect=failure),
                mock.patch.object(health, "_system", return_value={"services": "GREEN"}),
                contextlib.redirect_stdout(output),
            ):
                status = health.main()
        report = json.loads(output.getvalue())
        self.assertEqual(green_status, 0)
        self.assertTrue(json.loads(green_output.getvalue())["ok"])
        self.assertEqual(status, 44)
        self.assertEqual(report["outer_code"], "S10_2D_COMMUNITY_STATE_RED")
        self.assertEqual(report["child_code"], "S11_COMMUNITY_LATENCY_SLO_RED")

    def test_health_gate_preserves_child_for_s9_exit_44(self):
        report = contract.failure("S11_COMMUNITY_LATENCY_SLO_RED", "LATENCY_SLO").as_dict()
        client = FakeGateClient(report)
        client.start = lambda unit: 0 if unit == health_gate.HEALTH_UNITS[0] else 1
        client.show = lambda unit, prop: (
            "success" if unit == health_gate.HEALTH_UNITS[0] and prop == "Result"
            else "0" if unit == health_gate.HEALTH_UNITS[0] and prop == "ExecMainStatus"
            else "exit-code" if prop == "Result"
            else "44"
        )
        with self.assertRaises(health_gate.HealthGateFailure) as caught:
            health_gate.run_health_gates(client)
        gate_report = caught.exception.report
        self.assertEqual(gate_report["outer_code"], "S10_2D_COMMUNITY_STATE_RED")
        self.assertEqual(gate_report["child_code"], "S11_COMMUNITY_LATENCY_SLO_RED")
        self.assertFalse(gate_report["retry"])

    def test_recovery_simulator_matrix_and_shell_never_retry(self):
        report = diagnostic.simulate_contract()
        self.assertTrue(report["ok"])
        self.assertEqual(set(report["cases"]), set("ABCDEFGHI"))
        self.assertTrue(all(case["retry"] is False for case in report["cases"].values()))
        source = RECOVERY.read_text(encoding="utf-8")
        recover = source[source.index("recover() {"):source.index("usage() {")]
        self.assertEqual(recover.count('systemctl start "$S8_SERVICE"'), 1)
        self.assertIn("run_health_services", recover)
        self.assertNotIn("START_CANARY", source)
        self.assertNotIn("FULL_RELEASE", source)
        self.assertIn("simulate-diagnostic", source)

    def test_stream_parser_ignores_non_json_and_never_echoes_it(self):
        failure = contract.failure("BOT_EVENT_PATH_RED", "POLLING").as_dict()
        parsed = diagnostic.parse_stream("sensitive-looking unstructured line\n" + json.dumps(failure))
        report = diagnostic.diagnose(parsed)
        self.assertEqual(report["child_code"], "BOT_EVENT_PATH_RED")
        self.assertNotIn("sensitive", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
