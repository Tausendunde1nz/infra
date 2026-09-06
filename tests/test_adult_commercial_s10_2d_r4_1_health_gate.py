from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
HEALTH = ROOT / "scripts/tu1nz_adult_public_s10_1_health.py"
HEALTH_GATE = ROOT / "scripts/tu1nz_adult_public_s10_2d_health_gate.py"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s10_2d_release_simulator.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh"
S9_HEALTH = ROOT / "systemd/tu1nz-adult-public-s9-health.service.d/s10-wms.conf"
S10_HEALTH = ROOT / "systemd/tu1nz-adult-public-s10-health.service"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-community-instant.json"
DIAGNOSIS = ROOT / "analysis/COMMERCIAL_S10_2D_R4_1_HEALTH_GATE_START_2026-09-06.diagnose"


def load(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def community_arguments(release_id: str | None = "s10-2d-r3-5") -> SimpleNamespace:
    return SimpleNamespace(
        local_only=False,
        pre_growth=False,
        s8_contract=Path("/synthetic/s8-contract"),
        s8_copy=Path("/synthetic/s8-copy"),
        telegram_token=Path("/synthetic/token"),
        database_dsn=Path("/synthetic/dsn"),
        community_contract=Path("/synthetic/community-contract"),
        community_copy=Path("/synthetic/community-copy"),
        runtime_release_id=release_id,
    )


class CommercialS102DR41HealthGateTests(unittest.TestCase):
    def test_community_health_forwards_the_target_release_identity(self) -> None:
        module = load(HEALTH, "r4_1_health_forward")
        captured: list[str] = []

        def run(command, timeout=30):
            del timeout
            captured.extend(command)
            payload = {
                "ok": True,
                "state": "GREEN",
                "community": {
                    "provider": {"ok": True, "rules_pinned": True},
                    "latency_24h": {
                        "samples": 5,
                        "bot_response_p50_ms": 1,
                        "bot_response_p95_ms": 2,
                        "bot_response_p99_ms": 3,
                    },
                    "pending_moderation": 0,
                    "stuck_restrictions": 0,
                    "latency_degraded": False,
                },
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

        module._run = run
        result = module._community(community_arguments())
        self.assertEqual(result["provider"], "GREEN")
        position = captured.index("--runtime-release-id")
        self.assertEqual(captured[position + 1], "s10-2d-r3-5")
        self.assertLess(position, captured.index("--health-only"))

    def test_pre_fix_missing_release_binding_reproduces_precise_red(self) -> None:
        module = load(HEALTH, "r4_1_health_missing_release")
        with self.assertRaisesRegex(ValueError, "^S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED$"):
            module._community(community_arguments(None))
        self.assertEqual(module.health_exit_status("S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED"), 40)

    def test_runtime_contract_child_failure_is_not_collapsed(self) -> None:
        module = load(HEALTH, "r4_1_health_child_contract")

        def run(command, timeout=30):
            del timeout
            return subprocess.CompletedProcess(
                command,
                2,
                '{"ok":false,"safe_code":"BOT_RUNTIME_CONTRACT_MISMATCH"}',
                "",
            )

        module._run = run
        with self.assertRaisesRegex(ValueError, "^S10_2D_COMMUNITY_RUNTIME_CONTRACT_RED$"):
            module._community(community_arguments())

    def test_failure_envelope_is_bounded_and_fingerprint_is_deterministic(self) -> None:
        module = load(HEALTH_GATE, "r4_1_health_gate_envelope")
        first = module._failure_report(
            module.HEALTH_UNITS[1],
            start_status=1,
            result="exit-code",
            exit_status=40,
            elapsed_ms=123,
        )
        second = module._failure_report(
            module.HEALTH_UNITS[1],
            start_status=1,
            result="exit-code",
            exit_status=40,
            elapsed_ms=999,
        )
        self.assertEqual(
            first["safe_code"],
            "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED",
        )
        self.assertEqual(first["check_id"], "S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT")
        self.assertEqual(first["expected_state"], "SYSTEMD_RESULT_SUCCESS_EXIT_0")
        self.assertEqual(first["actual_state"], "PROCESS_EXIT_40")
        self.assertEqual(first["exit_code"], 40)
        self.assertEqual(first["result"], "exit-code")
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertRegex(first["fingerprint"], r"^[0-9a-f]{64}$")
        self.assertNotIn("unit", first)

    def test_units_and_controller_use_the_shared_release_bound_gate(self) -> None:
        for path in (S9_HEALTH, S10_HEALTH):
            source = path.read_text(encoding="utf-8")
            self.assertIn("--runtime-release-id s10-2d-r3-5", source)
        controller = CONTROLLER.read_text(encoding="utf-8")
        gate = controller.split("run_health_gates() {", 1)[1].split("start_target() {", 1)[0]
        self.assertIn('report="$("$HEALTH_GATE_SCRIPT")"', gate)
        self.assertIn("S10_2D_HEALTH_GATE_EVIDENCE", gate)
        self.assertNotIn("HEALTH_GATE_START_RED", gate)
        self.assertNotIn("HEALTH_GATE_RESULT_RED", gate)
        self.assertNotIn("HEALTH_GATE_STATUS_RED", gate)

    def test_release_simulator_runs_real_health_gate_and_all_expected_paths(self) -> None:
        application = ROOT.parent / "application"
        if not application.exists():
            self.skipTest("paired application source checkout is unavailable")
        python = application / ".venv/bin/python"
        if not python.exists():
            python = Path(sys.executable)
        completed = subprocess.run(
            [
                str(python),
                str(SIMULATOR),
                "--application-root",
                str(application),
                "--control-root",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["safe_code"], "S10_2D_R6_1_RELEASE_SIMULATOR_GREEN")
        self.assertTrue(report["production_health_gate_shared"])
        self.assertTrue(report["production_wms_listener_shared"])
        self.assertEqual(report["health_listener_owner"], "S10_WMS_RUNTIME")
        self.assertEqual(report["health_listener_production_port"], 18110)
        self.assertEqual(len(report["scenarios"]), 8)
        self.assertEqual(len(report["health_cases"]), 9)
        self.assertEqual(len(report["listener_cases"]), 9)
        self.assertTrue(all(item["ok"] for item in report["scenarios"]))
        self.assertTrue(all(item["ok"] for item in report["health_cases"]))
        self.assertTrue(all(item["ok"] for item in report["listener_cases"]))
        reproduction = next(
            item for item in report["health_cases"]
            if item["name"] == "r4_missing_health_release_binding"
        )
        self.assertEqual(
            reproduction["safe_code"],
            "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED",
        )

    def test_manifest_and_diagnosis_bind_the_proven_source_only_decision(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        release = manifest["health_gate_stabilization_r4_1"]
        self.assertEqual(release["status"], "GREEN_SOURCE_CONTRACT")
        self.assertTrue(release["source_only"])
        self.assertFalse(release["application_changed"])
        self.assertEqual(
            release["exact_failed_subcheck"],
            "S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT",
        )
        self.assertEqual(
            release["fixed_safe_code"],
            "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED",
        )
        self.assertTrue(release["pre_fix_red_reproduced"])
        self.assertTrue(release["production_health_gate_shared_with_simulator"])
        self.assertFalse(release["health_expectation_weakened"])
        self.assertEqual(release["health_cases_green_or_expected_red"], 9)
        self.assertEqual(release["full_release_scenarios_green"], 8)
        self.assertTrue(release["s10_2d_next_runtime_cutover_ready"])
        for boundary in ("server_mutation", "runtime_cutover", "community_activation", "real_acquisition"):
            self.assertFalse(release[boundary])
        diagnosis = DIAGNOSIS.read_text(encoding="utf-8")
        for value in (
            "DETERMINISTIC_CONFIGURATION_ERROR",
            "HEALTH_CONTRACT_ERROR",
            "BOT_RUNTIME_CONTRACT_MISMATCH",
            "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED",
            "No health expectation was weakened",
            "No server command, deployment",
        ):
            self.assertIn(value, diagnosis)


if __name__ == "__main__":
    unittest.main()
