from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_freeze as freeze
from scripts import tu1nz_adult_public_s11_2_gate as gate
from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration
from scripts import tu1nz_adult_public_s11_2_r15_17_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_r15_17_simulator.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
SSOT = ROOT / "docs/COMMERCIAL_S11_2_R15_16_4_TECHNICAL_PROFILE_SERIALIZATION.md"
FREEZE = ROOT / "scripts/tu1nz_adult_public_s11_2_freeze.py"


class R15164TechnicalProfileSerializationTests(unittest.TestCase):
    def test_live_r15_16_3_failure_is_reproduced_before_producer_filter(self):
        with self.assertRaisesRegex(
            orchestration.ContractError, "S11_2_TECHNICAL_SAMPLE_SET_INVALID"
        ):
            orchestration.technical_plan(
                {
                    "required_floor": 5,
                    "current_valid_samples": 0,
                    "state": "INSUFFICIENT_EVIDENCE",
                    "samples": [
                        {
                            "source": "DIRECT",
                            "evidence_class": "REAL",
                            "sample_type": "DIRECT_BOT_RESPONSE",
                            "interaction_path": "TELEGRAM_DIRECT",
                        }
                    ],
                    "health": "GREEN",
                }
            )

    def test_controller_serializer_excludes_real_and_preserves_plan_invariant(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["zero_technical_plus_real"]["current_valid_samples"], 0)
        self.assertEqual(report["zero_technical_plus_real"]["missing_samples"], 5)
        self.assertEqual(report["multiple_real"]["missing_samples"], 5)
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("snapshot = _technical_snapshot(technical_rows, technical)", source)
        self.assertIn(
            "if any(snapshot[key] != technical[key] for key in comparable):",
            source,
        )
        orchestration_source = (ROOT / "scripts/tu1nz_adult_public_s11_2_orchestration.py").read_text(encoding="utf-8")
        self.assertIn("len(samples) != current", orchestration_source)
        self.assertIn("S11_2_TECHNICAL_SAMPLE_SET_INVALID", orchestration_source)

    def test_dynamic_missing_four_and_five_samples_with_real(self):
        report = simulator.simulate()
        self.assertEqual(report["four_technical_plus_real"]["missing_samples"], 1)
        self.assertEqual(report["four_technical_plus_real"]["state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["five_technical_plus_real"]["missing_samples"], 0)
        self.assertEqual(report["five_technical_plus_real"]["state"], "GREEN")

    def test_real_concurrency_is_ignored_but_technical_drift_fails_closed(self):
        report = simulator.simulate()
        self.assertEqual(report["real_concurrency"]["current_valid_samples"], 0)
        self.assertEqual(
            report["technical_snapshot_drift_code"],
            "S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED",
        )
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn('"safe_code": TECHNICAL_SNAPSHOT_DRIFT_CODE', source)
        self.assertIn("DIRECT_PROFILE_PATHS", source)
        self.assertIn("DIRECT_SAMPLE_TYPES", source)

    def test_all_canonical_nontechnical_profiles_are_accepted_and_excluded(self):
        report = simulator.simulate()
        profile = report["canonical_nontechnical_profiles"]
        self.assertEqual(profile["current_valid_samples"], 0)
        self.assertEqual(profile["missing_samples"], 5)

    def test_concurrent_canonical_rows_with_invalid_metrics_fail_snapshot_closed(self):
        report = simulator.simulate()
        self.assertEqual(
            set(report["malformed_metric_snapshot_codes"].values()),
            {"S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED"},
        )
        self.assertEqual(len(report["malformed_metric_snapshot_codes"]), 4)
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("bot_response_latency_ms,poll_lag_ms,handler_duration_ms,send_ack_ms", source)
        self.assertIn("not 0 <= metric <= 300000", source)

    def test_equal_count_slo_change_fails_snapshot_closed(self):
        report = simulator.simulate()
        self.assertEqual(
            report["equal_count_slo_snapshot_drift_code"],
            "S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED",
        )
        source = CONTROLLER.read_text(encoding="utf-8")
        for field in ("p50_ms", "p95_ms", "p99_ms", "maximum_ms", "state", "reason"):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', source)

    def test_concurrent_unknown_and_malformed_rows_fail_snapshot_closed(self):
        report = simulator.simulate()
        self.assertEqual(
            report["unknown_snapshot_drift_code"],
            "S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED",
        )
        self.assertEqual(
            report["malformed_snapshot_drift_code"],
            "S11_2_TECHNICAL_PROFILE_SNAPSHOT_DRIFT_RED",
        )

    def test_unknown_and_malformed_stay_gate_owned_and_fail_closed(self):
        report = simulator.simulate()
        self.assertEqual(report["unknown_code"], "S11_2_TECHNICAL_PROVENANCE_RED")
        self.assertTrue(
            all(
                code in {
                    "S11_2_TECHNICAL_PROVENANCE_RED",
                    "S11_2_LATENCY_VALUE_INVALID",
                }
                for code in report["malformed_codes"].values()
            )
        )
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[source.index("write_technical_profile() {"):source.index("technical_plan_field() {")]
        query = helper[helper.index("SELECT source,evidence_class"):helper.index("ORDER BY recorded_at,sample_id")]
        self.assertNotIn("evidence_class='INTERNAL_TEST'", query)
        self.assertIn("WHERE source='DIRECT'", query)

    def test_probe_cardinality_slo_red_and_phase_order_are_preserved(self):
        report = simulator.simulate()
        self.assertTrue(report["probe_cardinality_green"])
        self.assertEqual(
            [item["missing"] for item in report["probe_progression"]],
            [5, 4, 3, 2, 1, 0],
        )
        self.assertEqual(report["technical_slo_red_code"], "S11_2_TECHNICAL_SLO_RED")
        self.assertLess(
            report["ordered_phases"].index("TECHNICAL_EVIDENCE_COMPLETE"),
            report["ordered_phases"].index("CANARY_ACTIVE"),
        )
        self.assertEqual(report["canary_starts"], 1)
        self.assertEqual(report["automatic_retries"], 0)

    def test_writer_and_shared_binding_contracts_are_unchanged(self):
        report = simulator.simulate()
        self.assertEqual(
            report["real_writer"],
            "DIRECT/REAL/DIRECT_BOT_RESPONSE/TELEGRAM_DIRECT",
        )
        self.assertEqual(
            report["technical_writer"],
            "DIRECT/INTERNAL_TEST/DIRECT_BOT_RESPONSE/INTERNAL_ACCEPTANCE",
        )
        self.assertTrue(report["shared_release_run_binding"])
        self.assertEqual(
            gate.TECHNICAL_PROFILE,
            ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE"),
        )

    def test_new_freeze_contract_retains_29_keys_and_old_v2_binding(self):
        self.assertEqual(len(freeze.REQUIRED_KEYS), 29)
        self.assertEqual(
            freeze.STATIC_BINDINGS["technical_evidence_contract"],
            "PROFILE_SCOPED_READER_SERIALIZER_SNAPSHOT_V3",
        )
        self.assertEqual(
            freeze.PROFILE_SCOPED_STATIC_BINDINGS["technical_evidence_contract"],
            "PROFILE_SCOPED_MIXED_PROVENANCE_DYNAMIC_HARD_CAP_V2",
        )
        self.assertEqual(
            freeze.PROFILE_SCOPED_FREEZE_TAG,
            "s11-2-r15-15-3-profile-scoped-technical-freeze-r1",
        )

    def test_manifest_binds_current_r15_16_4_artifacts(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        contract = manifest["r15_16_4_technical_profile_serialization"]
        bindings = contract["artifact_bindings"]
        expected = {
            "controller_sha256": CONTROLLER,
            "freeze_helper_sha256": FREEZE,
            "r15_17_simulator_sha256": SIMULATOR,
            "focused_suite_sha256": Path(__file__),
            "ssot_sha256": SSOT,
        }
        for key, path in expected.items():
            with self.subTest(binding=key):
                from tests.s11_historical_release import artifact_bytes
                self.assertEqual(
                    bindings[key], hashlib.sha256(artifact_bytes(path)).hexdigest()
                )

    def test_full_r15_17_source_simulator_is_green_and_source_only(self):
        completed = subprocess.run(
            [sys.executable, str(SIMULATOR)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(report["safe_code"], "S11_2_R15_17_SOURCE_ONLY_SIMULATOR_GREEN")
        self.assertTrue(report["next_r15_17_runtime_deployment_ready"])
        self.assertEqual(report["runtime_mutations"], 0)
        self.assertEqual(report["database_mutations"], 0)
        self.assertEqual(report["technical_probes_executed"], 0)
        self.assertEqual(report["s11_starts"], 0)
        self.assertEqual(report["yoti_calls"], 0)


if __name__ == "__main__":
    unittest.main()
