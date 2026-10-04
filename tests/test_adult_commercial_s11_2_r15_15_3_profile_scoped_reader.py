from __future__ import annotations

import json
import hashlib
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_gate as gate
from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration
from scripts import tu1nz_adult_public_s11_2_r15_16_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "tests/fixtures/s11-2-r15-15-3/application-latency-profile-contract.json"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"


def row(
    evidence_class: object,
    sample_type: object,
    interaction_path: object,
    *,
    bot: object = 200,
    poll: object = 20,
    handler: object = 100,
    send: object = 30,
) -> tuple[object, ...]:
    return evidence_class, sample_type, interaction_path, bot, poll, handler, send


def technical(handler: object = 100) -> tuple[object, ...]:
    return row("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", handler=handler)


def real_direct(bot: object = 200) -> tuple[object, ...]:
    return row("REAL", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT", bot=bot, handler=180)


def technical_plan(values: list[int]) -> dict[str, object]:
    result = gate._profile(values, "TECHNICAL_RUNTIME_LATENCY")
    return orchestration.technical_plan(
        {
            "required_floor": result["minimum_samples"],
            "current_valid_samples": result["samples"],
            "state": result["state"],
            "samples": [
                {
                    "source": "DIRECT",
                    "evidence_class": "INTERNAL_TEST",
                    "sample_type": "DIRECT_BOT_RESPONSE",
                    "interaction_path": "INTERNAL_ACCEPTANCE",
                }
                for _ in values
            ],
            "health": "GREEN",
        }
    )


class Result:
    def __init__(self, *, one=None, many=None):
        self.one = one
        self.many = many

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class Connection:
    def __init__(self, results):
        self.results = iter(results)

    def execute(self, *_args, **_kwargs):
        return next(self.results)


class ProfileScopedTechnicalReaderTests(unittest.TestCase):
    def test_manifest_binds_profile_scoped_reader_contract_artifacts(self):
        contract = json.loads(MANIFEST.read_text(encoding="utf-8"))[
            "r15_15_3_profile_scoped_technical_reader"
        ]
        self.assertEqual(contract["classification"], "EXPECTED_SHARED_BINDING_CONTRACT_MISMATCH")
        self.assertTrue(contract["shared_release_binding_intentional"])
        self.assertTrue(contract["shared_run_binding_intentional"])
        self.assertFalse(contract["real_writer_changed"])
        self.assertFalse(contract["technical_writer_changed"])
        bindings = contract["artifact_bindings"]
        expected = {
            "controller_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh",
            "gate_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py",
            "freeze_helper_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_freeze.py",
            "r15_16_simulator_sha256": ROOT / "scripts/tu1nz_adult_public_s11_2_r15_16_simulator.py",
            "focused_suite_sha256": Path(__file__),
            "profile_fixture_sha256": CONTRACT,
            "ssot_sha256": ROOT / "docs/COMMERCIAL_S11_2_R15_15_3_PROFILE_SCOPED_TECHNICAL_READER.md",
        }
        self.assertEqual(set(bindings), set(expected))
        for name, path in expected.items():
            with self.subTest(name=name):
                from tests.s11_historical_release import artifact_bytes
                self.assertEqual(bindings[name], hashlib.sha256(artifact_bytes(path)).hexdigest())

    def test_application_contract_fixture_and_control_selection_are_in_parity(self):
        fixture = json.loads(CONTRACT.read_text(encoding="ascii"))
        contract = fixture["profiles"]
        selection = fixture["selection_contract"]
        technical_contract = contract["TECHNICAL_RUNTIME_LATENCY"]
        self.assertEqual(
            gate.TECHNICAL_PROFILE,
            (
                technical_contract["evidence_class"],
                technical_contract["sample_type"],
                technical_contract["writer_interaction_path"],
            ),
        )
        samples = [technical(100), real_direct(900), technical(140)]
        application_selected = [
            sample[5]
            for sample in samples
            if sample[0] == technical_contract["evidence_class"]
            and sample[1] == technical_contract["sample_type"]
        ]
        control_selected = gate.technical_profile_values(samples)
        self.assertEqual(control_selected, application_selected)
        self.assertEqual(
            gate._profile(control_selected, "TECHNICAL_RUNTIME_LATENCY"),
            gate._profile(application_selected, "TECHNICAL_RUNTIME_LATENCY"),
        )
        self.assertEqual(selection["unknown_provenance_state"], "RED")
        self.assertEqual(selection["unknown_provenance_reason"], "UNKNOWN_PROVENANCE")
        self.assertEqual(selection["metric_bounds_ms"], [0, 300000])
        self.assertEqual(selection["minimum_samples"], 5)
        self.assertEqual(selection["technical_metric"], "HANDLER")
        self.assertEqual(
            selection["technical_writer_interaction_path"],
            gate.TECHNICAL_PROFILE[2],
        )
        with self.assertRaisesRegex(ValueError, "S11_2_TECHNICAL_PROVENANCE_RED"):
            gate.technical_profile_values(
                samples + [row("UNKNOWN", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT")]
            )

    def test_valid_real_and_technical_share_release_run(self):
        samples = [
            technical(101),
            real_direct(15000),
            row("REAL", "S11_CANARY_RESPONSE", "TELEGRAM_DIRECT", bot=9000),
            row("INTERNAL_TEST", "S11_CANARY_RESPONSE", "INTERNAL_ACCEPTANCE", handler=777),
            row("SYNTHETIC", "DIRECT_BOT_RESPONSE", "SYNTHETIC_FIXTURE", handler=888),
            row("HEALTH", "DIRECT_BOT_RESPONSE", "RUNTIME_HEALTH", handler=999),
            row("PROVIDER_PROBE", "DIRECT_BOT_RESPONSE", "PROVIDER_PROBE", handler=1111),
        ]
        self.assertEqual(gate.technical_profile_values(samples), [101])

    def test_zero_four_and_five_technical_with_real_have_dynamic_counts(self):
        for count, state, missing in (
            (0, "INSUFFICIENT_EVIDENCE", 5),
            (4, "INSUFFICIENT_EVIDENCE", 1),
            (5, "GREEN", 0),
        ):
            with self.subTest(count=count):
                samples = [technical(100 + index) for index in range(count)] + [real_direct()]
                values = gate.technical_profile_values(samples)
                profile = gate._profile(values, "TECHNICAL_RUNTIME_LATENCY")
                plan = technical_plan(values)
                self.assertEqual(profile["samples"], count)
                self.assertEqual(profile["state"], state)
                self.assertEqual(plan["missing_samples"], missing)

    def test_unknown_malformed_and_impossible_rows_fail_closed(self):
        invalid = (
            row("UNKNOWN", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT"),
            row("REAL", "UNKNOWN", "TELEGRAM_DIRECT"),
            row("REAL", "DIRECT_BOT_RESPONSE", "UNKNOWN"),
            row("REAL", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE"),
            row("", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT"),
            row(None, "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT"),
            row("UNRECOGNIZED", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT"),
            row("REAL", "DIRECT_BOT_RESPONSE", "TELEGRAM_DIRECT", bot=None),
            row("INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", handler=True),
            ("INTERNAL_TEST", "DIRECT_BOT_RESPONSE"),
        )
        for malformed in invalid:
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                ValueError, "S11_2_TECHNICAL_PROVENANCE_RED"
            ):
                gate.technical_profile_values([technical(), malformed])

    def test_unknown_with_real_or_technical_takes_precedence(self):
        unknown = row("UNKNOWN", "UNKNOWN", "UNKNOWN")
        for samples in ([real_direct(), unknown], [technical() for _ in range(5)] + [unknown]):
            with self.subTest(samples=len(samples)), self.assertRaisesRegex(
                ValueError, "S11_2_TECHNICAL_PROVENANCE_RED"
            ):
                gate.technical_profile_values(samples)

    def test_technical_slo_red_remains_blocking(self):
        values = gate.technical_profile_values(
            [technical(value) for value in (100, 200, 300, 400, 6000)] + [real_direct()]
        )
        self.assertEqual(gate._profile(values, "TECHNICAL_RUNTIME_LATENCY")["state"], "RED")
        with self.assertRaisesRegex(orchestration.ContractError, "S11_2_TECHNICAL_SLO_RED"):
            technical_plan(values)

    def test_r15_15_2_production_shape_is_insufficient_not_provenance_red(self):
        now = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
        connection = Connection(
            [
                Result(one=("S11_DISABLED", "NOT_STARTED", None, None, 10, None)),
                Result(one=("s10-2d-r3-5", "shared-run")),
                Result(many=[real_direct()]),
                Result(many=[]),
                Result(one=(0,)),
                Result(one=(0,)),
            ]
        )
        payload = gate._runtime_payload(connection, now, True)
        result = gate.evaluate(payload)
        self.assertEqual(result["technical_latency"]["state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["technical_latency"]["samples"], 0)
        self.assertEqual(technical_plan(payload["technical_values_ms"])["missing_samples"], 5)

    def test_r15_16_source_only_simulator_covers_happy_and_negative_paths(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["happy_path"]["shared_real_rows"], 1)
        self.assertEqual(report["happy_path"]["initial_technical_samples"], 0)
        self.assertEqual(report["happy_path"]["technical_probes_simulated"], 5)
        self.assertEqual(report["happy_path"]["final_state"], "GREEN")
        self.assertEqual(report["happy_path"]["synthetic_journeys_green"], 8)
        self.assertEqual(report["happy_path"]["canary_starts"], 1)
        self.assertTrue(report["next_r15_16_runtime_deployment_ready"])
        self.assertFalse(report["runtime_mutation"])
        for path in report["negative_paths"].values():
            self.assertTrue(path["stopped"])
            self.assertEqual(path["canary_starts"], 0)


if __name__ == "__main__":
    unittest.main()
