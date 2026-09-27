from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_gate as gate
from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration
from scripts import tu1nz_adult_public_s11_2_r15_15_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
GATE = ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py"
OBSERVED_AT = "2026-09-27T12:00:00Z"
RUN_ID = "r15-14-test"


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


def disabled_row():
    return ("S11_DISABLED", "NOT_STARTED", None, None, 10, None)


def write_payload(directory: str, payload) -> Path:
    path = Path(directory) / "gate.json"
    if isinstance(payload, str):
        path.write_text(payload, encoding="ascii")
    else:
        path.write_text(json.dumps(payload), encoding="ascii")
    return path


def normalize(path: Path, exit_code: int):
    return gate.normalize_technical_gate_output(
        path,
        gate_exit_code=exit_code,
        run_id=RUN_ID,
        observed_at=OBSERVED_AT,
    )


class R1514GateErrorContractTests(unittest.TestCase):
    def test_every_literal_gate_value_error_is_allowlisted(self):
        tree = ast.parse(GATE.read_text(encoding="utf-8"))
        raised = {
            node.exc.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "ValueError"
            and node.exc.args
            and isinstance(node.exc.args[0], ast.Constant)
            and isinstance(node.exc.args[0].value, str)
            and node.exc.args[0].value.startswith("S11_2_")
        }
        self.assertEqual(raised - set(gate.FAILURE_TAXONOMY), set())

    def test_canonical_value_error_is_preserved_without_raw_text(self):
        payload = gate.failure_envelope(ValueError("S11_2_TECHNICAL_BINDING_MISSING"))
        self.assertEqual(payload["schema"], "TU1NZ_S11_2_GATE_FAILURE")
        self.assertEqual(payload["version"], "GATE_FAILURE_V1")
        self.assertEqual(payload["safe_code"], "S11_2_TECHNICAL_BINDING_MISSING")
        self.assertEqual(payload["component"], "TECHNICAL_EVIDENCE")
        self.assertEqual(payload["classification"], "RELEASE_BINDING_BLOCKER")
        self.assertEqual(set(payload), gate.FAILURE_ENVELOPE_FIELDS)

    def test_unknown_value_error_is_bounded_and_secret_free(self):
        sensitive_detail = "SENSITIVE_FREE_FORM_DSN_DETAIL_DO_NOT_SERIALIZE"
        payload = gate.failure_envelope(ValueError(sensitive_detail))
        serialized = json.dumps(payload)
        self.assertEqual(payload["safe_code"], "S11_2_GATE_UNKNOWN_ERROR_RED")
        self.assertNotIn(sensitive_detail, serialized)
        self.assertNotIn("DSN_DETAIL", serialized)

    def test_database_os_and_json_failures_are_bounded(self):
        fixtures = (
            (gate.psycopg.Error("sensitive database detail"), "S11_2_GATE_DATABASE_ERROR_RED"),
            (OSError("sensitive filesystem detail"), "S11_2_GATE_IO_ERROR_RED"),
            (json.JSONDecodeError("sensitive json detail", "secret", 0), "S11_2_GATE_JSON_ERROR_RED"),
        )
        for error, expected in fixtures:
            with self.subTest(expected=expected):
                payload = gate.failure_envelope(error)
                self.assertEqual(payload["safe_code"], expected)
                self.assertNotIn("sensitive", json.dumps(payload))

    def test_runtime_payload_binding_and_control_row_codes_are_exact(self):
        now = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "S11_2_CONTROL_ROW_MISSING"):
            gate._runtime_payload(Connection([Result(one=None)]), now, True)
        with self.assertRaisesRegex(ValueError, "S11_2_TECHNICAL_BINDING_MISSING"):
            gate._runtime_payload(
                Connection([Result(one=disabled_row()), Result(one=None)]),
                now,
                True,
            )

    def test_runtime_payload_provenance_code_is_exact(self):
        now = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
        connection = Connection(
            [
                Result(one=disabled_row()),
                Result(one=("release", "run")),
                Result(many=[("REAL", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE", 100)]),
            ]
        )
        with self.assertRaisesRegex(ValueError, "S11_2_TECHNICAL_PROVENANCE_RED"):
            gate._runtime_payload(connection, now, True)

    def test_controller_diagnostic_preserves_outer_and_inner(self):
        for expected in (
            "S11_2_TECHNICAL_BINDING_MISSING",
            "S11_2_TECHNICAL_PROVENANCE_RED",
            "S11_2_CONTROL_ROW_MISSING",
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                path = write_payload(
                    directory,
                    gate.failure_envelope(ValueError(expected)),
                )
                payload, success = normalize(path, 2)
                self.assertFalse(success)
                self.assertEqual(
                    payload["outer_code"], "S11_2_TECHNICAL_GATE_READ_RED"
                )
                self.assertEqual(payload["inner_safe_code"], expected)
                self.assertEqual(payload["gate_exit_code"], 2)
                self.assertEqual(payload["contract_version"], "GATE_FAILURE_V1")
                self.assertEqual(payload["run_id"], RUN_ID)

    def test_malformed_unknown_and_exit_mismatch_fail_closed(self):
        cases = []
        with tempfile.TemporaryDirectory() as directory:
            malformed = write_payload(directory, "not-json")
            cases.append((normalize(malformed, 2)[0]["inner_safe_code"], "S11_2_TECHNICAL_GATE_ENVELOPE_INVALID_RED"))
        with tempfile.TemporaryDirectory() as directory:
            unknown = gate.failure_envelope(ValueError("S11_2_TECHNICAL_BINDING_MISSING"))
            unknown["safe_code"] = "S11_2_NOT_ALLOWLISTED"
            path = write_payload(directory, unknown)
            cases.append((normalize(path, 2)[0]["inner_safe_code"], "S11_2_TECHNICAL_GATE_CHILD_UNKNOWN_RED"))
        with tempfile.TemporaryDirectory() as directory:
            failure = write_payload(
                directory,
                gate.failure_envelope(ValueError("S11_2_TECHNICAL_BINDING_MISSING")),
            )
            cases.append((normalize(failure, 0)[0]["inner_safe_code"], "S11_2_TECHNICAL_GATE_EXIT_MISMATCH_RED"))
        self.assertEqual([actual for actual, _ in cases], [expected for _, expected in cases])

    def test_empty_and_oversized_gate_outputs_fail_closed(self):
        for size in (0, 8193):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "gate.json"
                path.write_text("x" * size, encoding="ascii")
                payload, success = normalize(path, 2)
                self.assertFalse(success)
                self.assertEqual(
                    payload["inner_safe_code"],
                    "S11_2_TECHNICAL_GATE_ENVELOPE_INVALID_RED",
                )

    def test_wrong_schema_version_missing_code_and_taxonomy_mismatch_fail_closed(self):
        canonical = gate.failure_envelope(
            ValueError("S11_2_TECHNICAL_BINDING_MISSING")
        )
        fixtures = []
        for field, replacement in (
            ("schema", "WRONG_SCHEMA"),
            ("version", "WRONG_VERSION"),
            ("component", "WRONG_COMPONENT"),
            ("classification", "WRONG_CLASSIFICATION"),
        ):
            payload = dict(canonical)
            payload[field] = replacement
            fixtures.append(payload)
        missing_code = dict(canonical)
        del missing_code["safe_code"]
        fixtures.append(missing_code)
        for payload in fixtures:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                normalized, success = normalize(write_payload(directory, payload), 2)
                self.assertFalse(success)
                self.assertEqual(
                    normalized["inner_safe_code"],
                    "S11_2_TECHNICAL_GATE_ENVELOPE_INVALID_RED",
                )

    def test_invalid_diagnostic_metadata_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_payload(
                directory,
                gate.failure_envelope(
                    ValueError("S11_2_TECHNICAL_BINDING_MISSING")
                ),
            )
            payload, success = gate.normalize_technical_gate_output(
                path,
                gate_exit_code=-1,
                run_id="unsafe run id containing spaces",
                observed_at="not-a-timestamp-or-private-data",
            )
        self.assertFalse(success)
        self.assertEqual(payload["gate_exit_code"], 255)
        self.assertEqual(payload["run_id"], "INVALID_RUN_ID")
        self.assertEqual(payload["observed_at"], "1970-01-01T00:00:00Z")

    def test_valid_0_4_5_profiles_and_slo_red_remain_distinct(self):
        for count, state, missing in (
            (0, "INSUFFICIENT_EVIDENCE", 5),
            (4, "INSUFFICIENT_EVIDENCE", 1),
            (5, "GREEN", 0),
        ):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                payload = {"ok": True, "technical_latency": {"samples": count, "minimum_samples": 5, "state": state}}
                normalized, success = normalize(write_payload(directory, payload), 0)
                self.assertTrue(success)
                plan = orchestration.technical_plan(
                    {
                        "required_floor": 5,
                        "current_valid_samples": count,
                        "state": state,
                        "samples": [
                            {
                                "source": "DIRECT",
                                "evidence_class": "INTERNAL_TEST",
                                "sample_type": "DIRECT_BOT_RESPONSE",
                                "interaction_path": "INTERNAL_ACCEPTANCE",
                            }
                            for _ in range(count)
                        ],
                        "health": "GREEN",
                    }
                )
                self.assertEqual(plan["missing_samples"], missing)
                self.assertEqual(normalized["technical_latency"]["state"], state)
        with self.assertRaisesRegex(orchestration.ContractError, "S11_2_TECHNICAL_SLO_RED"):
            orchestration.technical_plan(
                {
                    "required_floor": 5,
                    "current_valid_samples": 5,
                    "state": "RED",
                    "samples": [
                        {
                            "source": "DIRECT",
                            "evidence_class": "INTERNAL_TEST",
                            "sample_type": "DIRECT_BOT_RESPONSE",
                            "interaction_path": "INTERNAL_ACCEPTANCE",
                        }
                        for _ in range(5)
                    ],
                    "health": "GREEN",
                }
            )

    def test_controller_captures_exit_and_never_uses_old_generic_collapse(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[source.index("write_technical_profile() {"):source.index("technical_plan_field() {")]
        self.assertIn('gate_exit=$?', helper)
        self.assertIn('--validate-gate-output "$gate_file"', helper)
        self.assertIn('inner_safe_code', helper)
        self.assertIn('S11_2_TECHNICAL_GATE_READ_RED', helper)
        self.assertNotIn('gate_json true > "$gate_file" || { fail "S11_2_TECHNICAL_GATE_READ_RED"', helper)

    def test_gate_cli_outputs_structured_envelope_not_exception_type(self):
        completed = subprocess.run(
            [sys.executable, str(GATE), "--input", "/definitely/missing/r15-14.json"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["schema"], "TU1NZ_S11_2_GATE_FAILURE")
        self.assertEqual(payload["safe_code"], "S11_2_INPUT_UNSAFE")
        self.assertNotIn("ValueError", completed.stdout)

    def test_r15_15_source_only_simulator_covers_both_paths(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["happy_path"]["technical_start_0_of_5"]["serial_probes"], 5)
        self.assertEqual(report["happy_path"]["canary_starts"], 1)
        self.assertEqual(report["negative_gate_path"]["inner_safe_code"], "S11_2_TECHNICAL_BINDING_MISSING")
        self.assertEqual(report["negative_gate_path"]["technical_probes"], 0)
        self.assertEqual(report["negative_gate_path"]["s11_installs"], 0)
        self.assertEqual(report["negative_gate_path"]["canary_starts"], 0)
        self.assertEqual(report["negative_gate_path"]["rollback_executions"], 1)
        self.assertFalse(report["runtime_mutation"])


if __name__ == "__main__":
    unittest.main()
