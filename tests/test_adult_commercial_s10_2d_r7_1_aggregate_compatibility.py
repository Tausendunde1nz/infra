from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s10_2d_backup.sh"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s10_2d_release_simulator.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-r7-1-aggregate-compatibility.json"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2D_R7_1_AGGREGATE_COMPATIBILITY.md"

SPEC = importlib.util.spec_from_file_location("s10_2d_r7_1_aggregate_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class CommercialS102DR71AggregateCompatibilityTests(unittest.TestCase):
    RUN_ID = "20260908T000000Z-pre-s10-2d-community"

    @staticmethod
    def _source_payload() -> dict[str, int]:
        return {
            "2026-09-07|LANDING_VIEW|direct|none": 4,
            "2026-09-07|TELEGRAM_CTA|site|launch": 3,
        }

    def _fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        aggregate = root / "landing-aggregates.json"
        backup = root / "backup"
        backup.mkdir(mode=0o700)
        aggregate.write_bytes(CONTRACT.canonical_json(self._source_payload()))
        aggregate.chmod(0o600)
        CONTRACT.create_backup(
            aggregate,
            backup,
            target_release_id=CONTRACT.TARGET_RELEASE_ID,
            run_id=self.RUN_ID,
        )
        return aggregate, backup

    def test_event_matrix_is_explicit_and_unknown_is_not_permissive(self) -> None:
        self.assertEqual(CONTRACT.SOURCE_EVENTS, {"LANDING_VIEW", "TELEGRAM_CTA"})
        self.assertEqual(CONTRACT.TARGET_PRODUCT_EVENTS, {"COMMUNITY_CTA"})
        self.assertEqual(CONTRACT.TARGET_TECHNICAL_EVENTS, set())
        self.assertEqual(CONTRACT.EVENT_CLASSES["COMMUNITY_CTA"], "TARGET_ONLY_PRODUCT")
        payload = CONTRACT.parse_aggregate(
            b'{"2026-09-07|UNKNOWN|direct|none":1}'
        )
        with self.assertRaisesRegex(
            CONTRACT.AggregateContractError,
            "AGGREGATE_RECONCILIATION_UNKNOWN_EVENT_RED",
        ):
            CONTRACT.classify_aggregate(payload)

    def test_byte_backup_binds_hash_metadata_event_summary_and_restore_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            aggregate, backup = self._fixture(directory)
            material = aggregate.read_bytes()
            saved = (backup / CONTRACT.BACKUP_BYTES).read_bytes()
            metadata = json.loads((backup / CONTRACT.BACKUP_METADATA).read_text())
            self.assertEqual(saved, material)
            self.assertEqual(metadata["sha256"], CONTRACT.sha256_bytes(material))
            self.assertEqual(metadata["restore_path"], str(aggregate))
            self.assertEqual(metadata["mode"], "0600")
            self.assertEqual(metadata["target_release_id"], CONTRACT.TARGET_RELEASE_ID)
            self.assertEqual(metadata["run_id"], self.RUN_ID)
            report = CONTRACT.verify_backup(
                aggregate,
                backup,
                target_release_id=CONTRACT.TARGET_RELEASE_ID,
                run_id=self.RUN_ID,
            )
            self.assertTrue(report["aggregate_backup_present"])
            self.assertTrue(report["aggregate_backup_hash_valid"])
            self.assertTrue(report["aggregate_backup_mode_valid"])
            self.assertTrue(report["aggregate_backup_restore_path_valid"])

    def test_exact_r7_red_then_projection_preserves_source_and_archives_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            aggregate, backup = self._fixture(directory)
            target = self._source_payload()
            target["2026-09-08|COMMUNITY_CTA|community|launch"] = 2
            aggregate.write_bytes(CONTRACT.canonical_json(target))
            aggregate.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "S9_AGGREGATE_STATE_INVALID"):
                CONTRACT.verify_source_compatible(aggregate)
            report = CONTRACT.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=CONTRACT.TARGET_RELEASE_ID,
                run_id=self.RUN_ID,
            )
            self.assertEqual(CONTRACT.parse_aggregate(aggregate.read_bytes()), self._source_payload())
            archived = CONTRACT.parse_aggregate(
                (backup / CONTRACT.RECONCILIATION_DIRECTORY / CONTRACT.TARGET_ONLY_ARCHIVE).read_bytes()
            )
            self.assertEqual(archived, {"2026-09-08|COMMUNITY_CTA|community|launch": 2})
            self.assertTrue(report["original_preserved"])
            self.assertTrue(report["target_only_archived"])
            self.assertTrue(report["conservation_green"])

    def test_unknown_and_malformed_states_are_archived_but_never_installed(self) -> None:
        cases = (
            (
                CONTRACT.canonical_json(
                    {**self._source_payload(), "2026-09-08|UNKNOWN|direct|none": 1}
                ),
                "AGGREGATE_RECONCILIATION_UNKNOWN_EVENT_RED",
            ),
            (b'{"incomplete":', "AGGREGATE_JSON_RED"),
        )
        for material, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                aggregate, backup = self._fixture(directory)
                aggregate.write_bytes(material)
                aggregate.chmod(0o600)
                with self.assertRaisesRegex(CONTRACT.AggregateContractError, expected):
                    CONTRACT.reconcile_for_source(
                        aggregate,
                        backup,
                        target_release_id=CONTRACT.TARGET_RELEASE_ID,
                        run_id=self.RUN_ID,
                    )
                reconciliation = backup / CONTRACT.RECONCILIATION_DIRECTORY
                self.assertEqual(aggregate.read_bytes(), material)
                self.assertEqual((reconciliation / CONTRACT.CURRENT_BYTES).read_bytes(), material)
                failure = json.loads((reconciliation / CONTRACT.RECONCILIATION_FAILURE).read_text())
                self.assertEqual(failure["safe_code"], expected)
                self.assertTrue(failure["original_preserved"])

    def test_two_failed_attempts_restore_original_then_success_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            aggregate, backup = self._fixture(directory)
            target = {**self._source_payload(), "2026-09-08|COMMUNITY_CTA|community|launch": 1}
            aggregate.write_bytes(CONTRACT.canonical_json(target))
            aggregate.chmod(0o600)
            original = aggregate.read_bytes()

            def fail_after_replace() -> None:
                raise CONTRACT.AggregateContractError("SIMULATED_POST_REPLACE_RED")

            for _ in range(2):
                with self.assertRaisesRegex(
                    CONTRACT.AggregateContractError,
                    "SIMULATED_POST_REPLACE_RED",
                ):
                    CONTRACT.reconcile_for_source(
                        aggregate,
                        backup,
                        target_release_id=CONTRACT.TARGET_RELEASE_ID,
                        run_id=self.RUN_ID,
                        after_replace=fail_after_replace,
                    )
                self.assertEqual(aggregate.read_bytes(), original)
            first = CONTRACT.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=CONTRACT.TARGET_RELEASE_ID,
                run_id=self.RUN_ID,
            )
            second = CONTRACT.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=CONTRACT.TARGET_RELEASE_ID,
                run_id=self.RUN_ID,
            )
            continued = CONTRACT.parse_aggregate(aggregate.read_bytes())
            continued["2026-09-08|LANDING_VIEW|recovery|health"] = 1
            aggregate.write_bytes(CONTRACT.canonical_json(continued))
            aggregate.chmod(0o600)
            third = CONTRACT.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=CONTRACT.TARGET_RELEASE_ID,
                run_id=self.RUN_ID,
            )
            self.assertFalse(first["idempotent"])
            self.assertTrue(second["idempotent"])
            self.assertTrue(third["idempotent"])
            self.assertEqual(
                CONTRACT.parse_aggregate(aggregate.read_bytes())["2026-09-08|LANDING_VIEW|recovery|health"],
                1,
            )
            self.assertEqual(
                len(list((backup / CONTRACT.RECONCILIATION_DIRECTORY).glob(CONTRACT.CURRENT_BYTES))),
                1,
            )

    def test_count_regression_and_backup_hash_mismatch_fail_before_live_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            aggregate, backup = self._fixture(directory)
            regressed = self._source_payload()
            regressed["2026-09-07|LANDING_VIEW|direct|none"] = 3
            aggregate.write_bytes(CONTRACT.canonical_json(regressed))
            aggregate.chmod(0o600)
            original = aggregate.read_bytes()
            with self.assertRaisesRegex(
                CONTRACT.AggregateContractError,
                "AGGREGATE_SOURCE_COUNT_REGRESSION_RED",
            ):
                CONTRACT.reconcile_for_source(
                    aggregate,
                    backup,
                    target_release_id=CONTRACT.TARGET_RELEASE_ID,
                    run_id=self.RUN_ID,
                )
            self.assertEqual(aggregate.read_bytes(), original)

        with tempfile.TemporaryDirectory() as directory:
            aggregate, backup = self._fixture(directory)
            original = aggregate.read_bytes()
            (backup / CONTRACT.BACKUP_BYTES).write_bytes(b"{}")
            (backup / CONTRACT.BACKUP_BYTES).chmod(0o600)
            with self.assertRaisesRegex(CONTRACT.AggregateContractError, "AGGREGATE_BACKUP_HASH_RED"):
                CONTRACT.verify_backup(
                    aggregate,
                    backup,
                    target_release_id=CONTRACT.TARGET_RELEASE_ID,
                    run_id=self.RUN_ID,
                )
            self.assertEqual(aggregate.read_bytes(), original)

    def test_controller_orders_quiesce_projection_restore_start_and_source_health(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        rollback = controller.split("rollback() {", 1)[1].split("deploy() {", 1)[0]
        self.assertLess(rollback.index("quiesce"), rollback.index("reconcile_aggregate_for_source"))
        self.assertLess(rollback.index("reconcile_aggregate_for_source"), rollback.index("rollback_migration_if_unused"))
        self.assertLess(rollback.index("rollback_migration_if_unused"), rollback.index("restore_technical_state"))
        self.assertLess(rollback.index("restore_technical_state"), rollback.index("systemctl start"))
        self.assertLess(rollback.index("systemctl start"), rollback.index("require_source_green"))
        self.assertIn("require_source_aggregate_readable", controller)
        self.assertIn("tu1nz_adult_public_s10_2d_backup.sh", controller)
        backup = BACKUP.read_text(encoding="utf-8")
        self.assertIn("aggregate_backup_present", backup)
        self.assertIn("CUTOVER_PREFLIGHT_RED", backup)
        self.assertIn("sha256sum --check --strict", backup)

    def test_simulator_and_ssot_bind_full_source_target_rollback_contract(self) -> None:
        simulator = SIMULATOR.read_text(encoding="utf-8")
        for value in (
            "source_target_community_failure_rollback_source_health",
            "unknown_event_fails_closed",
            "malformed_incomplete_file_fails_closed",
            "two_failed_recoveries_then_idempotent_success",
            "S10_2D_R7_1_AGGREGATE_ROLLBACK_GREEN",
        ):
            self.assertIn(value, simulator)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertIn(
            manifest["decision"],
            {
                "S10_2D_R7_1_SOURCE_CONTRACT_PENDING_CI",
                "S10_2D_NEXT_RUNTIME_CUTOVER_READY",
            },
        )
        self.assertTrue(manifest["aggregate_contract"]["unknown_events_fail_closed"])
        self.assertTrue(manifest["aggregate_contract"]["byte_backup_mandatory"])
        self.assertFalse(manifest["scope"]["runtime_mutation"])
        self.assertFalse(manifest["product_boundary"]["real_acquisition"])
        bindings = manifest["artifact_bindings"]
        self.assertEqual(bindings["controller_sha256"], hashlib.sha256(CONTROLLER.read_bytes()).hexdigest())
        self.assertEqual(bindings["release_simulator_sha256"], hashlib.sha256(SIMULATOR.read_bytes()).hexdigest())
        self.assertEqual(bindings["aggregate_contract_sha256"], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        self.assertEqual(bindings["aggregate_backup_sha256"], hashlib.sha256(BACKUP.read_bytes()).hexdigest())
        control = CONTROL.read_text(encoding="utf-8")
        self.assertIn("COMMUNITY_CTA", control)
        self.assertIn("S9_AGGREGATE_STATE_INVALID", control)
        self.assertIn("SOURCE → TARGET → FAILURE → ROLLBACK → SOURCE", control)

    def test_scripts_avoid_destructive_shortcuts_and_personal_data(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("rm -rf", "git reset", "git clean", "psql", "docker"):
            self.assertNotIn(forbidden, source.lower())
        self.assertIn("os.replace", source)
        self.assertIn("os.fsync", source)
        self.assertIn("contains_personal_data\": False", source)
        self.assertEqual(os.stat(SCRIPT).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(BACKUP).st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
