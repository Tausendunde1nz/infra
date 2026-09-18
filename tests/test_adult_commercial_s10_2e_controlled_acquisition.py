from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "scripts/tu1nz_adult_public_s10_2e_evidence.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2e_acquisition.sh"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s10_2e_backup.sh"
BASE_BACKUP = ROOT / "scripts/tu1nz_adult_public_s10_1_backup.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2e-controlled-acquisition.json"


def load_module():
    specification = importlib.util.spec_from_file_location("tu1nz_s10_2e_evidence_tests", EVIDENCE)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


MODULE = load_module()


def snapshot(active: bool, baseline: str | None, offset: int = 0) -> dict[str, object]:
    return {
        "schema_version": 1,
        "collected_at": "2026-09-18T01:00:00.000000Z",
        "state": {
            "pre_acquisition_readiness": "GREEN",
            "real_acquisition_active": active,
            "real_acquisition_baseline_start": baseline,
            "community_enabled": True,
            "community_posting_enabled": True,
            "community_media_publishing_enabled": False,
            "community_automod_enabled": True,
            "community_welcome_enabled": True,
            "controlled_beta": False,
            "public_sfw_growth_enabled": True,
            "audience_seeding_enabled": True,
            "organic_discovery_enabled": True,
            "nurture_enabled": True,
        },
        "counts": {key: offset for key in MODULE.COUNT_KEYS},
    }


class CommercialS102EControlledAcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def write_json(self, directory: Path, name: str, value: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="ascii")
        path.chmod(0o600)
        return path

    def test_manifest_preserves_deferred_human_and_closed_product_gates(self) -> None:
        self.assertTrue(self.manifest["initial_state"]["WMS_REAL_ACQUISITION_TECHNICALLY_READY"])
        self.assertFalse(self.manifest["initial_state"]["REAL_ACQUISITION_ACTIVE"])
        self.assertIsNone(self.manifest["initial_state"]["REAL_ACQUISITION_BASELINE_START"])
        self.assertTrue(self.manifest["success_state"]["REAL_ACQUISITION_ACTIVE"])
        self.assertEqual(set(self.manifest["acceptance"].values()), {"DEFERRED", "NOT_MEASURED"})
        self.assertEqual(set(self.manifest["product_boundaries"].values()), {"CLOSED"})
        self.assertEqual(self.manifest["distribution"]["scope"], ["SFW", "OWNED", "ORGANIC", "NON_SPAM"])
        self.assertFalse(self.manifest["distribution"]["paid_campaigns"])

    def test_report_uses_exact_baseline_and_keeps_real_test_separation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            before = snapshot(False, None, 2)
            after = snapshot(True, "2026-09-18T01:05:00.000000Z", 5)
            before_path = self.write_json(directory, "before.json", before)
            after_path = self.write_json(directory, "after.json", after)
            baseline_aggregate = self.write_json(
                directory,
                "aggregate-before.json",
                {"2026-09-18|LANDING_VIEW|direct|s10_wms_launch": 10},
            )
            current_aggregate = self.write_json(
                directory,
                "aggregate-current.json",
                {
                    "2026-09-18|LANDING_VIEW|direct|s10_wms_launch": 13,
                    "2026-09-18|TELEGRAM_CTA|landing|s10_wms_launch": 1,
                },
            )
            report = MODULE.report(before_path, after_path, baseline_aggregate, current_aggregate)
            self.assertTrue(report["REAL_ACQUISITION_ACTIVE"])
            self.assertEqual(report["aggregate_since_baseline"]["LANDING_VIEW"], 3)
            self.assertEqual(report["aggregate_since_baseline"]["TELEGRAM_CTA"], 1)
            self.assertTrue(all(value == 3 for value in report["database_since_baseline"].values()))
            self.assertEqual(report["human_acceptance"], "DEFERRED")
            self.assertEqual(report["real_test_evidence_separation"], "INTACT")

    def test_baseline_and_aggregate_regression_fail_closed(self) -> None:
        with self.assertRaisesRegex(MODULE.EvidenceError, "^ACQUISITION_ALREADY_ACTIVE_RED$"):
            MODULE.validate_snapshot(
                snapshot(True, "2026-09-18T01:05:00.000000Z"),
                before_activation=True,
            )
        with self.assertRaisesRegex(MODULE.EvidenceError, "^AGGREGATE_COUNT_REGRESSION_RED$"):
            MODULE.delta({"a": 1}, {"a": 2})

    def test_target_state_aggregate_snapshot_accepts_community_and_rejects_unknown_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = self.write_json(
                directory,
                "live.json",
                {
                    "2026-09-18|LANDING_VIEW|direct|s10_wms_launch": 10,
                    "2026-09-18|TELEGRAM_CTA|landing|s10_wms_launch": 2,
                    "2026-09-18|COMMUNITY_CTA|bot|s10_2d_community": 1,
                },
            )
            destination = directory / "snapshot.json"
            report = MODULE.snapshot_aggregate(source, destination)
            self.assertEqual(report["safe_code"], "S10_2E_AGGREGATE_SNAPSHOT_GREEN")
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(MODULE.load_aggregate(destination)["2026-09-18|COMMUNITY_CTA|bot|s10_2d_community"], 1)
            with self.assertRaisesRegex(MODULE.EvidenceError, "^EVIDENCE_DESTINATION_RED$"):
                MODULE.snapshot_aggregate(source, destination)

            unknown = self.write_json(
                directory,
                "unknown.json",
                {"2026-09-18|UNKNOWN_EVENT|direct|s10_wms_launch": 1},
            )
            with self.assertRaisesRegex(MODULE.EvidenceError, "^AGGREGATE_EVENT_RED$"):
                MODULE.snapshot_aggregate(unknown, directory / "unknown-snapshot.json")

    def test_controller_activation_is_atomic_single_assignment_and_pause_preserves_baseline(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        activation = controller.split("activate() {", 1)[1].split("pause() {", 1)[0]
        pause = controller.split("pause_database() {", 1)[1].split("activate() {", 1)[0]
        self.assertIn("real_acquisition_baseline_start=CURRENT_TIMESTAMP,wms_real_acquisition_ready=true", activation)
        self.assertIn("NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL", activation)
        self.assertIn("SET wms_real_acquisition_ready=false", pause)
        self.assertNotIn("real_acquisition_baseline_start=NULL", pause)
        self.assertIn('preflight "$control_sha" "$control_tree" "$backup"', activation)
        self.assertIn('"$BACKUP_TOOL" verify-existing', controller)

    def test_backup_extends_verified_runtime_backup_and_has_exact_boundary(self) -> None:
        backup = BACKUP.read_text(encoding="utf-8")
        base = BASE_BACKUP.read_text(encoding="utf-8")
        self.assertIn('"$BASE_BACKUP" create "$BACKUP_PATH"', backup)
        self.assertIn("tu1nz_adult_public_s10_1_backup.sh", backup)
        self.assertNotIn("tu1nz_adult_public_s10_2d_backup.sh", backup)
        self.assertIn("snapshot-aggregate", backup)
        self.assertIn("verify-aggregate", backup)
        self.assertIn("database_snapshot", backup)
        self.assertIn("s10-2e-aggregate-before.sha256", backup)
        self.assertIn("-pre-s10-2d-community", backup)
        self.assertNotIn("-pre-s10-2e-acquisition", base)
        self.assertNotIn("telegram_user_id", backup)
        self.assertNotIn("private_chat_id", backup)


if __name__ == "__main__":
    unittest.main()
