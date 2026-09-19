from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HEALTH = ROOT / "scripts/tu1nz_adult_public_s10_1_health.py"
WMS_UNIT = ROOT / "systemd/tu1nz-adult-public-s10-wms.service"
HEALTH_UNIT = ROOT / "systemd/tu1nz-adult-public-s10-health.service"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2f_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2f-conversion-recovery.json"

SPEC = importlib.util.spec_from_file_location("s10_2f_health", HEALTH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CommercialS102FConversionRecoveryTests(unittest.TestCase):
    def test_units_bind_separate_quality_and_changeset_state(self) -> None:
        wms = WMS_UNIT.read_text(encoding="utf-8")
        health = HEALTH_UNIT.read_text(encoding="utf-8")
        self.assertIn("--traffic-quality-state /var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json", wms)
        self.assertIn("--traffic-quality-state /var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json", health)
        self.assertIn("--changeset-state /var/lib/tu1nz-adult-public-s9/s10-2f-changeset.json", health)
        self.assertIn("ReadWritePaths=/var/lib/tu1nz-adult-public-s9", wms)

    def test_health_accepts_only_privacy_safe_aggregate_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "quality.json"
            path.write_text(json.dumps({
                "2026-09-19|LANDING|HUMAN_LIKE": 3,
                "2026-09-19|LANDING|KNOWN_HEALTH": 4,
                "2026-09-19|TELEGRAM_CTA|PREFETCH_OR_PREVIEW": 1,
            }), encoding="ascii")
            os.chmod(path, 0o600)
            with patch.object(MODULE.os, "geteuid", return_value=path.stat().st_uid):
                report = MODULE._traffic_quality(path)
            self.assertEqual(report["samples"], 8)
            self.assertEqual(report["classes"]["HUMAN_LIKE"], 3)
            self.assertNotIn("address", repr(report).casefold())
            path.write_text('{"2026-09-19|LANDING|USER_1":1}', encoding="ascii")
            with patch.object(MODULE.os, "geteuid", return_value=path.stat().st_uid):
                with self.assertRaisesRegex(ValueError, "S10_TRAFFIC_QUALITY_STATE_RED"):
                    MODULE._traffic_quality(path)

    def test_changeset_preserves_original_baseline_and_new_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changeset.json"
            path.write_text(json.dumps({
                "version": "S10_2F",
                "started_at": "2026-09-19T08:00:00.000000Z",
                "acquisition_baseline_start": "2026-09-18T00:41:06.710027Z",
                "measurement_semantics": "HUMAN_LIKE_BROWSER_NAVIGATION_V1",
            }), encoding="ascii")
            os.chmod(path, 0o600)
            with (
                patch.object(MODULE.os, "geteuid", return_value=path.stat().st_uid),
                patch.object(MODULE, "datetime", wraps=datetime) as mocked_datetime,
            ):
                mocked_datetime.now.return_value = datetime(2026, 9, 19, 9, 0, tzinfo=timezone.utc)
                report = MODULE._changeset(path)
            self.assertEqual(report["version"], "S10_2F")
            self.assertEqual(report["acquisition_baseline_start"], "2026-09-18T00:41:06.710027Z")

    def test_manifest_and_controller_keep_every_product_gate_closed(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["root_cause"]["classification"], "MULTIPLE_CAUSES")
        self.assertFalse(manifest["measurement"]["historical_baseline_rewritten"])
        self.assertEqual(manifest["source"]["acquisition_baseline_start"], "2026-09-18T00:41:06.710027Z")
        self.assertTrue(all(value is False for key, value in manifest["boundaries"].items() if key != "human_acceptance"))
        self.assertEqual(manifest["boundaries"]["human_acceptance"], "DEFERRED")
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("git -C \"$APPLICATION_ROOT\" bundle verify", controller)
        self.assertIn("S10_2F_DEPLOYMENT_ROLLED_BACK", controller)
        self.assertIn("require_acquisition_state", controller)
        self.assertNotIn("reset --hard", controller)
        self.assertNotIn("cron", controller.casefold())


if __name__ == "__main__":
    unittest.main()
