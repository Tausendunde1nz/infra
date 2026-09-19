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
        self.assertIn('git_chatops "$APPLICATION_ROOT" bundle verify /dev/stdin', controller)
        self.assertIn('< "$backup_path/application.bundle"', controller)
        self.assertIn('git_chatops "$CONTROL_ROOT" bundle verify /dev/stdin', controller)
        self.assertIn('< "$backup_path/control.bundle"', controller)
        self.assertNotIn(
            'bundle verify "$backup_path/application.bundle"',
            controller,
        )
        self.assertIn("S10_2F_DEPLOYMENT_ROLLED_BACK", controller)
        self.assertIn('return 2', controller)
        self.assertNotIn('exit 2', controller)
        self.assertIn("require_acquisition_state", controller)
        self.assertIn('SOURCE_APPLICATION_COMMIT="312db84d5db6d76c9d6bb448459c9404b1dfcbe4"', controller)
        self.assertIn('SOURCE_APPLICATION_TREE="ac4f8bca1fd796626742a8ef6c6afcdda482fc68"', controller)
        self.assertIn('SOURCE_CONTROL_COMMIT="66e5b18c9d3bfc1082b1e2d0188cf14418f586a3"', controller)
        self.assertIn('SOURCE_CONTROL_TREE="04eec54c23ba15e5787712bac434ae2f5bf4ae36"', controller)
        self.assertIn('TARGET_APPLICATION_COMMIT="1d0dbb88603be49ea172178b77d86451036035a1"', controller)
        self.assertIn('TARGET_APPLICATION_TREE="49f82e23ba16f06ddc27ef13e0b3f3643bc9da3e"', controller)
        self.assertIn('TARGET_CONTROL_ARTIFACT_COMMIT="1d5e0d84451d35cb4148d0b52209002048db7e88"', controller)
        self.assertIn('TARGET_CONTROL_ARTIFACT_TREE="3e6ab73b929cd19a796cc8528cce06809e801d4c"', controller)
        self.assertIn('TARGET_CONTROL_ARTIFACT_TAG="s10-2f-control-artifacts-r1"', controller)
        self.assertIn('FINAL_CONTROL_TAG="s10-2f-conversion-recovery-freeze-r3"', controller)
        self.assertRegex(
            controller,
            r'FINAL_CONTROL_RELEASE_FINGERPRINT="(?:[0-9a-f]{64}|PENDING)"',
        )
        self.assertIn('runuser -u chatops -- git -C "$repository"', controller)
        self.assertEqual(controller.count("git -C"), 1)
        self.assertNotIn(' DATABASE_DSN="$DATABASE_DSN"', controller)
        self.assertNotIn(' ACQUISITION_BASELINE="$ACQUISITION_BASELINE"', controller)
        self.assertIn('merge-base --is-ancestor "$target_application" origin/main', controller)
        self.assertNotIn('rev-parse origin/main)" = "$target_application"', controller)
        self.assertNotIn('rev-parse origin/control-main)" = "$target_control"', controller)
        self.assertIn(
            'merge-base --is-ancestor "$target_control" origin/control-main',
            controller,
        )
        self.assertIn('refs/tags/${TARGET_CONTROL_ARTIFACT_TAG}^{commit}', controller)
        self.assertIn('grep -Fqx "control_commit=${TARGET_CONTROL_ARTIFACT_COMMIT}"', controller)
        self.assertIn('grep -Fqx "control_tree=${TARGET_CONTROL_ARTIFACT_TREE}"', controller)
        self.assertIn('show "${TARGET_CONTROL_ARTIFACT_COMMIT}:${path}"', controller)
        self.assertIn('switch --detach "$target_control"', controller)
        self.assertIn('control_release_fingerprint "$target_control"', controller)
        self.assertIn('S10_2F_FINAL_CONTROL_FINGERPRINT_RED', controller)
        self.assertIn('S10_2F_FINAL_CONTROL_CONSTANT_RED', controller)
        self.assertIn('repair_backup_bundle_modes()', controller)
        self.assertIn('S10_2F_BACKUP_MODE_REPAIR_GREEN', controller)
        self.assertIn(
            'chown root:chatops "$backup_path/application.bundle" "$backup_path/control.bundle"',
            controller,
        )
        self.assertGreaterEqual(controller.count('verify_backup_bundles "$backup_path"'), 3)
        self.assertIn(
            '"readonly FINAL_CONTROL_RELEASE_FINGERPRINT=\\\"${FINAL_CONTROL_RELEASE_FINGERPRINT}\\\""',
            controller,
        )
        verify_target = controller.index("verify_target()")
        deploy = controller.index("deploy()")
        self.assertIn(
            'require_target_release "$target_application" "$target_control"',
            controller[verify_target:deploy],
        )
        self.assertEqual(
            manifest["control_release"]["artifact_tag"],
            "s10-2f-control-artifacts-r1",
        )
        self.assertEqual(manifest["control_release"]["artifact_commit"], "1d5e0d84451d35cb4148d0b52209002048db7e88")
        self.assertEqual(manifest["control_release"]["artifact_tree"], "3e6ab73b929cd19a796cc8528cce06809e801d4c")
        self.assertIn('grep -Fqx "application_commit=${source_application}"', controller)
        self.assertIn('grep -Fqx "control_commit=${source_control}"', controller)
        self.assertIn('https://wantmeseen.com/health', controller)
        self.assertIn('https://wantmeseen.de/', controller)
        mutated = controller.index("mutated=1")
        quality = controller.index("\n  install_quality_state\n", mutated)
        restart = controller.index('systemctl restart "$WMS_SERVICE"', mutated)
        self.assertLess(quality, restart)
        self.assertLess(restart, controller.index("wait_target_runtime", restart))
        self.assertLess(controller.index("wait_target_runtime", restart), controller.index("install_changeset_state", restart))
        self.assertNotIn("reset --hard", controller)
        self.assertNotIn("cron", controller.casefold())


if __name__ == "__main__":
    unittest.main()
