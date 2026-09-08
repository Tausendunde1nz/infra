from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tu1nz_adult_public_s10_2d_r7_aggregate_recovery.py"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-r7-aggregate-recovery.json"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2D_R7_AGGREGATE_RECOVERY.md"
DIAGNOSIS = ROOT / "analysis/COMMERCIAL_S10_2D_R7_AGGREGATE_ROLLBACK_GAP_2026-09-08.diagnose"

SPEC = importlib.util.spec_from_file_location("s10_2d_r7_aggregate_recovery", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class CommercialS102DR7AggregateRecoveryTests(unittest.TestCase):
    def test_partition_preserves_every_entry_and_count(self) -> None:
        material = (
            b'{"2026-09-07|LANDING_VIEW|direct|none":4,'
            b'"2026-09-07|TELEGRAM_CTA|site|launch":3,'
            b'"2026-09-07|COMMUNITY_CTA|bot|organic":2}'
        )
        payload = RECOVERY.parse_aggregate(material)
        source, forward = RECOVERY.partition_aggregate(payload)
        self.assertEqual(len(payload), len(source) + len(forward))
        self.assertEqual(sum(payload.values()), sum(source.values()) + sum(forward.values()))
        self.assertEqual({key.split("|")[1] for key in source}, {"LANDING_VIEW", "TELEGRAM_CTA"})
        self.assertEqual({key.split("|")[1] for key in forward}, {"COMMUNITY_CTA"})
        self.assertEqual(RECOVERY.parse_aggregate(RECOVERY.canonical_json(source)), source)
        self.assertEqual(RECOVERY.parse_aggregate(RECOVERY.canonical_json(forward)), forward)

    def test_parser_rejects_unknown_events_duplicates_and_non_integer_counts(self) -> None:
        invalid = (
            b'{"2026-09-07|UNKNOWN|direct|none":1}',
            b'{"2026-09-07|LANDING_VIEW|direct|none":1,'
            b'"2026-09-07|LANDING_VIEW|direct|none":2}',
            b'{"2026-09-07|LANDING_VIEW|direct|none":true}',
            b'{"2026-09-07|LANDING_VIEW|direct|none":-1}',
        )
        for material in invalid:
            with self.subTest(material=material):
                with self.assertRaises(RECOVERY.RecoveryError):
                    RECOVERY.parse_aggregate(material)

    def test_partition_requires_forward_only_state(self) -> None:
        payload = RECOVERY.parse_aggregate(b'{"2026-09-07|LANDING_VIEW|direct|none":1}')
        with self.assertRaisesRegex(RECOVERY.RecoveryError, "FORWARD_AGGREGATE_NOT_PRESENT"):
            RECOVERY.partition_aggregate(payload)

    def test_atomic_replace_preserves_requested_metadata_and_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aggregate.json"
            path.write_bytes(b'{"before":1}')
            path.chmod(0o600)
            RECOVERY._atomic_replace(
                path,
                b'{"after":2}',
                uid=os.getuid(),
                gid=os.getgid(),
                mode=0o600,
            )
            self.assertEqual(path.read_bytes(), b'{"after":2}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_private_directory_normalizes_only_inherited_setgid_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recovery-prefix"
            path.mkdir(mode=0o700)
            path.chmod(0o2700)
            RECOVERY._normalize_private_directory(
                path,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertEqual(path.stat().st_mode & 0o7777, 0o700)

            path.chmod(0o750)
            with self.assertRaisesRegex(RECOVERY.RecoveryError, "RECOVERY_PREFIX_UNSAFE"):
                RECOVERY._normalize_private_directory(
                    path,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )

    def test_fail_closed_quiesce_stops_timers_then_workers_then_public_services(self) -> None:
        calls: list[tuple[str, ...]] = []

        def record(*arguments: str, **_keywords: object) -> None:
            calls.append(arguments)

        with mock.patch.object(RECOVERY, "_systemctl", side_effect=record), mock.patch.object(
            RECOVERY, "_unit_value", return_value="inactive"
        ):
            RECOVERY._quiesce_automation()

        stopped = [arguments[1] for arguments in calls]
        self.assertEqual(
            stopped,
            list(RECOVERY.TIMERS) + list(RECOVERY.RECOVERY_WORKERS) + list(RECOVERY.SERVICES),
        )

    def test_reset_failed_is_only_called_for_failed_units(self) -> None:
        with mock.patch.object(RECOVERY, "_unit_value", return_value="inactive"), mock.patch.object(
            RECOVERY, "_systemctl"
        ) as systemctl:
            RECOVERY._reset_failed_if_needed("inactive.service", safe_code="RESET_RED")
            systemctl.assert_not_called()

        with mock.patch.object(RECOVERY, "_unit_value", return_value="failed"), mock.patch.object(
            RECOVERY, "_systemctl"
        ) as systemctl:
            RECOVERY._reset_failed_if_needed("failed.service", safe_code="RESET_RED")
            systemctl.assert_called_once_with("reset-failed", "failed.service", safe_code="RESET_RED")

    def test_health_start_settle_is_bounded_and_stops_on_success(self) -> None:
        attempts = [
            subprocess.CompletedProcess([], 1, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with mock.patch.object(RECOVERY, "_run", side_effect=attempts) as run, mock.patch.object(
            RECOVERY, "_reset_failed_if_needed"
        ) as reset, mock.patch.object(RECOVERY.time, "sleep") as sleep:
            RECOVERY._start_health_with_settle("health.service")

        self.assertEqual(run.call_count, 3)
        self.assertEqual(reset.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 15])
        self.assertEqual(sum(RECOVERY.HEALTH_START_SETTLE_DELAYS_SECONDS), 50)

    def test_manifest_and_control_keep_recovery_narrow_and_fail_closed(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["decision"], "P0_SOURCE_PUBLIC_RECOVERY_GREEN")
        self.assertEqual(manifest["source_application"]["commit"], RECOVERY.SOURCE_SHA)
        self.assertEqual(manifest["source_application"]["tree"], RECOVERY.SOURCE_TREE)
        self.assertEqual(manifest["data_contract"]["source_events"], sorted(RECOVERY.SOURCE_EVENTS))
        self.assertEqual(manifest["data_contract"]["forward_events"], sorted(RECOVERY.FORWARD_EVENTS))
        self.assertTrue(manifest["backup"]["original_bytes_preserved"])
        self.assertTrue(manifest["backup"]["forward_entries_preserved"])
        self.assertTrue(manifest["backup"]["parent_directories_fsynced_before_replacement"])
        self.assertTrue(manifest["backup"]["timers_workers_quiesced_before_replacement"])
        self.assertTrue(manifest["backup"]["post_backup_race_check"])
        self.assertTrue(manifest["backup"]["inherited_setgid_normalized_to_0700"])
        self.assertTrue(manifest["runtime"]["reset_failed_only_when_active_state_failed"])
        self.assertEqual(manifest["runtime"]["health_start_settle_delays_seconds"], [0, 5, 15, 30])
        self.assertEqual(manifest["execution"]["control_commit"], "75afbf4586461bcce72b7d123910cfdf8e0f641b")
        self.assertEqual(manifest["execution"]["control_tree"], "67c55421b6e67f0ac2d890018a0ee4bdeb51c53a")
        self.assertEqual(manifest["execution"]["control_post_merge_ci"], 34247579828)
        self.assertEqual(manifest["execution"]["source_entries"], 37)
        self.assertEqual(manifest["execution"]["forward_entries"], 1)
        self.assertTrue(all(attempt["original_restored"] for attempt in manifest["execution"]["failed_closed_attempts"]))
        self.assertFalse(manifest["execution"]["database_mutation"])
        self.assertFalse(manifest["scope"]["database_mutation"])
        self.assertFalse(manifest["scope"]["application_change"])
        self.assertFalse(manifest["scope"]["second_cutover"])
        self.assertFalse(manifest["product_boundary"]["adult_media"])
        self.assertFalse(manifest["product_boundary"]["real_avs"])
        self.assertFalse(manifest["product_boundary"]["payments"])
        self.assertFalse(manifest["product_boundary"]["external_publishing"])
        control = CONTROL.read_text(encoding="utf-8")
        diagnosis = DIAGNOSIS.read_text(encoding="utf-8")
        self.assertIn("COMMUNITY_CTA", control)
        self.assertIn("S9_AGGREGATE_STATE_INVALID", diagnosis)
        self.assertIn("502", diagnosis)
        self.assertNotIn("second cutover", control.lower())

    def test_script_is_syntax_valid_and_avoids_destructive_shortcuts(self) -> None:
        subprocess.run(["python3", "-m", "py_compile", str(SCRIPT)], check=True)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("git reset", source)
        self.assertNotIn("git clean", source)
        self.assertNotIn("psql", source)
        self.assertNotIn("docker", source.lower())
        self.assertIn("landing-aggregates.original.json", source)
        self.assertIn("landing-aggregates.forward-only.json", source)
        self.assertIn("os.replace", source)
        self.assertIn("os.fsync", source)
        self.assertIn("AGGREGATE_CHANGED_AFTER_BACKUP", source)
        self.assertIn("FAIL_CLOSED_TIMER_STOP_RED", source)
        self.assertLess(source.index("_fsync_directory(recovery_dir)"), source.index("replacement_attempted = False"))


if __name__ == "__main__":
    unittest.main()
