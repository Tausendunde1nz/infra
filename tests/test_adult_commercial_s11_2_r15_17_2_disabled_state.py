from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_r15_17_2_simulator as simulator


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
FREEZE = ROOT / "scripts/tu1nz_adult_public_s11_2_freeze.py"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_r15_17_2_simulator.py"
SSOT = ROOT / "docs/COMMERCIAL_S11_2_R15_17_2_DISABLED_STATE_CONTRACT.md"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"


class R15172DisabledStateTests(unittest.TestCase):
    def test_prebootstrap_legacy_schema_is_clean_only_when_code_is_off(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        prelude_source = source[: source.index('\ncase "${1:-}" in')]
        for enabled, live_start, expected in (
            ("false", "NULL", "CLEAN_NOT_STARTED"),
            ("true", "NULL", "INVALID_DISABLED_STATE"),
            ("false", "SET", "INVALID_DISABLED_STATE"),
        ):
            with self.subTest(enabled=enabled, live_start=live_start):
                with tempfile.TemporaryDirectory() as directory:
                    prelude = Path(directory) / "controller-prelude.sh"
                    prelude.write_text(prelude_source, encoding="utf-8")
                    completed = subprocess.run(
                        ["bash", "-s", "--", str(prelude), enabled, live_start],
                        input=(
                            'set -Eeuo pipefail\nsource "$1"\n'
                            'fixture_enabled="$2"\nfixture_live="$3"\n'
                            'database_scalar() {\n'
                            '  if [[ "$1" == *"information_schema.columns"* ]]; then printf "0\\n"; '
                            '  else printf "%s|%s\\n" "$fixture_enabled" "$fixture_live"; fi\n'
                            '}\n'
                            'disabled_state_classification\n'
                        ),
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), expected)

    def test_partial_bootstrap_schema_is_invalid_without_postmigration_query(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        classifier = source[
            source.index("disabled_state_classification() {"):
            source.index("require_code_off_disabled_state() {")
        ]
        for column in (
            "release_state",
            "canary_release_id",
            "canary_evidence_start",
            "canary_live_start",
            "canary_horizon_at",
            "full_live_start",
            "promotion_state",
        ):
            self.assertIn(column, classifier)
        self.assertIn("    7) ;;", classifier)
        prelude_source = source[: source.index('\ncase "${1:-}" in')]
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            prelude.write_text(prelude_source, encoding="utf-8")
            completed = subprocess.run(
                ["bash", "-s", "--", str(prelude)],
                input=(
                    'set -Eeuo pipefail\nsource "$1"\n'
                    'database_scalar() {\n'
                    '  [[ "$1" == *"information_schema.columns"* ]] || return 99\n'
                    '  printf "3\\n"\n'
                    '}\n'
                    'test "$(disabled_state_classification)" = INVALID_DISABLED_STATE\n'
                ),
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_state_classifier_matrix_a_through_j(self):
        report = simulator.simulate()
        self.assertEqual(
            report["fixture_matrix"],
            {
                "A": "CLEAN_NOT_STARTED",
                "B": "TERMINAL_REARMABLE",
                "C": "TERMINAL_REARMABLE",
                "D": "INVALID_DISABLED_STATE",
                "E": "INVALID_DISABLED_STATE",
                "F": "INVALID_DISABLED_STATE",
                "G": "INVALID_DISABLED_STATE",
                "H": "INVALID_DISABLED_STATE",
                "I": "INVALID_DISABLED_STATE",
                "J": "PRE_CANARY_ARMED",
            },
        )

    def test_repeated_deployment_contract_is_green(self):
        report = simulator.simulate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["second_deploy_preflight"], "GREEN")
        self.assertEqual(report["second_deploy_install"], "GREEN")
        self.assertEqual(report["second_deploy_synthetic"], "GREEN")
        self.assertEqual(report["second_deploy_fallback"], "GREEN")
        self.assertEqual(report["canonical_rearm_history_delta"], 1)
        self.assertEqual(report["new_evidence_epoch"], "PRE_CANARY_ARMED")
        self.assertEqual(report["second_deploy_canary_starts"], 1)
        self.assertEqual(report["automatic_retries"], 0)
        self.assertEqual(report["technical_valid_samples"], 5)
        self.assertEqual(report["technical_missing_samples"], 0)
        self.assertFalse(report["evidence_deleted"])
        self.assertTrue(report["systemd_handoff_green"])
        self.assertTrue(report["standalone_verify_green"])

    def test_controller_uses_one_classifier_at_every_disabled_boundary(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        for name in (
            "require_source_state() {",
            "apply_migration() {",
            "rearm_canary() {",
            "restore_source() {",
            "install_s11_disabled() {",
            "run_remaining_phases() {",
        ):
            with self.subTest(name=name):
                self.assertIn("disabled_state_classification", source[source.index(name):])
        self.assertIn("CLEAN_NOT_STARTED|TERMINAL_REARMABLE", source)
        self.assertIn("PRE_CANARY_ARMED", source)
        self.assertIn("INVALID_DISABLED_STATE", source)
        self.assertIn("S11_2_CANARY_START_DISABLED_STATE_RED", source)

    def test_install_and_fallback_preserve_terminal_epoch_until_rearm(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        install = source[source.index("install_s11_disabled() {"):source.index("run_remaining_phases() {")]
        phases = source[source.index("run_remaining_phases() {"):source.index("finalize_deployment_evidence() {")]
        self.assertIn('disabled_state_after" = "$disabled_state_before', install)
        self.assertIn("S11_2_INSTALL_DISABLED_STATE_MUTATED_RED", install)
        self.assertIn("S11_2_FEATURE_OFF_FALLBACK_STATE_MUTATED_RED", phases)
        self.assertLess(phases.index("FALLBACK_GREEN)"), phases.index("CANARY_REARMED)"))
        self.assertLess(phases.index("CANARY_REARMED)"), phases.index("EVIDENCE_EPOCH_SET)"))
        self.assertLess(phases.index("EVIDENCE_EPOCH_SET)"), phases.index("CANARY_ACTIVE)"))

    def test_rearm_is_canonical_archival_and_never_direct_cleanup(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        rearm = source[source.index("rearm_canary() {"):source.index("run_synthetic_journeys() {")]
        self.assertIn("database_rearm", rearm)
        self.assertIn("history_before", rearm)
        self.assertIn("history_after", rearm)
        self.assertIn("history_delta", rearm)
        self.assertIn("CLEAN_NOT_STARTED", rearm)
        self.assertNotIn("UPDATE commercial_s11_runtime_control", rearm)
        self.assertNotIn("DELETE FROM commercial_s11_canary_epoch_history", source)

    def test_rearm_resume_proves_the_committed_archive_from_persisted_intent(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        prelude_source = source[: source.index('\ncase "${1:-}" in')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prelude = root / "controller-prelude.sh"
            backup = root / "backup"
            backup.mkdir()
            prelude.write_text(prelude_source, encoding="utf-8")
            completed = subprocess.run(
                ["bash", "-s", "--", str(prelude), str(backup)],
                input=(
                    'set -Eeuo pipefail\nsource "$1"\nS11_2_BACKUP_PATH="$2"\n'
                    'fixture_state=TERMINAL_REARMABLE\nfixture_history=7\n'
                    'disabled_state_classification() { printf "%s\\n" "$fixture_state"; }\n'
                    'database_admin_history_count() { printf "%s\\n" "$fixture_history"; }\n'
                    'database_rearm() { fixture_state=CLEAN_NOT_STARTED; fixture_history=8; }\n'
                    'complete_phase() { :; }\n'
                    'write_rearm_intent "$fixture_history"\n'
                    'database_rearm S11_2_R15_8_TERMINAL_EPOCH_REARMED\n'
                    'rearm_canary\n'
                    'python3 - "$S11_2_BACKUP_PATH/canary-rearm.json" <<\'PY\'\n'
                    'import json, sys\n'
                    'payload=json.load(open(sys.argv[1], encoding="utf-8"))\n'
                    'assert payload["before"] == "TERMINAL_REARMABLE"\n'
                    'assert payload["after"] == "CLEAN_NOT_STARTED"\n'
                    'assert payload["history_delta"] == 1\n'
                    'PY\n'
                ),
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rearm_resume_fails_closed_when_persisted_history_delta_is_not_one(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        prelude_source = source[: source.index('\ncase "${1:-}" in')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prelude = root / "controller-prelude.sh"
            backup = root / "backup"
            backup.mkdir()
            prelude.write_text(prelude_source, encoding="utf-8")
            completed = subprocess.run(
                ["bash", "-s", "--", str(prelude), str(backup)],
                input=(
                    'set -Eeuo pipefail\nsource "$1"\nS11_2_BACKUP_PATH="$2"\n'
                    'disabled_state_classification() { printf "CLEAN_NOT_STARTED\\n"; }\n'
                    'database_admin_history_count() { printf "7\\n"; }\n'
                    'complete_phase() { :; }\n'
                    'write_rearm_intent 7\n'
                    'rearm_canary\n'
                ),
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("S11_2_TERMINAL_EPOCH_RESUME_ARCHIVE_RED", completed.stderr)

    def test_runtime_evidence_contains_only_aggregate_classifications(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = source[source.index("write_disabled_state_evidence() {"):source.index("require_acquisition_state() {")]
        for key in ("phase", "before", "after", "history_delta", "safe_code"):
            self.assertIn(key, helper)
        for forbidden in ("canary_release_id", "canary_evidence_start", "canary_live_start"):
            self.assertNotIn(forbidden, helper)

    def test_previous_systemd_handoff_simulator_remains_green(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/tu1nz_adult_public_s11_2_r15_17_1_simulator.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(json.loads(completed.stdout)["ok"])

    def test_entrypoint_and_contract_files_are_bound(self):
        completed = subprocess.run(
            [sys.executable, str(SIMULATOR)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            json.loads(completed.stdout)["safe_code"],
            "S11_2_R15_17_2_SOURCE_ONLY_SIMULATOR_GREEN",
        )
        self.assertTrue(SSOT.is_file())
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["control_release"]["freeze_tag"],
            "s11-2-r15-18-2-activation-relative-timer-freeze-r1",
        )
        self.assertEqual(
            manifest["r15_17_2_disabled_state_contract"]["classification"],
            "DISABLED_STATE_CONTRACT_MISMATCH",
        )
        bindings = manifest["r15_17_2_disabled_state_contract"]["artifact_bindings"]
        for key in (
            "controller_sha256",
            "freeze_helper_sha256",
            "simulator_sha256",
            "focused_suite_sha256",
            "ssot_sha256",
        ):
            with self.subTest(key=key):
                self.assertRegex(bindings[key], r"^[0-9a-f]{64}$")
        self.assertEqual(
            manifest["r15_17_2_disabled_state_contract"]["replacement_freeze"],
            "s11-2-r15-17-2-disabled-state-contract-freeze-r1",
        )


if __name__ == "__main__":
    unittest.main()
