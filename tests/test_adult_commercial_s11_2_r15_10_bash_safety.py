from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_orchestration as orchestration


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s11-2-canary-bootstrap.json"
ORCHESTRATION = ROOT / "scripts/tu1nz_adult_public_s11_2_orchestration.py"
SSOT = ROOT / "docs/COMMERCIAL_S11_2_R15_10_BASH_SAFETY.md"


def controller_prelude() -> str:
    source = CONTROLLER.read_text(encoding="utf-8")
    return source[: source.index('\ncase "${1:-}" in')]


def same_local_dependencies(source: str) -> list[tuple[int, str, str]]:
    logical_lines: list[tuple[int, str]] = []
    pending = ""
    pending_line = 0
    for number, raw in enumerate(source.splitlines(), 1):
        if not pending:
            pending_line = number
        pending += raw.rstrip("\\").strip() + " "
        if raw.rstrip().endswith("\\"):
            continue
        logical_lines.append((pending_line, pending.strip()))
        pending = ""

    findings: list[tuple[int, str, str]] = []
    assignment = re.compile(
        r"(?<!\S)([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s]+)"
    )
    for number, line in logical_lines:
        match = re.match(r"^local\s+(.+)$", line)
        if not match:
            continue
        prior: list[str] = []
        for variable, value in assignment.findall(match.group(1)):
            for dependency in prior:
                reference = re.compile(
                    rf"\$(?:{re.escape(dependency)}\b|"
                    rf"\{{{re.escape(dependency)}(?:\}}|[^A-Za-z0-9_]))"
                )
                if reference.search(value):
                    findings.append((number, dependency, variable))
            prior.append(variable)
    return findings


def run_bash(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", *arguments],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )


class R1510BashSafetyTests(unittest.TestCase):
    def test_original_same_local_fixture_reproduces_nounset_and_skips_err_trap(self):
        fixture = r'''
set -Eeuo pipefail
trap 'printf trap-ran > "$1/trap"' ERR
probe() {
  local destination="$1/result.json" structured="${destination}.ndjson"
  printf '%s\n' "$structured"
}
probe "$1"
'''
        with tempfile.TemporaryDirectory() as directory:
            result = run_bash(fixture, "-s", "--", directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unbound variable", result.stderr)
            self.assertFalse((Path(directory) / "trap").exists())

    def test_complete_controller_has_no_same_local_dependency(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(same_local_dependencies(source), [])
        old_patterns = """
local destination="$1" gate_file="${destination}.gate"
local backup_path="$1" profile="$backup_path/technical-profile.json"
local destination="$1" structured="${destination}.ndjson" cursor start_green=true
"""
        self.assertEqual(len(same_local_dependencies(old_patterns)), 3)

    def test_pre_canary_health_expands_paths_under_nounset(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            destination = Path(directory) / "preflight.json"
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
journalctl() {
  if [[ " $* " == *" --show-cursor "* ]]; then
    printf '%s\n' '-- cursor: s=r15-10'
  else
    printf '%s\n' '{"contract_version":"fixture"}'
  fi
}
systemctl() { return 0; }
set +e
pre_canary_health "$2"
status=$?
set -e
[ "$status" -eq 2 ]
[ -s "${2}.ndjson" ]
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(destination))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("unbound variable", result.stderr)

    def test_failure_before_mutation_never_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            backup = Path(directory) / "backup"
            backup.mkdir()
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
acquire_lock() { return 0; }
restore_source() { printf restore >> "$S11_2_BACKUP_PATH/restore.log"; }
require_source_state() { return 0; }
S11_2_ROLLBACK_ARMED=true
S11_2_BACKUP_PATH="$2"
S11_2_TARGET_CONTROL=target
deployment_error 23
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(backup))
            self.assertEqual(result.returncode, 23)
            self.assertIn("S11_2_DEPLOYMENT_STOPPED_BEFORE_MUTATION", result.stderr)
            self.assertFalse((backup / "restore.log").exists())
            self.assertFalse((backup / "ROLLBACK_STARTED").exists())

    def test_nounset_in_pre_mutation_check_is_explicitly_propagated(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            backup = Path(directory) / "backup"
            backup.mkdir()
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
fetch_and_require_target() { printf '%s\n' "${R15_10_PRE_UNBOUND}"; }
run_pre_mutation_target_check target S11_2_FIXTURE_PRECHECK_RED
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(backup))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("unbound variable", result.stderr)
            self.assertIn("S11_2_FIXTURE_PRECHECK_RED", result.stderr)
            self.assertFalse((backup / "MUTATION_STARTED").exists())
            self.assertFalse((backup / "ROLLBACK_STARTED").exists())

    def test_nounset_after_mutation_triggers_exactly_one_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            backup = Path(directory) / "backup"
            backup.mkdir()
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
acquire_lock() { return 0; }
reacquire_inherited_lock() { return 0; }
restore_source() { printf 'restore\n' >> "$S11_2_BACKUP_PATH/restore.log"; }
require_source_state() { return 0; }
explode() { printf '%s\n' "${R15_10_UNBOUND}"; }
S11_2_ROLLBACK_ARMED=true
S11_2_BACKUP_PATH="$2"
S11_2_TARGET_CONTROL=target
run_guarded_deployment explode
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(backup))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unbound variable", result.stderr)
            self.assertIn("S11_2_DEPLOYMENT_ROLLED_BACK", result.stderr)
            self.assertEqual((backup / "restore.log").read_text().splitlines(), ["restore"])
            self.assertTrue((backup / "MUTATION_STARTED").exists())
            self.assertTrue((backup / "ROLLBACK_STARTED").exists())
            self.assertTrue((backup / "ROLLBACK_COMPLETED").exists())

    def test_rollback_operation_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            backup = Path(directory) / "backup"
            backup.mkdir()
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
restore_source() { printf 'restore\n' >> "$1/restore.log"; }
require_source_state() { return 0; }
run_rollback_strict "$2" target
[ "$S11_2_ROLLBACK_EXIT_STATUS" -eq 0 ]
run_rollback_strict "$2" target
[ "$S11_2_ROLLBACK_EXIT_STATUS" -eq 0 ]
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(backup))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((backup / "restore.log").read_text().splitlines(), ["restore"])

    def test_completed_rollback_still_requires_verified_source_state(self):
        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            backup = Path(directory) / "backup"
            backup.mkdir()
            (backup / "ROLLBACK_COMPLETED").touch()
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
restore_source() { return 0; }
require_source_state() { return 1; }
run_rollback_strict "$2" target
[ "$S11_2_ROLLBACK_EXIT_STATUS" -eq 1 ]
'''
            result = run_bash(fixture, "-s", "--", str(prelude), str(backup))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_guard_contract_does_not_depend_on_err_trap(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        precheck = source[
            source.index("run_pre_mutation_target_check() {"):
            source.index("run_guarded_deployment() {")
        ]
        guard = source[source.index("run_guarded_deployment() {"): source.index("deploy() {")]
        deploy = source[source.index("deploy() {"): source.index("resume() {")]
        resume = source[source.index("resume() {"): source.index("deployment_error() {")]
        self.assertIn("set -Eeuo pipefail", guard)
        self.assertIn("deployment_error \"$exit_status\"", guard)
        self.assertIn("MUTATION_STARTED", guard)
        self.assertIn("run_rollback_strict", source)
        self.assertNotIn("acquire_lock", guard)
        self.assertNotIn("trap 'deployment_error' ERR", source)
        self.assertIn("set -Eeuo pipefail", precheck)
        self.assertIn("fetch_and_require_target", precheck)
        self.assertLess(deploy.index("run_pre_mutation_target_check"), deploy.index("S11_2_ROLLBACK_ARMED=true"))
        self.assertLess(resume.index("run_pre_mutation_target_check"), resume.index("S11_2_ROLLBACK_ARMED=true"))
        self.assertNotIn("release_lock", deploy[: deploy.index("run_guarded_deployment")])
        self.assertNotIn("release_lock", resume[: resume.index("run_guarded_deployment")])
        self.assertIn("release_lock", deploy[deploy.index("run_guarded_deployment"):])
        self.assertIn("release_lock", resume[resume.index("run_guarded_deployment"):])
        error = source[source.index("deployment_error() {"): source.index("observe() {")]
        self.assertIn("reacquire_inherited_lock", error)

    @unittest.skipUnless(shutil.which("flock"), "flock unavailable")
    def test_systemd_handoff_reuses_inherited_lock_descriptor(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        phases = source[
            source.index("run_remaining_phases() {"):
            source.index("finalize_deployment_evidence() {")
        ]
        handoff_start = phases.index("SYSTEMD_HANDOFF)")
        handoff = phases[
            handoff_start:
            phases.index("COMPLETE)", handoff_start)
        ]
        self.assertIn("release_inherited_lock", handoff)
        self.assertIn("reacquire_inherited_lock", handoff)
        self.assertNotIn("release_lock", handoff)
        self.assertNotIn("acquire_lock", handoff)

        with tempfile.TemporaryDirectory() as directory:
            prelude = Path(directory) / "controller-prelude.sh"
            lock_path = Path(directory) / "controller.lock"
            prelude.write_text(controller_prelude(), encoding="utf-8")
            fixture = r'''
set -Eeuo pipefail
source "$1"
exec 9> "$2"
flock -n 9
(
  release_inherited_lock
  reacquire_inherited_lock
)
set +e
flock -n "$2" -c true
contender_status=$?
set -e
[ "$contender_status" -ne 0 ]
'''
            result = run_bash(
                fixture, "-s", "--", str(prelude), str(lock_path)
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_probe_matrix_includes_zero_of_five(self):
        expected = {
            "empty-0-of-5": 5,
            "happy-4-of-5": 1,
            "zero-missing-5-of-5": 0,
            "two-missing-3-of-5": 2,
        }
        for case, probes in expected.items():
            with self.subTest(case=case):
                report = orchestration.simulate(case)
                self.assertFalse(report["stopped"])
                self.assertEqual(report["technical_probes"], probes)
                self.assertEqual(report["technical_probe_hard_cap"], probes)
                self.assertEqual(report["canary_starts"], 1)

    def test_failure_simulators_never_retry_or_start_canary(self):
        expected = {
            "failure-before-mutation": (0, 0, False),
            "pre-canary-health-red-after-mutation": (1, 1, True),
            "nounset-after-mutation": (1, 1, True),
            "rollback-idempotent": (2, 1, True),
        }
        for case, (requests, restores, completed) in expected.items():
            with self.subTest(case=case):
                report = orchestration.simulate(case)
                self.assertTrue(report["stopped"])
                self.assertEqual(report["technical_probes"], 0)
                self.assertEqual(report["canary_starts"], 0)
                self.assertEqual(report["rollback_requests"], requests)
                self.assertEqual(report["restore_executions"], restores)
                self.assertEqual(report["rollback_completed"], completed)
                self.assertFalse(report["automatic_retry"])

    def test_r15_8_phase_and_health_contracts_remain_unchanged(self):
        self.assertEqual(orchestration.CONTRACT_VERSION, "S11_2_R15_8_ORCHESTRATION_V1")
        self.assertEqual(len(orchestration.PHASES), 11)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["r15_8_orchestration"]["health_contract_version"],
            "S10_1_HEALTH_CHILD_V1",
        )
        self.assertTrue(manifest["r15_8_orchestration"]["r15_4_access_contract_unchanged"])

    def test_manifest_binds_current_r15_10_artifacts(self):
        bindings = json.loads(MANIFEST.read_text(encoding="utf-8"))["r15_10_artifact_bindings"]
        expected = {
            "controller_sha256": CONTROLLER,
            "orchestration_sha256": ORCHESTRATION,
            "focused_suite_sha256": Path(__file__),
            "ssot_sha256": SSOT,
        }
        for key, path in expected.items():
            with self.subTest(binding=key):
                self.assertEqual(bindings[key], hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
