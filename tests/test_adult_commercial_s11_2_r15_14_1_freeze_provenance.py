import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import tu1nz_adult_public_s11_2_freeze as freeze


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
SIMULATOR = ROOT / "scripts/tu1nz_adult_public_s11_2_r15_15_simulator.py"
OLD_ANNOTATION = (
    ROOT / "tests/fixtures/s11-2-r15-14-1/old-freeze-r1.annotation"
)


def expected_fixture() -> dict[str, str]:
    values = {
        "application_commit": freeze.APPLICATION_COMMIT,
        "application_tree": freeze.APPLICATION_TREE,
        "control_commit": "1" * 40,
        "control_tree": "2" * 40,
    }
    values.update({key: hashlib.sha256(key.encode("ascii")).hexdigest() for key in freeze.ARTIFACT_PATHS})
    values.update(freeze.STATIC_BINDINGS)
    return values


def old_expected_fixture() -> dict[str, str]:
    values = {
        "application_commit": freeze.APPLICATION_COMMIT,
        "application_tree": freeze.APPLICATION_TREE,
        "control_commit": "54b67cfbe9aa6e762f612aa5fc5446c4def1c538",
        "control_tree": "c793fab81b74fc627dd9d600a9703ff2c4314e9f",
        "runtime_controller_sha256": "2a7978fa34041935e2c1192c21aecbe350680da68617d4cac3b0d2b2bb84c54b",
        "runtime_gate_sha256": "dd4d13a303efe0317832732ddafeda6d5fbb13aeb1514f1a97fb408f8b67e259",
        "runtime_orchestration_sha256": "3a026117bf0c516163401ef55f8197cd4cd79d51dacea69c63d5752e8a11942c",
        "controller_unit_sha256": "afa0ea4801404b34483adde8c63289b0b05f9b3392b2821fda0c1c52c1a22031",
        "controller_timer_sha256": "cb21506ba674c33c7ec654010cb4d51ca91b84a8db0dff7256d92533fe971ebd",
    }
    values.update(freeze.STATIC_BINDINGS)
    return values


class FreezeProvenanceTests(unittest.TestCase):
    def test_exact_29_key_ssot_matches_controller_order(self):
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(len(freeze.REQUIRED_KEYS), 29)
        self.assertEqual(freeze.controller_binding_keys(source), freeze.REQUIRED_KEYS)
        self.assertEqual(
            source.count(f'FINAL_CONTROL_TAG="{freeze.FREEZE_TAG}"'),
            1,
        )

    def test_exact_29_binding_annotation_is_green(self):
        expected = expected_fixture()
        report = freeze.verify_annotation(freeze.render_annotation(expected), expected)
        self.assertTrue(report["ok"])
        self.assertEqual(report["matching_count"], 29)
        self.assertEqual(report["binding_count"], 29)

    def test_28_of_29_is_red(self):
        expected = expected_fixture()
        annotation = freeze.render_annotation(expected).replace(
            f"rollback_contract={expected['rollback_contract']}\n", ""
        )
        report = freeze.verify_annotation(annotation, expected)
        self.assertFalse(report["ok"])
        self.assertEqual(report["missing"], ["rollback_contract"])

    def test_alias_cannot_substitute_for_canonical_key(self):
        expected = expected_fixture()
        annotation = freeze.render_annotation(expected).replace(
            "runtime_controller_sha256=", "controller_sha="
        )
        report = freeze.verify_annotation(annotation, expected)
        self.assertFalse(report["ok"])
        self.assertEqual(report["missing"], ["runtime_controller_sha256"])
        self.assertEqual(report["aliases"], ["controller_sha"])

    def test_duplicate_canonical_key_is_red(self):
        expected = expected_fixture()
        annotation = freeze.render_annotation(expected)
        annotation += f"control_tree={expected['control_tree']}\n"
        report = freeze.verify_annotation(annotation, expected)
        self.assertFalse(report["ok"])
        self.assertEqual(report["duplicates"], ["control_tree"])

    def test_wrong_artifact_commit_and_tree_are_red(self):
        expected = expected_fixture()
        for key, value in (
            ("runtime_gate_sha256", "a" * 64),
            ("control_commit", "b" * 40),
            ("control_tree", "c" * 40),
        ):
            with self.subTest(key=key):
                wrong = copy.deepcopy(expected)
                wrong[key] = value
                report = freeze.verify_annotation(
                    freeze.render_annotation(wrong), expected
                )
                self.assertFalse(report["ok"])
                self.assertEqual(report["incorrect"], [key])

    def test_old_immutable_tag_fixture_remains_expected_red(self):
        report = freeze.verify_annotation(
            OLD_ANNOTATION.read_text(encoding="ascii"), old_expected_fixture()
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["required_count"], 29)
        self.assertEqual(report["matching_count"], 22)
        self.assertEqual(
            report["missing"],
            [
                "runtime_controller_sha256",
                "runtime_gate_sha256",
                "runtime_orchestration_sha256",
                "controller_unit_sha256",
                "controller_timer_sha256",
                "runtime_access_contract",
                "umask_077_regression",
            ],
        )
        self.assertEqual(
            report["aliases"],
            [
                "controller_sha",
                "controller_unit_sha",
                "gate_sha",
                "orchestration_sha",
                "timer_sha",
            ],
        )

    def test_r15_15_source_simulator_starts_with_freeze_provenance(self):
        completed = subprocess.run(
            [sys.executable, str(SIMULATOR)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertTrue(report["ok"])
        self.assertTrue(report["freeze_provenance_green"])
        self.assertEqual(report["happy_path"]["first_gate"], "FREEZE_PROVENANCE")
        self.assertEqual(report["happy_path"]["next_gate"], "PRE_S11_DEPENDENCY")
        self.assertFalse(report["runtime_mutation"])


if __name__ == "__main__":
    unittest.main()
