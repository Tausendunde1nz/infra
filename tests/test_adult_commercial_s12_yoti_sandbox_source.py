import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import tu1nz_adult_commercial_s12_freeze as freeze


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s12-yoti-sandbox-source.json"
DOC = ROOT / "docs/COMMERCIAL_S12_YOTI_SANDBOX_SOURCE_CONTROL.md"


def fixture() -> dict[str, str]:
    values = {
        "application_commit": freeze.APPLICATION_COMMIT,
        "application_tree": freeze.APPLICATION_TREE,
        "control_commit": "1" * 40,
        "control_tree": "2" * 40,
    }
    values.update(
        {
            key: hashlib.sha256(key.encode("ascii")).hexdigest()
            for key in (*freeze.APPLICATION_ARTIFACTS, *freeze.CONTROL_ARTIFACTS)
        }
    )
    values.update(freeze.STATIC_BINDINGS)
    return values


class CommercialS12YotiSandboxSourceControlTests(unittest.TestCase):
    def test_committed_manifest_is_exactly_sandbox_only_and_inactive(self) -> None:
        report = freeze.validate_manifest(MANIFEST)
        self.assertTrue(report["ok"])
        self.assertEqual(report["failures"], [])
        raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(raw["application"]["commit"], freeze.APPLICATION_COMMIT)
        self.assertEqual(raw["application"]["tree"], freeze.APPLICATION_TREE)
        self.assertEqual(raw["sandbox_policy"]["allowed_methods"], ["AGE_ESTIMATION"])
        self.assertEqual(raw["sandbox_policy"]["threshold"], 18)
        self.assertFalse(raw["sandbox_policy"]["real_identity_allowed"])
        self.assertTrue(raw["sandbox_policy"]["synthetic_subject_only"])

    def test_manifest_rejects_runtime_network_credentials_and_open_gates(self) -> None:
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        for section, key in (
            ("runtime", "deployed"),
            ("network", "enabled"),
            ("boundaries", "real_avs_enabled"),
            ("boundaries", "adult_media_enabled"),
            ("boundaries", "external_publishing_enabled"),
            ("boundaries", "payments_enabled"),
            ("boundaries", "controlled_beta_enabled"),
            ("boundaries", "production_enabled"),
            ("feature_flags", "YOTI_SANDBOX_ENABLED"),
        ):
            changed = copy.deepcopy(original)
            changed[section][key] = True
            mutations.append((section + "." + key, changed))
        changed = copy.deepcopy(original)
        changed["credentials"]["values_committed"] = True
        mutations.append(("credentials.values_committed", changed))
        changed = copy.deepcopy(original)
        changed["sandbox_policy"]["real_identity_allowed"] = True
        mutations.append(("sandbox_policy.real_identity_allowed", changed))
        changed = copy.deepcopy(original)
        changed["network"]["allowed_hosts"].append("api.yoti.com")
        mutations.append(("network.allowed_hosts", changed))
        changed = copy.deepcopy(original)
        changed["credentials"]["private_key_reference"] = "/tmp/unapproved-key"
        mutations.append(("credentials.private_key_reference", changed))
        for section in (
            "boundaries",
            "credentials",
            "feature_flags",
            "network",
            "runtime",
            "sandbox_policy",
        ):
            changed = copy.deepcopy(original)
            changed[section] = {}
            mutations.append((section + ".empty", changed))
        changed = copy.deepcopy(original)
        del changed["runtime"]["unit_present"]
        mutations.append(("runtime.missing_key", changed))
        changed = copy.deepcopy(original)
        changed["unexpected"] = False
        mutations.append(("unexpected_top_level_key", changed))
        changed = copy.deepcopy(original)
        changed["runtime"]["deployed"] = 0
        mutations.append(("runtime.numeric_false", changed))
        changed = copy.deepcopy(original)
        changed["boundaries"]["sandbox_only"] = 1
        mutations.append(("boundaries.numeric_true", changed))
        changed = copy.deepcopy(original)
        changed["sandbox_policy"]["threshold"] = 18.0
        mutations.append(("sandbox_policy.numeric_type", changed))
        for name, value in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                self.assertFalse(freeze.validate_manifest(path)["ok"])

    def test_freeze_has_exact_canonical_key_order(self) -> None:
        expected = fixture()
        self.assertEqual(tuple(expected), freeze.REQUIRED_KEYS)
        self.assertEqual(len(freeze.REQUIRED_KEYS), 28)
        annotation = freeze.render_annotation(expected)
        report = freeze.verify_annotation(annotation, expected)
        self.assertTrue(report["ok"])
        self.assertEqual(report["matching_count"], 28)
        self.assertEqual(report["binding_count"], 28)

    def test_missing_duplicate_alias_wrong_and_unknown_bindings_are_red(self) -> None:
        expected = fixture()
        annotation = freeze.render_annotation(expected)
        missing = annotation.replace(
            f"runtime_deployed={expected['runtime_deployed']}\n", ""
        )
        self.assertEqual(
            freeze.verify_annotation(missing, expected)["missing"], ["runtime_deployed"]
        )
        duplicate = annotation + f"control_tree={expected['control_tree']}\n"
        self.assertEqual(
            freeze.verify_annotation(duplicate, expected)["duplicates"], ["control_tree"]
        )
        alias = annotation.replace("application_commit=", "app_commit=")
        alias_report = freeze.verify_annotation(alias, expected)
        self.assertEqual(alias_report["missing"], ["application_commit"])
        self.assertEqual(alias_report["aliases"], ["app_commit"])
        wrong_values = dict(expected)
        wrong_values["application_avs_sha256"] = "f" * 64
        wrong_report = freeze.verify_annotation(
            freeze.render_annotation(wrong_values), expected
        )
        self.assertEqual(wrong_report["incorrect"], ["application_avs_sha256"])
        unknown = annotation + "extra_binding=true\n"
        self.assertEqual(
            freeze.verify_annotation(unknown, expected)["unknown"], ["extra_binding"]
        )
        wrong_title = annotation.replace(
            "TU1NZ S12 Yoti Sandbox-only source freeze",
            "TU1NZ S12 unsafe title",
            1,
        )
        self.assertFalse(freeze.verify_annotation(wrong_title, expected)["format_exact"])
        contradictory_text = annotation + "THIS TAG ENABLES PRODUCTION\n"
        contradiction = freeze.verify_annotation(contradictory_text, expected)
        self.assertFalse(contradiction["ok"])
        self.assertFalse(contradiction["format_exact"])

    def test_control_ssot_names_no_activation_or_secret_value(self) -> None:
        raw = MANIFEST.read_text(encoding="utf-8") + DOC.read_text(encoding="utf-8")
        for value in (
            "SOURCE_GREEN_RUNTIME_NOT_AUTHORIZED",
            "YOTI_SANDBOX_CREDENTIALS_ABSENT",
            "YOTI_SANDBOX_CREDENTIALS_REQUIRED",
            "S12_SANDBOX_SOURCE_GREEN",
        ):
            self.assertIn(value, raw)
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertNotIn(private_key_marker, raw)
        self.assertNotRegex(raw, r"\d{7,16}:[A-Za-z0-9_-]{30,}")

    def test_freeze_cli_validates_manifest_without_mutation(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/tu1nz_adult_commercial_s12_freeze.py"),
                "verify-manifest",
                "--manifest",
                str(MANIFEST),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["safe_code"], "S12_CONTROL_MANIFEST_GREEN")

    def test_manifest_rejects_duplicate_keys(self) -> None:
        payload = MANIFEST.read_text(encoding="utf-8").replace(
            '"deployed": false,',
            '"deployed": true, "deployed": false,',
            1,
        )
        report = freeze.validate_manifest_payload(payload)
        self.assertFalse(report["ok"])
        self.assertEqual(report["safe_code"], "S12_CONTROL_MANIFEST_RED")
        self.assertEqual(report["failures"], ["S12_CONTROL_MANIFEST_JSON_RED"])

    def test_freeze_rejects_unsafe_manifest_at_bound_control_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "S12 Test"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "s12-test@invalid",
                ],
                check=True,
            )
            manifest_path = (
                repository
                / "manifests/adult-publishing-commercial-s12-yoti-sandbox-source.json"
            )
            manifest_path.parent.mkdir(parents=True)
            unsafe = json.loads(MANIFEST.read_text(encoding="utf-8"))
            unsafe["runtime"]["deployed"] = True
            manifest_path.write_text(json.dumps(unsafe), encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "unsafe fixture"],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            with self.assertRaisesRegex(
                freeze.FreezeError,
                "S12_FREEZE_TAGGED_MANIFEST_RED",
            ):
                freeze.validate_tagged_manifest(repository, commit)

    def test_verify_tag_cli_returns_bounded_json_for_missing_tag(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/tu1nz_adult_commercial_s12_freeze.py"),
                "verify-tag",
                "--control-repo",
                str(ROOT),
                "--application-repo",
                str(ROOT),
                "--tag",
                "s12-definitely-missing-test-tag",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("Traceback", completed.stderr)
        report = json.loads(completed.stdout)
        self.assertFalse(report["ok"])
        self.assertEqual(report["safe_code"], "S12_FREEZE_PROVENANCE_RED")
        self.assertEqual(report["failure"], "S12_FREEZE_GIT_RED")

    def test_annotated_tag_message_round_trip_has_no_formatter_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "S12 Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "s12-test@invalid"],
                check=True,
            )
            fixture_path = repository / "fixture"
            fixture_path.write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "fixture"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "fixture"],
                check=True,
            )
            annotation = "S12 canonical title\n\nkey=value\n"
            subprocess.run(
                ["git", "-C", str(repository), "tag", "-a", "s12-round-trip", "-F", "-"],
                input=annotation,
                check=True,
                text=True,
            )
            self.assertEqual(
                freeze.tag_annotation(repository, "s12-round-trip"),
                annotation,
            )


if __name__ == "__main__":
    unittest.main()
