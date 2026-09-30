import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

from scripts import tu1nz_adult_commercial_s12_1_freeze as freeze
from scripts import tu1nz_adult_commercial_s12_1_runtime as runtime
from scripts import tu1nz_adult_commercial_s12_1_simulator as control_simulator


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s12-1-yoti-sandbox-runtime.json"
UNIT = ROOT / "systemd/tu1nz-adult-commercial-s12-yoti-runtime.service"
NGINX = ROOT / "nginx/current/wantmeseen.s12-1-acceptance.conf"
DOC = ROOT / "docs/COMMERCIAL_S12_1_YOTI_SANDBOX_RUNTIME_CONTROL.md"


def freeze_fixture() -> dict[str, str]:
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


class CommercialS121YotiRuntimeControlTests(unittest.TestCase):
    def test_manifest_is_exact_sandbox_only_runtime_contract(self) -> None:
        report = freeze.validate_manifest(MANIFEST)
        self.assertTrue(report["ok"], report)
        raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(raw, freeze.expected_manifest_contract())
        self.assertEqual(raw, runtime.expected_manifest_contract())
        self.assertEqual(raw["application"]["commit"], runtime.APPLICATION_COMMIT)
        self.assertEqual(raw["application"]["tree"], runtime.APPLICATION_TREE)
        self.assertEqual(raw["environment"], "SANDBOX")
        self.assertEqual(raw["provider"], "YOTI")
        self.assertEqual(raw["sandbox_policy"]["allowed_methods"], ["AGE_ESTIMATION"])
        self.assertEqual(raw["sandbox_policy"]["threshold"], 18)
        self.assertTrue(raw["callback"]["trigger_only"])
        self.assertEqual(
            raw["callback"]["authority"], "AUTHENTICATED_RESULT_FETCH_ONLY"
        )
        self.assertEqual(
            raw["runtime_environment"]["python_sha256"],
            runtime.RUNTIME_PYTHON_SHA256,
        )
        self.assertEqual(
            raw["runtime_environment"]["venv_sha256"],
            runtime.RUNTIME_VENV_SHA256,
        )
        self.assertTrue(all(value is False for value in raw["hard_gates"].values()))

    def test_manifest_rejects_production_open_gates_and_second_deploy(self) -> None:
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        changed = copy.deepcopy(original)
        changed["environment"] = "PRODUCTION"
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["network"]["allowed_hosts"].append("api.yoti.com")
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["network"]["production_endpoint_allowed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["network"]["https_only"] = False
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["network"]["redirect_to_unknown_host_allowed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["hard_gates"]["real_avs"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["credentials"]["values_committed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["credentials"]["sdk_id_value"] = "must-not-be-frozen"
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["credentials"]["sdk_id_reference"] = "/tmp/unknown"
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["rollback"]["second_deployment_allowed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["callback"]["trigger_only"] = False
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["final_posture"]["yoti_sandbox_enabled_for_real_users"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["final_posture"]["yoti_sandbox_enabled_for_real_users"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["callback"]["body_limit_bytes"] = 16384.0
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["sandbox_policy"]["threshold"] = 18.0
        mutations.append(changed)
        for section, key, value in (
            ("health", "credential_values_visible", True),
            ("health", "privacy_safe", False),
            ("systemd", "unit", "arbitrary.service"),
            ("sandbox_policy", "provider_result_authority", "CALLBACK_PAYLOAD"),
            ("rollback", "credentials_preserved", False),
        ):
            changed = copy.deepcopy(original)
            changed[section][key] = value
            mutations.append(changed)
        for section in (
            "health",
            "systemd",
            "sandbox_policy",
            "rollback",
            "network",
        ):
            changed = copy.deepcopy(original)
            changed[section]["unknown_contract_field"] = "forbidden"
            mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["decision"] = "ARBITRARY"
        mutations.append(changed)
        for key, value in (
            ("signature", "NONE"),
            ("method", "GET"),
            ("bind", "0.0.0.0:18126"),
            ("body_limit_bytes", 32768),
            ("public_url", "http://wantmeseen.com/avs/sandbox/callback"),
        ):
            changed = copy.deepcopy(original)
            changed["callback"][key] = value
            mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value):
                report = freeze.validate_manifest_payload(json.dumps(value))
                self.assertFalse(report["ok"])
                self.assertFalse(runtime.manifest_contract_is_exact(value))

    def test_manifest_duplicate_key_is_red(self) -> None:
        payload = MANIFEST.read_text(encoding="utf-8").replace(
            '"environment": "SANDBOX",',
            '"environment": "PRODUCTION", "environment": "SANDBOX",',
            1,
        )
        report = freeze.validate_manifest_payload(payload)
        self.assertFalse(report["ok"])

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "manifest.json"
            candidate.write_text(payload, encoding="utf-8")
            with (
                mock.patch.object(runtime, "MANIFEST", candidate),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_CONTROL_MANIFEST_DUPLICATE_KEY_RED",
                ),
            ):
                runtime.validate_source_contract()
            with (
                mock.patch.object(runtime, "MANIFEST", candidate),
                mock.patch.object(control_simulator, "MANIFEST", candidate),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_CONTROL_MANIFEST_DUPLICATE_KEY_RED",
                ),
            ):
                control_simulator.run_simulator()

    def test_systemd_uses_fixed_loadcredential_and_no_secret_transport(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn(
            "LoadCredential=yoti-sdk-id:/etc/tu1nz/adult-commercial-s5.yoti-sdk-id",
            unit,
        )
        self.assertIn(
            "LoadCredential=yoti-private-key:/etc/tu1nz/adult-commercial-s5.yoti-private-key",
            unit,
        )
        self.assertIn(
            "LoadCredential=s12-runtime-contract:/etc/tu1nz/adult-commercial-s12-1-yoti-runtime.json",
            unit,
        )
        self.assertIn(
            "/run/credentials/tu1nz-adult-commercial-s12-yoti-runtime.service",
            unit,
        )
        self.assertNotRegex(unit, r"Environment=.*(?:TOKEN|SECRET|KEY|SDK_ID)=")
        self.assertNotIn("--sdk-id", unit)
        self.assertNotIn("--private-key", unit)
        self.assertNotIn("api.yoti.com", unit)
        self.assertEqual(unit.count("ExecStart="), 1)
        self.assertEqual(unit.count("ExecStartPost="), 1)
        self.assertIn("ExecStartPost=", unit)
        self.assertIn("tu1nz_s12.runtime safe-stop", unit)
        self.assertIn(
            "/etc/tu1nz/adult-commercial-s12-1-private/state/final-state.json",
            unit,
        )
        self.assertIn(
            "ReadWritePaths=/etc/tu1nz/adult-commercial-s12-1-private/state",
            unit,
        )
        self.assertIn(
            "WorkingDirectory=/etc/tu1nz/adult-commercial-s12-1-private/release/application",
            unit,
        )
        self.assertIn(
            "Environment=PYTHONPATH=/etc/tu1nz/adult-commercial-s12-1-private/release/application/src",
            unit,
        )
        self.assertIn("Environment=GIT_OPTIONAL_LOCKS=0", unit)
        self.assertIn(
            "ExecStart=/etc/tu1nz/adult-commercial-s12-1-private/release/venv/bin/python",
            unit,
        )
        self.assertIn(
            "ExecStartPost=/etc/tu1nz/adult-commercial-s12-1-private/release/venv/bin/python",
            unit,
        )
        self.assertIn(
            "--application-root /etc/tu1nz/adult-commercial-s12-1-private/release/application",
            unit,
        )
        self.assertIn(
            "--control-root /etc/tu1nz/adult-commercial-s12-1-private/release/control",
            unit,
        )
        self.assertNotIn(
            "--application-root /opt/tu1nz_repos/adult-publishing-core",
            unit,
        )
        self.assertNotIn("--control-root /opt/tu1nz_repos/control", unit)
        self.assertNotIn(
            "/opt/tu1nz_repos/adult-publishing-core/.venv/bin/python",
            unit,
        )
        self.assertNotIn("/var/lib/tausendunde1nz/s12-1-yoti-sandbox", unit)
        self.assertNotIn("WantedBy=multi-user.target", unit)

    def test_callback_nginx_is_exact_bounded_post_route(self) -> None:
        nginx = NGINX.read_text(encoding="utf-8")
        self.assertEqual(nginx.count("location = /avs/sandbox/callback"), 1)
        self.assertIn("$request_method != POST", nginx)
        self.assertIn("client_max_body_size 16k", nginx)
        self.assertIn("proxy_pass http://127.0.0.1:18126", nginx)
        self.assertNotIn("proxy_pass http://age.yoti.com", nginx)

    def test_controller_contract_is_exactly_once_backup_first(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("backup, index = create_backup(", source)
        self.assertIn("ATTEMPT_MARKER.exists()", source)
        self.assertIn("S12_1_SECOND_DEPLOYMENT_FORBIDDEN_RED", source)
        self.assertIn("rollback_once(backup, index)", source)
        self.assertIn("S12_1_ROLLBACK_DUPLICATE_RED", source)
        self.assertIn("S12_1_ROLLBACK_STOP_RED", source)
        self.assertIn("_rollback_unit_state()", source)
        self.assertIn('active_state != "inactive" or sub_state != "dead"', source)
        self.assertEqual(source.count('_run(["systemctl", "start", UNIT_NAME]'), 1)
        self.assertNotIn("def _safe_stop()", source)
        self.assertNotIn("retry", source.split("def deploy()", 1)[1].split("def simulator", 1)[0].lower())
        self.assertIn('"recover"', source)
        self.assertIn("S12_1_INTERRUPTED_DEPLOYMENT_RECOVERED", source)
        self.assertIn("with _exclusive_deployment_lock()", source)
        self.assertEqual(source.count('_run(["systemctl", "start", UNIT_NAME]'), 1)
        deploy = source.split("def _deploy_locked()", 1)[1].split("def deploy()", 1)[0]
        journal = deploy.index("_write_barrier_journal(path_records, parent_record)")
        barrier = deploy.index("with _serialized_repository_recovery(")
        backup = deploy.index("backup, index = create_backup(")
        attempt = deploy.index("ATTEMPT_MARKER,")
        sync = deploy.index("control_sha, control_tree = _sync_repositories(")
        immutable = deploy.index("_create_immutable_release_stage(")
        journal_clear = deploy.index("_durable_unlink(BARRIER_MARKER)")
        self.assertLess(journal, barrier)
        self.assertLess(barrier, backup)
        self.assertLess(backup, attempt)
        self.assertLess(
            attempt,
            sync,
        )
        self.assertLess(
            sync,
            immutable,
        )
        self.assertLess(immutable, journal_clear)
        self.assertLess(
            journal_clear,
            deploy.index('_run(["systemctl", "start", UNIT_NAME]'),
        )
        self.assertIn("RELEASE_CONTROL_ROOT / \"systemd\" / UNIT_NAME", deploy)

    def test_runtime_backup_root_is_outside_chatops_repository_ancestry(self) -> None:
        self.assertEqual(
            runtime.PRIVATE_ROOT,
            Path("/etc/tu1nz/adult-commercial-s12-1-private"),
        )
        self.assertEqual(
            runtime.BACKUP_ROOT,
            runtime.PRIVATE_ROOT / "backups",
        )
        self.assertEqual(runtime.STATE_ROOT, runtime.PRIVATE_ROOT / "state")
        self.assertNotEqual(runtime.BACKUP_ROOT, runtime.CONTROL_ROOT.parent)
        self.assertNotIn(runtime.CONTROL_ROOT.parent, runtime.BACKUP_ROOT.parents)

    def test_runtime_contract_keeps_every_hard_gate_closed(self) -> None:
        with mock.patch.object(runtime, "_provider_application_digest", return_value="a" * 64):
            contract = runtime.runtime_contract("1" * 40, "2" * 40)
        self.assertEqual(contract["environment"], "SANDBOX")
        self.assertEqual(contract["provider"], "YOTI")
        self.assertEqual(contract["allowed_method"], "AGE_ESTIMATION")
        self.assertEqual(contract["threshold"], 18)
        self.assertTrue(all(value is False for value in contract["hard_gates"].values()))
        starts = datetime.fromisoformat(contract["window_starts_at"].replace("Z", "+00:00"))
        ends = datetime.fromisoformat(contract["window_ends_at"].replace("Z", "+00:00"))
        self.assertEqual((ends - starts).total_seconds(), 20 * 60)

    def test_simulator_covers_full_runtime_and_negative_matrix(self) -> None:
        report = runtime.simulator()
        self.assertTrue(report["ok"])
        self.assertTrue(all(report["journeys"].values()))
        self.assertFalse(report["real_identity_used"])
        self.assertFalse(report["external_adult_actions"])
        self.assertTrue(report["hard_gates_closed"])

    def test_simulator_executes_and_rejects_broken_runtime_contracts(self) -> None:
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        broken_callback = copy.deepcopy(original)
        broken_callback["callback"]["authority"] = "CALLBACK_PAYLOAD"
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_callback)
        for key, value in (
            ("signature", "NONE"),
            ("method", "GET"),
            ("bind", "0.0.0.0:18126"),
            ("body_limit_bytes", 32768),
            ("public_url", "http://wantmeseen.com/avs/sandbox/callback"),
        ):
            with self.subTest(callback_key=key):
                broken_callback = copy.deepcopy(original)
                broken_callback["callback"][key] = value
                with self.assertRaises(runtime.S12ControlError):
                    control_simulator.simulate_manifest(broken_callback)
        broken_network = copy.deepcopy(original)
        broken_network["network"]["production_endpoint_allowed"] = True
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_network)
        broken_https = copy.deepcopy(original)
        broken_https["network"]["https_only"] = False
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_https)
        broken_redirect = copy.deepcopy(original)
        broken_redirect["network"]["redirect_to_unknown_host_allowed"] = True
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_redirect)
        broken_credentials = copy.deepcopy(original)
        broken_credentials["credentials"]["values_committed"] = True
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_credentials)
        broken_credentials_extra = copy.deepcopy(original)
        broken_credentials_extra["credentials"]["sdk_id_value"] = "forbidden"
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_credentials_extra)
        broken_final_posture = copy.deepcopy(original)
        broken_final_posture["final_posture"][
            "yoti_sandbox_enabled_for_real_users"
        ] = True
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_final_posture)
        for section in (
            "health", "systemd", "sandbox_policy", "rollback", "network"
        ):
            with self.subTest(extra_section=section):
                broken_nested_contract = copy.deepcopy(original)
                broken_nested_contract[section]["unknown_contract_field"] = "forbidden"
                with self.assertRaises(runtime.S12ControlError):
                    control_simulator.simulate_manifest(broken_nested_contract)
        broken_decision = copy.deepcopy(original)
        broken_decision["decision"] = "ARBITRARY"
        with self.assertRaises(runtime.S12ControlError):
            control_simulator.simulate_manifest(broken_decision)
        for hard_gates in ({}, {"arbitrary": False}):
            with self.subTest(hard_gates=hard_gates):
                broken_hard_gates = copy.deepcopy(original)
                broken_hard_gates["hard_gates"] = hard_gates
                with self.assertRaises(runtime.S12ControlError):
                    control_simulator.simulate_manifest(broken_hard_gates)

    def test_source_contract_requires_complete_nested_manifest(self) -> None:
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "manifest.json"
            for hard_gates in ({}, {"arbitrary": False}):
                with self.subTest(hard_gates=hard_gates):
                    changed = copy.deepcopy(original)
                    changed["hard_gates"] = hard_gates
                    candidate.write_text(json.dumps(changed), encoding="utf-8")
                    with (
                        mock.patch.object(runtime, "MANIFEST", candidate),
                        self.assertRaisesRegex(
                            runtime.S12ControlError,
                            "S12_1_CONTROL_MANIFEST_RED",
                        ),
                    ):
                        runtime.validate_source_contract()

            changed = copy.deepcopy(original)
            changed["final_posture"]["yoti_sandbox_enabled_for_real_users"] = True
            candidate.write_text(json.dumps(changed), encoding="utf-8")
            with (
                mock.patch.object(runtime, "MANIFEST", candidate),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_CONTROL_MANIFEST_RED",
                ),
            ):
                runtime.validate_source_contract()

            changed = copy.deepcopy(original)
            changed["credentials"]["sdk_id_value"] = "forbidden"
            candidate.write_text(json.dumps(changed), encoding="utf-8")
            with (
                mock.patch.object(runtime, "MANIFEST", candidate),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_CONTROL_MANIFEST_RED",
                ),
            ):
                runtime.validate_source_contract()

            for section in (
                "health", "systemd", "sandbox_policy", "rollback", "network"
            ):
                with self.subTest(extra_section=section):
                    changed = copy.deepcopy(original)
                    changed[section]["unknown_contract_field"] = "forbidden"
                    candidate.write_text(json.dumps(changed), encoding="utf-8")
                    with (
                        mock.patch.object(runtime, "MANIFEST", candidate),
                        self.assertRaisesRegex(
                            runtime.S12ControlError,
                            "S12_1_CONTROL_MANIFEST_RED",
                        ),
                    ):
                        runtime.validate_source_contract()

    def test_backup_bundle_verification_is_repository_bound(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(source.count("_verify_git_bundle("), 6)
        self.assertIn('"bundle", "verify", "/dev/stdin"', source)
        self.assertIn('"bundle", "list-heads", "/dev/stdin"', source)
        self.assertIn('revisions = ["HEAD", "--all"]', source)
        self.assertIn('revisions.append("ORIG_HEAD")', source)
        self.assertIn('"bundle", "create", "-", *revisions', source)
        self.assertIn('git_arguments("bundle", operation, "/dev/stdin")', source)
        self.assertIn("_git_arguments(root", source)

    def test_root_worktree_git_commands_drop_to_chatops(self) -> None:
        with mock.patch.object(runtime.os, "geteuid", return_value=0):
            arguments = runtime._git_arguments(ROOT, "status", "--porcelain")
        self.assertEqual(
            arguments[:4],
            [runtime.RUNUSER, "--user", runtime.CHATOPS_USER, "--"],
        )
        self.assertEqual(arguments[4], "git")
        with mock.patch.object(runtime.os, "geteuid", return_value=501):
            self.assertEqual(
                runtime._git_arguments(ROOT, "status", "--porcelain")[0], "git"
            )
        with mock.patch.object(runtime.os, "geteuid", return_value=0):
            recovery_arguments = runtime._recovery_git_arguments(
                ROOT, ROOT / runtime.RECOVERY_GIT_DIRECTORY, "status", "--porcelain"
            )
        self.assertEqual(recovery_arguments[:3], ["/usr/bin/env", "-i", "HOME=/"])
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", recovery_arguments)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", recovery_arguments)
        self.assertIn("/usr/bin/git", recovery_arguments)
        self.assertIn("core.hooksPath=/dev/null", recovery_arguments)
        self.assertIn("core.sshCommand=/bin/false", recovery_arguments)
        self.assertNotIn(runtime.RUNUSER, recovery_arguments)

    def test_root_git_contract_rejects_config_and_hook_execution_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo.git"
            subprocess.run(
                ["git", "init", "--bare", str(repository)],
                check=True,
                capture_output=True,
            )
            runtime._validate_root_git_contract(repository)
            subprocess.run(
                ["git", "--git-dir", str(repository), "config", "filter.evil.smudge", "/bin/false"],
                check=True,
            )
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_CONFIG_RED"
            ):
                runtime._validate_root_git_contract(repository)
            subprocess.run(
                [
                    "git", "--git-dir", str(repository), "config",
                    "--unset-all", "filter.evil.smudge",
                ],
                check=True,
            )
            hook = repository / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_HOOK_RED"
            ):
                runtime._validate_root_git_contract(repository)

    def test_root_git_contract_rejects_common_directory_and_object_alternates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo.git"
            subprocess.run(
                ["git", "init", "--bare", str(repository)],
                check=True,
                capture_output=True,
            )
            common = root / "common.git"
            subprocess.run(
                ["git", "init", "--bare", str(common)],
                check=True,
                capture_output=True,
            )
            (repository / "commondir").write_text(
                str(common) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_LAYOUT_RED"
            ):
                runtime._validate_root_git_contract(repository)
            (repository / "commondir").unlink()
            alternates = repository / "objects" / "info" / "alternates"
            alternates.write_text(str(common / "objects") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_LAYOUT_RED"
            ):
                runtime._validate_root_git_contract(repository)
            alternates.unlink()
            (repository / "objects" / "info" / "http-alternates").write_text(
                "https://example.invalid/objects\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_LAYOUT_RED"
            ):
                runtime._validate_root_git_contract(repository)

    def test_root_git_contract_rejects_nested_metadata_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, relative in enumerate(("refs/heads", "logs/refs/heads")):
                with self.subTest(relative=relative):
                    repository = root / f"repo-{index}.git"
                    subprocess.run(
                        ["git", "init", "--bare", str(repository)],
                        check=True,
                        capture_output=True,
                    )
                    external = root / f"external-{index}"
                    external.mkdir()
                    candidate = repository / relative
                    candidate.parent.mkdir(parents=True, exist_ok=True)
                    if candidate.exists():
                        shutil.rmtree(candidate)
                    candidate.symlink_to(external, target_is_directory=True)
                    with self.assertRaisesRegex(
                        runtime.S12ControlError, "S12_1_ROOT_GIT_LAYOUT_RED"
                    ):
                        runtime._validate_root_git_contract(repository)

    def test_root_git_contract_rejects_hardlinked_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo.git"
            subprocess.run(
                ["git", "init", "--bare", str(repository)],
                check=True,
                capture_output=True,
            )
            os.link(repository / "HEAD", root / "external-head")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_LAYOUT_RED"
            ):
                runtime._validate_root_git_contract(repository)

    def test_worktree_contract_rejects_hardlinked_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo"
            repository.mkdir()
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            runtime._validate_repository_worktree_contract(repository)
            os.link(tracked, root / "external-tracked.txt")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_WORKTREE_LAYOUT_RED"
            ):
                runtime._validate_repository_worktree_contract(repository)

    def test_deploy_and_recovery_require_digest_bound_root_controller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = root / "controller.py"
            controller.write_text("trusted-controller\n", encoding="ascii")
            controller.chmod(0o500)
            digest = hashlib.sha256(controller.read_bytes()).hexdigest()
            with (
                mock.patch.object(runtime, "__file__", str(controller)),
                mock.patch.object(runtime, "TRUSTED_CONTROLLER_PATH", controller),
                mock.patch.dict(
                    runtime.os.environ,
                    {runtime.TRUSTED_CONTROLLER_DIGEST_ENV: digest},
                    clear=False,
                ),
            ):
                self.assertEqual(runtime._trusted_controller_digest(), digest)
                controller.chmod(0o700)
                with self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_TRUSTED_CONTROLLER_RED"
                ):
                    runtime._trusted_controller_digest()

        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('arguments.operation in {"deploy", "recover"}', source)
        self.assertIn(
            "runtime_digest_bindings != [_trusted_controller_digest()]", source
        )

    def test_repository_barrier_checks_handles_across_complete_worktrees(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        barrier = source.index("def _serialized_repository_recovery(")
        end = source.index("def _seed_repository_from_bundle(", barrier)
        contract = source[barrier:end]
        self.assertGreaterEqual(
            contract.count("_active_recovery_git_handle_count(selected_roots)"),
            3,
        )
        self.assertIn(
            "tuple(selected_roots) + tuple(barriers.values())", contract
        )

    def test_release_acquisition_uses_only_digest_bound_offline_bundles(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("REMOTE_URL", source)
        self.assertNotIn("git@github", source)
        self.assertNotIn("_isolated_chatops_git_prefix", source)
        self.assertIn("_open_release_input_bundle(", source)
        self.assertIn("_copy_pinned_bundle(", source)
        self.assertIn("APPLICATION_BUNDLE_DIGEST_ENV", source)
        self.assertIn("CONTROL_BUNDLE_DIGEST_ENV", source)
        self.assertIn("APPLICATION_INPUT_BUNDLE", source)
        self.assertIn("CONTROL_INPUT_BUNDLE", source)
        self.assertIn('"refs/s12/application-main"', source)
        self.assertIn('"refs/s12/control-main"', source)

        deploy_start = source.index("def _deploy_locked()")
        deploy_end = source.index("def deploy()", deploy_start)
        deploy = source[deploy_start:deploy_end]
        self.assertNotIn("validate_source_contract()", deploy)
        self.assertNotIn("S12_1_CONTROLLER_FREEZE_RED", deploy)
        self.assertLess(
            deploy.index("_seal_release_fetch_stage(fetch_directories)"),
            deploy.index("backup, index = create_backup("),
        )
        self.assertLess(
            deploy.index("_pinned_release_input_bundles()"),
            deploy.index("_serialized_repository_recovery("),
        )
        self.assertLess(
            deploy.index("_serialized_repository_recovery("),
            deploy.index("_prepare_release_fetch_stage(pinned_bundles)"),
        )

    def test_descriptor_pinned_bundle_copy_ignores_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "release.bundle"
            original = b"pinned-reviewed-bundle\n"
            bundle.write_bytes(original)
            expected_digest = hashlib.sha256(original).hexdigest()
            descriptor = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                bundle.rename(root / "release.original")
                bundle.write_bytes(b"replacement\n")
                destination = root / "pinned-copy.bundle"
                runtime._copy_pinned_bundle(
                    descriptor, destination, expected_digest
                )
            finally:
                os.close(descriptor)
            self.assertEqual(destination.read_bytes(), original)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_repository_handle_gate_detects_closed_fd_writable_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapped = root / "tracked.bin"
            mapped.write_bytes(b"0" * 4096)
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import mmap,sys,time;"
                        "f=open(sys.argv[1],'r+b');"
                        "m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_WRITE);"
                        "f.close();print('ready',flush=True);time.sleep(30)"
                    ),
                    str(mapped),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                self.assertGreater(
                    runtime._active_recovery_git_handle_count((root,)), 0
                )
            finally:
                child.terminate()
                child.wait(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_repository_handle_gate_detects_upgradeable_shared_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapped = root / "tracked.bin"
            mapped.write_bytes(b"0" * 4096)
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import mmap,sys,time;"
                        "f=open(sys.argv[1],'r+b');"
                        "m=mmap.mmap(f.fileno(),0,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ);"
                        "f.close();print('ready',flush=True);time.sleep(30)"
                    ),
                    str(mapped),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                self.assertGreater(
                    runtime._active_recovery_git_handle_count((root,)), 0
                )
            finally:
                child.terminate()
                child.wait(timeout=10)

    def test_repository_barrier_journal_precedes_mutation_and_binds_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "application"
            control = root / "control"
            parent = root / "repositories"
            marker = root / "repository-barrier.json"
            record = {
                "root_uid": 501,
                "root_gid": 20,
                "root_mode": "0750",
                "git_uid": 501,
                "git_gid": 20,
                "git_mode": "0750",
            }
            parent_record = {
                "path": str(parent),
                "uid": 501,
                "gid": 20,
                "mode": "2775",
            }
            captured: dict[str, object] = {}

            def capture(path: Path, payload: dict[str, object]) -> None:
                self.assertEqual(path, marker)
                captured.update(payload)

            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
                mock.patch.object(runtime, "BARRIER_MARKER", marker),
                mock.patch.object(runtime, "_atomic_json", side_effect=capture),
            ):
                runtime._write_barrier_journal(
                    {application: record, control: record}, parent_record
                )
            self.assertEqual(captured["schema"], runtime.BARRIER_SCHEMA)
            self.assertEqual(captured["repository_parent"], parent_record)
            self.assertEqual(
                set(captured["repositories"]), {"application", "control"}
            )

    def test_backup_snapshot_rejects_post_capture_repository_race(self) -> None:
        expected = {
            "commit": "a" * 40,
            "bundle_sha256": "b" * 64,
        }
        index = {"application": expected, "control": expected}
        changed = {"commit": "c" * 40}
        with (
            mock.patch.object(runtime, "APPLICATION_ROOT", Path("/application")),
            mock.patch.object(runtime, "CONTROL_ROOT", Path("/control")),
            mock.patch.object(runtime, "_competing_control_sync_count", return_value=0),
            mock.patch.object(runtime, "_active_repository_git_count", return_value=0),
            mock.patch.object(runtime, "_repository_backup_state", return_value=changed),
            self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_BACKUP_REPOSITORY_RACE_RED"
            ),
        ):
            runtime._validate_backup_snapshot(Path("/backup"), index)

    def test_bundle_stream_is_created_and_verified_without_backup_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "control.bundle"
            runtime._create_git_bundle(ROOT, bundle)
            self.assertGreater(bundle.stat().st_size, 0)
            runtime._verify_git_bundle(ROOT, bundle)
            self.assertEqual(
                runtime._git_bundle_heads(ROOT, bundle)["HEAD"],
                runtime._git(ROOT, "rev-parse", "HEAD"),
            )

    def test_freeze_helper_scopes_safe_directory(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_freeze.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"-c", f"safe.directory={repo}", "-C", str(repo)', source)

    def test_detached_repository_state_is_recorded_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            repository = fixture / "repo"
            repository.mkdir()
            bundle = fixture / "control.bundle"
            subprocess.run(["git", "init", "-b", "control-main"], cwd=repository, check=True,
                           capture_output=True)
            subprocess.run(["git", "config", "user.name", "S12 Test"], cwd=repository,
                           check=True)
            subprocess.run(["git", "config", "user.email", "s12@example.invalid"],
                           cwd=repository, check=True)
            tracked = repository / "tracked.txt"
            tracked.write_text("one\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "one"], cwd=repository, check=True,
                           capture_output=True)
            commit, tree = runtime._identity(repository)
            subprocess.run(["git", "checkout", "--orphan", "later"], cwd=repository, check=True,
                           capture_output=True)
            subprocess.run(["git", "rm", "-rf", "."], cwd=repository, check=True,
                           capture_output=True)
            tracked.write_text("two\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "two"], cwd=repository, check=True,
                           capture_output=True)
            later = runtime._git(repository, "rev-parse", "HEAD")
            subprocess.run(["git", "checkout", "--detach", commit], cwd=repository, check=True,
                           capture_output=True)
            subprocess.run(["git", "branch", "-f", "control-main", later], cwd=repository,
                           check=True)
            freeze_ref = f"refs/tags/{runtime.FREEZE_TAG}"
            subprocess.run(["git", "update-ref", freeze_ref, later], cwd=repository,
                           check=True)
            subprocess.run(["git", "update-ref", "ORIG_HEAD", commit], cwd=repository,
                           check=True)
            runtime._create_git_bundle(repository, bundle)
            runtime._verify_git_bundle(repository, bundle)
            self.assertEqual(
                runtime._git_bundle_heads(repository, bundle)["ORIG_HEAD"], commit
            )
            subprocess.run(["git", "checkout", "--force", "control-main"], cwd=repository,
                           check=True, capture_output=True)
            subprocess.run(["git", "reflog", "expire", "--expire=now", "--all"],
                           cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "gc", "--prune=now"], cwd=repository, check=True,
                           capture_output=True)
            self.assertNotEqual(
                subprocess.run(
                    ["git", "cat-file", "-e", commit], cwd=repository,
                    capture_output=True,
                ).returncode,
                0,
            )
            tracked.write_text("interrupted\n", encoding="ascii")
            partial = repository / "partial-checkout.txt"
            partial.write_text("partial\n", encoding="ascii")
            subprocess.run(["git", "update-ref", "ORIG_HEAD", later], cwd=repository,
                           check=True)
            self.assertEqual(runtime._branch_or_none(repository), "control-main")
            runtime._restore_repository(
                repository,
                {
                    "branch": None,
                    "detached": True,
                    "commit": commit,
                    "tree": tree,
                    "release_branch": "control-main",
                    "release_branch_tip": later,
                    "orig_head": commit,
                    "bundle_sha256": runtime._sha256(bundle),
                    "managed_refs": {freeze_ref: later},
                },
                bundle,
            )
            self.assertIsNone(runtime._branch_or_none(repository))
            self.assertEqual(runtime._identity(repository), (commit, tree))
            self.assertEqual(tracked.read_text(encoding="ascii"), "one\n")
            self.assertFalse(partial.exists())
            self.assertEqual(
                runtime._git(repository, "rev-parse", "refs/heads/control-main"), later
            )
            self.assertEqual(runtime._ref_or_none(repository, freeze_ref), later)
            self.assertEqual(runtime._ref_or_none(repository, "ORIG_HEAD"), commit)

    def test_repository_restore_removes_previously_absent_orig_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            bundle = Path(directory) / "application.bundle"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            subprocess.run(["git", "config", "user.name", "S12 Test"],
                           cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "s12@example.invalid"],
                           cwd=repository, check=True)
            (repository / "tracked.txt").write_text("one\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "one"], cwd=repository,
                           check=True, capture_output=True)
            commit, tree = runtime._identity(repository)
            self.assertIsNone(runtime._ref_or_none(repository, "ORIG_HEAD"))
            runtime._create_git_bundle(repository, bundle)
            self.assertNotIn("ORIG_HEAD", runtime._git_bundle_heads(repository, bundle))
            subprocess.run(["git", "update-ref", "ORIG_HEAD", commit], cwd=repository,
                           check=True)
            runtime._restore_repository(
                repository,
                {
                    "branch": "main",
                    "detached": False,
                    "commit": commit,
                    "tree": tree,
                    "release_branch": "main",
                    "release_branch_tip": commit,
                    "orig_head": None,
                    "bundle_sha256": runtime._sha256(bundle),
                    "managed_refs": {},
                },
                bundle,
            )
            self.assertIsNone(runtime._ref_or_none(repository, "ORIG_HEAD"))

    def test_recovery_clears_only_validated_stale_git_locks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            subprocess.run(
                ["git", "init", "-b", "control-main", str(repository)],
                check=True,
                capture_output=True,
            )
            lock = repository / ".git/index.lock"
            lock.write_bytes(b"stale-index-lock")
            lock.chmod(0o600)
            runtime._clear_stale_git_locks(repository)
            self.assertFalse(lock.exists())

            lock.symlink_to(repository / "outside")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_RECOVERY_GIT_LOCK_RED"
            ):
                runtime._clear_stale_git_locks(repository)

    def test_runtime_unit_dropins_and_enablement_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            unit_root = Path(directory)
            self.assertEqual(runtime._runtime_unit_dropin_count((unit_root,)), 0)
            dropin = unit_root / f"{runtime.UNIT_NAME}.d"
            dropin.mkdir()
            (dropin / "override.conf").write_text(
                "[Service]\nExecStart=\nExecStart=/bin/false\n", encoding="ascii"
            )
            self.assertEqual(runtime._runtime_unit_dropin_count((unit_root,)), 1)

        for state in ("not-found", "disabled", "static", "enabled"):
            completed = subprocess.CompletedProcess(
                ["systemctl", "is-enabled", runtime.UNIT_NAME],
                0 if state != "not-found" else 1,
                stdout=f"{state}\n",
                stderr="",
            )
            with mock.patch.object(runtime, "_run", return_value=completed):
                self.assertEqual(runtime._runtime_unit_enablement_state(), state)

        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('not in {"not-found", "disabled", "static"}', source)
        self.assertIn('_runtime_unit_enablement_state() != "static"', source)
        self.assertIn('_systemctl_property(UNIT_NAME, "DropInPaths")', source)
        self.assertGreaterEqual(
            source.count('_systemctl_property(UNIT_NAME, "FragmentPath")'), 2
        )
        self.assertIn("S12_1_RUNTIME_UNIT_FRAGMENT_RED", source)

    def test_recovery_refuses_active_repository_git_process(self) -> None:
        with (
            mock.patch.object(runtime, "_competing_control_sync_count", return_value=0),
            mock.patch.object(runtime, "_active_repository_git_count", return_value=1),
        ):
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_RECOVERY_GIT_ACTIVE_RED"
            ):
                with runtime._serialized_repository_recovery((Path("/unused"),)):
                    self.fail("active Git process unexpectedly passed recovery gate")

    def test_recovery_barrier_blocks_new_git_and_restores_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            subprocess.run(
                ["git", "init", "-b", "control-main", str(repository)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "S12 Test"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "s12@example.invalid"],
                cwd=repository,
                check=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            commit = runtime._git(repository, "rev-parse", "HEAD")
            lock = repository / ".git/index.lock"
            lock.write_bytes(b"stale")
            lock.chmod(0o600)
            with (
                mock.patch.object(runtime, "_competing_control_sync_count", return_value=0),
                mock.patch.object(runtime, "_active_repository_git_count", return_value=0),
                mock.patch.object(runtime, "_active_recovery_git_handle_count", return_value=0),
            ):
                with runtime._serialized_repository_recovery((repository,)) as barriers:
                    recovery_git = barriers[repository]
                    self.assertTrue(recovery_git.is_dir())
                    self.assertFalse((recovery_git / "index.lock").exists())
                    self.assertEqual(stat.S_IMODE((repository / ".git").stat().st_mode), 0)
                    blocked = subprocess.run(
                        ["git", "-C", str(repository), "status", "--porcelain"],
                        check=False,
                        capture_output=True,
                    )
                    self.assertNotEqual(blocked.returncode, 0)
                    self.assertEqual(
                        runtime._recovery_git(
                            repository, recovery_git, "rev-parse", "HEAD"
                        ),
                        commit,
                    )
                    self.assertEqual(
                        runtime._selected_identity(repository, recovery_git)[0],
                        commit,
                    )
                    self.assertEqual(
                        runtime._selected_branch_or_none(repository, recovery_git),
                        "control-main",
                    )
                    dirty = repository / "actual-untracked.txt"
                    dirty.write_text("must remain visible\n", encoding="ascii")
                    with self.assertRaisesRegex(
                        runtime.S12ControlError, "S12_1_RELEASE_DIRTY_RED"
                    ):
                        runtime._selected_identity(repository, recovery_git)
                    dirty.unlink()
                    runtime._run(
                        runtime._recovery_git_arguments(
                            repository,
                            recovery_git,
                            "clean",
                            "-f",
                            "-d",
                            "-e",
                            runtime.RECOVERY_GIT_DIRECTORY,
                        )
                    )
                    self.assertTrue(recovery_git.is_dir())
            self.assertTrue((repository / ".git").is_dir())
            self.assertFalse(runtime._recovery_git_path(repository).exists())
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(repository), "status", "--porcelain"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )

    @unittest.skipUnless(sys.platform.startswith("linux"), "syncfs is Linux-specific")
    def test_repository_filesystem_sync_flushes_validated_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            runtime._sync_repository_filesystem(repository)

    def test_rollback_syncs_both_repositories_before_completion_marker(self) -> None:
        events: list[str] = []
        application = Path("/canonical/application")
        control = Path("/canonical/control")
        backup = Path("/private/backup")
        index = {
            "application": {},
            "control": {},
            "release_stage": {
                "path": str(runtime.RELEASE_ROOT),
                "present": False,
            },
            "fetch_stage": {
                "path": str(runtime.FETCH_ROOT),
                "present": False,
            },
            "repository_parent": {
                "path": str(runtime.DEPLOYMENT_LOCK_ROOT),
                "uid": 0,
                "gid": 0,
                "mode": "0755",
            },
            "files": {
                "unit": {},
                "runtime_contract": {},
                "nginx_site": {},
                "nginx_enabled": {},
                "acceptance_evidence": {},
                "final_state_evidence": {},
                "deployment_result": {},
            },
        }

        @contextmanager
        def recovery_barrier(*args, **kwargs):
            events.append("barrier-enter")
            yield {
                application: application / ".git.recovery",
                control: control / ".git.recovery",
            }
            events.append("barrier-exit")

        def sync(root: Path) -> None:
            events.append(f"sync:{root.name}")

        def run(arguments, **kwargs):
            if arguments == ["nginx", "-t"]:
                events.append("nginx-test")
            elif arguments == ["systemctl", "reload", "nginx.service"]:
                events.append("nginx-reload")
            elif arguments == ["systemctl", "daemon-reload"]:
                events.append("daemon-reload")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        def atomic_json(path: Path, payload: dict[str, object]) -> None:
            self.assertEqual(path, backup / "rollback-complete.json")
            self.assertEqual(payload["safe_code"], "S12_1_ROLLBACK_GREEN")
            events.append("marker")

        with (
            mock.patch.object(runtime, "APPLICATION_ROOT", application),
            mock.patch.object(runtime, "CONTROL_ROOT", control),
            mock.patch.object(
                runtime,
                "_rollback_unit_state",
                return_value=("inactive", "dead"),
            ),
            mock.patch.object(runtime, "_restore_file"),
            mock.patch.object(runtime, "_remove_release_stages"),
            mock.patch.object(runtime, "_remove_fetch_stage"),
            mock.patch.object(runtime, "_recorded_parent_metadata"),
            mock.patch.object(runtime, "_ensure_barrier_journal"),
            mock.patch.object(runtime, "_durable_unlink"),
            mock.patch.object(
                runtime,
                "_serialized_repository_recovery",
                side_effect=recovery_barrier,
            ),
            mock.patch.object(runtime, "_restore_repository"),
            mock.patch.object(runtime, "_sync_repository_filesystem", side_effect=sync),
            mock.patch.object(runtime, "_run", side_effect=run),
            mock.patch.object(runtime, "_atomic_json", side_effect=atomic_json),
            mock.patch.object(Path, "exists", return_value=False),
        ):
            runtime.rollback_once(backup, index)

        self.assertEqual(
            events,
            [
                "nginx-test",
                "nginx-reload",
                "barrier-enter",
                "sync:application",
                "sync:control",
                "barrier-exit",
                "sync:application",
                "sync:control",
                "daemon-reload",
                "marker",
            ],
        )

    def test_immutable_release_stage_survives_canonical_repository_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            application = root / "application"
            control = root / "control"
            for repository, branch in ((application, "main"), (control, "control-main")):
                subprocess.run(
                    ["git", "init", "-b", branch, str(repository)],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "config", "user.name", "S12 Test"],
                    cwd=repository,
                    check=True,
                )
                subprocess.run(
                    ["git", "config", "user.email", "s12@example.invalid"],
                    cwd=repository,
                    check=True,
                )
                (repository / "release.txt").write_text(
                    f"{branch}\n", encoding="ascii"
                )
                if repository == application:
                    (repository / ".gitignore").write_text(".venv/\n", encoding="ascii")
                subprocess.run(["git", "add", "-A"], cwd=repository, check=True)
                subprocess.run(
                    ["git", "commit", "-m", "release"],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                )
            subprocess.run(
                ["git", "tag", "-a", runtime.FREEZE_TAG, "-m", "freeze"],
                cwd=control,
                check=True,
            )
            application_identity = runtime._identity(application)
            control_identity = runtime._identity(control)
            source_venv = application / ".venv"
            (source_venv / "bin").mkdir(parents=True)
            shutil.copy2(Path(sys.executable).resolve(), source_venv / "bin/python")
            site_packages = (
                source_venv
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            site_packages.mkdir(parents=True)
            (source_venv / "lib64").symlink_to("lib", target_is_directory=True)
            for name, version in runtime.RUNTIME_DEPENDENCY_VERSIONS.items():
                metadata = site_packages / f"{name.replace('-', '_')}-{version}.dist-info"
                metadata.mkdir()
                (metadata / "METADATA").write_text(
                    f"Name: {name}\nVersion: {version}\n",
                    encoding="utf-8",
                )
            release = private / "release"
            staging = private / ".release-staging"
            release_application = release / "application"
            release_control = release / "control"
            release_venv = release / "venv"
            release_environment = release / "runtime-environment.json"

            source_venv_sha256 = runtime._runtime_environment_fingerprint(
                source_venv, allow_file_symlinks=True
            )
            source_python_sha256 = runtime._sha256(source_venv / "bin/python")

            try:
                with (
                    mock.patch.object(runtime, "PRIVATE_ROOT", private),
                    mock.patch.object(runtime, "APPLICATION_ROOT", application),
                    mock.patch.object(runtime, "CONTROL_ROOT", control),
                    mock.patch.object(runtime, "RELEASE_ROOT", release),
                    mock.patch.object(runtime, "RELEASE_STAGING_ROOT", staging),
                    mock.patch.object(
                        runtime, "RELEASE_APPLICATION_ROOT", release_application
                    ),
                    mock.patch.object(runtime, "RELEASE_CONTROL_ROOT", release_control),
                    mock.patch.object(runtime, "RELEASE_VENV_ROOT", release_venv),
                    mock.patch.object(
                        runtime, "RELEASE_ENVIRONMENT", release_environment
                    ),
                    mock.patch.object(
                        runtime, "APPLICATION_COMMIT", application_identity[0]
                    ),
                    mock.patch.object(
                        runtime, "APPLICATION_TREE", application_identity[1]
                    ),
                    mock.patch.object(
                        runtime, "RUNTIME_VENV_SHA256", source_venv_sha256
                    ),
                    mock.patch.object(
                        runtime, "RUNTIME_PYTHON_SHA256", source_python_sha256
                    ),
                    mock.patch.object(runtime.os, "chown"),
                    mock.patch.object(runtime, "_sync_repository_filesystem"),
                ):
                    runtime._create_immutable_release_stage(
                        {
                            application: application / ".git",
                            control: control / ".git",
                        },
                        control_identity[0],
                        control_identity[1],
                    )
                    self.assertFalse(staging.exists())
                    self.assertEqual(
                        runtime._verify_immutable_release_stage(
                            control_identity[0], control_identity[1]
                        ),
                        control_identity,
                    )
                    self.assertEqual(
                        stat.S_IMODE(release.stat().st_mode) & 0o222,
                        0,
                    )

                    (application / "release.txt").write_text(
                        "later canonical drift\n", encoding="ascii"
                    )
                    self.assertEqual(
                        runtime._root_identity(release_application),
                        application_identity,
                    )
                    environment = runtime._release_environment_record()
                    self.assertEqual(
                        environment,
                        runtime._runtime_environment_record(release_venv),
                    )
                    self.assertTrue((release_venv / "lib64").is_symlink())
                    self.assertEqual((release_venv / "lib64").readlink(), Path("lib"))
                    self.assertFalse(
                        any(
                            path.is_symlink() and not path.resolve().is_dir()
                            for path in release_venv.rglob("*")
                        )
                    )
                    staged_python = release_venv / "bin/python"
                    staged_python.chmod(0o700)
                    with staged_python.open("ab") as handle:
                        handle.write(b"review-drift")
                    staged_python.chmod(0o500)
                    with self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RELEASE_ENVIRONMENT_RED",
                    ):
                        runtime._verify_immutable_release_stage(
                            control_identity[0], control_identity[1]
                        )
            finally:
                if release.exists():
                    for current, directories, files in os.walk(release):
                        os.chmod(current, 0o700)
                        for name in directories:
                            path = Path(current) / name
                            if not path.is_symlink():
                                os.chmod(path, 0o700)
                        for name in files:
                            path = Path(current) / name
                            if not path.is_symlink():
                                os.chmod(path, 0o600)

    def test_git_activity_selectors_cover_cli_and_environment_forms(self) -> None:
        outside = Path("/tmp/outside")
        selectors = runtime._git_repository_selectors(
            [
                "git",
                f"--git-dir={runtime.CONTROL_ROOT / '.git'}",
                "--work-tree",
                str(runtime.APPLICATION_ROOT),
                f"-C{runtime.CONTROL_ROOT}",
            ],
            outside,
            {
                "GIT_DIR": str(runtime.APPLICATION_ROOT / ".git"),
                "GIT_WORK_TREE": str(runtime.CONTROL_ROOT),
                "GIT_COMMON_DIR": str(runtime.CONTROL_ROOT / ".git"),
                "GIT_OBJECT_DIRECTORY": str(runtime.APPLICATION_ROOT / ".git/objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.pathsep.join(
                    [
                        str(runtime.CONTROL_ROOT / ".git/objects"),
                        str(runtime.APPLICATION_ROOT / ".git/objects"),
                    ]
                ),
            },
        )
        self.assertIn(runtime.CONTROL_ROOT / ".git", selectors)
        self.assertIn(runtime.APPLICATION_ROOT, selectors)
        self.assertIn(runtime.CONTROL_ROOT, selectors)
        self.assertIn(runtime.APPLICATION_ROOT / ".git/objects", selectors)
        chained = runtime._git_repository_selectors(
            [
                "git", "-C", str(runtime.CONTROL_ROOT.parent),
                "-C", "control", "status",
            ],
            outside,
            {},
        )
        self.assertIn(runtime.CONTROL_ROOT, chained)

    def test_release_fetches_do_not_write_fetch_head_or_tracking_refs(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        sync = source.split("def _sync_repositories(", 1)[1].split(
            "def _verify_release_freeze", 1
        )[0]
        self.assertEqual(sync.count('"--no-write-fetch-head"'), 3)
        self.assertEqual(sync.count('"--no-tags"'), 3)
        self.assertEqual(sync.count('"--refmap="'), 3)
        self.assertNotIn('"--tags"', sync)
        self.assertIn('f"refs/tags/{FREEZE_TAG}:refs/tags/{FREEZE_TAG}"', sync)

    def test_empty_fetch_refmap_transfers_object_without_tracking_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            source = root / "source"
            checkout = root / "checkout"
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "init", "-b", "main", str(source)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "S12 Test"], cwd=source, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "s12@example.invalid"],
                cwd=source,
                check=True,
            )
            tracked = source / "tracked.txt"
            tracked.write_text("first\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
            subprocess.run(
                ["git", "commit", "-m", "first"],
                cwd=source,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "remote", "add", "origin", str(remote)],
                cwd=source,
                check=True,
            )
            subprocess.run(
                ["git", "push", "-u", "origin", "main"],
                cwd=source,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "clone", "--branch", "main", str(remote), str(checkout)],
                check=True,
                capture_output=True,
            )
            original_tracking = subprocess.run(
                ["git", "rev-parse", "refs/remotes/origin/main"],
                cwd=checkout,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tracked.write_text("second\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
            subprocess.run(
                ["git", "commit", "-m", "second"],
                cwd=source,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "push", "origin", "main"],
                cwd=source,
                check=True,
                capture_output=True,
            )
            new_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=source,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git", "fetch", "--no-write-fetch-head", "--no-tags",
                    "--refmap=", "origin", "main",
                ],
                cwd=checkout,
                check=True,
                capture_output=True,
            )
            self.assertEqual(
                subprocess.run(
                    ["git", "rev-parse", "refs/remotes/origin/main"],
                    cwd=checkout,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip(),
                original_tracking,
            )
            subprocess.run(
                ["git", "cat-file", "-e", f"{new_commit}^{{commit}}"],
                cwd=checkout,
                check=True,
            )
            self.assertFalse((checkout / ".git/FETCH_HEAD").exists())

    def test_competing_control_sync_is_detected_without_details(self) -> None:
        process_list = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=(
                "123 chatops  bash /usr/local/bin/tu1nz_sync_all.sh --loop\n"
                "456 root     /usr/bin/python3 harmless.py\n"
            ),
            stderr="",
        )
        with mock.patch.object(runtime, "_run", return_value=process_list):
            self.assertEqual(runtime._competing_control_sync_count(), 1)

    def test_install_atomically_replaces_mask_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.service"
            target = root / "mask-target"
            destination = root / "installed.service"
            source.write_text("reviewed-unit\n", encoding="ascii")
            target.write_text("do-not-touch\n", encoding="ascii")
            destination.symlink_to(target)
            target_mode = target.stat().st_mode
            with mock.patch.object(runtime.os, "chown"):
                runtime._install_file(source, destination, 0o644)
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(encoding="ascii"), "reviewed-unit\n")
            self.assertEqual(target.read_text(encoding="ascii"), "do-not-touch\n")
            self.assertEqual(target.stat().st_mode, target_mode)

    def test_rollback_treats_absent_unit_as_inactive_dead(self) -> None:
        absent = subprocess.CompletedProcess(
            args=[], returncode=4, stdout="", stderr="Unit example.service could not be found.\n"
        )
        with mock.patch.object(runtime, "_run", return_value=absent):
            self.assertEqual(runtime._rollback_unit_state(), ("inactive", "dead"))
        unknown_error = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="transport unavailable\n"
        )
        with mock.patch.object(runtime, "_run", return_value=unknown_error):
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROLLBACK_STATE_RED"
            ):
                runtime._rollback_unit_state()

    def test_recovery_is_rollback_only_and_never_restarts_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            backup = root / "backup"
            state.mkdir(mode=0o700)
            backup.mkdir(mode=0o700)
            with (
                mock.patch.object(runtime, "STATE_ROOT", state),
                mock.patch.object(runtime.os, "geteuid", return_value=0),
                mock.patch.object(
                    runtime,
                    "_load_recovery_backup",
                    return_value=(
                        backup,
                        {},
                        {
                            "attempt": 1,
                            "backup": str(backup),
                            "started_at": "2026-09-28T12:00:00Z",
                        },
                    ),
                ),
                mock.patch.object(
                    runtime, "_successful_result_matches_attempt", return_value=False
                ),
                mock.patch.object(runtime, "rollback_once") as rollback,
            ):
                result = runtime._recover_locked()
            rollback.assert_called_once_with(backup, {})
            self.assertEqual(result["safe_code"], "S12_1_INTERRUPTED_DEPLOYMENT_RECOVERED")
            self.assertNotIn("deployment_count", result)

    def test_success_result_must_bind_current_attempt_and_backup(self) -> None:
        attempt = {
            "attempt": 1,
            "backup": "/opt/tu1nz_repos/backups/s12/20260928T120000Z-predeploy",
            "started_at": "2026-09-28T12:00:00Z",
        }
        result = {
            "ok": True,
            "safe_code": "S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN",
            "deployment_count": 1,
            "backup": attempt["backup"],
            "attempt_started_at": attempt["started_at"],
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "deployment-result.json").write_text("{}\n", encoding="ascii")
            with (
                mock.patch.object(runtime, "STATE_ROOT", state),
                mock.patch.object(runtime, "_private_json", return_value=result),
            ):
                self.assertTrue(runtime._successful_result_matches_attempt(attempt))
                mismatched = dict(result, backup="/different/backup")
                runtime._private_json.return_value = mismatched
                self.assertFalse(runtime._successful_result_matches_attempt(attempt))
                runtime._private_json.side_effect = runtime.S12ControlError(
                    "S12_1_RECOVERY_RESULT_RED"
                )
                self.assertFalse(runtime._successful_result_matches_attempt(attempt))

    def test_atomic_writes_fsync_file_and_parent_directory(self) -> None:
        real_fsync = runtime.os.fsync
        kinds: list[bool] = []

        def tracking_fsync(descriptor: int) -> None:
            kinds.append(stat.S_ISDIR(runtime.os.fstat(descriptor).st_mode))
            real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(runtime.os, "fsync", side_effect=tracking_fsync):
                runtime._atomic_json(root / "state.json", {"ok": True})
            self.assertIn(False, kinds)
            self.assertIn(True, kinds)

            kinds.clear()
            source = root / "source"
            source.write_text("reviewed\n", encoding="ascii")
            with (
                mock.patch.object(runtime.os, "chown"),
                mock.patch.object(runtime.os, "fsync", side_effect=tracking_fsync),
            ):
                runtime._atomic_copy(source, root / "destination", 0o600, 0, 0)
            self.assertIn(False, kinds)
            self.assertIn(True, kinds)

    def test_restore_deletion_and_symlink_fsync_parent_directory(self) -> None:
        real_fsync = runtime.os.fsync
        kinds: list[bool] = []

        def tracking_fsync(descriptor: int) -> None:
            kinds.append(stat.S_ISDIR(runtime.os.fstat(descriptor).st_mode))
            real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "restored"
            destination.write_text("remove\n", encoding="ascii")
            with mock.patch.object(
                runtime.os, "fsync", side_effect=tracking_fsync
            ):
                runtime._restore_file({"present": False}, root / "unused", destination)
            self.assertFalse(destination.exists())
            self.assertTrue(kinds)
            self.assertTrue(all(kinds))

            kinds.clear()
            with mock.patch.object(
                runtime.os, "fsync", side_effect=tracking_fsync
            ):
                runtime._restore_file(
                    {"present": True, "symlink": "target"},
                    root / "unused",
                    destination,
                )
            self.assertTrue(destination.is_symlink())
            self.assertEqual(destination.readlink(), Path("target"))
            self.assertGreaterEqual(kinds.count(True), 2)

    def test_runtime_simulate_cli_is_standalone(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py"),
                "simulate",
            ],
            cwd="/",
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["safe_code"], "S12_1_RUNTIME_SIMULATOR_GREEN")

    def test_deployment_lock_rejects_a_concurrent_controller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stable_root = Path(directory)
            with mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", stable_root):
                with runtime._exclusive_deployment_lock():
                    with self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_DEPLOYMENT_ALREADY_RUNNING_RED",
                    ):
                        with runtime._exclusive_deployment_lock():
                            self.fail("concurrent controller lock unexpectedly acquired")

    def test_deployment_lock_is_outside_checked_out_worktrees(self) -> None:
        self.assertEqual(runtime.DEPLOYMENT_LOCK_ROOT, runtime.CONTROL_ROOT.parent)
        self.assertNotEqual(runtime.DEPLOYMENT_LOCK_ROOT, runtime.CONTROL_ROOT)
        self.assertNotEqual(runtime.DEPLOYMENT_LOCK_ROOT, runtime.APPLICATION_ROOT)

    def test_backup_and_new_private_directories_are_fully_durable(self) -> None:
        real_fsync = runtime.os.fsync
        kinds: list[bool] = []

        def tracking_fsync(descriptor: int) -> None:
            kinds.append(stat.S_ISDIR(runtime.os.fstat(descriptor).st_mode))
            real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "new-parent" / "state"
            with (
                mock.patch.object(runtime.os, "chown"),
                mock.patch.object(runtime.os, "fsync", side_effect=tracking_fsync),
            ):
                runtime._ensure_private_directory_durable(private, root)
            self.assertTrue(private.is_dir())
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertTrue(kinds)
            self.assertTrue(all(kinds))

            kinds.clear()
            backup = root / "backup"
            backup.mkdir(mode=0o700)
            (backup / "application.bundle").write_text("app\n", encoding="ascii")
            (backup / "restore-index.json").write_text("{}\n", encoding="ascii")
            with mock.patch.object(
                runtime.os, "fsync", side_effect=tracking_fsync
            ):
                runtime._durably_complete_backup(backup)
            self.assertIn(False, kinds)
            self.assertGreaterEqual(kinds.count(True), 2)
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in backup.iterdir()
                )
            )

    def test_existing_backup_chain_rejects_writable_or_wrong_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anchor = root / "anchor"
            anchor.mkdir(mode=0o700)
            anchor.chmod(0o770)
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_BACKUP_PATH_RED"
            ):
                runtime._ensure_private_directory_durable(anchor / "backup", anchor)
            anchor.chmod(0o700)
            metadata = anchor.lstat()
            wrong_owner = SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=metadata.st_uid + 1,
            )
            with mock.patch.object(Path, "lstat", return_value=wrong_owner):
                with self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_BACKUP_PATH_RED"
                ):
                    runtime._validate_secure_directory_chain(anchor, anchor)

    def test_fresh_evidence_rejects_stale_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_text('{"ok":true}\n', encoding="ascii")
            metadata = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=evidence.stat().st_size,
                st_mtime_ns=10,
            )
            with (
                mock.patch.object(Path, "lstat", return_value=metadata),
                mock.patch.object(Path, "is_symlink", return_value=False),
            ):
                with self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_FRESH_EVIDENCE_RED"
                ):
                    runtime._fresh_evidence(evidence, 11)
                metadata.st_mtime_ns = 11
                self.assertTrue(runtime._fresh_evidence(evidence, 11)["ok"])

    def test_freeze_annotation_is_exact_and_rejects_aliases(self) -> None:
        expected = freeze_fixture()
        self.assertEqual(tuple(expected), freeze.REQUIRED_KEYS)
        annotation = freeze.render_annotation(expected)
        report = freeze.verify_annotation(annotation, expected)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["matching_count"], len(freeze.REQUIRED_KEYS))
        alias = annotation.replace("application_commit=", "app_commit=", 1)
        alias_report = freeze.verify_annotation(alias, expected)
        self.assertFalse(alias_report["ok"])
        self.assertEqual(alias_report["aliases"], ["app_commit"])
        duplicate = annotation + f"control_tree={expected['control_tree']}\n"
        self.assertFalse(freeze.verify_annotation(duplicate, expected)["ok"])
        unknown = annotation + "unknown_key=true\n"
        self.assertFalse(freeze.verify_annotation(unknown, expected)["ok"])

    def test_freeze_cli_missing_tag_is_bounded(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/tu1nz_adult_commercial_s12_1_freeze.py"),
                "verify-tag",
                "--control-repo", str(ROOT),
                "--application-repo", str(ROOT),
                "--tag", "s12-1-missing-test-tag",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["safe_code"], "S12_1_FREEZE_PROVENANCE_RED")

    def test_no_secret_or_real_identity_material_in_control_artifacts(self) -> None:
        material = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                MANIFEST,
                UNIT,
                NGINX,
                DOC,
                ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py",
                ROOT / "scripts/tu1nz_adult_commercial_s12_1_freeze.py",
            )
        )
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertNotIn(marker, material)
        self.assertNotRegex(material, r"\d{7,16}:[A-Za-z0-9_-]{30,}")
        self.assertNotIn("date_of_birth", material)
        self.assertNotIn("selfie_image", material)
        self.assertNotIn("document_image", material)

    def test_old_source_freeze_remains_immutable(self) -> None:
        self.assertEqual(
            subprocess.run(
                ["git", "rev-parse", "refs/tags/s12-yoti-sandbox-source-freeze-r1"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
            "7803bc5804f5feadb613574a0e4eab221aae55d1",
        )


if __name__ == "__main__":
    unittest.main()
