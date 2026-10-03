import copy
import hashlib
import json
import mmap
import os
import pwd
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
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
BASE_NGINX = ROOT / "nginx/current/wantmeseen.s10-1-final.conf"
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
    def test_pre_sync_nginx_baseline_is_reviewed_and_checkout_independent(self) -> None:
        self.assertEqual(
            hashlib.sha256(BASE_NGINX.read_bytes()).hexdigest(),
            runtime.BASE_NGINX_SHA256,
        )
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        preflight = source[source.index("def read_only_preflight"):source.index(
            "def validate_source_contract"
        )]
        self.assertIn("_sha256(NGINX_SITE) != BASE_NGINX_SHA256", preflight)
        self.assertNotIn("SOURCE_BASE_NGINX", preflight)

    def test_s11_timer_accepts_finite_realtime_or_monotonic_elapse(self) -> None:
        for properties in (
            {
                "NextElapseUSecRealtime": "Wed 2026-10-01 00:15:00 UTC",
                "NextElapseUSecMonotonic": "n/a",
            },
            {
                "NextElapseUSecRealtime": "",
                "NextElapseUSecMonotonic": "10month 4w 1d 41min 1s",
            },
        ):
            with self.subTest(properties=properties), mock.patch.object(
                runtime,
                "_systemctl_property",
                side_effect=lambda _unit, name: properties[name],
            ):
                self.assertTrue(runtime._s11_timer_has_finite_next_elapse())

    def test_s11_timer_rejects_absent_or_infinite_elapse(self) -> None:
        for properties in (
            {
                "NextElapseUSecRealtime": "",
                "NextElapseUSecMonotonic": "n/a",
            },
            {
                "NextElapseUSecRealtime": "infinity",
                "NextElapseUSecMonotonic": "0",
            },
        ):
            with self.subTest(properties=properties), mock.patch.object(
                runtime,
                "_systemctl_property",
                side_effect=lambda _unit, name: properties[name],
            ):
                self.assertFalse(runtime._s11_timer_has_finite_next_elapse())

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
        self.assertIn("rollback_once(backup, index,", source)
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
        journal = deploy.index("_write_barrier_journal(")
        barrier = deploy.index("with _serialized_repository_recovery(")
        backup = deploy.index("backup, index = create_backup(")
        attempt = deploy.index("ATTEMPT_MARKER,")
        sync = deploy.index("control_sha, control_tree = _sync_repositories(")
        progress_start = deploy.index("_write_rollback_progress(", attempt)
        in_barrier_rollback = deploy.index(
            "_perform_restore_under_barrier(", sync
        )
        rollback_finalize = deploy.index("_finalize_rollback(backup, index)", sync)
        immutable = deploy.index("_create_immutable_release_stage(")
        journal_clear = deploy.index("_durable_unlink(BARRIER_MARKER)")
        self.assertLess(journal, barrier)
        self.assertLess(barrier, backup)
        self.assertLess(backup, attempt)
        self.assertLess(
            attempt,
            sync,
        )
        self.assertLess(attempt, progress_start)
        self.assertLess(progress_start, sync)
        self.assertLess(
            sync,
            immutable,
        )
        self.assertLess(sync, in_barrier_rollback)
        self.assertLess(in_barrier_rollback, rollback_finalize)
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
            subprocess.run(
                [
                    "git", "--git-dir", str(repository), "config",
                    "filter.evil.clean", "/bin/false",
                ],
                check=True,
            )
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROOT_GIT_CONFIG_RED"
            ):
                runtime._validate_root_git_contract(repository)
            subprocess.run(
                [
                    "git", "--git-dir", str(repository), "config",
                    "--unset-all", "filter.evil.clean",
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
            (repository / ".git").mkdir()
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            metadata = {
                "root_uid": os.getuid(),
                "root_gid": os.getgid(),
                "root_mode": "0755",
                "git_uid": os.getuid(),
                "git_gid": os.getgid(),
                "git_mode": "0755",
            }
            runtime._validate_repository_worktree_contract(repository, metadata)
            os.link(tracked, root / "external-tracked.txt")
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_WORKTREE_LAYOUT_RED"
            ):
                runtime._validate_repository_worktree_contract(repository, metadata)

    def test_worktree_contract_rejects_heterogeneous_nested_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            (repository / ".git").mkdir()
            protected = repository / "protected.bin"
            protected.write_bytes(b"private-local-state\n")
            metadata = {
                "root_uid": os.getuid(),
                "root_gid": os.getgid(),
                "root_mode": "0755",
                "git_uid": os.getuid(),
                "git_gid": os.getgid(),
                "git_mode": "0755",
            }
            real_scandir = os.scandir

            @contextmanager
            def fake_scandir(path):
                if Path(path) != repository:
                    with real_scandir(path) as entries:
                        yield entries
                    return
                changed = SimpleNamespace(
                    st_uid=os.getuid() + 1,
                    st_gid=os.getgid(),
                    st_mode=stat.S_IFREG | 0o600,
                    st_nlink=1,
                )
                entry = SimpleNamespace(
                    name=protected.name,
                    path=str(protected),
                    stat=lambda follow_symlinks=False: changed,
                )
                yield iter((entry,))

            with (
                mock.patch.object(runtime.os, "scandir", side_effect=fake_scandir),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_WORKTREE_LAYOUT_RED"
                ),
            ):
                runtime._validate_repository_worktree_contract(
                    repository, metadata
                )

    def test_chown_tree_does_not_touch_matching_or_excluded_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            git_directory = repository / ".git"
            git_directory.mkdir()
            (git_directory / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
            with mock.patch.object(runtime.os, "chown") as chown:
                runtime._chown_tree(
                    repository,
                    os.getuid(),
                    os.getgid(),
                    {".git"},
                )
            chown.assert_not_called()

    def test_journaled_recovery_accepts_locked_root_transition_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            git_directory = repository / ".git"
            git_directory.mkdir()
            (repository / "tracked.txt").write_text("reviewed\n", encoding="ascii")
            metadata = {
                "root_uid": os.getuid(),
                "root_gid": os.getgid(),
                "root_mode": "0755",
                "git_uid": os.getuid(),
                "git_gid": os.getgid(),
                "git_mode": "0755",
            }
            real_lstat = Path.lstat

            root_transition_gid = {"value": 0}

            def transition_lstat(path):
                actual = real_lstat(path)
                if path == repository:
                    return SimpleNamespace(
                        st_uid=0,
                        st_gid=root_transition_gid["value"],
                        st_mode=stat.S_IFDIR | 0o500,
                        st_nlink=actual.st_nlink,
                    )
                if path == git_directory:
                    return SimpleNamespace(
                        st_uid=0,
                        st_gid=0,
                        st_mode=stat.S_IFDIR | 0o700,
                        st_nlink=actual.st_nlink,
                    )
                return actual

            with mock.patch.object(Path, "lstat", new=transition_lstat):
                with self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_WORKTREE_LAYOUT_RED"
                ):
                    runtime._validate_repository_worktree_contract(
                        repository, metadata
                    )
                for transition_gid in (0, os.getgid()):
                    with self.subTest(root_transition_gid=transition_gid):
                        root_transition_gid["value"] = transition_gid
                        runtime._validate_repository_worktree_contract(
                            repository,
                            metadata,
                            allow_journaled_transition=True,
                        )

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

    def test_repository_barrier_checks_only_git_metadata_handles(self) -> None:
        source = (ROOT / "scripts/tu1nz_adult_commercial_s12_1_runtime.py").read_text(
            encoding="utf-8"
        )
        barrier = source.index("def _serialized_repository_recovery(")
        end = source.index("def _seed_repository_from_bundle(", barrier)
        contract = source[barrier:end]
        self.assertGreaterEqual(
            contract.count("_active_recovery_git_handle_count(metadata_paths)"),
            3,
        )
        self.assertIn(
            'tuple(root / ".git" for root in selected_roots)', contract
        )
        self.assertNotIn(
            "_active_recovery_git_handle_count(selected_roots)", contract
        )
        self.assertIn("_lock_repository_git_metadata(", contract)
        self.assertIn("_GitMetadataTransitionGuard(", contract)
        self.assertLess(
            contract.index("_GitMetadataTransitionGuard("),
            contract.index("_active_repository_git_count("),
        )
        self.assertLess(
            contract.index("_GitMetadataTransitionGuard("),
            contract.index("_lock_repository_root("),
        )
        self.assertLess(
            contract.index("transition_guard.assert_unchanged()"),
            contract.index("_install_repository_recovery_barrier("),
        )
        self.assertLess(
            contract.index("_install_repository_recovery_barrier("),
            contract.index("transition_guard.assert_no_writer_events()"),
        )
        self.assertIn("transition_guard.assert_quarantined_unchanged(", contract)
        self.assertGreaterEqual(
            contract.count("_active_tracked_worktree_write_handle_count("),
            6,
        )
        self.assertGreaterEqual(
            contract.count("allow_missing=allow_journaled_transition"), 3
        )
        self.assertIn("_tracked_worktree_regular_paths(selected_roots)", contract)
        self.assertIn("_selected_identity(root, git_directory)", contract)
        self.assertIn("_lock_worktree_write_barrier(", contract)
        self.assertGreaterEqual(
            contract.count("_assert_worktree_write_barrier("),
            3,
        )
        self.assertIn("_restore_worktree_write_barrier(", contract)
        self.assertIn("_WorktreeReleaseGuard(", contract)
        self.assertIn("_validate_released_worktree_contract(", contract)
        self.assertIn("_repository_git_metadata_directories(", contract)
        self.assertGreaterEqual(
            contract.count("_git_metadata_release_fingerprint("), 2
        )
        self.assertGreaterEqual(
            contract.count("_release_xattr_fingerprint("), 2
        )
        self.assertIn("release_paths.update(selected_roots)", contract)
        self.assertIn("_hard_lock_repository_parent(parent_record)", contract)
        self.assertNotIn("_active_guarded_owner_handle_count(", contract)
        self.assertIn("_restore_repository_worktree_metadata(", contract)
        self.assertIn("_restore_repository_git_metadata(", contract)
        self.assertIn("_GuardedHandleQuiescence(", contract)
        self.assertIn("release_quiescence.acquire()", contract)
        self.assertIn("def validate_final_release()", contract)
        self.assertIn("_PTRACE_SEIZE", source)
        self.assertIn("_PTRACE_INTERRUPT", source)
        self.assertIn("_PTRACE_DETACH", source)
        self.assertNotIn("PTRACE_O_EXITKILL", source)
        self.assertNotIn("pidfd_send_signal", source)
        self.assertNotIn("SIGSTOP", source)
        self.assertLess(
            contract.index("_WorktreeReleaseGuard("),
            contract.index("_GuardedHandleQuiescence("),
        )
        self.assertLess(
            contract.index("release_quiescence.acquire()"),
            contract.index("_restore_worktree_write_barrier("),
        )
        self.assertLess(
            contract.index("_restore_repository_git_metadata("),
            contract.index("release_guard.finalize_release("),
        )
        self.assertLess(
            contract.index("release_guard.finalize_release("),
            contract.index("_restore_repository_parent(parent_record)"),
        )
        self.assertLess(
            contract.index("_restore_repository_parent(parent_record)"),
            contract.index("release_quiescence.close()"),
        )
        self.assertGreaterEqual(contract.count("accept_release_attributes"), 2)
        self.assertGreaterEqual(
            contract.count("_validate_repository_worktree_contract("), 2
        )
        self.assertLess(
            contract.index("_validate_repository_worktree_contract("),
            contract.index("_lock_repository_parent("),
        )
        self.assertIn("fanotify_init", source)
        self.assertIn("_FAN_OPEN_PERM", source)
        self.assertIn("_FAN_DENY", source)
        holders_start = source.index("def _guarded_handle_processes(")
        holders_end = source.index(
            "class _GuardedHandleQuiescence:", holders_start
        )
        holders_contract = source[holders_start:holders_end]
        self.assertNotIn("_current_process_ancestry()", holders_contract)
        self.assertIn("process.name == controller_pid", holders_contract)

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
        self.assertNotIn("allow_journaled_transition=True", deploy)
        self.assertLess(
            deploy.index("_seal_release_fetch_stage(fetch_directories)"),
            deploy.index("_validate_ignored_release_collisions("),
        )
        self.assertLess(
            deploy.index("_validate_ignored_release_collisions("),
            deploy.index("backup, index = create_backup("),
        )
        self.assertEqual(deploy.count("_validate_ignored_release_collisions("), 2)
        self.assertLess(
            deploy.index("_pinned_release_input_bundles()"),
            deploy.index("_serialized_repository_recovery("),
        )
        self.assertLess(
            deploy.index("_serialized_repository_recovery("),
            deploy.index("_prepare_release_fetch_stage(pinned_bundles)"),
        )
        rollback = source[
            source.index("def rollback_once("):source.index("def _bare_root_git(")
        ]
        self.assertIn("allow_journaled_transition=True", rollback)

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
    def test_tracked_worktree_gate_detects_closed_fd_writable_mapping(self) -> None:
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
                    runtime._active_tracked_worktree_write_handle_count((mapped,)),
                    0,
                )
            finally:
                child.terminate()
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_tracked_worktree_gate_detects_upgradeable_shared_mapping(self) -> None:
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
                    runtime._active_tracked_worktree_write_handle_count((mapped,)),
                    0,
                )
            finally:
                child.terminate()
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_tracked_worktree_gate_detects_deleted_external_alias_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            tracked = repository / "tracked.bin"
            tracked.write_bytes(b"0" * 4096)
            external = root / "external.bin"
            os.link(tracked, external)
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import mmap,os,sys,time;"
                        "f=open(sys.argv[1],'r+b');"
                        "m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_WRITE);"
                        "f.close();os.unlink(sys.argv[1]);"
                        "print('ready',flush=True);time.sleep(30)"
                    ),
                    str(external),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                self.assertEqual(tracked.stat().st_nlink, 1)
                self.assertGreater(
                    runtime._active_tracked_worktree_write_handle_count((tracked,)),
                    0,
                )
            finally:
                child.terminate()
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_tracked_worktree_gate_detects_writable_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracked = Path(directory) / "tracked.bin"
            tracked.write_bytes(b"tracked\n")
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys,time;"
                        "f=open(sys.argv[1],'r+b');"
                        "print('ready',flush=True);time.sleep(30)"
                    ),
                    str(tracked),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                self.assertGreater(
                    runtime._active_tracked_worktree_write_handle_count((tracked,)),
                    0,
                )
            finally:
                child.terminate()
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_tracked_worktree_gate_allows_read_only_and_private_handles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tracked = Path(directory) / "tracked.bin"
            tracked.write_bytes(b"0" * 4096)
            cases = (
                "f=open(sys.argv[1],'rb')",
                (
                    "import mmap;f=open(sys.argv[1],'rb');"
                    "m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);f.close()"
                ),
                (
                    "import mmap;f=open(sys.argv[1],'rb');"
                    "m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY);f.close()"
                ),
            )
            for setup in cases:
                with self.subTest(setup=setup):
                    child = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import os,sys,time;os.chdir(sys.argv[2]);"
                                + setup
                                + ";print('ready',flush=True);time.sleep(30)"
                            ),
                            str(tracked),
                            directory,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        self.assertEqual(child.stdout.readline().strip(), "ready")
                        self.assertEqual(
                            runtime._active_tracked_worktree_write_handle_count(
                                (tracked,)
                            ),
                            0,
                        )
                    finally:
                        child.terminate()
                        child.communicate(timeout=10)

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
                "xattr_fingerprint": "a" * 64,
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
                mock.patch.object(
                    runtime,
                    "_capture_worktree_write_barrier",
                    return_value={application: {}, control: {}},
                ),
                mock.patch.object(
                    runtime, "_assert_repository_parent_xattrs"
                ),
                mock.patch.object(
                    runtime,
                    "_repository_root_xattr_fingerprint",
                    return_value="b" * 64,
                ),
                mock.patch.object(runtime, "_assert_repository_root_xattrs"),
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
            self.assertTrue(
                all(
                    item["root_xattr_fingerprint"] == "b" * 64
                    for item in captured["repositories"].values()
                )
            )
            self.assertEqual(
                set(captured["worktree_write_barrier"]),
                {"application", "control"},
            )

    def test_worktree_barrier_journal_roundtrip_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "application"
            control = root / "control"
            application.mkdir()
            control.mkdir()
            tracked = application / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            metadata = tracked.lstat()
            records = {
                application: {
                    tracked: {
                        "kind": "regular",
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                        "uid": metadata.st_uid,
                        "gid": metadata.st_gid,
                        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                        "xattr_fingerprint": "a" * 64,
                    }
                },
                control: {},
            }
            payload = runtime._worktree_barrier_payload(
                (application, control), records
            )
            self.assertEqual(
                runtime._parse_worktree_barrier_payload(
                    payload, (application, control)
                ),
                records,
            )

            escaped = copy.deepcopy(payload)
            escaped["application"][0]["path_hex"] = b"..".hex()
            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_REPOSITORY_BARRIER_JOURNAL_RED",
            ):
                runtime._parse_worktree_barrier_payload(
                    escaped, (application, control)
                )

    def test_legacy_parent_journal_upgrade_binds_xattrs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "repository-barrier.json"
            marker.touch()
            application = root / "application"
            control = root / "control"
            record = {
                "root_uid": 501,
                "root_gid": 20,
                "root_mode": "0750",
                "git_uid": 501,
                "git_gid": 20,
                "git_mode": "0750",
            }
            records = {application: record, control: record}
            parent_record = {
                "path": str(root),
                "uid": 501,
                "gid": 20,
                "mode": "0755",
            }
            barrier = {application: {}, control: {}}
            journal = {
                "schema": runtime.LEGACY_BARRIER_SCHEMA,
                "created_at": "2026-10-02T00:00:00Z",
                "repositories": {},
                "repository_parent": dict(parent_record),
                "worktree_write_barrier": {},
            }
            captured: dict[str, object] = {}

            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", root),
                mock.patch.object(runtime, "BARRIER_MARKER", marker),
                mock.patch.object(
                    runtime,
                    "_load_barrier_journal",
                    return_value=(
                        records,
                        dict(parent_record),
                        barrier,
                        runtime.LEGACY_BARRIER_SCHEMA,
                    ),
                ),
                mock.patch.object(
                    runtime, "_assert_legacy_repository_parent_xattrs_safe"
                ),
                mock.patch.object(
                    runtime,
                    "_repository_parent_xattr_fingerprint",
                    return_value="b" * 64,
                ),
                mock.patch.object(
                    runtime, "_assert_repository_parent_xattrs"
                ),
                mock.patch.object(runtime, "_assert_legacy_path_xattrs_safe"),
                mock.patch.object(
                    runtime,
                    "_repository_root_xattr_fingerprint",
                    return_value="c" * 64,
                ),
                mock.patch.object(runtime, "_assert_repository_root_xattrs"),
                mock.patch.object(
                    runtime, "_private_json", return_value=journal
                ),
                mock.patch.object(
                    runtime,
                    "_atomic_json",
                    side_effect=lambda _path, payload: captured.update(payload),
                ),
            ):
                self.assertIs(
                    runtime._ensure_barrier_journal(records, parent_record),
                    barrier,
                )

            self.assertEqual(parent_record["xattr_fingerprint"], "b" * 64)
            self.assertEqual(captured["schema"], runtime.BARRIER_SCHEMA)
            self.assertEqual(
                captured["repository_parent"]["xattr_fingerprint"],
                "b" * 64,
            )
            self.assertTrue(
                all(
                    item["root_xattr_fingerprint"] == "c" * 64
                    for item in captured["repositories"].values()
                )
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

    def test_backup_rejects_option_like_attached_branch_name(self) -> None:
        with (
            mock.patch.object(runtime, "_validate_canonical_index"),
            mock.patch.object(
                runtime, "_selected_identity", return_value=("a" * 40, "b" * 40)
            ),
            mock.patch.object(
                runtime, "_selected_branch_or_none", return_value="--detach"
            ),
            self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_BACKUP_REPOSITORY_BRANCH_RED"
            ),
        ):
            runtime._repository_backup_state(
                Path("/repository"),
                "main",
                path_metadata={
                    "root_uid": 501,
                    "root_gid": 20,
                    "root_mode": "0755",
                    "git_uid": 501,
                    "git_gid": 20,
                    "git_mode": "0755",
                },
            )

    def test_backup_state_excludes_barrier_only_root_fingerprint(self) -> None:
        metadata = {
            "root_uid": 501,
            "root_gid": 20,
            "root_mode": "0755",
            "git_uid": 501,
            "git_gid": 20,
            "git_mode": "0755",
            "root_xattr_fingerprint": "a" * 64,
        }
        with (
            mock.patch.object(runtime, "_validate_canonical_index"),
            mock.patch.object(
                runtime,
                "_selected_identity",
                return_value=("b" * 40, "c" * 40),
            ),
            mock.patch.object(
                runtime, "_selected_branch_or_none", return_value="main"
            ),
            mock.patch.object(
                runtime, "_selected_git", return_value="d" * 40
            ),
            mock.patch.object(
                runtime, "_selected_ref_or_none", return_value=None
            ),
        ):
            state = runtime._repository_backup_state(
                Path("/repository"), "main", path_metadata=metadata
            )

        expected_metadata = {
            name: value
            for name, value in metadata.items()
            if name != "root_xattr_fingerprint"
        }
        self.assertNotIn("root_xattr_fingerprint", state)
        self.assertEqual(
            {name: state[name] for name in expected_metadata},
            expected_metadata,
        )

    def test_backup_rejects_noncanonical_index_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            (repository / "tracked.txt").write_text("baseline\n", encoding="ascii")
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            subprocess.run(
                ["git", "commit", "-m", "baseline"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            metadata = {
                "root_uid": os.getuid(),
                "root_gid": os.getgid(),
                "root_mode": "0755",
                "git_uid": os.getuid(),
                "git_gid": os.getgid(),
                "git_mode": "0755",
            }
            for enable, disable in (
                ("--assume-unchanged", "--no-assume-unchanged"),
                ("--skip-worktree", "--no-skip-worktree"),
            ):
                with self.subTest(flag=enable):
                    subprocess.run(
                        ["git", "update-index", enable, "tracked.txt"],
                        cwd=repository,
                        check=True,
                    )
                    with self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_BACKUP_REPOSITORY_INDEX_RED",
                    ):
                        runtime._repository_backup_state(
                            repository, "main", path_metadata=metadata
                        )
                    subprocess.run(
                        ["git", "update-index", disable, "tracked.txt"],
                        cwd=repository,
                        check=True,
                    )

    def test_ignored_release_collision_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "application"
            control = root / "control"
            for repository, branch in (
                (application, "main"),
                (control, "control-main"),
            ):
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
                (repository / ".gitignore").write_text(
                    "runtime-only\n", encoding="ascii"
                )
                (repository / "tracked.txt").write_text(
                    "baseline\n", encoding="ascii"
                )
                subprocess.run(["git", "add", "."], cwd=repository, check=True)
                subprocess.run(
                    ["git", "commit", "-m", "baseline"],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                )
            ignored = application / "runtime-only"
            ignored.write_bytes(b"preserve-this-local-state\n")
            release = root / "release"
            subprocess.run(
                ["git", "clone", str(application), str(release)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "S12 Test"],
                cwd=release,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "s12@example.invalid"],
                cwd=release,
                check=True,
            )
            (release / "runtime-only").write_bytes(b"release-state\n")
            subprocess.run(
                ["git", "add", "-f", "runtime-only"],
                cwd=release,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "track release path"],
                cwd=release,
                check=True,
                capture_output=True,
            )
            application_fetch = root / "application.git"
            control_fetch = root / "control.git"
            for bare in (application_fetch, control_fetch):
                subprocess.run(
                    ["git", "init", "--bare", str(bare)],
                    check=True,
                    capture_output=True,
                )
            subprocess.run(
                [
                    "git", "--git-dir", str(application_fetch), "fetch",
                    str(release), "HEAD:refs/s12/application-main",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git", "--git-dir", str(control_fetch), "fetch",
                    str(control), f"HEAD:refs/tags/{runtime.FREEZE_TAG}",
                ],
                check=True,
                capture_output=True,
            )
            original = ignored.read_bytes()
            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_IGNORED_RELEASE_COLLISION_RED",
                ),
            ):
                runtime._validate_ignored_release_collisions(
                    {
                        application: application / ".git",
                        control: control / ".git",
                    },
                    {
                        application: application_fetch,
                        control: control_fetch,
                    },
                )
            self.assertEqual(ignored.read_bytes(), original)
            ignored.unlink()
            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
            ):
                runtime._validate_ignored_release_collisions(
                    {
                        application: application / ".git",
                        control: control / ".git",
                    },
                    {
                        application: application_fetch,
                        control: control_fetch,
                    },
                )

    def test_rollback_rejects_new_ignored_backup_collision_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory)
            application = backup / "application-worktree"
            control = backup / "control-worktree"
            application.mkdir()
            control.mkdir()
            blocked_path = b"previously-tracked/local-state"
            application_payload = runtime._tracked_path_hash_payload(
                {blocked_path, b"tracked.txt"}
            )
            control_payload = runtime._tracked_path_hash_payload({b"control.txt"})
            self.assertNotIn(blocked_path, application_payload)
            application_digest = runtime._write_private_backup_blob(
                backup / "application.tracked-path-hashes", application_payload
            )
            control_digest = runtime._write_private_backup_blob(
                backup / "control.tracked-path-hashes", control_payload
            )
            index = {
                "application": {
                    "tracked_path_hashes_sha256": application_digest,
                },
                "control": {
                    "tracked_path_hashes_sha256": control_digest,
                },
            }

            def ignored(root, git_directory, safe_code):
                self.assertEqual(
                    safe_code, "S12_1_ROLLBACK_IGNORED_COLLISION_RED"
                )
                return {blocked_path} if root == application else set()

            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
                mock.patch.object(
                    runtime, "_ignored_worktree_paths", side_effect=ignored
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_ROLLBACK_IGNORED_COLLISION_RED",
                ),
            ):
                runtime._validate_ignored_backup_collisions(
                    backup,
                    index,
                    {
                        application: application / ".git",
                        control: control / ".git",
                    },
                )

            collision = runtime.S12ControlError(
                "S12_1_ROLLBACK_IGNORED_COLLISION_RED"
            )
            with (
                mock.patch.object(
                    runtime,
                    "_validate_ignored_backup_collisions",
                    side_effect=collision,
                ),
                mock.patch.object(runtime, "_remove_release_stages") as remove,
                mock.patch.object(runtime, "_restore_repository") as restore,
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_ROLLBACK_IGNORED_COLLISION_RED",
                ),
            ):
                runtime._restore_repositories_under_barrier(
                    backup,
                    index,
                    {
                        runtime.APPLICATION_ROOT: Path("/recovery/application"),
                        runtime.CONTROL_ROOT: Path("/recovery/control"),
                    },
                )
            remove.assert_not_called()
            restore.assert_not_called()

    def test_release_state_detects_ref_and_reflog_only_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "application"
            control = root / "control"
            for repository, branch in (
                (application, "main"),
                (control, "control-main"),
            ):
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
                (repository / "tracked.txt").write_text("one\n", encoding="ascii")
                subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
                subprocess.run(
                    ["git", "commit", "-m", "one"],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                )
            git_directories = {
                application: application / ".git",
                control: control / ".git",
            }
            path_records = {
                application: runtime._repository_path_metadata(application),
                control: runtime._repository_path_metadata(control),
            }
            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
            ):
                expected = runtime._release_repository_states(
                    git_directories, path_records
                )
                subprocess.run(
                    ["git", "branch", "external"], cwd=application, check=True
                )
                with self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED",
                ):
                    runtime._validate_release_repository_states(
                        expected, git_directories, path_records
                    )
                subprocess.run(
                    ["git", "branch", "-D", "external"],
                    cwd=application,
                    check=True,
                    capture_output=True,
                )
                expected = runtime._release_repository_states(
                    git_directories, path_records
                )
                subprocess.run(
                    ["git", "checkout", "--detach"],
                    cwd=application,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "checkout", "main"],
                    cwd=application,
                    check=True,
                    capture_output=True,
                )
                with self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED",
                ):
                    runtime._validate_release_repository_states(
                        expected, git_directories, path_records
                    )

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
            reflog_snapshot = fixture / "control.reflogs"
            reflogs_present, reflog_digest = runtime._copy_reflog_snapshot(
                repository / ".git", reflog_snapshot
            )
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
                    "reflogs_present": reflogs_present,
                    "reflog_snapshot_sha256": reflog_digest,
                    "managed_refs": {freeze_ref: later},
                },
                bundle,
                reflog_snapshot,
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
            self.assertEqual(
                runtime._reflog_tree_digest(repository / ".git/logs"),
                reflog_digest,
            )

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
            reflog_snapshot = Path(directory) / "application.reflogs"
            reflogs_present, reflog_digest = runtime._copy_reflog_snapshot(
                repository / ".git", reflog_snapshot
            )
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
                    "reflogs_present": reflogs_present,
                    "reflog_snapshot_sha256": reflog_digest,
                    "managed_refs": {},
                },
                bundle,
                reflog_snapshot,
            )
            self.assertIsNone(runtime._ref_or_none(repository, "ORIG_HEAD"))
            self.assertEqual(
                runtime._reflog_tree_digest(repository / ".git/logs"),
                reflog_digest,
            )

    def test_reflog_restore_preserves_exact_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_directory = root / ".git"
            git_directory.mkdir()
            snapshot = root / "absent.reflogs"
            absent_digest = runtime._reflog_tree_digest(snapshot)
            logs = git_directory / "logs"
            (logs / "refs" / "heads").mkdir(parents=True)
            (logs / "HEAD").write_text("appended\n", encoding="ascii")
            (logs / "refs" / "heads" / "main").write_text(
                "appended\n", encoding="ascii"
            )

            runtime._restore_reflog_snapshot(
                git_directory,
                snapshot,
                {
                    "reflogs_present": False,
                    "reflog_snapshot_sha256": absent_digest,
                },
            )

            self.assertFalse(logs.exists())
            self.assertEqual(runtime._reflog_tree_digest(logs), absent_digest)

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
            mock.patch.object(
                runtime, "_repository_git_metadata_paths", return_value=()
            ),
            mock.patch.object(
                runtime, "_tracked_worktree_regular_paths", return_value=()
            ),
        ):
            with self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_RECOVERY_GIT_ACTIVE_RED"
            ):
                with runtime._serialized_repository_recovery((Path("/unused"),)):
                    self.fail("active Git process unexpectedly passed recovery gate")

    def test_journaled_index_scan_skips_only_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            present = repository / "present.txt"
            missing = repository / "missing.txt"
            present.write_text("present\n", encoding="ascii")
            missing.write_text("missing\n", encoding="ascii")
            subprocess.run(
                ["git", "add", "present.txt", "missing.txt"],
                cwd=repository,
                check=True,
            )
            missing.unlink()

            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_HANDLE_RED",
            ):
                runtime._tracked_worktree_regular_paths((repository,))

            self.assertEqual(
                runtime._tracked_worktree_regular_paths(
                    (repository,), allow_missing=True
                ),
                (present,),
            )
            self.assertEqual(
                runtime._tracked_worktree_barrier_paths(
                    repository, allow_missing=True
                ),
                (present,),
            )

    def test_worktree_barrier_rejects_owner_only_access_before_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            tracked.chmod(0o600)
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            repository_record = runtime._repository_path_metadata(repository)
            before = tracked.lstat()

            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ):
                runtime._capture_worktree_write_barrier(
                    (repository,), {repository: repository_record}
                )

            after = tracked.lstat()
            self.assertEqual(
                (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                (before.st_uid, before.st_gid, 0o600),
            )

    def test_worktree_barrier_mode_preserves_nonowner_read_and_traversal(
        self,
    ) -> None:
        uid = os.getuid()
        gid = os.getgid()
        self.assertEqual(runtime._worktree_barrier_mode(0o664, uid, gid), 0o444)
        self.assertEqual(runtime._worktree_barrier_mode(0o775, uid, gid), 0o555)
        with self.assertRaisesRegex(
            runtime.S12ControlError,
            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
        ):
            runtime._worktree_barrier_mode(0o604, uid, gid)
        with self.assertRaisesRegex(
            runtime.S12ControlError,
            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
        ):
            runtime._worktree_barrier_mode(0o700, uid, gid)
        with self.assertRaisesRegex(
            runtime.S12ControlError,
            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
        ):
            runtime._worktree_barrier_mode(0o4755, uid, gid)

        account = SimpleNamespace(pw_name="service", pw_gid=2001)
        with (
            mock.patch.object(runtime.pwd, "getpwuid", return_value=account),
            mock.patch.object(runtime.os, "getgrouplist", return_value=[2001]),
            self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ),
        ):
            runtime._worktree_barrier_mode(0o604, 2000, 2001)
        with (
            mock.patch.object(runtime.pwd, "getpwuid", return_value=account),
            mock.patch.object(runtime.os, "getgrouplist", return_value=[2002]),
        ):
            self.assertEqual(
                runtime._worktree_barrier_mode(0o604, 2000, 2001), 0o404
            )

    def test_worktree_barrier_rejects_setuid_file_before_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked"
            tracked.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            tracked.chmod(0o4755)
            subprocess.run(
                ["git", "add", "tracked"], cwd=repository, check=True
            )
            repository_record = runtime._repository_path_metadata(repository)

            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ):
                runtime._capture_worktree_write_barrier(
                    (repository,), {repository: repository_record}
                )

    def test_worktree_barrier_rejects_named_owner_acl_before_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            tracked.chmod(0o644)
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            uid = repository.lstat().st_uid
            if uid == 0:
                uid = 65534
                os.chown(repository, uid, repository.lstat().st_gid)
                os.chown(tracked, uid, tracked.lstat().st_gid)
            repository_record = runtime._repository_path_metadata(repository)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o6, 0xFFFFFFFF),
                    (0x02, 0o0, uid),
                    (0x04, 0o4, 0xFFFFFFFF),
                    (0x10, 0o4, 0xFFFFFFFF),
                    (0x20, 0o4, 0xFFFFFFFF),
                )
            )

            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    side_effect=lambda path, **_kwargs: (
                        ["system.posix_acl_access"]
                        if Path(path) == tracked
                        else []
                    ),
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                ),
            ):
                runtime._capture_worktree_write_barrier(
                    (repository,), {repository: repository_record}
                )

    def test_worktree_barrier_evaluates_group_acl_before_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            tracked.chmod(0o640)
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            uid = repository.lstat().st_uid
            gid = repository.lstat().st_gid
            if uid == 0:
                uid = 65534
                gid = 65534
                os.chown(repository, uid, gid)
                os.chown(tracked, uid, gid)
            repository_record = runtime._repository_path_metadata(repository)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o6, 0xFFFFFFFF),
                    (0x04, 0o0, 0xFFFFFFFF),
                    (0x08, 0o4, gid + 100000),
                    (0x10, 0o4, 0xFFFFFFFF),
                    (0x20, 0o0, 0xFFFFFFFF),
                )
            )

            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    side_effect=lambda path, **_kwargs: (
                        ["system.posix_acl_access"]
                        if Path(path) == tracked
                        else []
                    ),
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
                mock.patch.object(
                    runtime.pwd,
                    "getpwuid",
                    return_value=SimpleNamespace(
                        pw_name="service", pw_gid=gid
                    ),
                ),
                mock.patch.object(
                    runtime.os, "getgrouplist", return_value=[gid]
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                ),
            ):
                runtime._capture_worktree_write_barrier(
                    (repository,), {repository: repository_record}
                )

    def test_transition_accepts_valid_mask_only_access_acl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            gid = path.lstat().st_gid
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o5, 0xFFFFFFFF),
                    (0x20, 0o0, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os, "getxattr", return_value=acl, create=True
                ),
                mock.patch.object(
                    runtime.pwd,
                    "getpwuid",
                    return_value=SimpleNamespace(
                        pw_name="service", pw_gid=gid
                    ),
                ),
                mock.patch.object(
                    runtime.os, "getgrouplist", return_value=[gid]
                ),
            ):
                runtime._assert_post_chown_acl_preserves_access(
                    path,
                    1001,
                    0o5,
                    0o5,
                    0o0,
                    "S12_1_RECOVERY_GIT_BARRIER_RED",
                )

    def test_transition_rejects_mode_only_owner_outside_retained_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            gid = path.lstat().st_gid
            with (
                mock.patch.object(
                    runtime.os, "listxattr", return_value=[], create=True
                ),
                mock.patch.object(runtime.os, "getxattr", create=True),
                mock.patch.object(
                    runtime.pwd,
                    "getpwuid",
                    return_value=SimpleNamespace(
                        pw_name="service", pw_gid=gid + 1
                    ),
                ),
                mock.patch.object(
                    runtime.os, "getgrouplist", return_value=[gid + 1]
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RECOVERY_GIT_BARRIER_RED",
                ),
            ):
                runtime._assert_post_chown_acl_preserves_access(
                    path,
                    1001,
                    0o5,
                    0o5,
                    0o0,
                    "S12_1_RECOVERY_GIT_BARRIER_RED",
                )

    def test_worktree_barrier_rejects_xattr_drift_before_chown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            repository_record = runtime._repository_path_metadata(repository)
            xattrs = {tracked: b"baseline"}

            with mock.patch.object(
                runtime,
                "_stable_xattr_payload",
                side_effect=lambda path, *_args, **_kwargs: xattrs.get(
                    path, b""
                ),
            ):
                barrier = runtime._capture_worktree_write_barrier(
                    (repository,), {repository: repository_record}
                )
                xattrs[tracked] = b"named-acl-drift"
                with (
                    mock.patch.object(runtime.os, "geteuid", return_value=0),
                    mock.patch.object(runtime.os, "chown") as chown,
                    self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                    ),
                ):
                    runtime._lock_worktree_write_barrier(barrier)

            chown.assert_not_called()

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_metadata_handle_scope_allows_live_shaped_worktree_users(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("runtime-readable\n", encoding="ascii")
            (repository / ".gitignore").write_text(".venv/\n", encoding="ascii")
            venv = repository / ".venv"
            venv.mkdir()
            mapped = venv / "runtime.bin"
            mapped.write_bytes(b"0" * 4096)
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
            subprocess.run(
                ["git", "add", "tracked.txt", ".gitignore"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            child_identity = None
            if os.geteuid() == 0:
                chatops = pwd.getpwnam(runtime.CHATOPS_USER)
                if chatops.pw_uid != 0:
                    Path(directory).chmod(0o755)
                    for current, directories, files in os.walk(repository):
                        os.chown(current, chatops.pw_uid, chatops.pw_gid)
                        for name in (*directories, *files):
                            os.chown(
                                Path(current) / name,
                                chatops.pw_uid,
                                chatops.pw_gid,
                            )
                    repository.chmod(0o2770)
                    (repository / ".git").chmod(0o2770)

                    def become_chatops() -> None:
                        os.setgroups([chatops.pw_gid])
                        os.setgid(chatops.pw_gid)
                        os.setuid(chatops.pw_uid)

                    child_identity = become_chatops
            metadata = runtime._repository_git_metadata_paths((repository,))
            tracked_paths = runtime._tracked_worktree_regular_paths((repository,))
            unrelated_baseline = runtime._active_recovery_git_handle_count(metadata)
            child_code = (
                "import mmap,os,sys;"
                "os.chdir(sys.argv[1]);"
                "f=open(sys.argv[2],'rb');"
                "mfile=open(sys.argv[3],'rb');"
                "m=mmap.mmap(mfile.fileno(),0,access=mmap.ACCESS_READ);"
                "mfile.close();print('ready',flush=True);"
                "\nfor line in sys.stdin:\n"
                " open(sys.argv[2],'rb').read();os.stat(sys.argv[3]);"
                " print('ok',flush=True) if line.strip()=='probe' else None\n"
            )
            children = [
                subprocess.Popen(
                    [sys.executable, "-c", child_code, str(repository), str(tracked), str(mapped)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=child_identity,
                )
                for _ in range(4)
            ]
            try:
                for child in children:
                    self.assertEqual(child.stdout.readline().strip(), "ready")
                if child_identity is None:
                    self.assertEqual(
                        runtime._active_recovery_git_handle_count(metadata),
                        unrelated_baseline,
                    )
                self.assertEqual(
                    runtime._active_tracked_worktree_write_handle_count(
                        tracked_paths
                    ),
                    0,
                )
                with (
                    mock.patch.object(
                        runtime, "_competing_control_sync_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_repository_git_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_recovery_git_handle_count", return_value=0
                    ),
                ):
                    with runtime._serialized_repository_recovery((repository,)):
                        for child in children:
                            child.stdin.write("probe\n")
                            child.stdin.flush()
                            self.assertEqual(child.stdout.readline().strip(), "ok")
                            self.assertIsNone(child.poll())
            finally:
                for child in children:
                    child.terminate()
                for child in children:
                    child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_recovery_rejects_writable_tracked_worktree_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            tracked.write_text("runtime-readable\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys,time;f=open(sys.argv[1],'r+b');"
                        "print('ready',flush=True);time.sleep(30)"
                    ),
                    str(tracked),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with (
                    mock.patch.object(
                        runtime, "_competing_control_sync_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_repository_git_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_recovery_git_handle_count", return_value=0
                    ),
                    self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RECOVERY_GIT_ACTIVE_RED",
                    ),
                ):
                    with runtime._serialized_repository_recovery((repository,)):
                        self.fail("writable tracked handle reached protected body")
                self.assertFalse(runtime._recovery_git_path(repository).exists())
                self.assertTrue((repository / ".git").is_dir())
            finally:
                child.terminate()
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_recovery_rejects_closed_writer_dirtying_tracked_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            with (
                mock.patch.object(
                    runtime, "_competing_control_sync_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_repository_git_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_recovery_git_handle_count", return_value=0
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RELEASE_DIRTY_RED",
                ),
            ):
                with runtime._serialized_repository_recovery((repository,)):
                    tracked.write_text("unexpected writer\n", encoding="ascii")
            self.assertFalse(runtime._recovery_git_path(repository).exists())
            self.assertTrue((repository / ".git").is_dir())

    @unittest.skipUnless(
        Path("/proc").is_dir() and os.geteuid() == 0,
        "Linux root required",
    )
    def test_worktree_write_barrier_blocks_new_owner_write_until_teardown(
        self,
    ) -> None:
        try:
            chatops = pwd.getpwnam(runtime.CHATOPS_USER)
        except KeyError:
            self.skipTest("chatops account required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o755)
            repository = root / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            nested = repository / "nested"
            nested.mkdir()
            tracked = nested / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(["git", "add", "nested/tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            runtime._chown_tree(repository, chatops.pw_uid, chatops.pw_gid)
            os.chown(repository, chatops.pw_uid, chatops.pw_gid)

            def become_chatops() -> None:
                os.setgroups([])
                os.setgid(chatops.pw_gid)
                os.setuid(chatops.pw_uid)

            with (
                mock.patch.object(
                    runtime, "_competing_control_sync_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_repository_git_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_recovery_git_handle_count", return_value=0
                ),
                mock.patch.object(
                    runtime,
                    "_WorktreeReleaseGuard",
                    return_value=SimpleNamespace(
                        accept_release_attributes=lambda: None,
                        assert_no_events=lambda: None,
                        finalize_release=lambda validator, shutdown_validator: (
                            validator(),
                            shutdown_validator(),
                        ),
                        close=lambda: None,
                    ),
                ),
            ):
                with runtime._serialized_repository_recovery((repository,)):
                    locked = tracked.lstat()
                    self.assertEqual(locked.st_uid, 0)
                    self.assertEqual(stat.S_IMODE(locked.st_mode) & 0o222, 0)
                    child = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys;"
                                "p=pathlib.Path(sys.argv[1]);"
                                "\ntry:\n p.write_text('race\\n')\n"
                                "except PermissionError:\n print('blocked')\n"
                                "else:\n print('writable')"
                            ),
                            str(tracked),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        preexec_fn=become_chatops,
                    )
                    self.assertEqual(child.stdout.strip(), "blocked")
                    self.assertEqual(tracked.read_text(encoding="ascii"), "reviewed\n")
            restored = tracked.lstat()
            self.assertEqual(restored.st_uid, chatops.pw_uid)
            self.assertEqual(restored.st_gid, chatops.pw_gid)
            self.assertEqual(stat.S_IMODE(restored.st_mode), 0o644)

    @unittest.skipUnless(
        Path("/proc").is_dir() and os.geteuid() == 0,
        "Linux root required",
    )
    def test_worktree_write_barrier_resumes_root_owned_replacement(self) -> None:
        try:
            chatops = pwd.getpwnam(runtime.CHATOPS_USER)
        except KeyError:
            self.skipTest("chatops account required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o755)
            repository = root / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            nested = repository / "nested"
            nested.mkdir()
            tracked = nested / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(
                ["git", "add", "nested/tracked.txt"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            runtime._chown_tree(repository, chatops.pw_uid, chatops.pw_gid)
            os.chown(repository, chatops.pw_uid, chatops.pw_gid)
            repository_record = runtime._repository_path_metadata(repository)
            barrier = runtime._capture_worktree_write_barrier(
                (repository,), {repository: repository_record}
            )

            tracked_record = barrier[repository][tracked]
            restricted_mode = int(tracked_record["mode"], 8) & ~0o222
            os.chmod(tracked, restricted_mode)
            runtime._lock_worktree_write_barrier(barrier)
            partial_chmod = tracked.lstat()
            self.assertEqual(partial_chmod.st_uid, 0)
            self.assertEqual(
                stat.S_IMODE(partial_chmod.st_mode), restricted_mode
            )
            runtime._restore_worktree_write_barrier(barrier)
            runtime._restore_repository_path_metadata(
                repository, repository_record
            )

            os.chmod(tracked, restricted_mode)
            os.chown(tracked, 0, chatops.pw_gid)
            runtime._lock_worktree_write_barrier(barrier)
            partial_chown = tracked.lstat()
            self.assertEqual(partial_chown.st_uid, 0)
            self.assertEqual(
                stat.S_IMODE(partial_chown.st_mode), restricted_mode
            )
            runtime._restore_worktree_write_barrier(barrier)
            runtime._restore_repository_path_metadata(
                repository, repository_record
            )

            runtime._lock_worktree_write_barrier(barrier)
            replacement = nested / ".tracked.replacement"
            replacement.write_text("reviewed\n", encoding="ascii")
            os.chmod(replacement, 0o644)
            os.replace(replacement, tracked)
            added = nested / "added.txt"
            added.write_text("added\n", encoding="ascii")
            subprocess.run(
                [
                    "git",
                    "-c",
                    f"safe.directory={repository}",
                    "add",
                    "nested/added.txt",
                ],
                cwd=repository,
                check=True,
            )

            runtime._lock_worktree_write_barrier(barrier)
            runtime._assert_worktree_write_barrier((repository,), barrier)
            replacement_metadata = tracked.lstat()
            self.assertEqual(replacement_metadata.st_uid, 0)
            self.assertEqual(stat.S_IMODE(replacement_metadata.st_mode), 0o644)

            runtime._refresh_worktree_barrier_for_release(
                (repository,), {repository: repository_record}, barrier
            )
            runtime._restore_worktree_write_barrier(
                barrier, {repository: repository_record}
            )
            for current in (tracked, added):
                current_metadata = current.lstat()
                self.assertEqual(current_metadata.st_uid, chatops.pw_uid)
                self.assertEqual(current_metadata.st_gid, chatops.pw_gid)
            runtime._lock_worktree_write_barrier(barrier)
            runtime._assert_worktree_write_barrier((repository,), barrier)
            for current in (tracked, added):
                current_metadata = current.lstat()
                self.assertEqual(current_metadata.st_uid, 0)
                self.assertEqual(current_metadata.st_gid, chatops.pw_gid)
                self.assertEqual(
                    stat.S_IMODE(current_metadata.st_mode) & 0o222, 0
                )
            runtime._restore_worktree_write_barrier(
                barrier, {repository: repository_record}
            )
            runtime._restore_repository_path_metadata(
                repository, repository_record
            )
            restored = tracked.lstat()
            self.assertEqual(restored.st_uid, chatops.pw_uid)
            self.assertEqual(restored.st_gid, chatops.pw_gid)
            self.assertEqual(stat.S_IMODE(restored.st_mode), 0o644)
            self.assertEqual(
                subprocess.run(
                    [
                        "git",
                        "-c",
                        f"safe.directory={repository}",
                        "status",
                        "--porcelain",
                    ],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "A  nested/added.txt\n",
            )

            unjournaled = nested / ".tracked.unjournaled"
            unjournaled.write_text("untrusted\n", encoding="ascii")
            os.chown(unjournaled, chatops.pw_uid, chatops.pw_gid)
            os.chmod(unjournaled, 0o644)
            os.replace(unjournaled, tracked)
            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ):
                runtime._lock_worktree_write_barrier(barrier)

    def test_release_guard_allows_only_proven_read_only_open_syscalls(self) -> None:
        cases = (
            ("257 0 0 0x80000 0 0 0 0 0", True),
            ("257 0 0 0x80001 0 0 0 0 0", False),
            (f"257 0 0 {os.O_TRUNC:#x} 0 0 0 0 0", False),
            ("85 0 0 0 0 0 0 0 0", False),
            ("437 0 0 0x1234 0 0 0 0 0", False),
            ("999 0 0 0 0 0 0 0 0", False),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload), mock.patch.object(
                runtime.Path, "read_text", return_value=payload
            ), mock.patch.object(
                runtime.os,
                "uname",
                return_value=SimpleNamespace(machine="x86_64"),
            ):
                self.assertEqual(
                    runtime._WorktreeReleaseGuard._fanotify_request_is_read_only(
                        123
                    ),
                    expected,
                )

    def test_fanotify_worker_failure_precedes_sentinel_open(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.fanotify_descriptor = 123
        guard.fanotify_error = True
        guard.fanotify_thread = mock.MagicMock()
        guard.fanotify_lock = threading.Lock()
        guard.sentinel_path = Path("/guarded")

        with (
            mock.patch.object(runtime.os, "open") as open_path,
            self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ),
        ):
            guard._assert_fanotify_quiet()

        open_path.assert_not_called()

    def test_fanotify_worker_failure_closes_permission_group(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.fanotify_descriptor = 123
        guard.fanotify_error = False
        guard.fanotify_lock = threading.Lock()
        guard.fanotify_stop = threading.Event()

        with (
            mock.patch.object(
                runtime.select, "select", side_effect=OSError("overflow")
            ),
            mock.patch.object(runtime.os, "close") as close,
        ):
            guard._fanotify_loop()

        self.assertTrue(guard.fanotify_error)
        self.assertIsNone(guard.fanotify_descriptor)
        close.assert_called_once_with(123)

    def test_fanotify_close_denies_pending_open_with_cached_group(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.fanotify_descriptor = 123
        guard.fanotify_thread = None
        guard.fanotify_pending = [456]
        guard.fanotify_lock = threading.Lock()
        guard.fanotify_stop = threading.Event()
        guard.descriptor = None
        guard.inotify_watches = set()

        with (
            mock.patch.object(
                guard,
                "_flush_fanotify_marks",
                return_value=True,
            ),
            mock.patch.object(
                runtime.os,
                "read",
                side_effect=BlockingIOError,
            ),
            mock.patch.object(runtime.os, "write") as write,
            mock.patch.object(runtime.os, "close") as close,
        ):
            guard.close()

        write.assert_called_once_with(
            123,
            guard._FAN_RESPONSE.pack(456, guard._FAN_DENY),
        )
        self.assertEqual(
            [call.args for call in close.call_args_list], [(456,), (123,)]
        )
        self.assertIsNone(guard.fanotify_descriptor)

    def test_fanotify_close_drains_kernel_queued_open(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.fanotify_descriptor = 123
        guard.fanotify_thread = None
        guard.fanotify_pending = []
        guard.fanotify_lock = threading.Lock()
        guard.fanotify_stop = threading.Event()
        guard.descriptor = None
        guard.inotify_watches = set()
        payload = guard._FAN_EVENT.pack(
            guard._FAN_EVENT.size,
            guard._FANOTIFY_METADATA_VERSION,
            0,
            guard._FAN_EVENT.size,
            guard._FAN_OPEN_PERM,
            789,
            1001,
        )

        with (
            mock.patch.object(
                guard,
                "_flush_fanotify_marks",
                return_value=True,
            ) as flush,
            mock.patch.object(
                runtime.os,
                "read",
                side_effect=(payload, BlockingIOError()),
            ) as read,
            mock.patch.object(runtime.os, "write") as write,
            mock.patch.object(runtime.os, "close") as close,
        ):
            guard.close()

        flush.assert_called_once_with(123)
        self.assertEqual(read.call_args_list, [mock.call(123, 1024 * 1024)] * 2)
        write.assert_called_once_with(
            123,
            guard._FAN_RESPONSE.pack(789, guard._FAN_DENY),
        )
        self.assertEqual(
            [call.args for call in close.call_args_list], [(789,), (123,)]
        )
        self.assertIsNone(guard.fanotify_descriptor)

    def test_fanotify_mark_flush_closes_the_queue_entry_window(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        fanotify_mark = mock.MagicMock(return_value=0)
        library = SimpleNamespace(fanotify_mark=fanotify_mark)

        with mock.patch.object(runtime.ctypes, "CDLL", return_value=library):
            self.assertTrue(guard._flush_fanotify_marks(123))

        fanotify_mark.assert_called_once_with(
            123,
            guard._FAN_MARK_FLUSH,
            0,
            -100,
            None,
        )

    def test_repository_root_lock_resumes_legacy_chown_boundary(self) -> None:
        state = {"uid": 0, "gid": 1002, "mode": 0o500}

        class RootPath:
            parent = Path("/")

            @staticmethod
            def is_symlink() -> bool:
                return False

            @staticmethod
            def lstat():
                return SimpleNamespace(
                    st_uid=state["uid"],
                    st_gid=state["gid"],
                    st_mode=stat.S_IFDIR | state["mode"],
                )

        root = RootPath()
        record = {
            "root_uid": 1001,
            "root_gid": 1002,
            "root_mode": "0755",
        }

        with (
            mock.patch.object(runtime.os, "geteuid", return_value=0),
            mock.patch.object(
                runtime.os,
                "chmod",
                side_effect=lambda _path, mode: state.update(mode=mode),
            ) as chmod,
            mock.patch.object(runtime.os, "chown") as chown,
            mock.patch.object(runtime, "_assert_repository_root_xattrs"),
            mock.patch.object(
                runtime, "_assert_post_chown_acl_preserves_access"
            ),
            mock.patch.object(runtime, "_fsync_directory"),
        ):
            runtime._lock_repository_root(root, record)

        self.assertEqual(state, {"uid": 0, "gid": 1002, "mode": 0o555})
        chown.assert_not_called()
        chmod.assert_called_once_with(root, 0o555)

    def test_git_release_fingerprint_binds_nested_metadata_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=S12 Test",
                    "-c",
                    "user.email=s12@example.invalid",
                    "commit",
                    "-m",
                    "reviewed",
                ],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            directories = set(
                runtime._repository_git_metadata_directories((repository,))
            )
            self.assertIn(repository / ".git", directories)
            self.assertIn(repository / ".git" / "objects", directories)

            baseline = runtime._git_metadata_release_fingerprint((repository,))
            config = repository / ".git" / "config"
            original_mode = stat.S_IMODE(config.lstat().st_mode)
            os.chmod(config, original_mode ^ stat.S_IXUSR)
            self.assertNotEqual(
                runtime._git_metadata_release_fingerprint((repository,)),
                baseline,
            )
            os.chmod(config, original_mode)
            self.assertEqual(
                runtime._git_metadata_release_fingerprint((repository,)),
                baseline,
            )
            config.write_text(
                config.read_text(encoding="utf-8") + "\n# drift\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                runtime._git_metadata_release_fingerprint((repository,)),
                baseline,
            )

    def test_release_xattr_fingerprint_binds_guarded_paths(self) -> None:
        if not hasattr(os, "setxattr"):
            self.skipTest("extended attributes unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracked = root / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            try:
                baseline = runtime._release_xattr_fingerprint((root, tracked))
                os.setxattr(
                    tracked,
                    "user.tu1nz_s12_release",
                    b"external",
                    follow_symlinks=False,
                )
            except OSError as error:
                self.skipTest(f"extended attributes unavailable: {error.errno}")
            self.assertNotEqual(
                runtime._release_xattr_fingerprint((root, tracked)),
                baseline,
            )

    @unittest.skipUnless(
        Path("/proc").is_dir() and os.geteuid() == 0,
        "Linux root required",
    )
    def test_worktree_release_guard_detects_waiting_owner_writer(self) -> None:
        try:
            chatops = pwd.getpwnam(runtime.CHATOPS_USER)
        except KeyError:
            self.skipTest("chatops account required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o755)
            repository = root / "application"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=S12 Test",
                    "-c",
                    "user.email=s12@example.invalid",
                    "commit",
                    "-m",
                    "reviewed",
                ],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            runtime._chown_tree(repository, chatops.pw_uid, chatops.pw_gid)
            os.chown(repository, chatops.pw_uid, chatops.pw_gid)
            repository_record = runtime._repository_path_metadata(repository)
            barrier = runtime._capture_worktree_write_barrier(
                (repository,), {repository: repository_record}
            )
            runtime._lock_worktree_write_barrier(barrier)
            try:
                guard = runtime._WorktreeReleaseGuard((repository,))
            except runtime.S12ControlError as error:
                if str(error) == "S12_1_RECOVERY_WORKTREE_BARRIER_RED":
                    self.skipTest("fanotify permission events unavailable")
                raise

            def become_chatops() -> None:
                os.setgroups([])
                os.setgid(chatops.pw_gid)
                os.setuid(chatops.pw_uid)

            reader = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()",
                    str(tracked),
                ],
                check=False,
                capture_output=True,
                text=True,
                preexec_fn=become_chatops,
                timeout=5,
            )
            self.assertEqual(reader.returncode, 0, reader.stderr)
            self.assertFalse(guard.fanotify_external_open)

            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import mmap,pathlib,sys,time;"
                        "p=pathlib.Path(sys.argv[1]);"
                        "print('ready',flush=True);"
                        "\nwhile True:\n"
                        " try:\n  f=p.open('r+b');break\n"
                        " except PermissionError:\n  time.sleep(0.01)\n"
                        "\nwith f:\n"
                        " m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_WRITE)\n"
                        " m[0:1]=b'R';m.flush();m.close()\n"
                    ),
                    str(tracked),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=become_chatops,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                runtime._restore_worktree_write_barrier(barrier)
                runtime._restore_repository_path_metadata(
                    repository, repository_record
                )
                deadline = time.monotonic() + 5
                while (
                    not guard.fanotify_external_open
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue(guard.fanotify_external_open)
                with self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                ):
                    guard.accept_release_attributes()
            finally:
                runtime._reseal_released_worktree_contract(
                    (repository,),
                    {repository: repository_record},
                    barrier,
                    include_current=True,
                )
                guard.close()
                if child.poll() is None:
                    child.terminate()
                    child.communicate(timeout=5)

    @unittest.skipUnless(
        Path("/proc").is_dir() and os.geteuid() == 0,
        "Linux root required",
    )
    def test_release_rejects_attribute_drift_during_post_barrier_restore(
        self,
    ) -> None:
        try:
            chatops = pwd.getpwnam(runtime.CHATOPS_USER)
        except KeyError:
            self.skipTest("chatops account required")
        def exercise(mutation) -> None:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.chmod(root, 0o755)
                repository = root / "application"
                subprocess.run(
                    ["git", "init", "-b", "main", str(repository)],
                    check=True,
                    capture_output=True,
                )
                tracked = repository / "tracked.txt"
                tracked.write_text("reviewed\n", encoding="ascii")
                subprocess.run(
                    ["git", "add", "tracked.txt"], cwd=repository, check=True
                )
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=S12 Test",
                        "-c",
                        "user.email=s12@example.invalid",
                        "commit",
                        "-m",
                        "reviewed",
                    ],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                )
                runtime._chown_tree(repository, chatops.pw_uid, chatops.pw_gid)
                os.chown(repository, chatops.pw_uid, chatops.pw_gid)

                class ReleaseDriftGuard:
                    @staticmethod
                    def accept_release_attributes() -> None:
                        return None

                    @staticmethod
                    def assert_no_events() -> None:
                        return None

                    @staticmethod
                    def finalize_release(validator, shutdown_validator) -> None:
                        validator()
                        shutdown_validator()

                    @staticmethod
                    def close() -> None:
                        return None

                guard = ReleaseDriftGuard()
                restore_git_metadata = runtime._restore_repository_git_metadata

                def restore_then_mutate(root_path, record) -> None:
                    restore_git_metadata(root_path, record)
                    mutation(tracked)

                with (
                    mock.patch.object(
                        runtime, "_competing_control_sync_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_repository_git_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime,
                        "_active_recovery_git_handle_count",
                        return_value=0,
                    ),
                    mock.patch.object(
                        runtime, "_WorktreeReleaseGuard", return_value=guard
                    ),
                    mock.patch.object(
                        runtime,
                        "_restore_repository_git_metadata",
                        side_effect=restore_then_mutate,
                    ),
                    self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RECOVERY_GIT_BARRIER_RED",
                    ),
                ):
                    with runtime._serialized_repository_recovery((repository,)):
                        pass

        cases = {
            "mode": lambda path: os.chmod(path, 0o600),
            "xattr": lambda path: os.setxattr(
                path,
                "user.tu1nz_s12_release",
                b"external",
                follow_symlinks=False,
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(attribute=label):
                exercise(mutation)

    @unittest.skipUnless(
        Path("/proc").is_dir() and os.geteuid() == 0,
        "Linux root required",
    )
    def test_legacy_r3_namespace_locks_normalize_to_recorded_group(self) -> None:
        try:
            chatops = pwd.getpwnam(runtime.CHATOPS_USER)
        except KeyError:
            self.skipTest("chatops account required")
        with tempfile.TemporaryDirectory() as directory:
            deployment_root = Path(directory) / "repositories"
            deployment_root.mkdir(mode=0o755)
            repository = deployment_root / "application"
            repository.mkdir(mode=0o755)
            git_directory = repository / ".git"
            git_directory.mkdir(mode=0o755)
            runtime._chown_tree(repository, chatops.pw_uid, chatops.pw_gid)
            os.chown(repository, chatops.pw_uid, chatops.pw_gid)
            os.chown(deployment_root, chatops.pw_uid, chatops.pw_gid)

            with mock.patch.object(
                runtime, "DEPLOYMENT_LOCK_ROOT", deployment_root
            ):
                parent_record = runtime._repository_parent_metadata()
                repository_record = runtime._repository_path_metadata(repository)
                repository_record["root_xattr_fingerprint"] = (
                    runtime._repository_root_xattr_fingerprint(repository)
                )
                os.chown(deployment_root, 0, 0)
                os.chmod(deployment_root, 0o500)
                os.chown(repository, 0, 0)
                os.chmod(repository, 0o500)

                runtime._lock_repository_parent(parent_record)
                runtime._lock_repository_root(repository, repository_record)

                # Both syscall-boundary states of the hard parent lock must
                # be resumable by the hardener and by ordinary recovery.
                os.chown(deployment_root, 0, 0)
                runtime._hard_lock_repository_parent(parent_record)
                parent_metadata = deployment_root.lstat()
                self.assertEqual(
                    (
                        parent_metadata.st_uid,
                        parent_metadata.st_gid,
                        stat.S_IMODE(parent_metadata.st_mode),
                    ),
                    (0, 0, 0o500),
                )
                os.chown(deployment_root, 0, chatops.pw_gid)
                runtime._hard_lock_repository_parent(parent_record)
                os.chown(
                    deployment_root, chatops.pw_uid, chatops.pw_gid
                )
                runtime._lock_repository_parent(parent_record)

                for path in (deployment_root, repository):
                    metadata = path.lstat()
                    self.assertEqual(metadata.st_uid, 0)
                    self.assertEqual(metadata.st_gid, chatops.pw_gid)
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o555)

                runtime._restore_repository_path_metadata(
                    repository, repository_record
                )
                runtime._restore_repository_parent(parent_record)
                for path in (deployment_root, repository):
                    metadata = path.lstat()
                    self.assertEqual(metadata.st_uid, chatops.pw_uid)
                    self.assertEqual(metadata.st_gid, chatops.pw_gid)
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)

    def test_hard_parent_lock_resumes_every_syscall_boundary(self) -> None:
        state = {"uid": 1001, "gid": 1002, "mode": 0o755}

        class ParentPath:
            parent = Path("/")

            @staticmethod
            def is_symlink() -> bool:
                return False

            @staticmethod
            def lstat():
                return SimpleNamespace(
                    st_uid=state["uid"],
                    st_gid=state["gid"],
                    st_mode=stat.S_IFDIR | state["mode"],
                )

            def __str__(self) -> str:
                return "/srv/repositories"

        parent = ParentPath()
        record = {
            "path": str(parent),
            "uid": 1001,
            "gid": 1002,
            "mode": "0755",
            "xattr_fingerprint": "a" * 64,
        }

        def chown(_path, uid: int, gid: int) -> None:
            state.update(uid=uid, gid=gid)

        def chmod(_path, mode: int) -> None:
            state["mode"] = mode

        with (
            mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
            mock.patch.object(runtime.os, "geteuid", return_value=0),
            mock.patch.object(runtime.os, "chown", side_effect=chown),
            mock.patch.object(runtime.os, "chmod", side_effect=chmod),
            mock.patch.object(runtime, "_assert_repository_parent_xattrs"),
            mock.patch.object(
                runtime, "_assert_post_chown_acl_preserves_access"
            ),
            mock.patch.object(runtime, "_fsync_directory"),
        ):
            runtime._lock_repository_parent(record)
            self.assertEqual(state, {"uid": 0, "gid": 1002, "mode": 0o555})

            for interrupted in (
                {"uid": 0, "gid": 0, "mode": 0o555},
                {"uid": 0, "gid": 1002, "mode": 0o500},
                {"uid": 0, "gid": 0, "mode": 0o500},
            ):
                state.update(interrupted)
                runtime._hard_lock_repository_parent(record)
                self.assertEqual(
                    state, {"uid": 0, "gid": 0, "mode": 0o500}
                )

            state.update(uid=1001, gid=1002, mode=0o500)
            runtime._lock_repository_parent(record)
            self.assertEqual(state, {"uid": 0, "gid": 1002, "mode": 0o555})

            runtime._hard_lock_repository_parent(record)
            runtime._restore_repository_parent(record)
            self.assertEqual(
                state, {"uid": 1001, "gid": 1002, "mode": 0o755}
            )

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_metadata_handle_scope_rejects_git_and_recovery_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            recovery = repository / runtime.RECOVERY_GIT_DIRECTORY
            recovery.mkdir()
            (recovery / "held").write_text("metadata\n", encoding="ascii")
            cases = (
                ("cwd", repository / ".git"),
                ("fd", repository / ".git/HEAD"),
                ("fd", recovery / "held"),
            )
            for kind, target in cases:
                with self.subTest(kind=kind, target=target.name):
                    baseline = runtime._active_recovery_git_handle_count(
                        (repository / ".git", recovery)
                    )
                    code = (
                        "import os,sys,time;"
                        + (
                            "os.chdir(sys.argv[1]);"
                            if kind == "cwd"
                            else "f=open(sys.argv[1],'rb');"
                        )
                        + "print('ready',flush=True);time.sleep(30)"
                    )
                    child = subprocess.Popen(
                        [sys.executable, "-c", code, str(target)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        self.assertEqual(child.stdout.readline().strip(), "ready")
                        self.assertGreater(
                            runtime._active_recovery_git_handle_count(
                                (repository / ".git", recovery)
                            ),
                            baseline,
                        )
                    finally:
                        child.terminate()
                        child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_actual_git_writer_targeting_repository_remains_red(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            child = subprocess.Popen(
                ["git", "-C", str(repository), "hash-object", "--stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                self.assertGreater(runtime._active_repository_git_count((repository,)), 0)
            finally:
                child.communicate(timeout=10)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_new_git_writer_race_is_detected_before_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            writer: subprocess.Popen[bytes] | None = None
            original_lock = runtime._lock_repository_root

            def launch_writer(root: Path, record: dict[str, object]) -> None:
                nonlocal writer
                original_lock(root, record)
                writer = subprocess.Popen(
                    ["git", "-C", str(repository), "hash-object", "--stdin"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            try:
                with (
                    mock.patch.object(
                        runtime, "_competing_control_sync_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime, "_active_recovery_git_handle_count", return_value=0
                    ),
                    mock.patch.object(
                        runtime,
                        "_lock_repository_root",
                        side_effect=launch_writer,
                    ),
                ):
                    with self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RECOVERY_GIT_ACTIVE_RED",
                    ):
                        with runtime._serialized_repository_recovery((repository,)):
                            self.fail("racing Git writer reached protected body")
                self.assertIsNotNone(writer)
                self.assertFalse(runtime._recovery_git_path(repository).exists())
                self.assertTrue((repository / ".git").is_dir())
            finally:
                if writer is not None:
                    writer.communicate(timeout=10)

    def test_short_lived_metadata_writer_is_detected_before_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            original_lock = runtime._lock_repository_root
            exchange_reached = False

            def mutate_then_exit(root: Path, record: dict[str, object]) -> None:
                original_lock(root, record)
                subprocess.run(
                    [
                        "git", "-C", str(repository), "config", "--local",
                        "s12.racing-writer", "completed",
                    ],
                    check=True,
                    capture_output=True,
                )

            def reject_exchange(_first: Path, _second: Path) -> None:
                nonlocal exchange_reached
                exchange_reached = True
                raise AssertionError("metadata exchange must remain unreachable")

            with (
                mock.patch.object(
                    runtime, "_competing_control_sync_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_repository_git_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_recovery_git_handle_count", return_value=0
                ),
                mock.patch.object(
                    runtime,
                    "_active_tracked_worktree_write_handle_count",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime, "_lock_repository_root", side_effect=mutate_then_exit
                ),
                mock.patch.object(runtime, "_atomic_exchange", side_effect=reject_exchange),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_RECOVERY_GIT_ACTIVE_RED"
                ),
            ):
                with runtime._serialized_repository_recovery((repository,)):
                    self.fail("short-lived metadata writer reached protected body")
            self.assertFalse(exchange_reached)
            self.assertFalse(runtime._recovery_git_path(repository).exists())
            self.assertTrue((repository / ".git").is_dir())

    def test_transition_guard_rejects_drift_during_watch_installation(self) -> None:
        with (
            mock.patch.object(runtime.sys, "platform", "darwin"),
            mock.patch.object(
                runtime,
                "_git_metadata_transition_fingerprint",
                side_effect=("before-watch", "after-watch"),
            ) as fingerprint,
            self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_RECOVERY_GIT_ACTIVE_RED"
            ),
        ):
            runtime._GitMetadataTransitionGuard((Path("/metadata"),))
        self.assertEqual(fingerprint.call_count, 2)

    def test_transition_guard_finalizer_uses_ordered_watch_shutdown(self) -> None:
        guard = object.__new__(runtime._GitMetadataTransitionGuard)
        guard.descriptor = 123
        observed: list[str] = []

        with (
            mock.patch.object(
                guard,
                "assert_unchanged",
                side_effect=lambda: observed.append("validate"),
            ),
            mock.patch.object(
                guard,
                "_synchronized_inotify_shutdown",
                side_effect=lambda: observed.append("shutdown-watches"),
            ),
        ):
            guard.finalize_release()

        self.assertEqual(observed, ["validate", "shutdown-watches"])

    def test_transition_guard_shutdown_requires_every_ignored_barrier(self) -> None:
        guard = object.__new__(runtime._GitMetadataTransitionGuard)
        guard.descriptor = 123
        guard.watches = {7, 9}
        guard.root_watches = {7}
        remove = mock.MagicMock(return_value=0)
        library = SimpleNamespace(inotify_rm_watch=remove)
        payload = b"".join(
            guard._EVENT.pack(watch, guard._IN_IGNORED, 0, 0)
            for watch in (7, 9)
        )

        with (
            mock.patch.object(runtime.ctypes, "CDLL", return_value=library),
            mock.patch.object(runtime.os, "read", return_value=payload),
            mock.patch.object(runtime.os, "close") as close,
        ):
            guard._synchronized_inotify_shutdown()

        self.assertEqual(
            [call.args for call in remove.call_args_list],
            [(123, 7), (123, 9)],
        )
        close.assert_called_once_with(123)
        self.assertIsNone(guard.descriptor)
        self.assertEqual(guard.watches, set())
        self.assertEqual(guard.root_watches, set())

    def test_transition_fingerprint_binds_root_xattrs_not_lock_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ".git"
            root.mkdir(mode=0o755)
            xattrs = {"payload": b""}

            with mock.patch.object(
                runtime,
                "_stable_xattr_payload",
                side_effect=lambda path, _metadata, **_options: (
                    xattrs["payload"] if path == root else b""
                ),
            ):
                baseline = runtime._git_metadata_transition_fingerprint((root,))
                os.chmod(root, 0o700)
                self.assertEqual(
                    runtime._git_metadata_transition_fingerprint((root,)),
                    baseline,
                )
                xattrs["payload"] = b"external-root-xattr"
                self.assertNotEqual(
                    runtime._git_metadata_transition_fingerprint((root,)),
                    baseline,
                )

    def test_transition_acl_normalization_ignores_only_chmod_fields(self) -> None:
        header = struct.pack("<I", 2)
        entries = (
            (0x01, 0o7, 0xFFFFFFFF),
            (0x02, 0o6, 1001),
            (0x04, 0o5, 0xFFFFFFFF),
            (0x10, 0o5, 0xFFFFFFFF),
            (0x20, 0o5, 0xFFFFFFFF),
        )

        def acl(values) -> bytes:
            return header + b"".join(
                struct.pack("<HHI", *entry) for entry in values
            )

        baseline = runtime._normalize_posix_acl_mode_entries(acl(entries))
        chmod_rewrite = tuple(
            (tag, 0 if tag in {0x01, 0x10, 0x20} else permissions, identifier)
            for tag, permissions, identifier in entries
        )
        self.assertEqual(
            runtime._normalize_posix_acl_mode_entries(acl(chmod_rewrite)),
            baseline,
        )
        named_entry_drift = list(entries)
        named_entry_drift[1] = (0x02, 0o4, 1001)
        self.assertNotEqual(
            runtime._normalize_posix_acl_mode_entries(acl(named_entry_drift)),
            baseline,
        )

    def test_repository_parent_fingerprint_rejects_xattr_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            xattrs = {"payload": b"baseline"}
            with (
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
                mock.patch.object(
                    runtime,
                    "_stable_xattr_payload",
                    side_effect=lambda *_args, **_kwargs: xattrs["payload"],
                ),
            ):
                record = runtime._repository_parent_metadata()
                runtime._assert_repository_parent_xattrs(record)
                xattrs["payload"] = b"named-acl-drift"
                with self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_REPOSITORY_PARENT_RED",
                ):
                    runtime._assert_repository_parent_xattrs(record)

    def test_repository_root_fingerprint_rejects_drift_before_chown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            xattrs = {"payload": b"baseline"}
            with mock.patch.object(
                runtime,
                "_stable_xattr_payload",
                side_effect=lambda path, _metadata, **_options: (
                    xattrs["payload"] if path == repository else b""
                ),
            ):
                record = runtime._repository_path_metadata(repository)
                record["root_xattr_fingerprint"] = (
                    runtime._repository_root_xattr_fingerprint(repository)
                )
                xattrs["payload"] = b"root-xattr-drift"
                with (
                    mock.patch.object(runtime.os, "geteuid", return_value=0),
                    mock.patch.object(runtime.os, "chown") as chown,
                    self.assertRaisesRegex(
                        runtime.S12ControlError,
                        "S12_1_RECOVERY_GIT_BARRIER_RED",
                    ),
                ):
                    runtime._lock_repository_root(repository, record)
                chown.assert_not_called()

    def test_legacy_parent_upgrade_accepts_well_formed_named_acl_principal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x02, 0o7, 1001),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o7, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
            ):
                runtime._assert_legacy_repository_parent_xattrs_safe()

    def test_legacy_directory_xattrs_allow_well_formed_posix_acls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o5, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=[
                        "system.posix_acl_access",
                        "system.posix_acl_default",
                    ],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    path, "S12_1_TEST_RED"
                )

            named_acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x02, 0o7, 1000),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o5, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=named_acl,
                    create=True,
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    path, "S12_1_TEST_RED"
                )

            duplicate_named_acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x02, 0o7, 1000),
                    (0x02, 0o5, 1000),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o5, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=duplicate_named_acl,
                    create=True,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_TEST_RED"
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    path, "S12_1_TEST_RED"
                )

            unmasked_named_acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x08, 0o5, 1001),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=unmasked_named_acl,
                    create=True,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_TEST_RED"
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    path, "S12_1_TEST_RED"
                )

            regular = path / "tracked.txt"
            regular.write_text("tracked", encoding="utf-8")
            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_default"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_TEST_RED"
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    regular, "S12_1_TEST_RED"
                )

            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["user.unbound"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=b"",
                    create=True,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_TEST_RED"
                ),
            ):
                runtime._assert_legacy_path_xattrs_safe(
                    path, "S12_1_TEST_RED"
                )

    def test_release_finalizer_rechecks_quiescence_after_watch_shutdown(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.descriptor = 123
        guard.fanotify_descriptor = None
        guard.fanotify_error = False
        observed: list[str] = []

        with (
            mock.patch.object(
                guard,
                "assert_no_events",
                side_effect=lambda: observed.append("drain"),
            ),
            mock.patch.object(
                guard,
                "_synchronized_inotify_shutdown",
                side_effect=lambda: (
                    setattr(guard, "descriptor", None),
                    observed.append("shutdown-watches"),
                ),
            ),
            mock.patch.object(
                guard,
                "close",
                side_effect=lambda: observed.append("shutdown"),
            ),
        ):
            guard.finalize_release(
                lambda: observed.append(f"validate:{guard.descriptor}"),
                lambda: observed.append(f"quiesced:{guard.descriptor}"),
            )

        self.assertEqual(
            observed,
            [
                "drain",
                "validate:123",
                "shutdown-watches",
                "quiesced:None",
                "shutdown",
            ],
        )

    def test_inotify_shutdown_requires_every_ignored_barrier(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.descriptor = 123
        guard.inotify_watches = {7, 9}
        remove = mock.MagicMock(return_value=0)
        library = SimpleNamespace(inotify_rm_watch=remove)
        payload = b"".join(
            guard._EVENT.pack(watch, guard._IN_IGNORED, 0, 0)
            for watch in (7, 9)
        )

        with (
            mock.patch.object(runtime.ctypes, "CDLL", return_value=library),
            mock.patch.object(runtime.os, "read", return_value=payload),
            mock.patch.object(runtime.os, "close") as close,
        ):
            guard._synchronized_inotify_shutdown()

        self.assertEqual(
            [call.args for call in remove.call_args_list],
            [(123, 7), (123, 9)],
        )
        close.assert_called_once_with(123)
        self.assertIsNone(guard.descriptor)
        self.assertEqual(guard.inotify_watches, set())

    def test_release_finalizer_keeps_fanotify_on_validation_failure(self) -> None:
        guard = object.__new__(runtime._WorktreeReleaseGuard)
        guard.descriptor = 123
        guard.fanotify_descriptor = None

        with (
            mock.patch.object(guard, "assert_no_events"),
            mock.patch.object(guard, "_synchronized_inotify_shutdown"),
            mock.patch.object(guard, "close") as shutdown,
            self.assertRaisesRegex(RuntimeError, "final validation failed"),
        ):
            guard.finalize_release(
                lambda: (_ for _ in ()).throw(
                    RuntimeError("final validation failed")
                ),
                lambda: None,
            )

        shutdown.assert_not_called()
        self.assertEqual(guard.descriptor, 123)

    def test_guarded_handle_quiescence_uses_crash_safe_ptrace_lifecycle(self) -> None:
        quiescence = runtime._GuardedHandleQuiescence(
            (Path("/guarded/file"),), (Path("/guarded"),)
        )
        running = {123: ("S", 456)}
        stopped = {123: ("t", 456)}
        ptrace = mock.MagicMock()

        with (
            mock.patch.object(runtime.os, "geteuid", return_value=0),
            mock.patch.object(
                runtime,
                "_guarded_handle_processes",
                side_effect=(running, stopped, stopped),
            ),
            mock.patch.object(
                runtime,
                "_process_state_and_start_time",
                side_effect=(("S", 456), ("t", 456), ("t", 789)),
            ),
            mock.patch.object(
                runtime.os, "pidfd_open", return_value=77, create=True
            ),
            mock.patch.object(
                runtime,
                "_process_threads",
                return_value={123: 789},
            ),
            mock.patch.object(runtime, "_ptrace", ptrace),
            mock.patch.object(runtime, "_wait_ptrace_stop", return_value=0),
            mock.patch.object(runtime.os, "close") as close,
        ):
            quiescence.acquire()
            quiescence.close()

        self.assertEqual(
            [call.args for call in ptrace.call_args_list],
            [
                (runtime._PTRACE_SEIZE, 123),
                (runtime._PTRACE_INTERRUPT, 123),
                (runtime._PTRACE_DETACH, 123, 0),
            ],
        )
        close.assert_called_once_with(77)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_guarded_handle_scan_includes_controller_parent_holder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guarded = root / "guarded.txt"
            guarded.write_text("read-only holder\n", encoding="ascii")
            child_code = (
                "import os,sys;from pathlib import Path;"
                "from scripts import tu1nz_adult_commercial_s12_1_runtime as r;"
                "holders=r._guarded_handle_processes((Path(sys.argv[1]),),"
                "(Path(sys.argv[2]),));"
                "print('included' if os.getppid() in holders else 'excluded')"
            )
            with guarded.open("rb"):
                child = subprocess.run(
                    [sys.executable, "-c", child_code, str(guarded), str(root)],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            self.assertEqual(child.stdout.strip(), "included")

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_guarded_handle_scan_skips_deleted_journal_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "deleted-by-checkout.txt"

            self.assertEqual(
                runtime._guarded_handle_processes((missing,), (root,)),
                {},
            )

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux /proc required")
    def test_guarded_handle_scan_continues_after_unlinked_directory_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deleted = root / "deleted-directory"
            deleted.mkdir()
            guarded = root / "guarded.txt"
            guarded.write_text("read-only holder\n", encoding="ascii")
            child_code = (
                "import os,sys,time;"
                "directory_fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY);"
                "os.rmdir(sys.argv[1]);"
                "guarded_fd=os.open(sys.argv[2],os.O_RDONLY);"
                "print('ready',flush=True);time.sleep(30)"
            )
            child = subprocess.Popen(
                [sys.executable, "-c", child_code, str(deleted), str(guarded)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                holders = runtime._guarded_handle_processes(
                    (guarded,), (root,)
                )
                self.assertIn(child.pid, holders)
            finally:
                child.terminate()
                child.wait(timeout=5)

    def test_guarded_handle_quiescence_detaches_after_stop_wait_failure(self) -> None:
        quiescence = runtime._GuardedHandleQuiescence(
            (Path("/guarded/file"),), (Path("/guarded"),)
        )
        ptrace = mock.MagicMock()

        with (
            mock.patch.object(runtime.os, "geteuid", return_value=0),
            mock.patch.object(
                runtime,
                "_guarded_handle_processes",
                return_value={123: ("S", 456)},
            ),
            mock.patch.object(
                runtime,
                "_process_state_and_start_time",
                return_value=("S", 456),
            ),
            mock.patch.object(
                runtime.os, "pidfd_open", return_value=77, create=True
            ),
            mock.patch.object(
                runtime,
                "_process_threads",
                return_value={123: 789},
            ),
            mock.patch.object(runtime, "_ptrace", ptrace),
            mock.patch.object(
                runtime,
                "_wait_ptrace_stop",
                side_effect=(
                    runtime.S12ControlError(
                        "S12_1_RECOVERY_WORKTREE_HANDLE_RED"
                    ),
                    0,
                ),
            ),
            mock.patch.object(runtime.os, "close") as close,
        ):
            with self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_HANDLE_RED",
            ):
                quiescence.acquire()
            quiescence.close()

        self.assertEqual(
            [call.args for call in ptrace.call_args_list],
            [
                (runtime._PTRACE_SEIZE, 123),
                (runtime._PTRACE_INTERRUPT, 123),
                (runtime._PTRACE_INTERRUPT, 123),
                (runtime._PTRACE_DETACH, 123, 0),
            ],
        )
        close.assert_called_once_with(77)

    def test_release_fingerprints_normalize_only_acl_mode_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = struct.pack("<I", 2)
            entries = [
                (0x01, 0o7, 0xFFFFFFFF),
                (0x02, 0o6, 1001),
                (0x04, 0o5, 0xFFFFFFFF),
                (0x10, 0o5, 0xFFFFFFFF),
                (0x20, 0o5, 0xFFFFFFFF),
            ]

            def encoded_acl() -> bytes:
                return header + b"".join(
                    struct.pack("<HHI", *entry) for entry in entries
                )

            with (
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    side_effect=lambda *_args, **_kwargs: encoded_acl(),
                    create=True,
                ),
            ):
                baseline = runtime._release_xattr_fingerprint((root,))
                entries[0] = (0x01, 0o5, 0xFFFFFFFF)
                entries[3] = (0x10, 0o0, 0xFFFFFFFF)
                entries[4] = (0x20, 0o0, 0xFFFFFFFF)
                self.assertEqual(
                    runtime._release_xattr_fingerprint((root,)), baseline
                )
                entries[1] = (0x02, 0o4, 1001)
                self.assertNotEqual(
                    runtime._release_xattr_fingerprint((root,)), baseline
                )

    def test_worktree_barrier_rejects_file_capability_before_chown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracked = root / "tracked"
            tracked.write_text("reviewed\n", encoding="ascii")
            metadata = tracked.lstat()
            records = {
                root: {
                    tracked: {
                        "kind": "regular",
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                        "uid": metadata.st_uid,
                        "gid": metadata.st_gid,
                        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    }
                }
            }
            with (
                mock.patch.object(runtime.os, "geteuid", return_value=0),
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["security.capability"],
                    create=True,
                ),
                mock.patch.object(
                    runtime, "_assert_worktree_path_xattrs"
                ),
                mock.patch.object(runtime.os, "chown") as chown,
                self.assertRaisesRegex(
                    runtime.S12ControlError,
                    "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                ),
            ):
                runtime._lock_worktree_write_barrier(records)

            chown.assert_not_called()

    def test_closed_mmap_writer_is_detected_after_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
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
            config = repository / ".git/config"
            original_install = runtime._install_repository_recovery_barrier

            def mutate_quarantined_metadata(
                root: Path, record: dict[str, object]
            ) -> Path:
                recovery = original_install(root, record)
                quarantined_config = recovery / "config"
                with quarantined_config.open("r+b") as handle:
                    mapping = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE)
                    try:
                        mapping[0:1] = b"#"
                        mapping.flush()
                    finally:
                        mapping.close()
                return recovery

            with (
                mock.patch.object(
                    runtime, "_competing_control_sync_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_repository_git_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_recovery_git_handle_count", return_value=0
                ),
                mock.patch.object(
                    runtime,
                    "_active_tracked_worktree_write_handle_count",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime,
                    "_install_repository_recovery_barrier",
                    side_effect=mutate_quarantined_metadata,
                ),
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_RECOVERY_GIT_ACTIVE_RED"
                ),
            ):
                with runtime._serialized_repository_recovery((repository,)):
                    self.fail("closed mmap writer reached protected body")
            self.assertTrue(config.is_file())
            self.assertFalse(runtime._recovery_git_path(repository).exists())

    def test_metadata_barrier_modes_preserve_existing_traversal_classes(self) -> None:
        self.assertEqual(runtime._metadata_barrier_mode(0o2770), 0o2550)
        self.assertEqual(runtime._metadata_barrier_mode(0o2775), 0o2555)
        self.assertEqual(runtime._metadata_barrier_mode(0o755), 0o555)
        with self.assertRaisesRegex(
            runtime.S12ControlError, "S12_1_RECOVERY_GIT_BARRIER_RED"
        ):
            runtime._metadata_barrier_mode(0o600)
        with self.assertRaisesRegex(
            runtime.S12ControlError, "S12_1_RECOVERY_GIT_BARRIER_RED"
        ):
            runtime._metadata_barrier_mode(0o700)

    def test_parent_and_repository_root_reject_named_owner_acl_before_chown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            parent.chmod(0o775)
            repository.chmod(0o775)
            uid = parent.lstat().st_uid
            if uid == 0:
                uid = 65534
                os.chown(parent, uid, parent.lstat().st_gid)
                os.chown(repository, uid, repository.lstat().st_gid)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (0x01, 0o7, 0xFFFFFFFF),
                    (0x02, 0o0, uid),
                    (0x04, 0o5, 0xFFFFFFFF),
                    (0x10, 0o5, 0xFFFFFFFF),
                    (0x20, 0o5, 0xFFFFFFFF),
                )
            )

            with (
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
                mock.patch.object(
                    runtime.os,
                    "listxattr",
                    return_value=["system.posix_acl_access"],
                    create=True,
                ),
                mock.patch.object(
                    runtime.os,
                    "getxattr",
                    return_value=acl,
                    create=True,
                ),
                mock.patch.object(runtime, "_assert_repository_root_xattrs"),
            ):
                parent_record = runtime._repository_parent_metadata()
                repository_record = runtime._repository_path_metadata(repository)
                for target, action, error in (
                    (
                        parent,
                        lambda: runtime._lock_repository_parent(parent_record),
                        "S12_1_REPOSITORY_PARENT_RED",
                    ),
                    (
                        repository,
                        lambda: runtime._lock_repository_root(
                            repository, repository_record
                        ),
                        "S12_1_RECOVERY_GIT_BARRIER_RED",
                    ),
                ):
                    with self.subTest(target=target):
                        with (
                            mock.patch.object(
                                runtime.os, "geteuid", return_value=0
                            ),
                            mock.patch.object(runtime.os, "chmod"),
                            mock.patch.object(runtime.os, "chown") as chown,
                            self.assertRaisesRegex(
                                runtime.S12ControlError, error
                            ),
                        ):
                            action()
                        chown.assert_not_called()

    def test_group_writable_canonical_git_metadata_is_scannable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            git_directory = repository / ".git"
            git_directory.chmod(0o2770)
            self.assertEqual(
                runtime._repository_git_metadata_paths((repository,)),
                (git_directory,),
            )

    def test_git_metadata_lock_resumes_recorded_owner_0700_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            git_directory = repository / ".git"
            git_directory.mkdir(parents=True)
            record = {
                "git_uid": 501,
                "git_gid": 20,
                "git_mode": "2770",
            }
            transition = SimpleNamespace(
                st_uid=501,
                st_gid=20,
                st_mode=stat.S_IFDIR | 0o700,
            )
            locked = SimpleNamespace(
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFDIR | 0o700,
            )
            state = {"locked": False}
            real_lstat = Path.lstat

            def recovery_lstat(path: Path):
                if path == git_directory:
                    return locked if state["locked"] else transition
                return real_lstat(path)

            def finish_chown(*_args, **_kwargs) -> None:
                state["locked"] = True

            with (
                mock.patch.object(runtime.os, "geteuid", return_value=0),
                mock.patch.object(Path, "lstat", new=recovery_lstat),
                mock.patch.object(runtime.os, "chmod") as chmod,
                mock.patch.object(runtime.os, "chown", side_effect=finish_chown) as chown,
                mock.patch.object(runtime, "_fsync_directory"),
            ):
                runtime._lock_repository_git_metadata(repository, record)
            chown.assert_called_once_with(git_directory, 0, 0)
            chmod.assert_called_once_with(git_directory, 0o700)

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
                mock.patch.object(
                    runtime,
                    "_active_tracked_worktree_write_handle_count",
                    return_value=0,
                ),
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

    def test_recovery_barrier_is_preserved_when_restore_body_fails(self) -> None:
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
            (repository / "tracked.txt").write_text("reviewed\n", encoding="ascii")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "reviewed"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            records = {repository: runtime._repository_path_metadata(repository)}
            checks = (
                mock.patch.object(runtime, "_competing_control_sync_count", return_value=0),
                mock.patch.object(runtime, "_active_repository_git_count", return_value=0),
                mock.patch.object(runtime, "_active_recovery_git_handle_count", return_value=0),
                mock.patch.object(
                    runtime,
                    "_active_tracked_worktree_write_handle_count",
                    return_value=0,
                ),
            )
            with checks[0], checks[1], checks[2], checks[3]:
                with self.assertRaisesRegex(RuntimeError, "restore interrupted"):
                    with runtime._serialized_repository_recovery(
                        roots=(repository,),
                        records=records,
                        preserve_on_error=True,
                    ):
                        raise RuntimeError("restore interrupted")
                self.assertTrue(runtime._is_recovery_guard(repository / ".git"))
                self.assertTrue(
                    runtime._is_recovery_git_directory(
                        runtime._recovery_git_path(repository)
                    )
                )
                with runtime._serialized_repository_recovery(
                    roots=(repository,), records=records
                ):
                    pass
            self.assertTrue((repository / ".git").is_dir())
            self.assertFalse(runtime._recovery_git_path(repository).exists())

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
        restored_state = {"application": {}, "control": {}}
        restored_progress = {
            "schema": runtime.ROLLBACK_PROGRESS_SCHEMA,
            "backup": str(backup),
            "phase": runtime.ROLLBACK_PHASE_REPOSITORIES_RESTORED,
            "repository_state": restored_state,
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
            if path == backup / "rollback-progress.json":
                events.append(f"progress:{payload['phase']}")
            else:
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
            mock.patch.object(runtime, "_validate_ignored_backup_collisions"),
            mock.patch.object(runtime, "_recorded_parent_metadata"),
            mock.patch.object(runtime, "_ensure_barrier_journal"),
            mock.patch.object(runtime, "_durable_unlink"),
            mock.patch.object(
                runtime,
                "_serialized_repository_recovery",
                side_effect=recovery_barrier,
            ),
            mock.patch.object(runtime, "_restore_repository"),
            mock.patch.object(
                runtime, "_release_repository_states", return_value=restored_state
            ),
            mock.patch.object(
                runtime,
                "_load_rollback_progress",
                side_effect=[None, restored_progress],
            ),
            mock.patch.object(
                runtime, "_validate_release_repository_states"
            ) as validate,
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
                f"progress:{runtime.ROLLBACK_PHASE_STARTED}",
                "sync:application",
                "sync:control",
                f"progress:{runtime.ROLLBACK_PHASE_REPOSITORIES_RESTORED}",
                "barrier-exit",
                "barrier-enter",
                "sync:application",
                "sync:control",
                "daemon-reload",
                "marker",
                "barrier-exit",
                "sync:application",
                "sync:control",
            ],
        )
        validate.assert_called_once_with(
            restored_state,
            {
                application: application / ".git.recovery",
                control: control / ".git.recovery",
            },
            {application: {}, control: {}},
        )

    def test_rollback_rejects_post_release_drift_before_mutation(self) -> None:
        backup = Path("/backup")
        index = {
            "application": {},
            "control": {},
            "repository_parent": {},
        }

        @contextmanager
        def recovery_barrier(**_kwargs):
            yield {
                runtime.APPLICATION_ROOT: Path("/recovery/application"),
                runtime.CONTROL_ROOT: Path("/recovery/control"),
            }

        with (
            mock.patch.object(
                runtime, "_rollback_unit_state", return_value=("inactive", "dead")
            ),
            mock.patch.object(runtime, "_recorded_parent_metadata"),
            mock.patch.object(runtime, "_ensure_barrier_journal"),
            mock.patch.object(
                runtime, "_restore_public_nginx_backup"
            ) as restore_nginx,
            mock.patch.object(
                runtime,
                "_serialized_repository_recovery",
                side_effect=recovery_barrier,
            ),
            mock.patch.object(
                runtime,
                "_validate_release_repository_states",
                side_effect=runtime.S12ControlError(
                    "S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED"
                ),
            ),
            mock.patch.object(runtime, "_remove_release_stages") as remove_stages,
            mock.patch.object(Path, "exists", return_value=False),
            self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_REPOSITORY_POST_RELEASE_DRIFT_RED",
            ),
        ):
            runtime.rollback_once(
                backup,
                index,
                {"application": {}, "control": {}},
            )

        restore_nginx.assert_called_once_with(backup, index)
        remove_stages.assert_not_called()

    def test_recovery_finalizes_completed_repository_restore_without_replay(self) -> None:
        backup = Path("/private/backup")
        index: dict[str, object] = {}
        with (
            mock.patch.object(
                runtime, "_rollback_unit_state", return_value=("inactive", "dead")
            ),
            mock.patch.object(runtime, "_restore_public_nginx_backup") as nginx,
            mock.patch.object(
                runtime,
                "_load_rollback_progress",
                return_value={
                    "schema": runtime.ROLLBACK_PROGRESS_SCHEMA,
                    "backup": str(backup),
                    "phase": runtime.ROLLBACK_PHASE_REPOSITORIES_RESTORED,
                    "repository_state": {"application": {}, "control": {}},
                },
            ),
            mock.patch.object(runtime, "_recover_repository_barrier_only") as barrier,
            mock.patch.object(runtime, "_finalize_rollback") as finalize,
            mock.patch.object(runtime, "_serialized_repository_recovery") as recovery,
            mock.patch.object(runtime, "_restore_repositories_under_barrier") as restore,
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "is_symlink", return_value=False),
        ):
            runtime.rollback_once(backup, index)

        nginx.assert_called_once_with(backup, index)
        barrier.assert_not_called()
        recovery.assert_not_called()
        restore.assert_not_called()
        finalize.assert_called_once_with(backup, index)

    def test_started_rollback_requires_still_installed_barriers(self) -> None:
        backup = Path("/private/backup")
        index: dict[str, object] = {}
        with (
            mock.patch.object(
                runtime, "_rollback_unit_state", return_value=("inactive", "dead")
            ),
            mock.patch.object(runtime, "_restore_public_nginx_backup"),
            mock.patch.object(
                runtime,
                "_load_rollback_progress",
                return_value={
                    "schema": runtime.ROLLBACK_PROGRESS_SCHEMA,
                    "backup": str(backup),
                    "phase": runtime.ROLLBACK_PHASE_STARTED,
                },
            ),
            mock.patch.object(
                runtime, "_repository_barriers_are_installed", return_value=False
            ),
            mock.patch.object(Path, "exists", return_value=False),
            self.assertRaisesRegex(
                runtime.S12ControlError, "S12_1_ROLLBACK_PROGRESS_RED"
            ),
        ):
            runtime.rollback_once(backup, index)

    def test_started_rollback_resumes_without_rechecking_post_sync_state(self) -> None:
        backup = Path("/private/backup")
        index = {
            "application": {},
            "control": {},
            "repository_parent": {},
        }
        git_directories = {
            runtime.APPLICATION_ROOT: Path("/recovery/application"),
            runtime.CONTROL_ROOT: Path("/recovery/control"),
        }
        progress = {
            "schema": runtime.ROLLBACK_PROGRESS_SCHEMA,
            "backup": str(backup),
            "phase": runtime.ROLLBACK_PHASE_STARTED,
        }

        @contextmanager
        def recovery_barrier(**_kwargs):
            yield git_directories

        with (
            mock.patch.object(
                runtime, "_rollback_unit_state", return_value=("inactive", "dead")
            ),
            mock.patch.object(runtime, "_restore_public_nginx_backup"),
            mock.patch.object(
                runtime,
                "_load_rollback_progress",
                return_value=progress,
            ),
            mock.patch.object(
                runtime, "_repository_barriers_are_installed", return_value=True
            ),
            mock.patch.object(runtime, "_recorded_parent_metadata"),
            mock.patch.object(runtime, "_ensure_barrier_journal"),
            mock.patch.object(
                runtime,
                "_serialized_repository_recovery",
                side_effect=recovery_barrier,
            ),
            mock.patch.object(
                runtime, "_validate_release_repository_states"
            ) as validate,
            mock.patch.object(runtime, "_perform_restore_under_barrier") as restore,
            mock.patch.object(runtime, "_finalize_rollback") as finalize,
            mock.patch.object(Path, "exists", return_value=False),
        ):
            runtime.rollback_once(
                backup,
                index,
                {"application": {}, "control": {}},
            )

        validate.assert_not_called()
        restore.assert_called_once_with(
            backup,
            index,
            git_directories,
            progress,
            {
                runtime.APPLICATION_ROOT: {},
                runtime.CONTROL_ROOT: {},
            },
        )
        finalize.assert_called_once_with(backup, index)

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
            rollback.assert_called_once_with(backup, {}, None)
            self.assertEqual(result["safe_code"], "S12_1_INTERRUPTED_DEPLOYMENT_RECOVERED")
            self.assertNotIn("deployment_count", result)

    def test_pristine_legacy_orphan_recovery_skips_new_barrier_transition(
        self,
    ) -> None:
        records = {
            runtime.APPLICATION_ROOT: {},
            runtime.CONTROL_ROOT: {},
        }
        parent_record: dict[str, object] = {}
        metadata_guard = mock.Mock(unsafe=True)
        worktree_guard = mock.Mock(unsafe=True)
        with (
            mock.patch.object(
                runtime,
                "_load_barrier_journal",
                return_value=(
                    records,
                    parent_record,
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                ),
            ),
            mock.patch.object(
                runtime,
                "_pristine_legacy_orphan_is_releasable",
                side_effect=(True, True, True),
            ) as releasable,
            mock.patch.object(
                runtime,
                "_repository_git_metadata_paths",
                return_value=(Path("/application/.git"), Path("/control/.git")),
            ),
            mock.patch.object(
                runtime,
                "_tracked_worktree_barrier_paths",
                return_value=(),
            ),
            mock.patch.object(
                runtime,
                "_GitMetadataTransitionGuard",
                return_value=metadata_guard,
            ) as metadata_guard_type,
            mock.patch.object(
                runtime,
                "_WorktreeReleaseGuard",
                return_value=worktree_guard,
            ) as worktree_guard_type,
            mock.patch.object(
                runtime, "_sync_repository_filesystem"
            ) as sync,
            mock.patch.object(
                runtime, "_prepare_barrier_release_backup"
            ) as prepare_release_backup,
            mock.patch.object(
                runtime, "_write_barrier_release_completion"
            ) as write_release_completion,
            mock.patch.object(runtime, "_durable_unlink") as unlink,
            mock.patch.object(runtime, "_ensure_barrier_journal") as ensure,
            mock.patch.object(
                runtime, "_serialized_repository_recovery"
            ) as barrier,
        ):
            result = runtime._recover_repository_barrier_only()

        self.assertEqual(
            releasable.call_args_list,
            [
                mock.call(
                    records,
                    parent_record,
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                    guarded_git_checks=False,
                ),
                mock.call(
                    records,
                    parent_record,
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                ),
                mock.call(
                    records,
                    parent_record,
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                ),
            ],
        )
        metadata_guard_type.assert_called_once_with(
            (Path("/application/.git"), Path("/control/.git")),
            allow_root_lock_events=False,
        )
        worktree_guard_type.assert_called_once_with(
            (
                runtime.DEPLOYMENT_LOCK_ROOT,
                runtime.APPLICATION_ROOT,
                runtime.CONTROL_ROOT,
            ),
            tracked_paths=(),
        )
        self.assertEqual(
            sync.call_args_list,
            [
                mock.call(runtime.APPLICATION_ROOT),
                mock.call(runtime.CONTROL_ROOT),
            ],
        )
        prepare_release_backup.assert_called_once_with()
        write_release_completion.assert_called_once_with()
        self.assertEqual(
            unlink.call_args_list,
            [
                mock.call(runtime.BARRIER_MARKER),
                mock.call(runtime.BARRIER_RELEASE_BACKUP),
            ],
        )
        worktree_guard.finalize_release.assert_called_once_with(
            metadata_guard.assert_unchanged,
            metadata_guard.assert_unchanged,
        )
        metadata_guard.finalize_release.assert_called_once_with()
        ensure.assert_not_called()
        barrier.assert_not_called()
        self.assertEqual(result["safe_code"], "S12_1_ORPHAN_BARRIER_RECOVERED")
        self.assertEqual(result["rollback_count"], 0)

    def test_pristine_legacy_orphan_retains_backup_when_guard_finalization_fails(
        self,
    ) -> None:
        metadata_guard = mock.Mock(unsafe=True)
        worktree_guard = mock.Mock(unsafe=True)
        worktree_guard.finalize_release.side_effect = runtime.S12ControlError(
            "S12_1_RECOVERY_WORKTREE_BARRIER_RED"
        )
        with (
            mock.patch.object(
                runtime,
                "_load_barrier_journal",
                return_value=(
                    {
                        runtime.APPLICATION_ROOT: {},
                        runtime.CONTROL_ROOT: {},
                    },
                    {},
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                ),
            ),
            mock.patch.object(
                runtime,
                "_pristine_legacy_orphan_is_releasable",
                side_effect=(True, True, True),
            ),
            mock.patch.object(
                runtime,
                "_repository_git_metadata_paths",
                return_value=(Path("/application/.git"), Path("/control/.git")),
            ),
            mock.patch.object(
                runtime, "_tracked_worktree_barrier_paths", return_value=()
            ),
            mock.patch.object(
                runtime,
                "_GitMetadataTransitionGuard",
                return_value=metadata_guard,
            ),
            mock.patch.object(
                runtime,
                "_WorktreeReleaseGuard",
                return_value=worktree_guard,
            ),
            mock.patch.object(runtime, "_sync_repository_filesystem"),
            mock.patch.object(runtime, "_prepare_barrier_release_backup") as prepare,
            mock.patch.object(runtime, "_durable_unlink") as unlink,
            self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
            ),
        ):
            runtime._recover_repository_barrier_only()

        prepare.assert_called_once_with()
        unlink.assert_called_once_with(runtime.BARRIER_MARKER)
        metadata_guard.finalize_release.assert_not_called()

    def test_barrier_release_backup_restores_interrupted_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            marker = state / "repository-barrier.json"
            backup = state / "repository-barrier.release-backup.json"
            marker.write_text("{}\n", encoding="ascii")
            marker.chmod(0o600)
            with (
                mock.patch.object(runtime, "STATE_ROOT", state),
                mock.patch.object(runtime, "BARRIER_MARKER", marker),
                mock.patch.object(runtime, "BARRIER_RELEASE_BACKUP", backup),
            ):
                runtime._prepare_barrier_release_backup()
                self.assertEqual(marker.stat().st_ino, backup.stat().st_ino)
                self.assertEqual(marker.stat().st_nlink, 2)
                runtime._durable_unlink(marker)
                runtime._normalize_barrier_release_backup()

            self.assertTrue(marker.is_file())
            self.assertFalse(backup.exists())
            self.assertEqual(marker.stat().st_nlink, 1)

    def test_completed_barrier_release_is_retryable_without_journal_link(
        self,
    ) -> None:
        completion = {
            "schema": runtime.BARRIER_RELEASE_COMPLETION_SCHEMA,
            "completed_at": "2026-10-02T00:00:00Z",
            "journal_sha256": "a" * 64,
        }
        with (
            mock.patch.object(runtime.os, "geteuid", return_value=0),
            mock.patch.object(runtime, "_normalize_barrier_release_backup"),
            mock.patch.object(runtime, "_barrier_journal_present", return_value=False),
            mock.patch.object(runtime, "_barrier_release_completion", return_value=completion),
            mock.patch.object(runtime, "ATTEMPT_MARKER", Path("/missing-attempt")),
            mock.patch.object(runtime, "_atomic_json") as atomic_json,
        ):
            result = runtime._recover_locked()

        self.assertEqual(result["safe_code"], "S12_1_ORPHAN_BARRIER_RECOVERED")
        self.assertEqual(result["rollback_count"], 0)
        atomic_json.assert_called_once_with(
            runtime.STATE_ROOT / "recovery-result.json", result
        )

    def test_completed_barrier_release_keeps_backup_until_completion_fsync(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            marker = state / "repository-barrier.json"
            backup = state / "repository-barrier.release-backup.json"
            completion_path = state / "repository-barrier.release-complete.json"
            backup.write_text("{}\n", encoding="ascii")
            backup.chmod(0o600)
            completion = {
                "schema": runtime.BARRIER_RELEASE_COMPLETION_SCHEMA,
                "completed_at": "2026-10-02T00:00:00Z",
                "journal_sha256": runtime._sha256(backup),
            }
            with (
                mock.patch.object(runtime, "STATE_ROOT", state),
                mock.patch.object(runtime, "BARRIER_MARKER", marker),
                mock.patch.object(runtime, "BARRIER_RELEASE_BACKUP", backup),
                mock.patch.object(
                    runtime, "BARRIER_RELEASE_COMPLETION", completion_path
                ),
                mock.patch.object(
                    runtime,
                    "_barrier_release_completion",
                    return_value=completion,
                ),
                mock.patch.object(
                    runtime,
                    "_fsync_directory",
                    side_effect=runtime.S12ControlError("S12_1_DURABILITY_RED"),
                ),
                mock.patch.object(runtime, "_durable_unlink") as unlink,
                self.assertRaisesRegex(
                    runtime.S12ControlError, "S12_1_DURABILITY_RED"
                ),
            ):
                runtime._normalize_barrier_release_backup()

            unlink.assert_not_called()
            self.assertTrue(backup.is_file())

    def test_pristine_legacy_orphan_rechecks_before_journal_release(self) -> None:
        metadata_guard = mock.Mock(unsafe=True)
        worktree_guard = mock.Mock(unsafe=True)
        with (
            mock.patch.object(
                runtime,
                "_load_barrier_journal",
                return_value=(
                    {
                        runtime.APPLICATION_ROOT: {},
                        runtime.CONTROL_ROOT: {},
                    },
                    {},
                    None,
                    runtime.LEGACY_BARRIER_SCHEMA,
                ),
            ),
            mock.patch.object(
                runtime,
                "_pristine_legacy_orphan_is_releasable",
                side_effect=(True, True, False),
            ),
            mock.patch.object(
                runtime,
                "_repository_git_metadata_paths",
                return_value=(Path("/application/.git"), Path("/control/.git")),
            ),
            mock.patch.object(
                runtime,
                "_tracked_worktree_barrier_paths",
                return_value=(),
            ),
            mock.patch.object(
                runtime,
                "_GitMetadataTransitionGuard",
                return_value=metadata_guard,
            ),
            mock.patch.object(
                runtime,
                "_WorktreeReleaseGuard",
                return_value=worktree_guard,
            ),
            mock.patch.object(runtime, "_sync_repository_filesystem"),
            mock.patch.object(runtime, "_durable_unlink") as unlink,
            self.assertRaisesRegex(
                runtime.S12ControlError,
                "S12_1_RECOVERY_GIT_BARRIER_RED",
            ),
        ):
            runtime._recover_repository_barrier_only()

        unlink.assert_not_called()

    def test_pristine_legacy_orphan_rejects_nonpristine_marker_shapes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            absent_attempt = root / "attempt.json"
            absent_fetch = root / "fetch"
            with (
                mock.patch.object(runtime, "ATTEMPT_MARKER", absent_attempt),
                mock.patch.object(runtime, "FETCH_ROOT", absent_fetch),
            ):
                self.assertFalse(
                    runtime._pristine_legacy_orphan_is_releasable(
                        {}, {}, {}, runtime.LEGACY_BARRIER_SCHEMA
                    )
                )
                self.assertFalse(
                    runtime._pristine_legacy_orphan_is_releasable(
                        {}, {}, None, runtime.BARRIER_SCHEMA
                    )
                )
                absent_attempt.write_text("{}\n", encoding="ascii")
                self.assertFalse(
                    runtime._pristine_legacy_orphan_is_releasable(
                        {}, {}, None, runtime.LEGACY_BARRIER_SCHEMA
                    )
                )

    def test_pristine_legacy_orphan_accepts_clean_owner_only_worktrees(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            application = parent / "application"
            control = parent / "control"
            for repository in (application, control):
                subprocess.run(
                    ["git", "init", "-b", "main", str(repository)],
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
                subprocess.run(
                    ["git", "add", "tracked.txt"],
                    cwd=repository,
                    check=True,
                )
                subprocess.run(
                    ["git", "commit", "-m", "reviewed"],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                )
                tracked.chmod(0o600)
            with (
                mock.patch.object(runtime, "APPLICATION_ROOT", application),
                mock.patch.object(runtime, "CONTROL_ROOT", control),
                mock.patch.object(runtime, "DEPLOYMENT_LOCK_ROOT", parent),
                mock.patch.object(
                    runtime, "ATTEMPT_MARKER", parent / "attempt.json"
                ),
                mock.patch.object(runtime, "FETCH_ROOT", parent / "fetch"),
                mock.patch.object(
                    runtime, "_competing_control_sync_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_active_repository_git_count", return_value=0
                ),
                mock.patch.object(
                    runtime,
                    "_active_recovery_git_handle_count",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime,
                    "_active_tracked_worktree_write_handle_count",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime, "_active_exact_directory_handle_count", return_value=0
                ),
                mock.patch.object(
                    runtime, "_assert_legacy_repository_parent_xattrs_safe"
                ) as parent_xattrs,
                mock.patch.object(
                    runtime, "_assert_legacy_path_xattrs_safe"
                ) as path_xattrs,
                mock.patch.object(
                    runtime, "_validate_root_git_contract"
                ) as root_git_contract,
            ):
                records = {
                    application: runtime._repository_path_metadata(application),
                    control: runtime._repository_path_metadata(control),
                }
                parent_record = runtime._repository_parent_metadata()
                self.assertTrue(
                    runtime._pristine_legacy_orphan_is_releasable(
                        records,
                        parent_record,
                        None,
                        runtime.LEGACY_BARRIER_SCHEMA,
                    )
                )
                parent_xattrs.assert_called_once_with()
                self.assertEqual(
                    path_xattrs.call_args_list,
                    [
                        mock.call(
                            application,
                            "S12_1_RECOVERY_GIT_BARRIER_RED",
                        ),
                        mock.call(
                            application / "tracked.txt",
                            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                        ),
                        mock.call(
                            control,
                            "S12_1_RECOVERY_GIT_BARRIER_RED",
                        ),
                        mock.call(
                            control / "tracked.txt",
                            "S12_1_RECOVERY_WORKTREE_BARRIER_RED",
                        ),
                    ],
                )
                self.assertEqual(
                    root_git_contract.call_args_list,
                    [
                        mock.call(application / ".git"),
                        mock.call(control / ".git"),
                    ],
                )
                parent_xattrs.reset_mock()
                path_xattrs.reset_mock()
                root_git_contract.reset_mock()
                with (
                    mock.patch.object(
                        runtime,
                        "_tracked_worktree_barrier_paths",
                        side_effect=AssertionError("unguarded Git path lookup"),
                    ),
                    mock.patch.object(
                        runtime,
                        "_validate_canonical_index",
                        side_effect=AssertionError("unguarded index check"),
                    ),
                    mock.patch.object(
                        runtime,
                        "_selected_identity",
                        side_effect=AssertionError("unguarded identity check"),
                    ),
                    mock.patch.object(
                        runtime,
                        "_tracked_worktree_regular_paths",
                        side_effect=AssertionError("unguarded tracked scan"),
                    ),
                ):
                    self.assertTrue(
                        runtime._pristine_legacy_orphan_is_releasable(
                            records,
                            parent_record,
                            None,
                            runtime.LEGACY_BARRIER_SCHEMA,
                            guarded_git_checks=False,
                        )
                    )
                root_git_contract.assert_not_called()
                self.assertEqual(
                    path_xattrs.call_args_list,
                    [
                        mock.call(
                            application,
                            "S12_1_RECOVERY_GIT_BARRIER_RED",
                        ),
                        mock.call(
                            control,
                            "S12_1_RECOVERY_GIT_BARRIER_RED",
                        ),
                    ],
                )

    def test_pristine_legacy_checks_use_isolated_git_configuration(self) -> None:
        repository = Path("/repository")
        git_directory = repository / ".git"
        completed = (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "a" * 40 + "\n", ""),
            subprocess.CompletedProcess([], 0, "b" * 40 + "\n", ""),
        )
        with mock.patch.object(
            runtime, "_run", side_effect=completed
        ) as run:
            identity = runtime._selected_identity(repository, git_directory)
        self.assertEqual(identity, ("a" * 40, "b" * 40))
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list:
            arguments = call.args[0]
            self.assertEqual(arguments[:3], ["/usr/bin/env", "-i", "HOME=/"])
            self.assertIn("GIT_CONFIG_NOSYSTEM=1", arguments)
            self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", arguments)
            self.assertIn("GIT_OPTIONAL_LOCKS=0", arguments)
            self.assertIn("core.hooksPath=/dev/null", arguments)
            self.assertIn("core.fsmonitor=false", arguments)
            self.assertIn(f"--git-dir={git_directory}", arguments)

        with mock.patch.object(
            runtime,
            "_bounded_nul_command_records",
            return_value=(b"H tracked.txt",),
        ) as bounded:
            runtime._validate_canonical_index(repository, git_directory)
        arguments = bounded.call_args.args[0]
        self.assertEqual(arguments[:3], ["/usr/bin/env", "-i", "HOME=/"])
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", arguments)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", arguments)
        self.assertIn("GIT_OPTIONAL_LOCKS=0", arguments)
        self.assertIn("core.hooksPath=/dev/null", arguments)
        self.assertIn("core.fsmonitor=false", arguments)
        self.assertIn(f"--git-dir={git_directory}", arguments)

    def test_isolated_pristine_identity_never_executes_local_fsmonitor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            subprocess.run(
                ["git", "init", "-b", "main", str(repository)],
                check=True,
                capture_output=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="ascii")
            subprocess.run(
                ["git", "add", "tracked.txt"], cwd=repository, check=True
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=S12 Test",
                    "-c",
                    "user.email=s12@example.invalid",
                    "commit",
                    "-m",
                    "reviewed",
                ],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            marker = Path(directory) / "fsmonitor-executed"
            hook = Path(directory) / "fsmonitor-hook"
            hook.write_text(
                f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 97\n",
                encoding="ascii",
            )
            hook.chmod(0o700)
            subprocess.run(
                ["git", "config", "core.fsmonitor", str(hook)],
                cwd=repository,
                check=True,
            )

            runtime._validate_canonical_index(repository, repository / ".git")
            commit, tree = runtime._selected_identity(
                repository, repository / ".git"
            )

            self.assertRegex(commit, r"^[0-9a-f]{40}$")
            self.assertRegex(tree, r"^[0-9a-f]{40}$")
            self.assertFalse(marker.exists())

    def test_completed_rollback_recovery_removes_lingering_barrier_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            backup = root / "backup"
            state.mkdir(mode=0o700)
            backup.mkdir(mode=0o700)
            attempt_marker = state / "deployment-attempt.json"
            barrier_marker = state / "repository-recovery.json"
            attempt_marker.write_text("{}\n", encoding="ascii")
            barrier_marker.write_text("{}\n", encoding="ascii")
            (backup / "rollback-complete.json").write_text(
                json.dumps(
                    {
                        "ok": True,
                        "safe_code": "S12_1_ROLLBACK_GREEN",
                        "count": 1,
                        "credentials_preserved": True,
                    }
                )
                + "\n",
                encoding="ascii",
            )
            with (
                mock.patch.object(runtime, "STATE_ROOT", state),
                mock.patch.object(runtime, "ATTEMPT_MARKER", attempt_marker),
                mock.patch.object(runtime, "BARRIER_MARKER", barrier_marker),
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
                mock.patch.object(
                    runtime,
                    "_private_json",
                    return_value={
                        "ok": True,
                        "safe_code": "S12_1_ROLLBACK_GREEN",
                        "count": 1,
                        "credentials_preserved": True,
                    },
                ),
                mock.patch.object(
                    runtime, "_recover_repository_barrier_only"
                ) as recover_barrier,
                mock.patch.object(runtime, "rollback_once") as rollback,
            ):
                result = runtime._recover_locked()
            recover_barrier.assert_called_once_with()
            rollback.assert_not_called()
            self.assertEqual(result["safe_code"], "S12_1_RECOVERY_ALREADY_COMPLETE")

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
            reflogs = backup / "application.reflogs" / "refs" / "heads"
            reflogs.mkdir(parents=True)
            reflog = reflogs / "main"
            reflog.write_text("history\n", encoding="ascii")
            reflog.chmod(0o640)
            with mock.patch.object(
                runtime.os, "fsync", side_effect=tracking_fsync
            ):
                runtime._durably_complete_backup(backup)
            self.assertIn(False, kinds)
            self.assertGreaterEqual(kinds.count(True), 5)
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in backup.iterdir()
                    if path.is_file()
                )
            )
            self.assertEqual(stat.S_IMODE(reflog.stat().st_mode), 0o640)

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
