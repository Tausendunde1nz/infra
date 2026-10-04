"""Real Git / installed-artifact contracts; only PID-1 is an offline boundary."""
from contextlib import ExitStack, contextmanager
import hashlib
import inspect
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from scripts import tu1nz_adult_commercial_s12_1_runtime as r

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"


def git(root, *args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(root),
                                   "-C", str(root), *args], stderr=subprocess.PIPE).decode().strip()


def function(name):
    source = SOURCE.read_text()
    start = source.index(name + "() {")
    following = re.search(r"\n[a-zA-Z_]\w*\(\) \{", source[start + 1:])
    end = start + 1 + following.start() if following else len(source)
    return source[start:end] + "\n"


@contextmanager
def installed_fixture(base, app, *, historical_pair=None):
    """Prospectively pin isolated real artifacts, never mock the verifier."""
    with ExitStack() as stack:
        installed = base / "s11-installed"
        installed.mkdir(mode=0o700)
        paths = {}
        for name, (original, mode, digest) in r.S11_ARTIFACTS.items():
            path = installed / original.name
            if name == "controller":
                data = subprocess.check_output(["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT), "show",
                    "4652b1725dd2444c805d643dcb6381dfeb423ab8:scripts/tu1nz_adult_public_s11_2_control.sh"])
            else:
                candidates = list(ROOT.glob("scripts/" + original.name)) + list(ROOT.glob("systemd/" + original.name))
                data = candidates[0].read_bytes() if candidates else (name + " fixture\n").encode()
            path.write_bytes(data); path.chmod(mode)
            paths[name] = (path, mode, hashlib.sha256(data).hexdigest())
        pair = historical_pair or (git(app, "rev-parse", "HEAD"), git(app, "rev-parse", "HEAD^{tree}"))
        access = installed / "access.json"
        payload = dict(schema="TU1NZ_S11_2_RUNTIME_ACCESS_V1", freeze_tag=r.S11_LEGACY_TAG,
            application_commit=pair[0], application_tree=pair[1],
            control_commit="a" * 40, control_tree="b" * 40,
            source_access_identity="chatops", runtime_access_identity="root:root+chatops",
            runtime_interpreter=str(app / ".venv/bin/python"), artifacts={})
        for name, (path, mode, digest) in paths.items():
            if name in {"experience_contract", "experience_copy", "landing_copy"}:
                continue
            payload["artifacts"][name] = dict(path=str(path), mode=f"0{mode:o}", owner=0, group=0, sha256=digest)
        access.write_text(json.dumps(payload)); access.chmod(0o644)
        for name, value in dict(S11_ARTIFACTS=paths, S11_ACCESS=access,
                S11_CONTROLLER=paths["controller"][0], S11_LEGACY_APPLICATION=pair,
                S11_LEGACY_ACCESS_SHA256=r._sha256(access), S11_LOCK=installed / "transition.lock",
                APPLICATION_ROOT=app).items():
            stack.enter_context(mock.patch.object(r, name, value))
        try:
            yield payload
        finally:
            r._s11_release_transition()


class GitDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, "init")
        git(self.root, "config", "user.name", "Fixture")
        git(self.root, "config", "user.email", "fixture@example.invalid")
        (self.root / "file").write_text("approved\n")
        git(self.root, "add", "."); git(self.root, "commit", "-m", "approved")
        self.commit = git(self.root, "rev-parse", "HEAD")
        self.tree = git(self.root, "rev-parse", "HEAD^{tree}")

    def check(self, *, commit=None, reader=None):
        script = "set -Eeuo pipefail\n" + function("fail") + function("require_clean_commit")
        script += "git_chatops() { local p=$1; shift; " + (reader or 'GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$p" -C "$p" "$@"') + "; }\n"
        script += "require_clean_commit " + " ".join(shlex.quote(v) for v in
                    (str(self.root), commit or self.commit, self.tree, "TARGET_APPLICATION"))
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_real_git_historical_target_and_rollback(self):
        before = (self.root / ".git/index").read_bytes()
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual((self.root / ".git/index").read_bytes(), before)
        old = self.commit
        (self.root / "file").write_text("new approved release\n")
        git(self.root, "commit", "-am", "target")
        self.assertIn("COMMIT_DRIFT", self.check().stderr)
        self.commit = git(self.root, "rev-parse", "HEAD"); self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.assertEqual(self.check().returncode, 0)
        git(self.root, "checkout", "--detach", old)
        self.commit = old; self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.assertEqual(self.check().returncode, 0)

    def test_read_failure_is_never_drift(self):
        result = self.check(reader="return 128")
        self.assertEqual(result.returncode, 2)
        self.assertIn("COMMIT_READ_RED", result.stderr)
        self.assertNotIn("DRIFT", result.stderr)

    def test_status_failure_is_not_empty_clean_success(self):
        result = self.check(reader='if [ "$1" = status ]; then return 128; fi; GIT_OPTIONAL_LOCKS=0 git -C "$p" "$@"')
        self.assertIn("WORKTREE_READ_RED", result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_dirty_worktree_is_drift_not_read_failure(self):
        (self.root / "file").write_text("unauthorized\n")
        self.assertIn("WORKTREE_DIRTY", self.check().stderr)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "native root permission boundary")
    def test_real_quarantine_permission_failure(self):
        self.root.chmod(0o755)
        (self.root / ".git").chmod(0)
        try:
            result = self.check(reader='runuser -u nobody -- env GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$p" -C "$p" "$@"')
            self.assertIn("COMMIT_READ_RED", result.stderr)
            self.assertNotIn("DRIFT", result.stderr)
        finally:
            (self.root / ".git").chmod(0o755)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root installed-artifact boundary")
class InstalledContractTests(GitDiagnosticTests):
    def setUp(self):
        super().setUp()
        self.fixture = installed_fixture(self.root, self.root)
        self.payload = self.fixture.__enter__()
        self.addCleanup(self.fixture.__exit__, None, None, None)
        # Installed artifacts are outside the tracked tree in production.
        (self.root / ".git/info/exclude").write_text("s11-installed/\n")
        self.properties = {
            "FragmentPath": str(r.S11_ARTIFACTS["controller_unit"][0]), "DropInPaths": "",
            "NeedDaemonReload": "no", "RefuseManualStart": "yes", "TriggeredBy": r.S11_TIMER,
            "InvocationID": "2" * 32, "ExecMainStartTimestampMonotonic": "30",
            "ExecMainExitTimestampMonotonic": "40", "LastTriggerUSecMonotonic": "25",
            "ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
        }
        patch = mock.patch.object(r, "_systemctl_property", side_effect=lambda u, n:
            str(r.S11_ARTIFACTS["controller_timer"][0]) if u == r.S11_TIMER and n == "FragmentPath"
            else self.properties.get(n, ""))
        patch.start(); self.addCleanup(patch.stop)

    def test_legacy_binding_and_artifact_tamper(self):
        self.assertEqual(r._s11_release_binding()["application_commit"], self.commit)
        r.S11_CONTROLLER.write_text("unreviewed controller\n")
        with self.assertRaisesRegex(r.S12ControlError, "ARTIFACT_DRIFT"):
            r._s11_release_binding()

    def test_metadata_alias_is_red(self):
        os.link(r.S11_CONTROLLER, r.S11_CONTROLLER.with_suffix(".alias"))
        with self.assertRaisesRegex(r.S12ControlError, "ARTIFACT_READ"):
            r._s11_release_binding()

    def test_target_pair_cannot_reuse_legacy_manifest(self):
        with self.assertRaisesRegex(r.S12ControlError, "APPLICATION_DRIFT"):
            r._s11_release_binding(target=True)

    def test_target_install_actual_s11_checks_and_rollback(self):
        backup = self.root / "s11-installed/backup"; backup.mkdir()
        old_pair = r.S11_LEGACY_APPLICATION
        index = dict(schema=r.COMPATIBLE_BACKUP_SCHEMA, s11_release_contract="S11_S12_R14", files={})
        for key, path, filename in (("s11_controller", r.S11_CONTROLLER, "s11-controller.before"),
                                    ("s11_access", r.S11_ACCESS, "s11-access.before")):
            index["files"][key] = r._copy_if_present(path, backup / filename)
        control = self.root / "s11-installed/control"; control.mkdir()
        git(control, "init"); git(control, "config", "user.name", "Fixture")
        git(control, "config", "user.email", "fixture@example.invalid")
        script = control / "scripts" / r.S11_CONTROLLER.name; script.parent.mkdir()
        script.write_bytes(SOURCE.read_bytes()); git(control, "add", "."); git(control, "commit", "-m", "reviewed")
        (self.root / "file").write_text("target\n"); git(self.root, "commit", "-am", "target")
        target = (git(self.root, "rev-parse", "HEAD"), git(self.root, "rev-parse", "HEAD^{tree}"))
        r._s11_acquire_transition()
        with mock.patch.object(r, "RELEASE_CONTROL_ROOT", control), \
             mock.patch.object(r, "APPLICATION_COMMIT", target[0]), mock.patch.object(r, "APPLICATION_TREE", target[1]):
            r._install_s11_compatibility(backup, index)
            self.assertEqual(r._s11_release_binding(target=True)["application_commit"], target[0])
            # Execute the actual S11 functions with only isolated release/path
            # parameters substituted. No successful verifier result is mocked.
            definitions = "\n".join(function(n) for n in ("fail", "runtime_application_identity",
                "require_clean_commit", "require_runtime_application", "verify_runtime_access_contract"))
            for before, after in zip(("db87896697d56b24f192fc1cd0324b6fe46d734b", "b915a04e19eef8a244c300b16577a44cea89e2ab",
                                      "93555d8a141caf8ace33522f9340d30bfc47d2bb", "1e8a644115127818f394b6f9d24f31826e04ecba"),
                                     (*old_pair, *target)):
                definitions = definitions.replace(before, after)
            interpreter = self.root / ".venv/bin/python"; interpreter.parent.mkdir(parents=True)
            interpreter.write_text("#!/bin/sh\nexit 0\n"); interpreter.chmod(0o755)
            (self.root / ".git/info/exclude").write_text("s11-installed/\n.venv/\n")
            env_paths = dict(APPLICATION_ROOT=self.root, RUNTIME_ACCESS_MANIFEST=r.S11_ACCESS,
                APPLICATION_RUNTIME_PYTHON=interpreter, INSTALLED_CONTROLLER=r.S11_CONTROLLER,
                INSTALLED_GATE=r.S11_ARTIFACTS["gate"][0], INSTALLED_ORCHESTRATION=r.S11_ARTIFACTS["orchestration"][0],
                CONTROLLER_UNIT=r.S11_ARTIFACTS["controller_unit"][0], CONTROLLER_TIMER=r.S11_ARTIFACTS["controller_timer"][0],
                RETIRED_S8_HEALTH_TIMER_PATH=r.S11_ARTIFACTS["retired_s8_health_timer"][0], FINAL_CONTROL_TAG=r.S11_LEGACY_TAG)
            shell = "set -Eeuo pipefail\n" + "\n".join(k + "=" + shlex.quote(str(v)) for k, v in env_paths.items())
            shell += "\n" + definitions + '\ngit_chatops() { local p=$1; shift; GIT_OPTIONAL_LOCKS=0 git -C "$p" "$@"; }\n'
            shell += "require_runtime_application\nverify_runtime_access_contract\n"
            completed = subprocess.run(["bash", "-c", shell], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            # Byte-identical rollback and a restored real old commit cannot use
            # the target pair or its successful invocation as authorization.
            for key, filename, path in (("s11_controller", "s11-controller.before", r.S11_CONTROLLER),
                                        ("s11_access", "s11-access.before", r.S11_ACCESS)):
                r._restore_file(index["files"][key], backup / filename, path)
            git(self.root, "checkout", "--detach", old_pair[0])
            self.assertEqual(r._s11_release_binding()["application_commit"], old_pair[0])
            with self.assertRaisesRegex(r.S12ControlError, "APPLICATION_DRIFT"):
                r._s11_release_binding(target=True)

    def test_loaded_unit_bypass_rejected(self):
        self.properties["RefuseManualStart"] = "no"
        with self.assertRaisesRegex(r.S12ControlError, "LOADED_UNIT"):
            r._s11_release_binding()

    def test_fresh_natural_proof_rejects_stale_wrong_boot_and_failure(self):
        binding = r._s11_release_binding()
        epoch = r._s11_epoch(); epoch.update(after_us=20, previous_invocation="1" * 32)
        record = json.dumps(dict(_SYSTEMD_INVOCATION_ID="2" * 32, MESSAGE='{"ok":true}'))
        job = json.dumps(dict(_PID="1", UNIT=r.S11_SERVICE, JOB_TYPE="start",
            MESSAGE_ID="7d4958e842da4a758f6c1cdc7b36dcc5", __MONOTONIC_TIMESTAMP="26", INVOCATION_ID="2"*32))
        with mock.patch.object(r, "_run", side_effect=lambda argv, **kwargs:
                subprocess.CompletedProcess(argv, 0, job if "_PID=1" in argv else record, "")):
            self.assertIsNotNone(r._s11_completed_invocation(epoch, binding))
            for key, value in {"ExecMainStartTimestampMonotonic": "19", "LastTriggerUSecMonotonic": "19",
                    "InvocationID": "1" * 32, "Result": "exit-code", "ExecMainStatus": "2",
                    "ActiveState": "activating"}.items():
                with self.subTest(key=key), mock.patch.dict(self.properties, {key: value}):
                    self.assertIsNone(r._s11_completed_invocation(epoch, binding))
            with self.assertRaisesRegex(r.S12ControlError, "BOOT_CHANGED"):
                r._s11_completed_invocation(dict(epoch, boot="other"), binding)

    def test_formatted_systemd_timestamp_uses_canonical_parser(self):
        self.assertEqual(r._s11_usec("2h 3min 4s 5ms 6us"), 7384005006)
        for value in ("infinity", "18446744073709551615", "not a timestamp"):
            with self.assertRaisesRegex(r.S12ControlError, "CLOCK_VALUE"):
                r._s11_usec(value)

    def test_lock_and_interrupted_copy_restore(self):
        r._s11_acquire_transition()
        original = r.S11_CONTROLLER.read_bytes()
        backup = self.root / "s11-installed/backup"; backup.mkdir()
        index = dict(schema=r.COMPATIBLE_BACKUP_SCHEMA, s11_release_contract="S11_S12_R14", files={})
        for key, path, filename in (("s11_controller", r.S11_CONTROLLER, "s11-controller.before"),
                                     ("s11_access", r.S11_ACCESS, "s11-access.before")):
            index["files"][key] = r._copy_if_present(path, backup / filename)
        r.S11_CONTROLLER.write_text("interrupted installation\n")
        # Test actual backup hash/restore code; remaining legacy backup records
        # are not part of this isolated transition and must not be accessed.
        index["files"].update({key: {"present": False} for key in
            ("unit", "runtime_contract", "acceptance_evidence", "final_state_evidence", "deployment_result")})
        with mock.patch.object(r, "UNIT_PATH", backup / "unused-unit"), \
             mock.patch.object(r, "RUNTIME_CONTRACT", backup / "unused-runtime"), \
             mock.patch.object(r, "STATE_ROOT", backup):
            r._restore_non_repository_backup(backup, index)
        self.assertEqual(r.S11_CONTROLLER.read_bytes(), original)
        r._s11_release_binding()


class SourceContractTests(unittest.TestCase):
    def test_no_manual_s11_start_or_new_slot(self):
        self.assertEqual(r.FOLLOWUP_SLOT, "r13-followup-1")
        source = inspect.getsource(r._s11_wait_natural)
        self.assertNotIn("systemctl", source)
        self.assertIn("_s11_completed_invocation", source)
        deploy = inspect.getsource(r._deploy_locked)
        self.assertLess(deploy.index("create_backup("), deploy.index("_install_s11_compatibility("))
        self.assertLess(deploy.index("installed_s11_proof ="), deploy.index('"start", UNIT_NAME'))
        self.assertLess(deploy.index("completed_s11_proof ="), deploy.index('"deployment-result.json", result'))
        self.assertEqual(deploy.count('"start", UNIT_NAME'), 1)


if __name__ == "__main__":
    unittest.main()
