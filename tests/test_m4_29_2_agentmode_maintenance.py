from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / "scripts" / "tu1nz_sync_all.sh"
HEALTH = ROOT / "scripts" / "tu1nz_agent_health.sh"
REQUIRE_SYNC = ROOT / "scripts" / "tu1nz_require_sync.sh"
INTEGRITY = ROOT / "scripts" / "tu1nz_integrity_consolidation.sh"
MONITOR_WRAP = ROOT / "scripts" / "tu1nz_monitor_wrap.sh"
AGENT_UNIT = ROOT / "systemd" / "tu1nz_agentmode.service"
INTEGRITY_UNIT = ROOT / "systemd" / "tu1nz_integrity.service"
MONITOR_UNIT = ROOT / "systemd" / "tu1nz_monitor.service"
CANDIDATE_UNIT = ROOT / "systemd" / "tu1nz-adult-commercial-s0.service"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        command,
        cwd=cwd,
        env=merged,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def git(cwd: Path, *arguments: str) -> str:
    return run(["git", *arguments], cwd=cwd).stdout.strip()


def file_inventory(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if ".git" not in p.parts):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative + b"\0")
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode("utf-8") + b"\0")
        elif path.is_file():
            digest.update(b"F" + path.read_bytes() + b"\0")
        elif path.is_dir():
            digest.update(b"D\0")
    return digest.hexdigest()


def control_snapshot(checkout: Path) -> dict[str, str]:
    return {
        "head": git(checkout, "rev-parse", "HEAD^{commit}"),
        "tree": git(checkout, "rev-parse", "HEAD^{tree}"),
        "refs": git(checkout, "for-each-ref", "--format=%(refname) %(objectname)"),
        "tracked": git(checkout, "status", "--porcelain=v1", "--untracked-files=no"),
        "files": file_inventory(checkout),
    }


class AgentmodeMaintenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.control_remote, self.control_seed, self.control = self.make_repository(
            "control", "control-main"
        )
        self.docs_remote, self.docs_seed, self.docs = self.make_repository(
            "docs", "main"
        )
        (self.docs / "guide.pdf").write_bytes(b"synthetic-pdf-v1\n")
        git(self.docs, "add", "guide.pdf")
        git(self.docs, "commit", "-m", "add synthetic PDF")
        git(self.docs, "push", "origin", "main")
        git(self.docs, "fetch", "origin")
        git(self.docs_seed, "pull", "--ff-only", "origin", "main")

        self.state = self.root / "runtime-state"
        self.logs = self.root / "logs"
        self.run_dir = self.root / "run"
        self.notify = self.root / "missing-notify.conf"
        self.base_env = {
            "TU1NZ_CONTROL_DIR": str(self.control),
            "TU1NZ_DOCS_DIR": str(self.docs),
            "TU1NZ_STATE_DIR": str(self.state),
            "TU1NZ_LOG_DIR": str(self.logs),
            "TU1NZ_LOCK_FILE": str(self.run_dir / "observer.lock"),
            "TU1NZ_INTEGRITY_LOCK_FILE": str(self.run_dir / "integrity.lock"),
            "TU1NZ_NOTIFY_CONFIG": str(self.notify),
            "TU1NZ_REMOTE_TIMEOUT_SECONDS": "5",
            "TU1NZ_FLOCK_BIN": "/usr/bin/true",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_repository(self, name: str, branch: str) -> tuple[Path, Path, Path]:
        remote = self.root / f"{name}.git"
        seed = self.root / f"{name}-seed"
        checkout = self.root / f"{name}-checkout"
        run(["git", "init", "--bare", str(remote)])
        run(["git", "init", "-b", branch, str(seed)])
        git(seed, "config", "user.name", "TU1NZ Test")
        git(seed, "config", "user.email", "test@example.invalid")
        (seed / "README.txt").write_text(f"{name}-v1\n", encoding="ascii")
        git(seed, "add", "README.txt")
        git(seed, "commit", "-m", "initial")
        git(seed, "remote", "add", "origin", str(remote))
        git(seed, "push", "-u", "origin", branch)
        run(["git", "clone", "--branch", branch, str(remote), str(checkout)])
        git(checkout, "config", "user.name", "TU1NZ Test")
        git(checkout, "config", "user.email", "test@example.invalid")
        return remote, seed, checkout

    def advance(self, seed: Path, filename: str, content: str, branch: str) -> str:
        (seed / filename).write_text(content, encoding="ascii")
        git(seed, "add", filename)
        git(seed, "commit", "-m", f"advance {filename}")
        git(seed, "push", "origin", branch)
        return git(seed, "rev-parse", "HEAD")

    def run_sync(self, mode: str, *, extra_env: dict[str, str] | None = None, check: bool = True):
        environment = dict(self.base_env)
        if extra_env:
            environment.update(extra_env)
        return run(["bash", str(SYNC), mode], env=environment, check=check)

    def test_check_current_is_completely_read_only(self) -> None:
        before = control_snapshot(self.control)
        result = self.run_sync("--check")
        after = control_snapshot(self.control)

        self.assertEqual(before, after)
        self.assertTrue(result.stdout.startswith("CONTROL_CURRENT "))
        self.assertFalse(self.state.exists())
        self.assertFalse(self.logs.exists())
        self.assertFalse(self.run_dir.exists())

    def test_remote_drift_reports_update_without_fast_forward_or_ref_change(self) -> None:
        remote_head = self.advance(
            self.control_seed, "remote.txt", "remote-v2\n", "control-main"
        )
        before = control_snapshot(self.control)
        result = self.run_sync("--check")
        after = control_snapshot(self.control)

        self.assertEqual(before, after)
        self.assertIn("CONTROL_UPDATE_AVAILABLE", result.stdout)
        self.assertIn(f"remote={remote_head}", result.stdout)
        self.assertNotEqual(before["head"], remote_head)

    def test_observe_preserves_docs_policy_but_never_mutates_control(self) -> None:
        new_docs_head = self.advance(self.docs_seed, "new.pdf", "pdf-v2\n", "main")
        remote_control_head = self.advance(
            self.control_seed, "remote.txt", "remote-v2\n", "control-main"
        )
        before = control_snapshot(self.control)
        self.run_sync("--observe-once")
        after = control_snapshot(self.control)

        self.assertEqual(before, after)
        self.assertEqual(git(self.docs, "rev-parse", "HEAD"), new_docs_head)
        state = json.loads((self.state / "control_update_state.json").read_text())
        self.assertEqual(state["status"], "CONTROL_UPDATE_AVAILABLE")
        self.assertEqual(state["remote_sha"], remote_control_head)
        self.assertEqual(state["docs_status"], "DOCS_SYNCED")
        self.assertTrue((self.state / "last_sync.ok").is_file())
        self.assertTrue((self.state / "docs-checksums.txt").is_file())
        self.assertFalse((self.control / "last_sync.ok").exists())
        self.assertFalse((self.control / "checksums.txt").exists())

    def test_state_aware_transition_notification_does_not_spam(self) -> None:
        self.notify.write_text("BOT_TOKEN=test-token\nALERT_CHAT_ID=12345\n", encoding="ascii")
        curl_log = self.root / "curl.log"
        fake_curl = self.root / "fake-curl"
        fake_curl.write_text(
            "#!/usr/bin/env bash\ncat >/dev/null\nprintf 'call\\n' >>\"$TU1NZ_TEST_CURL_LOG\"\n",
            encoding="ascii",
        )
        fake_curl.chmod(0o755)
        environment = {
            "TU1NZ_CURL_BIN": str(fake_curl),
            "TU1NZ_TEST_CURL_LOG": str(curl_log),
        }

        self.run_sync("--observe-once", extra_env=environment)
        self.run_sync("--observe-once", extra_env=environment)
        self.assertEqual(curl_log.read_text().splitlines(), ["call"])
        self.assertEqual(
            (self.logs / "control-transitions.log").read_text().count("CONTROL_CURRENT"),
            1,
        )

        self.advance(self.control_seed, "remote.txt", "remote-v2\n", "control-main")
        self.run_sync("--observe-once", extra_env=environment)
        self.run_sync("--observe-once", extra_env=environment)
        self.assertEqual(curl_log.read_text().splitlines(), ["call", "call"])
        self.assertEqual(
            (self.logs / "control-transitions.log").read_text().count(
                "CONTROL_UPDATE_AVAILABLE"
            ),
            1,
        )

    def test_network_failure_is_fail_closed(self) -> None:
        git(self.control, "remote", "set-url", "origin", str(self.root / "absent.git"))
        before = control_snapshot(self.control)
        result = self.run_sync("--check", check=False)
        after = control_snapshot(self.control)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CONTROL_REMOTE_CHECK_FAILED", result.stdout)
        self.assertEqual(before, after)

    def test_malformed_remote_response_is_fail_closed(self) -> None:
        real_git = shutil.which("git")
        assert real_git is not None
        fake_git = self.root / "fake-git"
        fake_git.write_text(
            "#!/usr/bin/env bash\n"
            "for argument in \"$@\"; do\n"
            "  if [[ \"$argument\" == ls-remote ]]; then\n"
            "    printf 'not-a-sha refs/heads/control-main\\n'\n"
            "    exit 0\n"
            "  fi\n"
            "done\n"
            "exec \"$TU1NZ_REAL_GIT\" \"$@\"\n",
            encoding="ascii",
        )
        fake_git.chmod(0o755)
        before = control_snapshot(self.control)
        result = self.run_sync(
            "--check",
            extra_env={"TU1NZ_GIT_BIN": str(fake_git), "TU1NZ_REAL_GIT": real_git},
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CONTROL_REMOTE_RESPONSE_INVALID", result.stdout)
        self.assertEqual(before, control_snapshot(self.control))

    def test_health_uses_true_check_without_control_mutation(self) -> None:
        marker = self.root / "agent-mode.marker"
        marker.touch()
        fake_systemctl = self.root / "fake-systemctl"
        fake_systemctl.write_text("#!/usr/bin/env bash\nprintf 'inactive\\n'\n", encoding="ascii")
        fake_systemctl.chmod(0o755)
        before = control_snapshot(self.control)
        result = run(
            ["bash", str(HEALTH)],
            env={
                **self.base_env,
                "TU1NZ_SYNC_COMMAND": str(SYNC),
                "TU1NZ_SYSTEMCTL_BIN": str(fake_systemctl),
                "TU1NZ_AGENT_MODE_MARKER": str(marker),
                "TU1NZ_SSOT_CHECKSUM": str(self.root / "missing-checksum"),
            },
        )
        self.assertIn("CONTROL: CONTROL_CURRENT", result.stdout)
        self.assertEqual(before, control_snapshot(self.control))
        self.assertFalse(self.state.exists())

    def test_integrity_writes_only_external_state_and_is_transition_aware(self) -> None:
        self.state.mkdir(mode=0o750)
        (self.state / "last_sync.ok").write_text(
            "status=CONTROL_CURRENT local_sha=abc remote_sha=abc observed_at=2026-08-28T20:00:00Z\n",
            encoding="ascii",
        )
        before = control_snapshot(self.control)
        environment = {
            **self.base_env,
            "TU1NZ_REQUIRE_SYNC": str(REQUIRE_SYNC),
            "TU1NZ_LAST_SYNC_FILE": str(self.state / "last_sync.ok"),
            "TU1NZ_INTEGRITY_DIR": str(self.state / "integrity"),
        }
        run(["bash", str(INTEGRITY)], env=environment)
        run(["bash", str(INTEGRITY)], env=environment)
        self.assertEqual(before, control_snapshot(self.control))
        integrity_state = json.loads(
            (self.state / "integrity" / "integrity_state.json").read_text()
        )
        self.assertEqual(integrity_state["status"], "INTEGRITY_OK")
        self.assertEqual(integrity_state["control_head"], before["head"])
        self.assertEqual(
            (self.logs / "integrity-transitions.log").read_text().count("INTEGRITY_OK"),
            1,
        )

    def test_monitor_output_is_external(self) -> None:
        fake_monitor = self.root / "fake-monitor"
        fake_alert = self.root / "fake-alert"
        fake_monitor.write_text("#!/usr/bin/env bash\nprintf 'MONITOR_OK\\n'\n", encoding="ascii")
        fake_alert.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="ascii")
        fake_monitor.chmod(0o755)
        fake_alert.chmod(0o755)
        before = control_snapshot(self.control)
        run(
            ["bash", str(MONITOR_WRAP)],
            env={
                "TU1NZ_STATE_DIR": str(self.state),
                "TU1NZ_MONITOR_COMMAND": str(fake_monitor),
                "TU1NZ_ALERT_COMMAND": str(fake_alert),
            },
        )
        self.assertEqual(before, control_snapshot(self.control))
        self.assertEqual((self.state / "monitor_last.txt").read_text(), "MONITOR_OK\n")

    def test_runtime_permissions_and_static_control_boundary(self) -> None:
        self.run_sync("--observe-once")
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o750)
        for name in (
            "control_update_state.json",
            "last_sync.ok",
            "docs-checksums.txt",
            "notification_state",
        ):
            self.assertEqual(stat.S_IMODE((self.state / name).stat().st_mode), 0o640)

        agent_unit = AGENT_UNIT.read_text(encoding="ascii")
        integrity_unit = INTEGRITY_UNIT.read_text(encoding="ascii")
        monitor_unit = MONITOR_UNIT.read_text(encoding="ascii")
        for unit in (agent_unit, integrity_unit, monitor_unit):
            self.assertIn("ReadOnlyPaths=/opt/tu1nz_repos/control", unit)
            self.assertNotIn("tu1nz-adult-commercial-s0", unit)
        self.assertIn("PrivateNetwork=yes", integrity_unit)

    def test_no_forbidden_control_git_mutators_or_candidate_activation(self) -> None:
        sync_source = SYNC.read_text(encoding="ascii")
        for forbidden in (" pull ", " merge ", " checkout ", " clean "):
            self.assertNotIn(forbidden, sync_source)
        self.assertNotIn('"$CONTROL_DIR" fetch', sync_source)
        self.assertNotIn('"$CONTROL_DIR" reset', sync_source)
        self.assertIn('"$DOCS_DIR" fetch --all -q', sync_source)
        self.assertIn('"$DOCS_DIR" reset --hard', sync_source)

        candidate = CANDIDATE_UNIT.read_text(encoding="ascii")
        self.assertIn("Restart=no", candidate)
        self.assertNotIn("[Install]", candidate)
        for path in (SYNC, HEALTH, REQUIRE_SYNC, INTEGRITY, MONITOR_WRAP):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("systemctl start", source)
            self.assertNotIn("systemctl restart", source)
            self.assertNotIn("systemctl enable", source)


if __name__ == "__main__":
    unittest.main()
