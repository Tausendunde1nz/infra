import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("tu1nz_privilege_inventory.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InventoryTests(unittest.TestCase):
    def test_known_rule(self):
        rule = b"chatops ALL=(ALL) NOPASSWD: /bin/mkdir, /bin/chown"
        self.assertEqual(m.policy_lines(rule)[0]["definition"], rule.decode())

    def test_unknown_rule_not_disclosed(self):
        for raw in (b"Defaults env_keep += SECRET_CANARY", b"chatops ALL=(ALL) NOPASSWD: /bin/chown SECRET_CANARY", b"SECRET_CANARY ALL=(ALL) ALL"):
            rows = m.policy_lines(raw)
            self.assertNotIn("SECRET_CANARY", str(rows))
            self.assertEqual(rows[0]["classification"], "UNREVIEWED")

    def test_include_not_silently_ignored(self):
        self.assertEqual(m.policy_lines(b"#includedir /private/SECRET_CANARY")[0]["classification"], "UNREVIEWED")

    def test_comments_not_disclosed(self):
        self.assertEqual(m.policy_lines(b"# SECRET_CANARY\n\n"), [])

    def test_extra_args_rejected(self):
        with patch.object(m.sys, "argv", ["inventory", "--path=/etc"]):
            self.assertEqual(m.main(), 3)

    def test_nonroot_rejected(self):
        with patch.object(m.sys, "argv", ["inventory"]), patch.object(m.os, "geteuid", return_value=1001):
            self.assertEqual(m.main(), 3)

    def test_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"link"
            p.symlink_to("/does/not/exist")
            with patch.object(m, "command", return_value=({"complete": True}, b"")):
                info = m.metadata(str(p))
            self.assertEqual(info["type"], "symlink")
            self.assertNotIn("sha256", info)

    def test_file_contents_and_acl_comments_not_disclosed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"fixture"
            p.write_text("SECRET_CANARY")
            with patch.object(m, "command", return_value=({"complete": True}, b"# SECRET_CANARY\nuser::rw-\nmask::r--\n")):
                info = m.metadata(str(p))
            self.assertNotIn("SECRET_CANARY", str(info))
            self.assertEqual(info["acl"], ["user::rw-", "mask::r--"])

    def test_program_failure_redacted(self):
        with patch.object(m.subprocess, "Popen", side_effect=PermissionError("SECRET_CANARY")):
            info = m.command(("/fixed/fake",))
        self.assertFalse(info["complete"])
        self.assertNotIn("SECRET_CANARY", str(info))

    def test_timeout_kills_group(self):
        class Fake:
            pid = 987654321
            returncode = -9
            first = True
            def wait(self, timeout=None):
                if self.first:
                    self.first = False
                    raise m.subprocess.TimeoutExpired("SECRET_CANARY", 1)
                return self.returncode
        with patch.object(m.subprocess, "Popen", return_value=Fake()) as popen, patch.object(m.os, "killpg") as kill:
            info, data = m.command(("/fixed/fake",), 1)
        self.assertTrue(info["timeout"])
        self.assertFalse(info["complete"])
        self.assertEqual(data, b"")
        kill.assert_called_once_with(987654321, m.signal.SIGKILL)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["env"], m.ENV)


if __name__ == "__main__":
    unittest.main()
