"""Non-root fixtures only; no production writes or service execution."""
import copy
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from tu1nz_privilege_root_writer_guard import classify, UNITS, PARENT


def fixture():
    return {
        "collector_uid": 1001,
        "files": {PARENT: {"path": PARENT, "uid": 1001, "mode": "0755",
                            "symlink": False, "writable_by_collector": True}},
        "fixed_write_verified": {"mkdir_line_23": True, "tee_line_24": True},
        "units": {u: {
            "execstart_exact_fixed_script": True,
            "timer": {"ActiveState": "active"},
            "service": {"User": "", "ProtectSystem": "no", "RootDirectory": "",
                        "RootImage": "", "ReadOnlyPaths": "", "ReadWritePaths": "",
                        "InaccessiblePaths": "", "DropInPaths": ""}
        } for u in UNITS},
    }


class EvidenceTests(unittest.TestCase):
    def test_root_default_is_blocker(self):
        self.assertEqual(classify(fixture()), "BLOCKED_ROOT_WRITE_THROUGH_CHATOPS_DIRECTORY")

    def test_explicit_root_is_blocker(self):
        e = fixture()
        for u in UNITS:
            e["units"][u]["service"]["User"] = "root"
        self.assertEqual(classify(e), "BLOCKED_ROOT_WRITE_THROUGH_CHATOPS_DIRECTORY")

    def test_nonroot_is_not_this_finding(self):
        e = fixture()
        for u in UNITS:
            e["units"][u]["service"]["User"] = "chatops"
        self.assertEqual(classify(e), "NOT_THIS_FINDING")

    def test_unknown_sandbox_cannot_be_declared_safe(self):
        for key, value in [("ProtectSystem", "strict"), ("ReadOnlyPaths", "/opt"),
                           ("ReadWritePaths", "/opt/trendwatch"),
                           ("RootDirectory", "/unknown"), ("DropInPaths", "/unknown")]:
            e = fixture()
            e["units"][UNITS[0]]["service"][key] = value
            self.assertEqual(classify(e), "REVIEW_REQUIRED")

    def test_missing_evidence_fails_closed(self):
        for key in fixture():
            e = fixture()
            del e[key]
            self.assertEqual(classify(e), "REVIEW_REQUIRED")

    def test_unknown_writer_or_parent_fails_closed(self):
        e = fixture()
        e["fixed_write_verified"]["tee_line_24"] = False
        self.assertEqual(classify(e), "REVIEW_REQUIRED")
        e = fixture()
        e["files"][PARENT]["symlink"] = True
        self.assertEqual(classify(e), "REVIEW_REQUIRED")

    def test_removing_unrelated_grants_does_not_change_root_writer(self):
        e = fixture()
        before = classify(e)
        e["chatops_sudo_grants"] = []
        e["chatops_docker_member"] = False
        self.assertEqual(classify(e), before)


class FilesystemSemanticsTests(unittest.TestCase):
    def setUp(self):
        if os.getuid() == 0:
            self.fail("This proof must run without root")
        self.temp = tempfile.TemporaryDirectory(prefix="privilege-root-writer-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.base.chmod(0o700)

    def test_tee_follows_replaced_entry_in_owned_directory(self):
        owned = self.base / "owned"
        owned.mkdir(mode=0o755)
        owned.chmod(0o755)
        intended = owned / "status.txt"
        intended.write_bytes(b"previous-status\n")
        # The target represents a separate file, NOT a real privileged path.
        other = self.base / "separate-fixture.txt"
        other.write_bytes(b"previous-separate-content\n")
        other.chmod(0o600)
        intended.unlink()
        intended.symlink_to(other)
        result = subprocess.run(["/usr/bin/tee", str(intended)], input=b"fixture-status\n",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(other.read_bytes(), b"fixture-status\n")
        self.assertTrue(intended.is_symlink())
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o600)
        self.assertEqual(other.stat().st_uid, os.getuid())

    def test_nofollow_rejects_same_fixture(self):
        other = self.base / "separate-fixture.txt"
        other.write_bytes(b"unchanged\n")
        link = self.base / "status.txt"
        link.symlink_to(other)
        with self.assertRaises(OSError):
            os.open(link, os.O_WRONLY | os.O_NOFOLLOW)
        self.assertEqual(other.read_bytes(), b"unchanged\n")


if __name__ == "__main__":
    unittest.main()
