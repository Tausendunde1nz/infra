"""Real one-shot journal/fence handoff. Only disposable native Linux CI."""
import array
import fcntl
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tu1nz_s8_execution_contract import ContractError
from tu1nz_s8_journal_fence import APPEND, GET_FLAGS, SET_FLAGS
from tu1nz_s8_protected_journal import ProtectedJournal


def flags(fd, value=None):
    raw = array.array("L", [0 if value is None else value])
    fcntl.ioctl(fd, GET_FLAGS if value is None else SET_FLAGS, raw, True)
    return raw[0]


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0
                    and os.environ.get("container") == "docker", "disposable native Linux only")
class ProtectedJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="s8-protected-log-", dir="/var/tmp")
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "one-shot"
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        flags(self.parent_fd, flags(self.parent_fd) | APPEND)
        self.journal = None

    def tearDown(self):
        if self.journal is not None:
            self.journal.close()
        # Test-only removal of flags on this case's exact disposable objects.
        # No such reset/cleanup operation exists in the production contract.
        objects = list(self.root.iterdir()) + [self.root] if self.root.exists() else []
        for path in objects:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                flags(fd, flags(fd) & ~0x30)
            finally:
                os.close(fd)
        flags(self.parent_fd, flags(self.parent_fd) & ~APPEND)
        os.close(self.parent_fd)
        self.temporary.cleanup()

    def test_successful_records_remain_sealed_after_fence_handoff(self):
        self.journal = ProtectedJournal(self.root)
        for name in ("operation.json", "activation.json", "execution.json"):
            self.assertEqual(self.journal.once(name, {"bound": name}), {"bound": name})
        self.journal.handoff()
        for path in self.root.iterdir():
            with self.assertRaises(PermissionError):
                path.write_bytes(b"forged")
            with self.assertRaises(PermissionError):
                path.chmod(0o644)
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED_NO_RETRY"):
            ProtectedJournal(self.root)
        with self.assertRaisesRegex(ContractError, "JOURNAL_NO_AUTHORITY"):
            self.journal.read("execution.json")

    def test_unprotected_parent_is_not_a_provenance_anchor(self):
        flags(self.parent_fd, flags(self.parent_fd) & ~APPEND)
        with self.assertRaisesRegex(ContractError, "APPEND_ONLY_PARENT_REQUIRED"):
            ProtectedJournal(self.root)
        self.assertFalse(self.root.exists())

    def test_lost_write_ack_consumes_slot_and_latches_failure(self):
        self.journal = ProtectedJournal(self.root)
        original_write = os.write
        def lost_record_write(fd, value):
            if value == b'{"bound":true}':
                raise OSError("offline lost write")
            return original_write(fd, value)
        with patch("tu1nz_s8_execution_contract.os.write", side_effect=lost_record_write):
            with self.assertRaises(OSError):
                self.journal.once("operation.json", {"bound": True})
        self.assertEqual((self.root / "operation.json").stat().st_size, 0)
        with self.assertRaisesRegex(ContractError, "JOURNAL_NO_AUTHORITY"):
            self.journal.once("operation.json", {"bound": True})
        self.journal.close()
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED_NO_RETRY"):
            ProtectedJournal(self.root)

    def test_sigkill_after_first_sealed_record_never_reopens_slot(self):
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                journal = ProtectedJournal(self.root)
                journal.once("operation.json", {"consumed": True})
                os.write(writer, b"ready")
                signal.pause()
            except BaseException:
                os._exit(99)
        os.close(writer)
        try:
            self.assertEqual(os.read(reader, 5), b"ready")
            os.kill(child, signal.SIGKILL)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), -signal.SIGKILL)
            child = None
            with self.assertRaises(PermissionError):
                (self.root / "operation.json").write_bytes(b"forged")
            with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED_NO_RETRY"):
                ProtectedJournal(self.root)
        finally:
            os.close(reader)
            if child is not None:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)

    def test_competitor_cannot_adopt_empty_created_directory(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED_NO_RETRY"):
            ProtectedJournal(self.root)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
