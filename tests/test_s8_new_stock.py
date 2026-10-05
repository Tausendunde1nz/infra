"""Native new-object provenance, immutable handoff and interruption refusal."""
import array
import fcntl
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tu1nz_s8_execution_contract import ContractError
from tu1nz_s8_new_stock import NewStock, ParentCreationWitness
from tu1nz_s8_protected_journal import ProtectedJournal


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and
                    os.environ.get("container") == "docker", "disposable native kernel only")
class NewStockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tu1nz-new-stock-", dir="/etc")
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "stock"
        self.umask = os.umask(0o077)
        self.content = b"frozen isolated fixture\n"
        self.plan = {"component": dict(sha256=hashlib.sha256(self.content).hexdigest(), size=len(self.content))}

    def tearDown(self):
        # Only disposable fixture inodes. The source API never clears flags.
        for path in sorted([*self.parent.rglob("*"), self.parent], key=lambda p: len(p.parts), reverse=True):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                flags = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, flags, True)
                flags[0] &= ~0x30; fcntl.ioctl(fd, 0x40086602, flags)
            finally: os.close(fd)
        self.temporary.cleanup()
        os.umask(self.umask)

    def test_new_bound_files_sealed_but_separate_state_accepts_one_journal(self):
        stock = NewStock(self.root, self.plan, state_directory=True)
        stock.put("component", self.content)
        result = stock.seal()
        self.assertIs(result["live_authority"], False)
        self.assertEqual((self.root / "component").read_bytes(), self.content)
        for action in (lambda: (self.root / "component").write_bytes(b"foreign"),
                       lambda: (self.root / "component").chmod(0o666),
                       lambda: (self.root / "unexpected").write_bytes(b"foreign"),
                       lambda: self.root.rename(self.parent / "rebound")):
            with self.assertRaises(OSError): action()
        journal = ProtectedJournal(self.root / "state/attempt")
        journal.once("consumed.json", dict(test_only=True)); journal.handoff()
        with self.assertRaisesRegex(ContractError, "ALREADY_CONSUMED"):
            ProtectedJournal(self.root / "state/attempt")
        with self.assertRaisesRegex(ContractError, "NO_ADOPTION"):
            NewStock(self.root, self.plan)

    def test_wrong_input_and_acl_drift_do_not_publish_authority(self):
        stock = NewStock(self.root, self.plan)
        try:
            with self.assertRaisesRegex(ContractError, "STOCK_INPUT_RED"):
                stock.put("component", b"foreign")
            self.assertFalse((self.root / "component").exists())
            with self.assertRaisesRegex(ContractError, "NO_AUTHORITY"): stock.seal()
        finally: stock.close()
        with self.assertRaisesRegex(ContractError, "NO_ADOPTION"): NewStock(self.root, self.plan)

    def test_acl_event_is_latched_before_any_seal(self):
        stock = NewStock(self.root, self.plan)
        try:
            os.setxattr(self.root, "user.synthetic", b"foreign")
            os.removexattr(self.root, "user.synthetic")
            with self.assertRaises(ContractError): stock.put("component", self.content)
            with self.assertRaisesRegex(ContractError, "NO_AUTHORITY"): stock.seal()
        finally: stock.close()

    def test_interrupted_new_stock_is_never_adopted(self):
        pid = os.fork()
        if pid == 0:
            NewStock(self.root, self.plan)
            os._exit(0)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
        with self.assertRaisesRegex(ContractError, "NO_ADOPTION"): NewStock(self.root, self.plan)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {"stock-plan.json"})

    def test_parent_witness_rejects_rename_and_restore(self):
        witness = ParentCreationWitness(self.parent, self.root.name)
        try:
            self.root.mkdir(mode=0o700)
            witness.check(require_creation=True)
            other = self.parent / "other"
            self.root.rename(other); other.rename(self.root)
            with self.assertRaisesRegex(ContractError, "STOCK_PATH_CHANGED"):
                witness.check(require_creation=True)
        finally: witness.close()


if __name__ == "__main__": unittest.main()
